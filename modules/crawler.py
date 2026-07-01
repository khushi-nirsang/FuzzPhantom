"""
FuzzPhantom — URL Crawler
Async BFS crawler that extracts all reachable URLs, form actions,
script sources, and parameterized URLs from a target domain.
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

from bs4 import BeautifulSoup
import tldextract

from core.context import ScanContext
from core.session import FuzzSession
from core.logger import get_logger, console

logger = get_logger(__name__)

# Regex to find URLs in JavaScript source
_JS_URL_RE = re.compile(
    r"""(?:["'`])(\/[a-zA-Z0-9_/\-\.]+(?:\?[^"'`\s]*)?)(?:["'`])""",
    re.MULTILINE,
)

_STATIC_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".pdf",
    ".css",
}


def _is_same_domain(url: str, root_domain: str) -> bool:
    """Check if a URL belongs to the same registered root domain."""
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" == root_domain


def _is_static(url: str) -> bool:
    """Return True if the URL points to a known static asset."""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXTS)


def _has_params(url: str) -> bool:
    """Return True if the URL has query parameters."""
    return bool(urlparse(url).query)


def _extract_links(html: str, base_url: str) -> set[str]:
    """Parse HTML and extract all links, form actions, and script src."""
    soup = BeautifulSoup(html, "lxml")
    links: set[str] = set()

    for tag in soup.find_all("a", href=True):
        href = str(tag["href"]).strip()
        if href and not href.startswith(("javascript:", "mailto:", "#")):
            links.add(urljoin(base_url, href))

    for form in soup.find_all("form", action=True):
        action = str(form["action"]).strip()
        if action:
            links.add(urljoin(base_url, action))

    for script in soup.find_all("script", src=True):
        src = str(script["src"]).strip()
        if src:
            links.add(urljoin(base_url, src))

    return links


def _extract_js_routes(js_content: str, base_url: str) -> set[str]:
    """Extract URL-like paths from JavaScript source."""
    routes: set[str] = set()
    for match in _JS_URL_RE.finditer(js_content):
        path = match.group(1)
        full = urljoin(base_url, path)
        routes.add(full)
    return routes


async def _fetch_page(
    url: str, session: FuzzSession
) -> tuple[str, str]:
    """Fetch a page and return (final_url, html_body)."""
    try:
        resp = await session.get(url, allow_redirects=True)
        if resp is None:
            return url, ""
        async with resp:
            final_url = str(resp.url)
            content_type = resp.headers.get("Content-Type", "").lower()
            
            # Check Content-Length if present
            content_length = resp.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > 2 * 1024 * 1024:  # 2MB limit
                        logger.debug(f"Skipping large resource {url} ({content_length} bytes)")
                        return final_url, ""
                except ValueError:
                    pass

            if resp.status >= 400:
                return final_url, ""

            if any(t in content_type for t in ("html", "javascript", "text", "json")):
                # Read at most 2MB of body in chunks
                chunks = []
                bytes_read = 0
                max_bytes = 2 * 1024 * 1024
                while bytes_read < max_bytes:
                    chunk = await resp.content.read(65536)  # 64KB chunks
                    if not chunk:
                        break
                    chunks.append(chunk)
                    bytes_read += len(chunk)
                
                body = b"".join(chunks).decode(errors="replace")
                return final_url, body
            return final_url, ""
    except Exception as exc:
        logger.debug(f"Fetch error {url}: {exc}")
        return url, ""


async def crawl(ctx: ScanContext, start_urls: list[str] | None = None) -> None:
    """
    Async BFS crawler. Discovers all reachable URLs up to ctx.crawl_depth.
    Populates ctx.crawled_urls, ctx.parameterized_urls, ctx.js_files.
    """
    console.rule("[bold cyan]URL Crawler[/bold cyan]")

    if start_urls is None:
        targets = [ctx.target_domain] + ctx.subdomains
        start_urls = [
            u if u.startswith("http") else f"https://{u}"
            for u in targets
        ]

    # Derive root domain for scope filtering
    ext = tldextract.extract(ctx.target_domain)
    root_domain = f"{ext.domain}.{ext.suffix}"

    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque(
        [(url, 0) for url in start_urls]
    )

    async with FuzzSession(ctx) as session:
        while queue:
            # Process up to `threads` URLs concurrently per BFS level
            batch: list[tuple[str, int]] = []
            while queue and len(batch) < ctx.threads:
                item = queue.popleft()
                url, depth = item
                # Normalise URL
                parsed = urlparse(url)
                clean = urlunparse(parsed._replace(fragment=""))
                if clean in visited:
                    continue
                if not _is_same_domain(clean, root_domain):
                    continue
                if _is_static(clean):
                    continue
                if depth > ctx.crawl_depth:
                    continue
                visited.add(clean)
                batch.append((clean, depth))

            if not batch:
                continue

            results = await asyncio.gather(
                *[_fetch_page(url, session) for url, _ in batch]
            )

def _extract_parent_directories(url: str) -> list[str]:
    """Extract parent directory paths from a URL to enable recursive crawling."""
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == "/":
        return []
    parts = [p for p in path.split("/") if p]
    dirs = []
    for i in range(1, len(parts)):
        subpath = "/" + "/".join(parts[:i])
        if not subpath.endswith("/"):
            subpath += "/"
        dirs.append(urlunparse(parsed._replace(path=subpath, query="", fragment="")))
    return dirs


async def crawl(ctx: ScanContext, start_urls: list[str] | None = None) -> None:
    """
    Async BFS crawler. Discovers all reachable URLs up to ctx.crawl_depth.
    Populates ctx.crawled_urls, ctx.parameterized_urls, ctx.js_files.
    """
    console.rule("[bold cyan]URL Crawler[/bold cyan]")

    if start_urls is None:
        targets = [ctx.target_domain] + ctx.subdomains
        start_urls = [
            u if u.startswith("http") else f"https://{u}"
            for u in targets
        ]

    # Derive root domain for scope filtering
    ext = tldextract.extract(ctx.target_domain)
    root_domain = f"{ext.domain}.{ext.suffix}"

    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque(
        [(url, 0) for url in start_urls]
    )

    async with FuzzSession(ctx) as session:
        while queue:
            # Process up to `threads` URLs concurrently per BFS level
            batch: list[tuple[str, int]] = []
            while queue and len(batch) < ctx.threads:
                item = queue.popleft()
                url, depth = item
                # Normalise URL
                parsed = urlparse(url)
                clean = urlunparse(parsed._replace(fragment=""))
                if clean in visited:
                    continue
                if not _is_same_domain(clean, root_domain):
                    continue
                if _is_static(clean):
                    continue
                if depth > ctx.crawl_depth:
                    continue
                visited.add(clean)
                batch.append((clean, depth))

            if not batch:
                continue

            results = await asyncio.gather(
                *[_fetch_page(url, session) for url, _ in batch]
            )

            for (url, depth), (final_url, body) in zip(batch, results):
                if not body:
                    continue

                ctx.add_url(final_url)
                logger.info(f"  Crawled: [cyan]{final_url}[/cyan]")

                if _has_params(final_url):
                    ctx.add_parameterized_url(final_url)

                for parent_dir in _extract_parent_directories(final_url):
                    if parent_dir not in visited:
                        queue.append((parent_dir, depth + 1))

                if final_url.endswith(".js") or ".js?" in final_url:
                    ctx.add_js_file(final_url)
                    js_routes = _extract_js_routes(body, final_url)
                    for route in js_routes:
                        if _is_same_domain(route, root_domain):
                            queue.append((route, depth + 1))

                new_links = _extract_links(body, final_url)
                for link in new_links:
                    if link.endswith(".js") or ".js?" in link:
                        ctx.add_js_file(link)
                    if _has_params(link):
                        ctx.add_parameterized_url(link)
                    if link not in visited:
                        queue.append((link, depth + 1))
                    for parent_dir in _extract_parent_directories(link):
                        if parent_dir not in visited:
                            queue.append((parent_dir, depth + 1))

    logger.info(
        f"[bold green]Crawl complete.[/bold green] "
        f"URLs: [bold]{len(ctx.crawled_urls)}[/bold]  "
        f"Parameterized: [bold]{len(ctx.parameterized_urls)}[/bold]  "
        f"JS files: [bold]{len(ctx.js_files)}[/bold]"
    )
