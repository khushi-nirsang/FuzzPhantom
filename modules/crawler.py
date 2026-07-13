"""
FuzzPhantom — URL Crawler  v2
Async BFS crawler that extracts all reachable URLs, form actions,
script sources, and parameterized URLs from a target domain.

Phase 1: BFS crawl of all in-scope HTML pages
Phase 2: Analyse ALL collected JS files (including CDN-hosted) for
         hidden API routes, fetch/axios calls, and router definitions
Phase 3: Extract form <input> fields to build parameterised URL list
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
import tldextract

from core.context import ScanContext
from core.session import FuzzSession
from core.logger import get_logger, console

logger = get_logger(__name__)

# ── JS Route Extraction Patterns ──────────────────────────────────────────────
# 1. Plain string paths
_JS_PLAIN_RE = re.compile(
    r"""(?:["'`])(\/[a-zA-Z0-9_/\-\.]+(?:\?[^"'`\s]*)?)(?:["'`])""",
    re.MULTILINE,
)
# 2. fetch() / axios.get|post|put|patch|delete|head
_JS_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch|head)|http\.(?:get|post|put|delete))\s*\(\s*["'`](\/[^"'`\s\)]{2,})["'`]""",
    re.MULTILINE | re.IGNORECASE,
)
# 3. API prefix strings  /api/... /v1/... /rest/... /graphql
_JS_API_RE = re.compile(
    r"""["'`](\/(?:api|v\d+|rest|graphql|gql|service|services|rpc|data|backend)[^"'`\s\)]{0,120})["'`]""",
    re.MULTILINE,
)
# 4. Route definitions — React Router / Vue Router / Angular
_JS_ROUTEDEF_RE = re.compile(
    r"""(?:path|route|href|url|endpoint|to)\s*[:=]\s*["'`](\/[^"'`\s\)]{2,})["'`]""",
    re.MULTILINE,
)
# 5. XMLHttpRequest open()
_JS_XHR_RE = re.compile(
    r"""\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'`](\/[^"'`\s]{2,})["'`]""",
    re.MULTILINE | re.IGNORECASE,
)

_STATIC_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".pdf", ".css",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_same_domain(url: str, root_domain: str) -> bool:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" == root_domain


def _is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXTS)


def _has_params(url: str) -> bool:
    return bool(urlparse(url).query)


def _extract_links(html: str, base_url: str) -> tuple[set[str], list[str]]:
    """Parse HTML → (all links, form_param_urls)."""
    soup = BeautifulSoup(html, "lxml")
    links: set[str] = set()
    form_urls: list[str] = []

    # <a href>
    for tag in soup.find_all("a", href=True):
        href = str(tag["href"]).strip()
        if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
            links.add(urljoin(base_url, href))

    # <form action> with input names → parameterised URL
    for form in soup.find_all("form"):
        action = str(form.get("action", "")).strip()
        action_url = urljoin(base_url, action) if action else base_url
        inputs = form.find_all(["input", "select", "textarea"])
        params = {
            inp.get("name"): inp.get("value", "FUZZ")
            for inp in inputs
            if inp.get("name")
        }
        if params:
            from urllib.parse import urlencode
            qs = urlencode(params)
            param_url = f"{action_url}?{qs}" if "?" not in action_url else f"{action_url}&{qs}"
            form_urls.append(param_url)
            links.add(action_url)

    # <script src>
    for script in soup.find_all("script", src=True):
        src = str(script["src"]).strip()
        if src:
            links.add(urljoin(base_url, src))

    # <link href> (non-stylesheet)
    for link in soup.find_all("link", href=True):
        href = str(link["href"]).strip()
        if href and not href.endswith(".css"):
            links.add(urljoin(base_url, href))

    return links, form_urls


def _extract_js_routes(js_content: str, base_url: str) -> set[str]:
    """Extract URL-like paths from JavaScript source using multiple patterns."""
    routes: set[str] = set()
    parsed = urlparse(base_url)
    scheme_host = f"{parsed.scheme}://{parsed.netloc}"

    def _add(path: str) -> None:
        path = path.strip()
        if len(path) < 2 or path in ("/", "//"):
            return
        # Skip webpack chunk paths like /__webpack_require__
        if any(kw in path for kw in ["webpack", "__", "chunk", "bundle", "vendor"]):
            return
        full = urljoin(scheme_host, path)
        routes.add(full)

    for pattern in (_JS_PLAIN_RE, _JS_FETCH_RE, _JS_API_RE, _JS_ROUTEDEF_RE, _JS_XHR_RE):
        for m in pattern.finditer(js_content):
            _add(m.group(1))

    return routes


def _extract_parent_directories(url: str) -> list[str]:
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == "/":
        return []
    parts = [p for p in path.split("/") if p]
    dirs = []
    for i in range(1, len(parts)):
        subpath = "/" + "/".join(parts[:i]) + "/"
        dirs.append(urlunparse(parsed._replace(path=subpath, query="", fragment="")))
    return dirs


async def _fetch(url: str, session: FuzzSession) -> tuple[str, str, str]:
    """Fetch a URL → (final_url, content_type, body). Empty body on failure."""
    try:
        resp = await session.get(url, allow_redirects=True)
        if resp is None:
            return url, "", ""
        async with resp:
            final_url = str(resp.url)
            content_type = resp.headers.get("Content-Type", "").lower()
            if resp.status >= 400:
                return final_url, content_type, ""
            if not any(t in content_type for t in ("html", "javascript", "text", "json")):
                return final_url, content_type, ""
            # Read at most 4 MB
            chunks, total = [], 0
            limit = 4 * 1024 * 1024
            while total < limit:
                chunk = await resp.content.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            return final_url, content_type, b"".join(chunks).decode(errors="replace")
    except Exception as exc:
        logger.debug(f"Fetch error {url}: {exc}")
        return url, "", ""


# ── Main Crawl ────────────────────────────────────────────────────────────────

async def crawl(ctx: ScanContext, start_urls: list[str] | None = None) -> None:
    """
    Two-phase async BFS crawler.

    Phase 1: BFS across all in-scope HTML pages — adds URLs, parameterised
             URLs, JS file references.
    Phase 2: Fetches every collected JS file (including CDN) and extracts
             hidden API routes/paths that are then added to crawled_urls.

    Redirect-aware scoping: if the initial target redirects to a different
    path (e.g. /books/ -> /book/), both paths are treated as in-scope.
    """
    console.rule("[bold cyan]URL Crawler[/bold cyan]")

    if start_urls is None:
        targets = [ctx.target_domain] + ctx.subdomains
        start_urls = [
            u if u.startswith("http") else f"https://{u}"
            for u in targets
        ]

    ext = tldextract.extract(ctx.target_domain)
    root_domain = f"{ext.domain}.{ext.suffix}"

    norm_target = (
        ctx.target_domain
        if ctx.target_domain.startswith("http")
        else f"https://{ctx.target_domain}"
    )
    target_parsed = urlparse(norm_target)
    original_scope = target_parsed.path.rstrip("/")  # e.g. "/books" or ""

    # effective_scopes grows when we detect redirects to different paths
    effective_scopes: list[str] = [original_scope] if original_scope else []

    def _in_scope(url: str) -> bool:
        """True if the URL path starts with ANY of our effective scope prefixes."""
        if not effective_scopes:
            return True  # No path scope — whole domain is fair game
        path = urlparse(url).path.rstrip("/")
        return any(path.startswith(sc) for sc in effective_scopes)

    visited: set[str] = set()
    js_queue: set[str] = set()
    bfs: deque[tuple[str, int]] = deque((url, 0) for url in start_urls)

    # ── Phase 1: BFS HTML Crawl ───────────────────────────────────────────────
    async with FuzzSession(ctx) as session:
        while bfs:
            # Fill a batch
            batch: list[tuple[str, int]] = []
            while bfs and len(batch) < ctx.threads:
                url, depth = bfs.popleft()
                parsed = urlparse(url)
                clean = urlunparse(parsed._replace(fragment=""))

                if clean in visited:
                    continue
                if not _is_same_domain(clean, root_domain):
                    continue
                if not _in_scope(clean):
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
                *[_fetch(url, session) for url, _ in batch],
                return_exceptions=True,
            )

            for (url, depth), result in zip(batch, results):
                if isinstance(result, Exception):
                    continue
                final_url, content_type, body = result

                # ── Redirect-scope expansion ──────────────────────────────────
                # If the server redirected us to a different path, add the new
                # path prefix to our effective scope so we keep crawling there.
                if original_scope:
                    final_path = urlparse(final_url).path.rstrip("/")
                    if final_path and not any(
                        final_path.startswith(sc) for sc in effective_scopes
                    ):
                        new_scope = "/".join(
                            final_path.split("/")[:len(original_scope.split("/"))]
                        )
                        if new_scope and new_scope != original_scope:
                            logger.info(
                                f"Scope expanded: {original_scope!r} → {new_scope!r} "
                                f"(redirect detected)"
                            )
                            effective_scopes.append(new_scope)

                if not body:
                    continue

                # Record this URL
                ctx.add_url(final_url)
                logger.info(f"  Crawled: [cyan]{final_url}[/cyan]")

                if _has_params(final_url):
                    ctx.add_parameterized_url(final_url)

                # Queue parent directories
                for parent in _extract_parent_directories(final_url):
                    if parent not in visited:
                        bfs.append((parent, depth + 1))

                # Process JS files (any domain → js_queue for Phase 2)
                if "javascript" in content_type or final_url.endswith(".js") or ".js?" in final_url:
                    ctx.add_js_file(final_url)
                    js_queue.add(final_url)
                    routes = _extract_js_routes(body, final_url)
                    for route in routes:
                        if _is_same_domain(route, root_domain):
                            bfs.append((route, depth + 1))
                    continue  # No HTML link extraction for JS

                # HTML extraction
                links, form_urls = _extract_links(body, final_url)

                # Add form-derived parameterised URLs
                for furl in form_urls:
                    if _is_same_domain(furl, root_domain):
                        ctx.add_parameterized_url(furl)
                        ctx.add_url(furl)

                for link in links:
                    # Collect ALL JS files regardless of domain
                    if link.endswith(".js") or ".js?" in link:
                        ctx.add_js_file(link)
                        js_queue.add(link)

                    if _has_params(link):
                        if _is_same_domain(link, root_domain):
                            ctx.add_parameterized_url(link)

                    if link not in visited:
                        bfs.append((link, depth + 1))

                    # Queue parent directories of new links
                    for parent in _extract_parent_directories(link):
                        if parent not in visited:
                            bfs.append((parent, depth + 1))

        # ── Phase 2: Analyse ALL JS files (including CDN) ─────────────────────
        new_js = js_queue - {f for f in js_queue if f in visited}
        logger.info(f"Analysing [bold]{len(new_js)}[/bold] JS files for hidden API routes…")

        js_tasks = [_fetch(js_url, session) for js_url in new_js]
        js_results = await asyncio.gather(*js_tasks, return_exceptions=True)

        for js_url, result in zip(new_js, js_results):
            if isinstance(result, Exception):
                continue
            _, _, js_body = result
            if not js_body:
                continue

            routes = _extract_js_routes(js_body, js_url)
            for route in routes:
                if not _is_same_domain(route, root_domain):
                    continue
                if not _in_scope(route):
                    continue
                if route not in visited:
                    ctx.add_url(route)
                    if _has_params(route):
                        ctx.add_parameterized_url(route)
                    logger.info(f"  JS route: [yellow]{route}[/yellow]")

    logger.info(
        f"[bold green]Crawl complete.[/bold green] "
        f"URLs: [bold]{len(ctx.crawled_urls)}[/bold]  "
        f"Parameterized: [bold]{len(ctx.parameterized_urls)}[/bold]  "
        f"JS files: [bold]{len(ctx.js_files)}[/bold]"
    )
