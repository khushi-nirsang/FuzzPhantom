"""
FuzzPhantom — API Endpoint Discovery & JavaScript Analysis
Discovers hidden API routes by:
  1. Parsing JavaScript files for fetch/axios calls and path strings
  2. Probing a wordlist of common API paths against all known hosts
  3. Detecting API key / auth token patterns in JS source
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.context import ScanContext, Finding
from core.session import FuzzSession
from core.logger import get_logger, log_finding, console

logger = get_logger(__name__)

# ── Regex patterns ─────────────────────────────────────────────────────────────

# Fetch / Axios / XHR calls in JS (supporting templates)
_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch|request)|\.open)\s*\(\s*["'`]([^"'`\s\)]+)["'`]""",
    re.IGNORECASE,
)

# General path strings in JS covering wider range of API frameworks
_PATH_RE = re.compile(
    r"""["'`](\/(?:api|v[0-9]|graphql|rest|internal|admin|auth|oauth|token|user|account|data|search|upload|download|config|settings|json|xml|ws|rpc|feed)[a-zA-Z0-9_/\-\.\?=&%${}]*)["'`]""",
    re.IGNORECASE,
)

# API key / secret patterns
_APIKEY_RE = re.compile(
    r"""(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer|client[_-]?secret)\s*[:=]\s*["'`]([A-Za-z0-9\-_\.]{8,})["'`]""",
    re.IGNORECASE,
)

# AWS / GCP / Azure credential hints
_CLOUD_KEY_RE = re.compile(
    r"""(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|[A-Za-z0-9+/]{88}=)""",
)


def _load_api_wordlist(path: str | None = None) -> list[str]:
    """Load API path wordlist."""
    if path is None:
        path = str(Path(__file__).parent.parent / "wordlists" / "api_paths.txt")
    p = Path(path)
    if not p.exists():
        return []
    with open(p, encoding="utf-8", errors="ignore") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


def _clean_path(path: str) -> str:
    """Sanitize templated variable strings from JS code into a probeable URL."""
    # Replace ${var} or similar interpolation with a placeholder '1'
    path = re.sub(r'\$\{[^}]+\}', '1', path)
    # Remove JS concatenation like + userId or + "abc"
    path = re.sub(r'["\'`]?\s*\+\s*[a-zA-Z0-9_]+', '', path)
    return path


def _analyze_js(js_content: str, base_url: str) -> tuple[set[str], list[str]]:
    """
    Analyze JavaScript source for API routes and credential leaks.
    Returns (routes, credential_snippets).
    """
    routes: set[str] = set()

    for match in _FETCH_RE.finditer(js_content):
        path = _clean_path(match.group(1))
        if path.startswith("/") or path.startswith("http"):
            routes.add(urljoin(base_url, path) if path.startswith("/") else path)

    for match in _PATH_RE.finditer(js_content):
        path = _clean_path(match.group(1))
        routes.add(urljoin(base_url, path))

    credentials: list[str] = []
    for match in _APIKEY_RE.finditer(js_content):
        credentials.append(f"API key/token: {match.group(0)[:80]}…")
    for match in _CLOUD_KEY_RE.finditer(js_content):
        credentials.append(f"Cloud credential: {match.group(0)[:80]}…")

    return routes, credentials


async def _probe_endpoint(
    url: str,
    session: FuzzSession,
    ctx: ScanContext,
    semaphore: asyncio.Semaphore,
) -> None:
    """Probe a single API endpoint and record if it responds."""
    async with semaphore:
        try:
            resp = await session.get(url, allow_redirects=True)
            if resp is None:
                return
            async with resp:
                status = resp.status
                length = (await resp.read()).__len__()
                if status not in (404, 400, 410):
                    ctx.add_api_endpoint(url)
                    log_finding(
                        "API Endpoint",
                        url,
                        f"HTTP {status} — {length} bytes",
                        "MEDIUM" if status == 200 else "INFO",
                    )
                    if status == 200:
                        ctx.add_finding(
                            Finding(
                                category="API Endpoint",
                                url=url,
                                status_code=status,
                                response_length=length,
                                severity="MEDIUM",
                                detail=f"API endpoint responds with HTTP 200 ({length} bytes)",
                            )
                        )
        except Exception as exc:
            logger.debug(f"Probe error {url}: {exc}")


async def analyze_js_files(ctx: ScanContext, session: FuzzSession) -> set[str]:
    """
    Fetch and analyze all known JS files from the crawl.
    Returns set of discovered API routes.
    """
    console.rule("[bold cyan]JavaScript Analysis[/bold cyan]")
    all_routes: set[str] = set()

    for js_url in ctx.js_files:
        try:
            resp = await session.get(js_url)
            if resp is None:
                continue
            async with resp:
                if resp.status >= 400:
                    continue
                content = await resp.text(errors="replace")
        except Exception as exc:
            logger.debug(f"JS fetch error {js_url}: {exc}")
            continue

        routes, creds = _analyze_js(content, js_url)
        all_routes.update(routes)

        logger.info(
            f"  JS: [cyan]{js_url}[/cyan] → "
            f"{len(routes)} routes, {len(creds)} credentials"
        )

        for cred in creds:
            log_finding("JS Credential Leak", js_url, cred, "CRITICAL")
            ctx.add_finding(
                Finding(
                    category="Credential Leak (JS)",
                    url=js_url,
                    severity="CRITICAL",
                    detail=cred,
                    evidence=cred,
                )
            )

    return all_routes


async def run_api_discovery(ctx: ScanContext) -> None:
    """
    Main entry point for API discovery:
    1. Analyze all discovered JS files
    2. Probe API paths wordlist against all known hosts
    """
    console.rule("[bold cyan]API Endpoint Discovery[/bold cyan]")

    wordlist_paths = _load_api_wordlist()
    hosts = list(
        {
            f"https://{sd}" if not sd.startswith("http") else sd
            for sd in ([ctx.target_domain] + ctx.subdomains)
        }
    )

    semaphore = asyncio.Semaphore(ctx.threads)

    async with FuzzSession(ctx) as session:
        # Step 1: JS analysis
        js_routes = await analyze_js_files(ctx, session)
        logger.info(f"JS analysis found [bold]{len(js_routes)}[/bold] routes")

        # Step 2: Probe JS-discovered routes
        probe_targets: list[str] = list(js_routes)

        # Step 3: Build probe list from wordlist × all hosts
        for host in hosts:
            for path in wordlist_paths:
                url = urljoin(host.rstrip("/") + "/", path.lstrip("/"))
                probe_targets.append(url)

        logger.info(
            f"Probing [bold]{len(probe_targets)}[/bold] API endpoint candidates…"
        )
        tasks = [
            _probe_endpoint(url, session, ctx, semaphore)
            for url in probe_targets
        ]
        await asyncio.gather(*tasks)

    logger.info(
        f"[bold green]API discovery complete.[/bold green] "
        f"Endpoints found: [bold]{len(ctx.api_endpoints)}[/bold]"
    )
