"""
FuzzPhantom — Parameter Recon Fuzzer
Profiles URL parameters to detect behavior changes, parameter reflection, and page structure deltas.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.context import ScanContext, Finding
from core.session import FuzzSession
from core.logger import get_logger, log_finding, console

logger = get_logger(__name__)


def _load_payloads(payload_files: list[str]) -> list[str]:
    """Load and deduplicate payloads from one or more files."""
    payloads: list[str] = []
    seen: set[str] = set()
    for path in payload_files:
        p = Path(path)
        if not p.exists():
            logger.warning(f"Wordlist file not found: {path}")
            continue
        with open(p, encoding="utf-8", errors="ignore") as f:
            for line in f:
                payload = line.strip()
                if payload and payload not in seen and not payload.startswith("#"):
                    seen.add(payload)
                    payloads.append(payload)
    return payloads


def _inject_payload(url: str, param: str, payload: str) -> str:
    """Return a new URL with `payload` injected into `param`."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _get_baseline(
    url: str, session: FuzzSession
) -> tuple[int, int, str]:
    """Fetch baseline response: (status, length, body)."""
    try:
        resp = await session.get(url)
        if resp is None:
            return 0, 0, ""
        async with resp:
            body = await resp.text(errors="replace")
            return resp.status, len(body), body
    except Exception:
        return 0, 0, ""


async def _fuzz_param_payload(
    url: str,
    param_name: str,
    payload: str,
    baseline_status: int,
    baseline_len: int,
    baseline_body: str,
    ctx: ScanContext,
    session: FuzzSession,
    semaphore: asyncio.Semaphore,
    param_state: dict[str, bool],
) -> None:
    """Fuzz a single parameter value combination for a URL."""
    if param_state["reflection_detected"] and param_state["status_change_detected"]:
        return

    import secrets
    canary = f"fp_{secrets.token_hex(4)}"
    fuzzed_payload = f"{payload}_{canary}"
    fuzzed_url = _inject_payload(url, param_name, fuzzed_payload)

    async with semaphore:
        # Check again under lock to avoid unnecessary network queries
        if param_state["reflection_detected"] and param_state["status_change_detected"]:
            return
        try:
            resp = await session.get(fuzzed_url, allow_redirects=False)
            if resp is None:
                return
            async with resp:
                body = await resp.text(errors="replace")
                status = resp.status
                length = len(body)
        except Exception as exc:
            logger.debug(f"Fuzz error {fuzzed_url}: {exc}")
            return

    # ── Recon Analysis ───────────────────────────────────────────
    # 1. Parameter Reflection
    is_reflected = False
    if canary in body:
        is_reflected = True
    elif len(payload) > 3 and payload in body and payload not in baseline_body:
        is_reflected = True

    if is_reflected and not param_state["reflection_detected"]:
        param_state["reflection_detected"] = True
        finding = Finding(
            category="Parameter Reflection",
            url=fuzzed_url,
            parameter=param_name,
            payload=payload,
            status_code=status,
            original_status=baseline_status,
            response_length=length,
            original_length=baseline_len,
            severity="INFO",
            detail=f"Parameter value reflected in response body (verified via canary)",
        )
        ctx.add_finding(finding)
        log_finding("Parameter Reflection", fuzzed_url, f"Parameter '{param_name}' reflects input", "INFO")

    # 2. Significant Status Code Change
    if status != baseline_status and not param_state["status_change_detected"]:
        if status in (403, 401, 500) or baseline_status in (403, 401):
            param_state["status_change_detected"] = True
            finding = Finding(
                category="Status Code Delta",
                url=fuzzed_url,
                parameter=param_name,
                payload=payload,
                status_code=status,
                original_status=baseline_status,
                response_length=length,
                original_length=baseline_len,
                severity="INFO",
                detail=f"Injected parameter altered response status: {baseline_status} → {status}",
            )
            ctx.add_finding(finding)
            log_finding("Status Delta", fuzzed_url, f"Status changed to {status}", "INFO")


async def _fuzz_url(
    url: str,
    payloads: list[str],
    ctx: ScanContext,
    session: FuzzSession,
    semaphore: asyncio.Semaphore,
) -> None:
    """Analyze behavior of parameters on a single URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    async with semaphore:
        baseline_status, baseline_len, baseline_body = await _get_baseline(url, session)
    if baseline_status == 0:
        return

    queue: asyncio.Queue[tuple[str, str, dict[str, bool]] | None] = asyncio.Queue(
        maxsize=max(1, ctx.threads * 4)
    )
    worker_count = max(1, min(ctx.threads, len(params) * len(payloads)))

    async def worker() -> None:
        while True:
            item = await queue.get()
            try:
                if item is None:
                    return

                param_name, payload, param_state = item
                await _fuzz_param_payload(
                    url, param_name, payload,
                    baseline_status, baseline_len, baseline_body,
                    ctx, session, semaphore, param_state
                )
            finally:
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

    for param_name in params:
        param_state = {
            "reflection_detected": False,
            "status_change_detected": False,
        }
        for payload in payloads:
            await queue.put((param_name, payload, param_state))

    for _ in workers:
        await queue.put(None)

    await queue.join()
    await asyncio.gather(*workers)


async def _run_url_fuzzers(
    urls: list[str],
    payloads: list[str],
    ctx: ScanContext,
    session: FuzzSession,
    semaphore: asyncio.Semaphore,
) -> None:
    """Run URL fuzzing with bounded workers instead of one task per URL."""
    worker_count = max(1, min(ctx.threads, len(urls)))
    queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=worker_count * 4)

    async def worker() -> None:
        while True:
            url = await queue.get()
            try:
                if url is None:
                    return
                await _fuzz_url(url, payloads, ctx, session, semaphore)
            finally:
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

    for url in urls:
        await queue.put(url)

    for _ in workers:
        await queue.put(None)

    await queue.join()
    await asyncio.gather(*workers)


async def run_fuzzer(ctx: ScanContext) -> None:
    """
    Main entry point for parameter/directory reconnaissance fuzzing.
    """
    console.rule("[bold cyan]Parameter Recon Fuzzer[/bold cyan]")

    payload_files = ctx.payload_files
    if not payload_files:
        default_dir = Path(__file__).parent.parent / "payloads"
        payload_files = [str(f) for f in default_dir.glob("*.txt")]

    payloads = _load_payloads(payload_files)
    if not payloads:
        logger.warning("No fuzzing inputs loaded. Skipping fuzzer.")
        return

    urls = ctx.parameterized_urls
    synthetic_probe_mode = False
    if not urls and ctx.crawled_urls:
        logger.info("No parameterized URLs found. Constructing test candidates using common parameters...")
        param_wordlist = Path(__file__).parent.parent / "wordlists" / "params.txt"
        common_params = []
        if param_wordlist.exists():
            with open(param_wordlist, encoding="utf-8", errors="ignore") as f:
                common_params = [line.strip() for line in f if line.strip() and not line.startswith("#")][:12]
        if not common_params:
            common_params = ["id", "file", "page", "path", "url", "redirect", "dir", "cmd"]

        constructed_urls = []
        for url in ctx.crawled_urls[:500]:
            parsed = urlparse(url)
            if not parsed.query:
                for param in common_params:
                    separator = "&" if parsed.query else "?"
                    candidate = f"{url.rstrip('/')}{separator}{param}=1"
                    constructed_urls.append(candidate)
                    ctx.add_parameterized_url(candidate)
            else:
                constructed_urls.append(url)
        urls = list(set(constructed_urls))
        synthetic_probe_mode = True

    if synthetic_probe_mode and len(payloads) > 8:
        payloads = payloads[:8]
        logger.info("Synthetic parameter probe mode enabled: using first 8 payloads for speed.")

    if not urls:
        logger.warning("No URLs to fuzz. Run crawler first or specify a URL list.")
        return

    logger.info(
        f"Fuzzing parameters on [bold]{len(urls)}[/bold] URLs..."
    )

    semaphore = asyncio.Semaphore(ctx.threads)
    async with FuzzSession(ctx) as session:
        await _run_url_fuzzers(urls, payloads, ctx, session, semaphore)

    findings_count = len(
        [f for f in ctx.findings if f.category in ("Parameter Reflection", "Status Code Delta")]
    )
    logger.info(
        f"[bold green]Recon fuzzing complete.[/bold green] Unique behaviors mapped: [bold]{findings_count}[/bold]"
    )
