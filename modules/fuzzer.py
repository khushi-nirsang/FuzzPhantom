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

        for param_name in params:
            # We track if we already flagged reflections or status changes for this param
            reflection_detected = False
            status_change_detected = False

            for payload in payloads:
                # Limit fuzzing overhead if we already found basic parameter behaviors
                if reflection_detected and status_change_detected:
                    break

                import secrets
                canary = f"fp_{secrets.token_hex(4)}"
                fuzzed_payload = f"{payload}_{canary}"
                fuzzed_url = _inject_payload(url, param_name, fuzzed_payload)
                try:
                    resp = await session.get(fuzzed_url, allow_redirects=False)
                    if resp is None:
                        continue
                    async with resp:
                        body = await resp.text(errors="replace")
                        status = resp.status
                        length = len(body)
                except Exception as exc:
                    logger.debug(f"Fuzz error {fuzzed_url}: {exc}")
                    continue

                # ── Recon Analysis ───────────────────────────────────────────
                # 1. Parameter Reflection (Checked via unique canary to avoid false positives)
                is_reflected = False
                if canary in body:
                    is_reflected = True
                elif len(payload) > 3 and payload in body and payload not in baseline_body:
                    # Fallback for strict input validation where canary format was rejected but base payload was reflected
                    is_reflected = True

                if is_reflected and not reflection_detected:
                    reflection_detected = True
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
                if status != baseline_status and not status_change_detected:
                    # Ignore minor variations like 200 vs 302 unless it's an authorization/error boundary
                    if status in (403, 401, 500) or baseline_status in (403, 401):
                        status_change_detected = True
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
    if not urls:
        logger.warning("No parameterized URLs to fuzz. Run crawler first.")
        return

    logger.info(
        f"Fuzzing parameters on [bold]{len(urls)}[/bold] URLs..."
    )

    semaphore = asyncio.Semaphore(ctx.threads)
    async with FuzzSession(ctx) as session:
        tasks = [
            _fuzz_url(url, payloads, ctx, session, semaphore)
            for url in urls
        ]
        await asyncio.gather(*tasks)

    findings_count = len(
        [f for f in ctx.findings if f.category in ("Parameter Reflection", "Status Code Delta")]
    )
    logger.info(
        f"[bold green]Recon fuzzing complete.[/bold green] Unique behaviors mapped: [bold]{findings_count}[/bold]"
    )
