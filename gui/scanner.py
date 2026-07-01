"""
FuzzPhantom GUI -- Async Scan Runner
Wraps the existing module pipeline with WebSocket queue integration.
"""
from __future__ import annotations

import asyncio
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core.context import ScanContext, Finding


# ---------------------------------------------------------------------------
# Extended ScanContext: emits WS messages on every state change
# ---------------------------------------------------------------------------

class GUIScanContext(ScanContext):
    """ScanContext that streams live updates to the WebSocket queue."""

    def __init__(self, queue: asyncio.Queue, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._ws_queue = queue

    def _emit(self, msg: dict) -> None:
        try:
            self._ws_queue.put_nowait(msg)
        except asyncio.QueueFull:
            pass

    def add_finding(self, finding: Finding) -> None:
        super().add_finding(finding)
        self._emit({"type": "finding", "finding": finding.to_dict()})
        self._emit({"type": "stats", "stats": self.summary()})

    def add_subdomain(self, subdomain: str) -> None:
        super().add_subdomain(subdomain)
        self._emit({"type": "stats", "stats": self.summary()})

    def add_url(self, url: str) -> None:
        super().add_url(url)
        if len(self.crawled_urls) % 20 == 0:
            self._emit({"type": "stats", "stats": self.summary()})

    def add_api_endpoint(self, endpoint: str) -> None:
        super().add_api_endpoint(endpoint)
        self._emit({"type": "stats", "stats": self.summary()})


# ---------------------------------------------------------------------------
# WebSocket logging handler
# ---------------------------------------------------------------------------

_RICH_MARKUP_RE = re.compile(r"\[/?[a-zA-Z0-9 _#/]+\]")
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _clean(text: str) -> str:
    return _ANSI_RE.sub("", _RICH_MARKUP_RE.sub("", text)).strip()


class WSLogHandler(logging.Handler):
    """Logging handler that forwards records to the WS queue."""

    def __init__(self, queue: asyncio.Queue) -> None:
        super().__init__()
        self._queue = queue
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = _clean(self.format(record))
            if not msg:
                return
            self._queue.put_nowait({
                "type": "log",
                "level": record.levelname,
                "text": msg,
                "ts": datetime.now().strftime("%H:%M:%S"),
                "src": record.name.split(".")[-1],
            })
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Scan pipeline
# ---------------------------------------------------------------------------

async def run_scan(config: Any, queue: asyncio.Queue) -> None:
    """Run the full FuzzPhantom pipeline, streaming events to `queue`."""

    def log(text: str, level: str = "INFO") -> None:
        queue.put_nowait({
            "type": "log", "level": level, "text": text,
            "ts": datetime.now().strftime("%H:%M:%S"), "src": "scanner",
        })

    def stage(name: str, text: str) -> None:
        queue.put_nowait({"type": "stage", "stage": name, "text": text})

    # Attach WS logging handler to root logger
    ws_handler = WSLogHandler(queue)
    root_log = logging.getLogger()
    root_log.addHandler(ws_handler)

    try:
        log(f"Initialising scan → {config.domain}")

        payload_files = config.payload_files or []
        if not payload_files:
            payload_dir = ROOT / "payloads"
            payload_files = [str(f) for f in payload_dir.glob("*.txt")]

        # Determine if we have a directory path scope (e.g. /book)
        from urllib.parse import urlparse
        parsed_target = urlparse(config.domain.strip())
        has_path_scope = bool(parsed_target.path and parsed_target.path != "/")

        # Automatically disable subdomains if a path scope is specified (to stay folder-locked)
        should_run_subdomains = config.run_subdomains and not has_path_scope

        ctx = GUIScanContext(
            queue=queue,
            target_domain=config.domain.strip(),
            domains=[config.domain.strip()],
            wordlist_path=config.wordlist or str(ROOT / "wordlists" / "subdomains.txt"),
            payload_files=payload_files,
            output_formats=config.output_formats or ["json", "hackerone"],
            output_dir=config.output_dir or "reports",
            crawl_depth=config.crawl_depth,
            rate_limit=config.rate_limit,
            threads=config.threads,
            timeout=config.timeout,
            proxy=config.proxy or None,
            smart_wordlist=config.run_smart_wordlist,
        )

        if should_run_subdomains:
            stage("subdomains", "Subdomain discovery in progress...")
            log("Starting subdomain discovery (CT logs + DNS brute-force + zone transfer)")
            from modules.subdomain import run_subdomain_discovery
            await run_subdomain_discovery(ctx)
            log(f"Subdomains complete — {len(ctx.subdomains)} discovered")
        else:
            if has_path_scope:
                log("Path scope directory detected. Skipping subdomain discovery to lock scan to folder.")
            else:
                log("Subdomain discovery disabled by configuration.")

        if config.run_crawl:
            stage("crawl", "URL crawling in progress...")
            log("Starting async BFS crawler")
            from modules.crawler import crawl
            await crawl(ctx)
            log(
                f"Crawl complete — {len(ctx.crawled_urls)} URLs, "
                f"{len(ctx.parameterized_urls)} parameterized, "
                f"{len(ctx.js_files)} JS files"
            )

        if config.run_fuzz:
            stage("fuzz", "Parameter fuzzing in progress...")
            log(
                f"Starting parameter fuzzer on {len(ctx.parameterized_urls)} URLs "
                f"with {len(payload_files)} payload file(s)"
            )
            from modules.fuzzer import run_fuzzer
            await run_fuzzer(ctx)
            fuzz_findings = sum(1 for f in ctx.findings if f.category == "Parameter Fuzzing")
            log(f"Fuzzer complete — {fuzz_findings} findings")

        if config.run_api:
            stage("api", "API endpoint discovery in progress...")
            log("Starting API discovery + JavaScript analysis")
            from modules.api_discovery import run_api_discovery
            await run_api_discovery(ctx)
            log(f"API discovery complete — {len(ctx.api_endpoints)} endpoints found")

        if config.run_smart_wordlist:
            stage("wordlist", "Generating smart wordlist...")
            log("Generating NLP/TF-IDF smart wordlist from page content")
            from modules.wordlist_gen import generate_smart_wordlist
            await generate_smart_wordlist(ctx)
            log(f"Wordlist generated — {len(ctx.smart_wordlist_terms)} terms")

        # Reports
        stage("reports", "Generating reports...")
        log("Writing reports...")
        from reporting.reporter import generate_reports
        report_files = generate_reports(ctx)
        log(f"Reports saved: {len(report_files)} file(s)")

        summary = ctx.summary()
        queue.put_nowait({
            "type": "complete",
            "summary": summary,
            "reports": [Path(f).name for f in report_files],
            "text": (
                f"Scan complete — "
                f"{summary['findings']} findings across "
                f"{summary['crawled_urls']} URLs"
            ),
        })

    except asyncio.CancelledError:
        log("Scan cancelled by user.", "WARNING")
        queue.put_nowait({"type": "stopped", "text": "Scan stopped by user."})

    except Exception as exc:
        log(f"Scan error: {exc}", "ERROR")
        queue.put_nowait({"type": "error", "text": str(exc)})

    finally:
        root_log.removeHandler(ws_handler)
