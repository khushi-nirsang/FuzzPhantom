"""
FuzzPhantom GUI -- Async Scan Runner
Wraps the full module pipeline with WebSocket queue integration.
Emits structured messages for every discovered item so the frontend
can populate each result tab in real time.
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
# Helpers
# ---------------------------------------------------------------------------
_RICH_RE = re.compile(r"\[/?[a-zA-Z0-9 _#/]+\]")
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

def _clean(text: str) -> str:
    return _ANSI_RE.sub("", _RICH_RE.sub("", text)).strip()


# ---------------------------------------------------------------------------
# GUIScanContext — streams live updates over WebSocket
# ---------------------------------------------------------------------------

class GUIScanContext(ScanContext):
    """ScanContext that streams every discovery to the frontend in real time."""

    def __init__(self, queue: asyncio.Queue, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._ws_queue = queue
        self._url_buf: list[str] = []   # batch URLs to reduce message volume

    def _emit(self, msg: dict) -> None:
        try:
            self._ws_queue.put_nowait(msg)
        except asyncio.QueueFull:
            pass

    # ── Subdomains ────────────────────────────────────────────────────────────
    def add_subdomain(self, subdomain: str) -> None:
        super().add_subdomain(subdomain)
        self._emit({"type": "subdomain", "value": subdomain})
        self._emit({"type": "stats", "stats": self.summary()})

    # ── Crawled URLs ──────────────────────────────────────────────────────────
    def add_url(self, url: str) -> None:
        super().add_url(url)
        self._url_buf.append(url)
        if len(self._url_buf) >= 5:          # Emit in batches of 5
            self._emit({"type": "urls_batch", "values": self._url_buf[:]})
            self._url_buf.clear()
            self._emit({"type": "stats", "stats": self.summary()})

    # ── API Endpoints ─────────────────────────────────────────────────────────
    def add_api_endpoint(self, endpoint: str) -> None:
        super().add_api_endpoint(endpoint)
        self._emit({"type": "api_endpoint", "value": endpoint})
        if len(self.api_endpoints) % 10 == 0:
            self._emit({"type": "stats", "stats": self.summary()})

    # ── Findings (includes Directory Found) ───────────────────────────────────
    def add_finding(self, finding: Finding) -> None:
        super().add_finding(finding)
        self._emit({"type": "finding", "finding": finding.to_dict()})
        self._emit({"type": "stats", "stats": self.summary()})

    def flush_url_buf(self) -> None:
        """Flush remaining URL buffer at end of crawl and emit updated stats."""
        if self._url_buf:
            self._emit({"type": "urls_batch", "values": self._url_buf[:]})
            self._url_buf.clear()
        # Always emit stats so the counter updates even if fewer than 5 URLs were found
        self._emit({"type": "stats", "stats": self.summary()})


# ---------------------------------------------------------------------------
# WebSocket logging handler
# ---------------------------------------------------------------------------

class WSLogHandler(logging.Handler):
    """Forwards Python log records to the WebSocket queue."""

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
# Main scan pipeline
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

    ws_handler = WSLogHandler(queue)
    root_log = logging.getLogger()
    root_log.addHandler(ws_handler)

    try:
        all_targets = config.all_targets  # list of unique targets
        log(f"Initialising scan → {len(all_targets)} target(s): {', '.join(all_targets)}")

        payload_files = config.payload_files or []
        if not payload_files:
            payload_dir = ROOT / "payloads"
            payload_files = [str(f) for f in payload_dir.glob("*.txt")]

        from urllib.parse import urlparse
        parsed_target = urlparse(config.domain.strip())
        has_path_scope = bool(parsed_target.path and parsed_target.path not in ("/", ""))
        should_run_subdomains = config.run_subdomains and not has_path_scope

        ctx = GUIScanContext(
            queue=queue,
            target_domain=config.domain.strip(),
            domains=[config.domain.strip()],
            wordlist_path=config.wordlist or str(ROOT / "wordlists" / "subdomains.txt"),
            dir_wordlist_path=config.dir_wordlist or str(ROOT / "wordlists" / "directories.txt"),
            dir_depth=max(1, config.dir_depth),
            dir_extensions=config.dir_extensions,
            mutate_wordlist=config.mutate_wordlist,
            mutate_depth=max(1, min(2, config.mutate_depth)),
            request_method=(config.request_method or "GET").upper(),
            request_headers=config.request_headers,
            request_body=config.request_body,
            follow_redirects=config.follow_redirects,
            recursion_status=config.recursion_status or None,
            recursion_match=config.recursion_match or None,
            recursion_filter=config.recursion_filter or None,
            match_status=config.match_status or None,
            payload_files=payload_files,
            output_formats=config.output_formats or ["json", "hackerone"],
            output_dir=config.output_dir or "reports",
            crawl_depth=config.crawl_depth,
            rate_limit=config.rate_limit,
            threads=config.threads,
            timeout=config.timeout,
            delay_ms=max(0, config.delay_ms),
            jitter_ms=max(0, config.jitter_ms),
            max_errors=max(0, config.max_errors),
            max_hits=max(0, config.max_hits),
            proxy=config.proxy or None,
            proxy_max_failures=max(1, config.proxy_max_failures),
            replay_proxy=config.replay_proxy or None,
            calibration_profile=config.calibration_profile,
            resume=config.resume,
            resume_file=config.resume_file,
            smart_wordlist=config.run_smart_wordlist,
        )

        # ── Stage 1: Subdomain Discovery ──────────────────────────────────────
        if should_run_subdomains:
            stage("subdomains", "Subdomain discovery in progress…")
            log("Starting subdomain discovery (CT logs + DNS brute-force + zone transfer)")
            from modules.subdomain import run_subdomain_discovery
            await run_subdomain_discovery(ctx)
            log(f"Subdomains complete — {len(ctx.subdomains)} discovered")
        else:
            if has_path_scope:
                log("Path scope detected. Subdomain discovery skipped (locked to directory).")
            else:
                log("Subdomain discovery disabled.")
            stage("subdomains", "Skipped")

        # ── Stage 2: URL Crawler ──────────────────────────────────────────────
        if config.run_crawl:
            stage("crawl", "URL crawling in progress…")
            log("Starting async BFS crawler")
            from modules.crawler import crawl
            await crawl(ctx)
            ctx.flush_url_buf()
            log(f"Crawl complete — {len(ctx.crawled_urls)} URLs, "
                f"{len(ctx.parameterized_urls)} parameterized, "
                f"{len(ctx.js_files)} JS files")
        else:
            stage("crawl", "Skipped")

        # ── Stage 3: Directory Fuzzer ─────────────────────────────────────────
        discovered_dirs = []
        if config.run_dir_fuzz:
            stage("dir_fuzz", "Directory brute-force in progress…")
            log("Starting directory fuzzer (ffuf-style path discovery)")
            from modules.dir_fuzzer import run_dir_fuzzer
            await run_dir_fuzzer(ctx)
            discovered_dirs = [f.url for f in ctx.findings if f.category == "Directory Found"]
            log(f"Directory fuzzer complete — {len(discovered_dirs)} paths discovered")
        else:
            stage("dir_fuzz", "Skipped")

        # ── Stage 3.5: Secondary Crawl on Discovered Directories ──────────────
        if config.run_crawl and discovered_dirs:
            log(f"Starting secondary BFS crawl on {len(discovered_dirs)} discovered directories…")
            from modules.crawler import crawl
            await crawl(ctx, start_urls=discovered_dirs)
            ctx.flush_url_buf()
            log(f"Secondary crawl complete — total crawled: {len(ctx.crawled_urls)} URLs, "
                f"{len(ctx.parameterized_urls)} parameterized")

        # ── Stage 4: Parameter Fuzzer ─────────────────────────────────────────
        if config.run_fuzz:
            stage("fuzz", "Parameter fuzzing in progress…")
            log(f"Starting parameter fuzzer on {len(ctx.parameterized_urls)} URLs "
                f"with {len(payload_files)} payload file(s)")
            from modules.fuzzer import run_fuzzer
            await run_fuzzer(ctx)
            fuzz_count = sum(1 for f in ctx.findings
                             if f.category in ("Parameter Reflection", "Status Code Delta"))
            log(f"Fuzzer complete — {fuzz_count} findings")
        else:
            stage("fuzz", "Skipped")

        # ── Stage 5: API Discovery ────────────────────────────────────────────
        if config.run_api:
            stage("api", "API endpoint discovery in progress…")
            log("Starting API discovery + JavaScript analysis")
            from modules.api_discovery import run_api_discovery
            await run_api_discovery(ctx)
            log(f"API discovery complete — {len(ctx.api_endpoints)} endpoints found")
        else:
            stage("api", "Skipped")

        # ── Stage 6: Smart Wordlist ───────────────────────────────────────────
        if config.run_smart_wordlist:
            stage("wordlist", "Generating smart wordlist…")
            log("Generating NLP/TF-IDF smart wordlist from page content")
            from modules.wordlist_gen import generate_smart_wordlist
            await generate_smart_wordlist(ctx)
            log(f"Wordlist generated — {len(ctx.smart_wordlist_terms)} terms")
        else:
            stage("wordlist", "Skipped")

        # ── Stage 7: Reports ──────────────────────────────────────────────────
        stage("reports", "Generating reports…")
        log("Writing reports…")
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
