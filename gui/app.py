"""
FuzzPhantom GUI -- FastAPI Backend
Serves the dashboard SPA and streams scan results via WebSocket.
"""
from __future__ import annotations

import asyncio
import io
import logging
import sys
import uuid
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="FuzzPhantom GUI", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ---------------------------------------------------------------------------
# App-level state (single scan at a time)
# ---------------------------------------------------------------------------
app.state.active_task: asyncio.Task | None = None
app.state.scan_queue: asyncio.Queue | None = None
app.state.scan_id: str | None = None


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class ScanConfig(BaseModel):
    domain: str
    targets: list[str] = []          # Extra targets for multi-target mode
    run_subdomains: bool = True
    run_crawl: bool = True
    run_dir_fuzz: bool = True
    run_fuzz: bool = True
    run_api: bool = True
    run_smart_wordlist: bool = False
    wordlist: str = ""
    dir_wordlist: str = ""
    dir_depth: int = 3
    dir_extensions: list[str] = []
    mutate_wordlist: bool = False
    mutate_depth: int = 1
    request_method: str = "GET"
    request_headers: dict[str, str] = {}
    request_body: str = ""
    follow_redirects: bool = False
    recursion_status: str = ""
    recursion_match: str = ""
    recursion_filter: str = ""
    match_status: str = ""
    payload_files: list[str] = []
    output_formats: list[str] = ["json", "pdf", "hackerone"]
    output_dir: str = "reports"
    crawl_depth: int = 3
    rate_limit: int = 200
    threads: int = 80
    timeout: int = 10
    delay_ms: int = 0
    jitter_ms: int = 0
    max_errors: int = 0
    max_hits: int = 0
    proxy: str = ""
    proxy_max_failures: int = 3
    replay_proxy: str = ""
    calibration_profile: str = "balanced"
    resume: bool = False
    resume_file: str = ""

    @property
    def all_targets(self) -> list[str]:
        """Return all unique targets (primary domain + extras)."""
        seen: set[str] = set()
        out: list[str] = []
        for t in [self.domain] + self.targets:
            t = t.strip()
            if t and t not in seen:
                seen.add(t)
                out.append(t)
        return out


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
async def serve_index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.post("/api/scan/start")
async def start_scan(config: ScanConfig):
    if app.state.active_task and not app.state.active_task.done():
        raise HTTPException(status_code=409, detail="A scan is already running")

    scan_id = str(uuid.uuid4())[:8]
    queue: asyncio.Queue = asyncio.Queue(maxsize=100_000)

    from gui.scanner import run_scan
    task = asyncio.create_task(run_scan(config, queue))

    app.state.scan_id = scan_id
    app.state.scan_queue = queue
    app.state.active_task = task

    return {"scan_id": scan_id, "status": "started"}


@app.post("/api/scan/stop")
async def stop_scan():
    task = app.state.active_task
    if task and not task.done():
        task.cancel()
        return {"status": "stopping"}
    return {"status": "not_running"}


@app.get("/api/scan/status")
async def scan_status():
    task = app.state.active_task
    running = bool(task and not task.done())
    return {"running": running, "scan_id": app.state.scan_id}


@app.websocket("/ws/{scan_id}")
async def ws_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    queue = app.state.scan_queue
    if queue is None or scan_id != app.state.scan_id:
        await websocket.send_json({"type": "error", "text": "No active scan with this ID"})
        await websocket.close()
        return

    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(msg)
                if msg.get("type") in ("complete", "error", "stopped"):
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                task = app.state.active_task
                if (task is None or task.done()) and queue.empty():
                    await websocket.send_json({"type": "complete", "text": "Scan finished."})
                    break
    except WebSocketDisconnect:
        logger.info("Browser disconnected — shutting down server.")
        import os, signal
        os.kill(os.getpid(), signal.SIGTERM)
    except Exception:
        pass


@app.get("/api/reports")
async def list_reports():
    reports_dir = ROOT / "reports"
    if not reports_dir.exists():
        return {"reports": []}
    files = []
    for f in sorted(reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.is_file() and f.suffix in (".json", ".jsonl", ".md", ".txt", ".csv", ".pdf"):
            files.append({
                "name": f.name,
                "size": f.stat().st_size,
                "ext": f.suffix.lstrip("."),
                "modified": f.stat().st_mtime,
            })
    return {"reports": files[:200]}


@app.get("/api/reports/download/{filename}")
async def download_report(filename: str):
    safe = Path(filename).name
    filepath = ROOT / "reports" / safe
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    media_type = {
        ".json": "application/json",
        ".jsonl": "application/x-ndjson",
        ".csv": "text/csv",
        ".pdf": "application/pdf",
        ".md": "text/markdown",
        ".txt": "text/plain",
    }.get(filepath.suffix, "application/octet-stream")
    return FileResponse(str(filepath), filename=safe, media_type=media_type)


@app.get("/api/reports/zip")
async def download_all_reports_zip():
    """Bundle all reports into a ZIP and stream it to the browser."""
    reports_dir = ROOT / "reports"
    if not reports_dir.exists():
        raise HTTPException(status_code=404, detail="No reports directory")

    files = [
        f for f in reports_dir.iterdir()
        if f.is_file() and f.suffix in (".json", ".jsonl", ".md", ".txt", ".csv", ".pdf")
    ]
    if not files:
        raise HTTPException(status_code=404, detail="No report files found")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            zf.write(f, f.name)
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=fuzzphantom_reports.zip"},
    )
