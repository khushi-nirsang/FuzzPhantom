"""
FuzzPhantom GUI -- FastAPI Backend
Serves the dashboard SPA and streams scan results via WebSocket.
"""
from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="FuzzPhantom GUI", docs_url=None, redoc_url=None)

# Mount static files BEFORE defining routes so root "/" overrides correctly
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
    run_subdomains: bool = True
    run_crawl: bool = True
    run_fuzz: bool = True
    run_api: bool = True
    run_smart_wordlist: bool = False
    wordlist: str = ""
    payload_files: list[str] = []
    output_formats: list[str] = ["json", "hackerone"]
    output_dir: str = "reports"
    crawl_depth: int = 3
    rate_limit: int = 50
    threads: int = 20
    timeout: int = 10
    proxy: str = ""


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
    queue: asyncio.Queue = asyncio.Queue(maxsize=50_000)

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
                # Wait up to 30 s for next message (keeps connection alive)
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(msg)
                if msg.get("type") in ("complete", "error", "stopped"):
                    break
            except asyncio.TimeoutError:
                # Keepalive ping
                await websocket.send_json({"type": "ping"})
                # If task is done and queue empty, we're finished
                task = app.state.active_task
                if (task is None or task.done()) and queue.empty():
                    await websocket.send_json({"type": "complete", "text": "Scan finished."})
                    break
    except WebSocketDisconnect:
        # Client closed browser/tab -> shut down the server cleanly
        logger.info("Browser disconnected. Shutting down server...")
        import os
        import signal
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
        if f.is_file() and f.suffix in (".json", ".md"):
            files.append({
                "name": f.name,
                "size": f.stat().st_size,
                "ext": f.suffix.lstrip("."),
            })
    return {"reports": files[:100]}


@app.get("/api/reports/download/{filename}")
async def download_report(filename: str):
    safe = Path(filename).name
    filepath = ROOT / "reports" / safe
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(str(filepath), filename=safe)
