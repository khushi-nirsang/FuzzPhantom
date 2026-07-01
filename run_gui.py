#!/usr/bin/env python3
"""
FuzzPhantom GUI Launcher
Run: python run_gui.py
Then open http://localhost:8080 in your browser.
"""
import sys
import os
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)  # Ensure relative paths (wordlists/, reports/) resolve correctly

import uvicorn
import socket

def find_free_port(start_port: int) -> int:
    """Find the first available port starting from start_port."""
    port = start_port
    while port < 65535:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('0.0.0.0', port))
                return port
            except OSError:
                port += 1
    raise RuntimeError("No free ports available")

if __name__ == "__main__":
    port = find_free_port(8080)
    print("\n  FuzzPhantom GUI")
    print(f"  Dashboard -> http://localhost:{port}\n")
    uvicorn.run(
        "gui.app:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="warning",
    )
