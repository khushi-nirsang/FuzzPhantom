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

if __name__ == "__main__":
    print("\n  FuzzPhantom GUI")
    print("  Dashboard -> http://localhost:8080\n")
    uvicorn.run(
        "gui.app:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_level="warning",
    )
