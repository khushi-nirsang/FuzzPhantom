"""
FuzzPhantom — JSON Export
Exports full scan context to structured JSON for programmatic consumption.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from core.context import ScanContext
from core.logger import get_logger

logger = get_logger(__name__)


def export_json(ctx: ScanContext, output_dir: str) -> str:
    """Export complete scan results to a timestamped JSON file."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = out_dir / f"fuzzphantom_{ctx.target_domain}_{timestamp}.json"

    data = {
        "meta": {
            "tool": "FuzzPhantom",
            "version": "1.0.0",
            "target": ctx.target_domain,
            "timestamp": datetime.now().isoformat(),
            "summary": ctx.summary(),
        },
        "subdomains": ctx.subdomains,
        "crawled_urls": ctx.crawled_urls,
        "parameterized_urls": ctx.parameterized_urls,
        "api_endpoints": ctx.api_endpoints,
        "js_files": ctx.js_files,
        "smart_wordlist": ctx.smart_wordlist_terms,
        "findings": [f.to_dict() for f in ctx.findings],
    }

    with open(filename, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)

    logger.info(f"JSON report saved: [cyan]{filename}[/cyan]")
    return str(filename)
