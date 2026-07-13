"""
FuzzPhantom - Flat exports for automation.
JSONL and CSV are better suited for large fuzzing runs than pretty reports.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from core.context import ScanContext, Finding
from core.logger import get_logger

logger = get_logger(__name__)


def _clean_target(target: str) -> str:
    return (
        target.replace("https://", "")
        .replace("http://", "")
        .replace(":", "_")
        .replace("/", "_")
        .replace("\\", "_")
        or "unknown"
    )


def _filename(ctx: ScanContext, output_dir: str, suffix: str) -> Path:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return out_dir / f"fuzzphantom_{_clean_target(ctx.target_domain)}_{timestamp}.{suffix}"


def _finding_row(finding: Finding) -> dict[str, Any]:
    data = finding.to_dict()
    extra = data.pop("extra", {}) or {}
    return {
        "category": data.get("category", ""),
        "severity": data.get("severity", ""),
        "url": data.get("url", ""),
        "parameter": data.get("parameter", ""),
        "payload": data.get("payload", ""),
        "status_code": data.get("status_code", 0),
        "original_status": data.get("original_status", 0),
        "response_length": data.get("response_length", 0),
        "original_length": data.get("original_length", 0),
        "detail": data.get("detail", ""),
        "evidence": data.get("evidence", ""),
        "extra": json.dumps(extra, ensure_ascii=False, sort_keys=True),
    }


def export_jsonl(ctx: ScanContext, output_dir: str) -> str:
    """Export one JSON object per finding for streaming-friendly processing."""
    filename = _filename(ctx, output_dir, "jsonl")
    meta = {
        "type": "meta",
        "tool": "FuzzPhantom",
        "version": "1.0.0",
        "target": ctx.target_domain,
        "timestamp": datetime.now().isoformat(),
        "summary": ctx.summary(),
    }

    with open(filename, "w", encoding="utf-8") as fp:
        fp.write(json.dumps(meta, ensure_ascii=False) + "\n")
        for finding in ctx.findings:
            item = finding.to_dict()
            item["type"] = "finding"
            fp.write(json.dumps(item, ensure_ascii=False) + "\n")

    logger.info(f"JSONL report saved: [cyan]{filename}[/cyan]")
    return str(filename)


def export_csv(ctx: ScanContext, output_dir: str) -> str:
    """Export findings as a flat CSV table."""
    filename = _filename(ctx, output_dir, "csv")
    fieldnames = [
        "category",
        "severity",
        "url",
        "parameter",
        "payload",
        "status_code",
        "original_status",
        "response_length",
        "original_length",
        "detail",
        "evidence",
        "extra",
    ]

    with open(filename, "w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for finding in ctx.findings:
            writer.writerow(_finding_row(finding))

    logger.info(f"CSV report saved: [cyan]{filename}[/cyan]")
    return str(filename)
