"""
FuzzPhantom — Report Orchestrator
Dispatches results from ScanContext to all requested output formats.
"""

from __future__ import annotations

from core.context import ScanContext
from core.logger import get_logger, console
from reporting.json_export import export_json
from reporting.flat_exports import export_csv, export_jsonl
from reporting.pdf_export import export_pdf
from reporting.formats.hackerone import export_hackerone
from reporting.formats.bugcrowd import export_bugcrowd
from reporting.formats.intigriti import export_intigriti

logger = get_logger(__name__)

FORMAT_DISPATCH = {
    "json": export_json,
    "jsonl": export_jsonl,
    "csv": export_csv,
    "pdf": export_pdf,
    "hackerone": export_hackerone,
    "bugcrowd": export_bugcrowd,
    "intigriti": export_intigriti,
}


def generate_reports(ctx: ScanContext) -> list[str]:
    """
    Generate reports in all formats specified in ctx.output_formats.
    Defaults to JSON if no format specified.
    Returns list of generated file paths.
    """
    console.rule("[bold cyan]Generating Reports[/bold cyan]")

    formats = ctx.output_formats or ["json"]
    output_dir = ctx.output_dir
    generated: list[str] = []

    for fmt in formats:
        fmt_lower = fmt.lower()
        if fmt_lower not in FORMAT_DISPATCH:
            logger.warning(f"Unknown output format '{fmt}'. Skipping.")
            continue
        try:
            path = FORMAT_DISPATCH[fmt_lower](ctx, output_dir)
            generated.append(path)
        except Exception as exc:
            logger.error(f"Failed to generate {fmt} report: {exc}")

    console.print(
        f"\n[bold green]✔ Reports generated:[/bold green]"
    )
    for path in generated:
        console.print(f"  • [cyan]{path}[/cyan]")

    return generated
