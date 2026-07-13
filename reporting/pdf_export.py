"""
Professional PDF export for FuzzPhantom scan results.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from core.context import Finding, ScanContext
from core.logger import get_logger

logger = get_logger(__name__)


BRAND = colors.HexColor("#06B6D4")
BRAND_DARK = colors.HexColor("#0B1020")
PANEL = colors.HexColor("#111827")
MUTED = colors.HexColor("#64748B")
TEXT = colors.HexColor("#111827")
SOFT = colors.HexColor("#E2E8F0")
LIGHT = colors.HexColor("#F8FAFC")

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#EF4444"),
    "HIGH": colors.HexColor("#F97316"),
    "MEDIUM": colors.HexColor("#F59E0B"),
    "LOW": colors.HexColor("#22C55E"),
    "INFO": colors.HexColor("#06B6D4"),
}


class HeroBand(Flowable):
    def __init__(self, target: str, generated_at: str) -> None:
        super().__init__()
        self.target = target
        self.generated_at = generated_at
        self.width = 170 * mm
        self.height = 45 * mm

    def draw(self) -> None:
        canvas = self.canv
        canvas.saveState()
        canvas.setFillColor(BRAND_DARK)
        canvas.roundRect(0, 0, self.width, self.height, 8, stroke=0, fill=1)
        canvas.setFillColor(colors.HexColor("#0EA5E9"))
        canvas.circle(self.width - 18 * mm, self.height - 11 * mm, 23 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.HexColor("#10B981"))
        canvas.circle(self.width - 36 * mm, 4 * mm, 14 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 24)
        canvas.drawString(10 * mm, 27 * mm, "FuzzPhantom Scan Report")
        canvas.setFont("Helvetica", 10)
        canvas.setFillColor(colors.HexColor("#BAE6FD"))
        canvas.drawString(10 * mm, 19 * mm, "Professional reconnaissance and fuzzing summary")
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 11)
        canvas.drawString(10 * mm, 9 * mm, self.target[:85])
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#CBD5E1"))
        canvas.drawRightString(self.width - 8 * mm, 8 * mm, self.generated_at)
        canvas.restoreState()


class MetricCard(Flowable):
    def __init__(self, label: str, value: str, color: colors.Color = BRAND) -> None:
        super().__init__()
        self.label = label
        self.value = value
        self.color = color
        self.width = 39 * mm
        self.height = 21 * mm

    def draw(self) -> None:
        canvas = self.canv
        canvas.saveState()
        canvas.setFillColor(colors.white)
        canvas.setStrokeColor(SOFT)
        canvas.roundRect(0, 0, self.width, self.height, 5, stroke=1, fill=1)
        canvas.setFillColor(self.color)
        canvas.roundRect(0, self.height - 3, self.width, 3, 5, stroke=0, fill=1)
        canvas.setFillColor(TEXT)
        canvas.setFont("Helvetica-Bold", 16)
        canvas.drawCentredString(self.width / 2, 8 * mm, self.value)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawCentredString(self.width / 2, 3 * mm, self.label.upper())
        canvas.restoreState()


class SeverityBar(Flowable):
    def __init__(self, counts: dict[str, int]) -> None:
        super().__init__()
        self.counts = counts
        self.width = 170 * mm
        self.height = 13 * mm

    def draw(self) -> None:
        total = sum(self.counts.values()) or 1
        canvas = self.canv
        canvas.saveState()
        x = 0
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = self.counts.get(sev, 0)
            segment = self.width * (count / total)
            if segment <= 0:
                continue
            canvas.setFillColor(SEV_COLORS[sev])
            canvas.rect(x, 4 * mm, segment, 5 * mm, stroke=0, fill=1)
            x += segment
        canvas.setStrokeColor(SOFT)
        canvas.roundRect(0, 4 * mm, self.width, 5 * mm, 3, stroke=1, fill=0)
        canvas.restoreState()


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=18, textColor=TEXT, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=13, textColor=TEXT, spaceBefore=12, spaceAfter=8),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9, leading=12, textColor=TEXT),
        "muted": ParagraphStyle("muted", parent=base["BodyText"], fontName="Helvetica", fontSize=8, leading=11, textColor=MUTED),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontName="Helvetica", fontSize=7.2, leading=9, textColor=TEXT),
        "center": ParagraphStyle("center", parent=base["BodyText"], fontName="Helvetica", fontSize=8, alignment=TA_CENTER, textColor=MUTED),
        "cell": ParagraphStyle("cell", parent=base["BodyText"], fontName="Helvetica", fontSize=7, leading=8.5, textColor=TEXT, alignment=TA_LEFT),
    }


def _clean_target(target: str) -> str:
    return (
        target.replace("https://", "")
        .replace("http://", "")
        .replace(":", "_")
        .replace("/", "_")
        .replace("\\", "_")
        or "unknown"
    )


def _filename(ctx: ScanContext, output_dir: str) -> Path:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return out_dir / f"fuzzphantom_{_clean_target(ctx.target_domain)}_{timestamp}.pdf"


def _safe(text: object, limit: int = 140) -> str:
    value = str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if len(value) > limit:
        return value[: limit - 1] + "..."
    return value


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity for f in findings)
    return {sev: counts.get(sev, 0) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}


def _table(data: list[list[object]], widths: list[float], header: bool = True) -> Table:
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.25, SOFT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
    ]
    if header:
        style.extend([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
        ])
    table.setStyle(TableStyle(style))
    return table


def _severity_table(findings: list[Finding], styles: dict[str, ParagraphStyle]) -> Table:
    counts = _severity_counts(findings)
    rows = [["Severity", "Count", "Meaning"]]
    meanings = {
        "CRITICAL": "Immediate attention recommended.",
        "HIGH": "Strong signal or exposed sensitive surface.",
        "MEDIUM": "Useful security signal requiring review.",
        "LOW": "Informational behavior change.",
        "INFO": "Reconnaissance result or soft signal.",
    }
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        rows.append([
            Paragraph(f"<b>{sev}</b>", styles["cell"]),
            str(counts[sev]),
            Paragraph(meanings[sev], styles["cell"]),
        ])
    table = _table(rows, [38 * mm, 22 * mm, 105 * mm])
    for idx, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), start=1):
        table.setStyle(TableStyle([("TEXTCOLOR", (0, idx), (0, idx), SEV_COLORS[sev])]))
    return table


def _findings_table(findings: list[Finding], styles: dict[str, ParagraphStyle], limit: int = 35) -> Table:
    rows: list[list[object]] = [["Severity", "Category", "Status", "URL", "Detail"]]
    ordered = sorted(
        findings,
        key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 9),
    )
    for finding in ordered[:limit]:
        rows.append([
            Paragraph(f"<b>{_safe(finding.severity, 20)}</b>", styles["cell"]),
            Paragraph(_safe(finding.category, 42), styles["cell"]),
            str(finding.status_code or ""),
            Paragraph(_safe(finding.url, 80), styles["cell"]),
            Paragraph(_safe(finding.detail, 110), styles["cell"]),
        ])
    if len(rows) == 1:
        rows.append(["-", "-", "-", Paragraph("No findings recorded.", styles["cell"]), "-"])
    return _table(rows, [22 * mm, 30 * mm, 15 * mm, 52 * mm, 50 * mm])


def _asset_table(title: str, values: list[str], styles: dict[str, ParagraphStyle], limit: int = 30) -> list[object]:
    flow: list[object] = [Paragraph(title, styles["h2"])]
    rows: list[list[object]] = [["#", "Value"]]
    for idx, value in enumerate(values[:limit], start=1):
        rows.append([str(idx), Paragraph(_safe(value, 130), styles["cell"])])
    if len(rows) == 1:
        rows.append(["-", Paragraph("None discovered.", styles["cell"])])
    flow.append(_table(rows, [12 * mm, 155 * mm]))
    if len(values) > limit:
        flow.append(Paragraph(f"Showing first {limit} of {len(values)} items.", styles["muted"]))
    return flow


def _header_footer(canvas, doc) -> None:
    canvas.saveState()
    width, height = A4
    canvas.setStrokeColor(SOFT)
    canvas.line(18 * mm, 13 * mm, width - 18 * mm, 13 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 8 * mm, "FuzzPhantom - Authorized security testing report")
    canvas.drawRightString(width - 18 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def export_pdf(ctx: ScanContext, output_dir: str) -> str:
    """Export a polished PDF report for executive and technical review."""
    filename = _filename(ctx, output_dir)
    styles = _styles()
    summary = ctx.summary()
    findings = ctx.findings
    severity_counts = _severity_counts(findings)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    doc = SimpleDocTemplate(
        str(filename),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title=f"FuzzPhantom Report - {ctx.target_domain}",
        author="FuzzPhantom",
    )

    story: list[object] = [
        HeroBand(ctx.target_domain or "unknown target", generated),
        Spacer(1, 7 * mm),
        Table(
            [[
                MetricCard("Subdomains", str(summary.get("subdomains", 0)), colors.HexColor("#8B5CF6")),
                MetricCard("URLs Crawled", str(summary.get("crawled_urls", 0)), colors.HexColor("#06B6D4")),
                MetricCard("Directories", str(summary.get("directories", 0)), colors.HexColor("#F97316")),
                MetricCard("API Endpoints", str(summary.get("api_endpoints", 0)), colors.HexColor("#10B981")),
            ], [
                MetricCard("Parameters", str(summary.get("parameterized_urls", 0)), colors.HexColor("#F59E0B")),
                MetricCard("Findings", str(summary.get("findings", 0)), colors.HexColor("#EF4444")),
                MetricCard("Critical", str(severity_counts["CRITICAL"]), colors.HexColor("#DC2626")),
                MetricCard("High", str(severity_counts["HIGH"]), colors.HexColor("#EA580C")),
            ]],
            colWidths=[42 * mm] * 4,
            rowHeights=[24 * mm, 24 * mm],
            hAlign="LEFT",
        ),
        Spacer(1, 8 * mm),
        Paragraph("Executive Overview", styles["h1"]),
        Paragraph(
            "This report summarizes the attack surface discovered by FuzzPhantom, including reachable paths, "
            "parameters, API endpoints, and prioritized findings. Validate all findings manually before reporting.",
            styles["body"],
        ),
        Spacer(1, 5 * mm),
        SeverityBar(severity_counts),
        Spacer(1, 2 * mm),
        _severity_table(findings, styles),
        Spacer(1, 7 * mm),
        Paragraph("Priority Findings", styles["h1"]),
        _findings_table(findings, styles),
        PageBreak(),
        Paragraph("Discovered Surface", styles["h1"]),
    ]

    sections: list[list[object]] = [
        _asset_table("Subdomains", ctx.subdomains, styles),
        _asset_table("Crawled URLs", ctx.crawled_urls, styles),
        _asset_table("Parameterized URLs", ctx.parameterized_urls, styles),
        _asset_table("API Endpoints", ctx.api_endpoints, styles),
        _asset_table("JavaScript Files", ctx.js_files, styles),
    ]
    for section in sections:
        story.extend(section)
        story.append(Spacer(1, 5 * mm))

    story.extend([
        PageBreak(),
        Paragraph("Methodology Snapshot", styles["h1"]),
        _table(
            [
                ["Setting", "Value"],
                ["Target", Paragraph(_safe(ctx.target_domain, 120), styles["cell"])],
                ["Rate limit", f"{ctx.rate_limit} req/s"],
                ["Threads", str(ctx.threads)],
                ["Timeout", f"{ctx.timeout}s"],
                ["Directory depth", str(ctx.dir_depth)],
                ["Crawler depth", str(ctx.crawl_depth)],
                ["Calibration", "enabled" if ctx.auto_calibration else "disabled"],
                ["Calibration profile", ctx.calibration_profile],
                ["Follow redirects", "yes" if ctx.follow_redirects else "no"],
                ["Proxy", ctx.proxy or "none"],
            ],
            [45 * mm, 122 * mm],
        ),
        Spacer(1, 8 * mm),
        Paragraph("Recommended Next Actions", styles["h1"]),
        _table(
            [
                ["Priority", "Action"],
                ["1", Paragraph("Manually verify critical and high findings with a browser or proxy.", styles["cell"])],
                ["2", Paragraph("Review exposed directories and API endpoints for authentication and authorization gaps.", styles["cell"])],
                ["3", Paragraph("Use JSONL/CSV exports for deduplication, ticketing, and long-term tracking.", styles["cell"])],
                ["4", Paragraph("Run a second pass with target-specific wordlists and replay proxy enabled.", styles["cell"])],
            ],
            [18 * mm, 149 * mm],
        ),
    ])

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    logger.info(f"PDF report saved: [cyan]{filename}[/cyan]")
    return str(filename)
