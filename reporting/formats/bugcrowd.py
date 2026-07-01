"""
FuzzPhantom — Bugcrowd Report Format
Generates reports formatted for Bugcrowd VRT submissions.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from core.context import ScanContext, Finding
from core.logger import get_logger

logger = get_logger(__name__)

# Bugcrowd VRT severity levels
VRT_SEVERITY = {
    "CRITICAL": "P1",
    "HIGH": "P2",
    "MEDIUM": "P3",
    "LOW": "P4",
    "INFO": "P5",
}


def _format_finding(finding: Finding, index: int) -> str:
    priority = VRT_SEVERITY.get(finding.severity.upper(), "P5")

    return f"""### [{priority}] Finding #{index} — {finding.category}

**URL:** `{finding.url}`
**Parameter:** `{finding.parameter or "N/A"}`
**Payload:** `{finding.payload or "N/A"}`
**HTTP Status:** `{finding.status_code}` (baseline: `{finding.original_status}`)
**Response Length:** `{finding.response_length}` bytes (baseline: `{finding.original_length}`)

**Summary:**
{finding.detail}

**Steps to Reproduce:**
1. Send a `GET` request to `{finding.url}`
2. Inject payload `{finding.payload or "N/A"}` into parameter `{finding.parameter or "N/A"}`
3. Observe the anomalous response

**Evidence:**
```
{finding.evidence[:400] if finding.evidence else "See detail above"}
```

**CVSS Base Score Estimate:** {"9.0" if priority == "P1" else "7.5" if priority == "P2" else "5.0" if priority == "P3" else "3.0"}

---
"""


def export_bugcrowd(ctx: ScanContext, output_dir: str) -> str:
    """Generate a Bugcrowd-formatted Markdown report."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    clean_target = ctx.target_domain.replace("https://", "").replace("http://", "").replace(":", "_").replace("/", "_").replace("\\", "_")
    filename = out_dir / f"bugcrowd_{clean_target}_{timestamp}.md"

    summary = ctx.summary()
    findings_md = "\n".join(
        _format_finding(f, i + 1) for i, f in enumerate(ctx.findings)
    )

    report = f"""# Bug Report — Bugcrowd Submission
## Researcher Tool: FuzzPhantom v1.0.0

**Target Program:** {ctx.target_domain}
**Report Date:** {datetime.now().strftime("%Y-%m-%d")}
**Researcher:** [Your Handle]

---

## Scope Assessment Summary

| Item | Count |
|---|---|
| Subdomains in Scope | {summary["subdomains"]} |
| Endpoints Tested | {summary["crawled_urls"]} |
| Parameters Fuzzed | {summary["parameterized_urls"]} |
| API Routes Found | {summary["api_endpoints"]} |
| Total Issues | **{summary["findings"]}** |

### Priority Breakdown (Bugcrowd VRT)

| Priority | Count | Meaning |
|---|---|---|
| P1 (Critical) | {sum(1 for f in ctx.findings if f.severity == "CRITICAL")} | Immediate critical risk |
| P2 (High) | {sum(1 for f in ctx.findings if f.severity == "HIGH")} | Significant security risk |
| P3 (Medium) | {sum(1 for f in ctx.findings if f.severity == "MEDIUM")} | Moderate security risk |
| P4 (Low) | {sum(1 for f in ctx.findings if f.severity == "LOW")} | Low security risk |
| P5 (Info) | {sum(1 for f in ctx.findings if f.severity == "INFO")} | Informational |

---

## Subdomains Discovered

```
{chr(10).join(ctx.subdomains[:50]) or "None"}
```

---

## Vulnerability Reports

{findings_md if ctx.findings else "_No actionable findings._"}

---
*Generated with FuzzPhantom. Always validate before submission.*
"""

    with open(filename, "w", encoding="utf-8") as fp:
        fp.write(report)

    logger.info(f"Bugcrowd report saved: [cyan]{filename}[/cyan]")
    return str(filename)
