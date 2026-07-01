"""
FuzzPhantom — Intigriti Report Format
Generates reports formatted for Intigriti bug bounty platform submissions.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from core.context import ScanContext, Finding
from core.logger import get_logger

logger = get_logger(__name__)

INTIGRITI_SEVERITY = {
    "CRITICAL": "Critical (10.0)",
    "HIGH": "High (7.0–8.9)",
    "MEDIUM": "Medium (4.0–6.9)",
    "LOW": "Low (0.1–3.9)",
    "INFO": "Informational",
}

IMPACT_MAP = {
    "CRITICAL": "Complete system compromise or data exfiltration possible.",
    "HIGH": "Significant data exposure or unauthorized access to sensitive features.",
    "MEDIUM": "Partial data exposure or limited unauthorized access.",
    "LOW": "Minimal impact; theoretical attack surface.",
    "INFO": "No direct exploitable impact; informational.",
}


def _format_finding(finding: Finding, index: int) -> str:
    severity_label = INTIGRITI_SEVERITY.get(finding.severity.upper(), "Informational")
    impact = IMPACT_MAP.get(finding.severity.upper(), "N/A")

    return f"""---

## Report #{index}: {finding.category}

**Severity:** {severity_label}
**Endpoint:** `{finding.url}`
**Parameter:** `{finding.parameter or "N/A"}`

### Vulnerability Description

{finding.detail}

### Proof of Concept

**Step 1:** Send the following request:
```http
GET {finding.url} HTTP/1.1
Host: {finding.url.split("/")[2] if "/" in finding.url else finding.url}
User-Agent: Mozilla/5.0
```

**Step 2:** The server responded with HTTP `{finding.status_code}` instead of the baseline `{finding.original_status}`.

**Payload injected into `{finding.parameter or "N/A"}`:**
```
{finding.payload or "N/A"}
```

**Response evidence:**
```
{finding.evidence[:400] if finding.evidence else "Anomalous response length or status code change observed."}
```

### Impact

{impact}

### Remediation Recommendation

- Implement allowlist-based input validation on parameter `{finding.parameter or "all parameters"}`.
- Enable WAF rules for common attack patterns.
- Disable verbose error messages in production.

"""


def export_intigriti(ctx: ScanContext, output_dir: str) -> str:
    """Generate an Intigriti-formatted Markdown report."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = out_dir / f"intigriti_{ctx.target_domain}_{timestamp}.md"

    summary = ctx.summary()
    findings_md = "\n".join(
        _format_finding(f, i + 1) for i, f in enumerate(ctx.findings)
    )

    report = f"""# Security Vulnerability Report — Intigriti Submission

**Tool:** FuzzPhantom v1.0.0
**Target:** `{ctx.target_domain}`
**Assessment Date:** {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}

---

## Assessment Overview

| Category | Results |
|---|---|
| Subdomains Discovered | {summary["subdomains"]} |
| Endpoints Crawled | {summary["crawled_urls"]} |
| Parameterized Endpoints | {summary["parameterized_urls"]} |
| API Endpoints | {summary["api_endpoints"]} |
| JS Files Analyzed | {summary["js_files"]} |
| Total Findings | **{summary["findings"]}** |

### Risk Distribution

| Severity | Count |
|---|---|
| Critical | {sum(1 for f in ctx.findings if f.severity == "CRITICAL")} |
| High | {sum(1 for f in ctx.findings if f.severity == "HIGH")} |
| Medium | {sum(1 for f in ctx.findings if f.severity == "MEDIUM")} |
| Low | {sum(1 for f in ctx.findings if f.severity == "LOW")} |
| Informational | {sum(1 for f in ctx.findings if f.severity == "INFO")} |

---

## Discovered Assets

### Subdomains
```
{chr(10).join(ctx.subdomains[:50]) or "None"}
```

### API Endpoints
```
{chr(10).join(ctx.api_endpoints[:30]) or "None"}
```

---

## Vulnerability Reports

{findings_md if ctx.findings else "_No exploitable findings were identified in this assessment._"}

---

*Report generated automatically by FuzzPhantom. Human verification required before submission.*
"""

    with open(filename, "w", encoding="utf-8") as fp:
        fp.write(report)

    logger.info(f"Intigriti report saved: [cyan]{filename}[/cyan]")
    return str(filename)
