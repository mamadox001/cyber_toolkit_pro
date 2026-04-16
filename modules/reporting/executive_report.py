# =============================================================================
# CyberToolkit Pro — Executive Summary Report
# =============================================================================
# Generates non-technical executive summary reports suitable for
# management and stakeholder review.
# =============================================================================

import os
import json
from datetime import datetime
from core.models import ToolResult, Finding, Severity
from core.database import get_db

TOOL_INFO = {
    "name": "executive_report",
    "category": "reporting",
    "description": "Generate non-technical executive summary security reports",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": False, "default": "",
         "description": "Target filter (empty = all assessments)"},
        {"name": "campaign_id", "required": False, "default": "",
         "description": "Campaign ID to report on"},
        {"name": "output", "required": False, "default": "reports/executive_summary.html",
         "description": "Output file path"},
    ],
    "tags": ["reporting", "executive", "summary", "management"],
}


def run(args):
    target = args.get("target", "")
    campaign_id = args.get("campaign_id", "")
    output_path = args.get("output", "reports/executive_summary.html")

    db = get_db()

    # Get data
    if campaign_id:
        scans = db.get_scans(campaign_id=campaign_id, limit=1000)
    elif target:
        scans = db.get_scans(target=target, limit=1000)
    else:
        scans = db.get_scans(limit=1000)

    all_findings = []
    for scan in scans:
        all_findings.extend(db.get_findings(scan_id=scan.get("scan_id", "")))

    # Severity statistics
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        s = f.get("severity", "info")
        if s in sev_counts:
            sev_counts[s] += 1

    total_scans = len(scans)
    total_findings = len(all_findings)
    risk_score = (sev_counts["critical"] * 10 + sev_counts["high"] * 7 +
                  sev_counts["medium"] * 4 + sev_counts["low"] * 1)

    if risk_score == 0:
        risk_level = "Low"
        risk_color = "#22c55e"
    elif risk_score < 20:
        risk_level = "Moderate"
        risk_color = "#eab308"
    elif risk_score < 50:
        risk_level = "High"
        risk_color = "#f97316"
    else:
        risk_level = "Critical"
        risk_color = "#ef4444"

    # Top issues
    critical_findings = [f for f in all_findings if f.get("severity") in ("critical", "high")]

    # Generate HTML
    html = _build_executive_html(
        target=target or "All Targets",
        date=datetime.utcnow().strftime("%B %d, %Y"),
        total_scans=total_scans,
        total_findings=total_findings,
        sev_counts=sev_counts,
        risk_level=risk_level,
        risk_color=risk_color,
        risk_score=risk_score,
        critical_findings=critical_findings[:10],
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return ToolResult(
        tool_name="executive_report",
        target=target,
        status="success",
        data={
            "output_file": output_path,
            "total_scans": total_scans,
            "total_findings": total_findings,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "severity_breakdown": sev_counts,
        },
        findings=[Finding(
            title=f"Executive report generated: {risk_level} risk ({output_path})",
            severity=Severity.INFO,
        )],
    )


def _build_executive_html(target, date, total_scans, total_findings,
                           sev_counts, risk_level, risk_color, risk_score,
                           critical_findings):
    """Build the executive summary HTML."""
    critical_rows = ""
    for i, f in enumerate(critical_findings, 1):
        sev = f.get("severity", "info").upper()
        sev_color = "#ef4444" if sev == "CRITICAL" else "#f97316"
        critical_rows += f"""
        <tr>
            <td>{i}</td>
            <td><span style="color:{sev_color};font-weight:700">{sev}</span></td>
            <td>{f.get('title', 'N/A')}</td>
            <td>{f.get('remediation', 'Review and remediate')[:100]}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Executive Security Summary — {target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:40px}}
.report{{max-width:900px;margin:0 auto;background:#1e293b;border-radius:16px;padding:48px;box-shadow:0 20px 60px rgba(0,0,0,.3)}}
h1{{font-size:28px;color:#f1f5f9;margin-bottom:8px}}
.subtitle{{color:#94a3b8;font-size:14px;margin-bottom:32px}}
.risk-banner{{background:linear-gradient(135deg,{risk_color}22,{risk_color}11);border:1px solid {risk_color}44;
border-radius:12px;padding:24px;text-align:center;margin-bottom:32px}}
.risk-level{{font-size:36px;font-weight:800;color:{risk_color}}}
.risk-label{{color:#94a3b8;font-size:14px;margin-top:4px}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}}
.metric{{background:#0f172a;border-radius:10px;padding:20px;text-align:center}}
.metric-value{{font-size:28px;font-weight:700}}
.metric-label{{color:#64748b;font-size:12px;margin-top:4px;text-transform:uppercase}}
.critical{{color:#ef4444}} .high{{color:#f97316}} .medium{{color:#eab308}} .low{{color:#22c55e}} .info{{color:#3b82f6}}
h2{{font-size:18px;color:#f1f5f9;margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid #334155}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}
th{{background:#0f172a;color:#94a3b8;text-align:left;padding:10px 12px;font-size:12px;text-transform:uppercase}}
td{{padding:10px 12px;border-bottom:1px solid #1e293b;font-size:13px}}
tr:hover{{background:#0f172a55}}
.footer{{text-align:center;color:#475569;font-size:11px;margin-top:32px;padding-top:16px;border-top:1px solid #334155}}
</style></head><body>
<div class="report">
<h1>🛡️ Executive Security Summary</h1>
<div class="subtitle">Assessment Target: <strong>{target}</strong> — Generated: {date}</div>

<div class="risk-banner">
<div class="risk-level">{risk_level.upper()} RISK</div>
<div class="risk-label">Overall Risk Score: {risk_score}</div>
</div>

<div class="metrics">
<div class="metric"><div class="metric-value">{total_scans}</div><div class="metric-label">Scans Run</div></div>
<div class="metric"><div class="metric-value">{total_findings}</div><div class="metric-label">Total Findings</div></div>
<div class="metric"><div class="metric-value critical">{sev_counts['critical']}</div><div class="metric-label">Critical</div></div>
<div class="metric"><div class="metric-value high">{sev_counts['high']}</div><div class="metric-label">High</div></div>
</div>

<div class="metrics">
<div class="metric"><div class="metric-value medium">{sev_counts['medium']}</div><div class="metric-label">Medium</div></div>
<div class="metric"><div class="metric-value low">{sev_counts['low']}</div><div class="metric-label">Low</div></div>
<div class="metric"><div class="metric-value info">{sev_counts['info']}</div><div class="metric-label">Info</div></div>
<div class="metric"><div class="metric-value" style="color:#a78bfa">{risk_score}</div><div class="metric-label">Risk Score</div></div>
</div>

<h2>⚠️ Critical & High Priority Findings</h2>
<table>
<tr><th>#</th><th>Severity</th><th>Finding</th><th>Recommendation</th></tr>
{critical_rows if critical_rows else '<tr><td colspan="4" style="text-align:center;color:#22c55e">No critical or high findings — excellent security posture!</td></tr>'}
</table>

<h2>📋 Recommendations</h2>
<table>
<tr><th>Priority</th><th>Action</th></tr>
<tr><td><span class="critical">Immediate</span></td><td>Address all Critical findings within 24 hours</td></tr>
<tr><td><span class="high">Short-term</span></td><td>Remediate High findings within 1 week</td></tr>
<tr><td><span class="medium">Medium-term</span></td><td>Plan Medium finding remediation within 30 days</td></tr>
<tr><td><span class="low">Ongoing</span></td><td>Review Low/Info findings during regular maintenance</td></tr>
</table>

<div class="footer">
Generated by CyberToolkit Pro v2.0 — Confidential — For authorized recipients only
</div>
</div></body></html>"""
