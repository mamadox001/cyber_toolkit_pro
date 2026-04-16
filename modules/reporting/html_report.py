# =============================================================================
# CyberToolkit Pro — HTML Report Generator
# =============================================================================
# Generates professional HTML security reports with CSS styling,
# severity badges, findings tables, and executive summary.
# =============================================================================

import os
import json
from datetime import datetime
from core.models import ToolResult

TOOL_INFO = {
    "name": "html_report",
    "category": "reporting",
    "description": "Generate professional HTML security assessment reports",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": False, "default": "", "description": "Target that was assessed"},
        {"name": "output_file", "required": False, "default": "",
         "description": "Output file path (auto-generated if empty)"},
    ],
    "tags": ["reporting", "html", "output"],
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report — {target}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --text: #e2e8f0;
    --accent: #38bdf8; --border: #334155;
    --critical: #ef4444; --high: #f97316; --medium: #eab308;
    --low: #22c55e; --info: #60a5fa;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
    padding: 2rem; max-width: 1200px; margin: 0 auto;
  }}
  .header {{
    text-align: center; padding: 2rem; margin-bottom: 2rem;
    background: linear-gradient(135deg, #1e293b, #0f172a);
    border: 1px solid var(--border); border-radius: 12px;
  }}
  .header h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: 0.5rem; }}
  .header .subtitle {{ color: #94a3b8; font-size: 0.9rem; }}
  .section {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem;
  }}
  .section h2 {{
    color: var(--accent); font-size: 1.2rem; margin-bottom: 1rem;
    padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);
  }}
  .summary-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem; margin-bottom: 1rem;
  }}
  .stat-card {{
    background: var(--bg); border-radius: 8px; padding: 1rem;
    text-align: center; border: 1px solid var(--border);
  }}
  .stat-card .number {{ font-size: 2rem; font-weight: bold; color: var(--accent); }}
  .stat-card .label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; }}
  table {{
    width: 100%; border-collapse: collapse; font-size: 0.9rem;
  }}
  th {{
    background: var(--bg); color: var(--accent); padding: 0.75rem;
    text-align: left; border-bottom: 2px solid var(--border);
  }}
  td {{ padding: 0.75rem; border-bottom: 1px solid var(--border); }}
  tr:hover {{ background: rgba(56, 189, 248, 0.05); }}
  .badge {{
    padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem;
    font-weight: bold; text-transform: uppercase; display: inline-block;
  }}
  .badge-critical {{ background: var(--critical); color: white; }}
  .badge-high {{ background: var(--high); color: white; }}
  .badge-medium {{ background: var(--medium); color: #000; }}
  .badge-low {{ background: var(--low); color: white; }}
  .badge-info {{ background: var(--info); color: white; }}
  .footer {{
    text-align: center; color: #475569; font-size: 0.8rem;
    margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border);
  }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Security Assessment Report</h1>
  <div class="subtitle">
    Target: <strong>{target}</strong> | Generated: {timestamp} | CyberToolkit Pro v2.0
  </div>
</div>

<div class="section">
  <h2>📊 Executive Summary</h2>
  <div class="summary-grid">
    <div class="stat-card">
      <div class="number">{total_findings}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="stat-card">
      <div class="number" style="color: var(--critical)">{critical_count}</div>
      <div class="label">Critical</div>
    </div>
    <div class="stat-card">
      <div class="number" style="color: var(--high)">{high_count}</div>
      <div class="label">High</div>
    </div>
    <div class="stat-card">
      <div class="number" style="color: var(--medium)">{medium_count}</div>
      <div class="label">Medium</div>
    </div>
    <div class="stat-card">
      <div class="number" style="color: var(--low)">{low_count}</div>
      <div class="label">Low</div>
    </div>
    <div class="stat-card">
      <div class="number">{tools_run}</div>
      <div class="label">Tools Run</div>
    </div>
  </div>
</div>

<div class="section">
  <h2>🔍 Findings</h2>
  {findings_table}
</div>

<div class="section">
  <h2>🛠️ Tools Executed</h2>
  {tools_table}
</div>

<div class="footer">
  Generated by CyberToolkit Pro v2.0 — Offensive & Defensive Security Framework<br>
  This report is confidential and intended for authorized recipients only.
</div>
</body>
</html>"""


def _severity_badge(sev):
    return f'<span class="badge badge-{sev}">{sev}</span>'


def run(args):
    target = args.get("target", "unknown")
    output_file = args.get("output_file", "")
    pipeline_context = args.get("_pipeline_context", [])

    if not output_file:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = f"reports/report_{timestamp}.html"

    # Collect findings
    all_findings = []
    for result in pipeline_context:
        for f in result.get("findings", []):
            f["_tool"] = result.get("tool_name", "")
            all_findings.append(f)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Build findings table
    if all_findings:
        rows = ""
        for f in all_findings:
            sev = f.get("severity", "info")
            rows += f"""<tr>
              <td>{_severity_badge(sev)}</td>
              <td>{f.get('title', '')}</td>
              <td>{f.get('description', '')[:150]}</td>
              <td>{f.get('_tool', '')}</td>
              <td>{f.get('remediation', '')[:150]}</td>
            </tr>"""
        findings_table = f"""<table>
          <thead><tr><th>Severity</th><th>Finding</th><th>Description</th><th>Tool</th><th>Remediation</th></tr></thead>
          <tbody>{rows}</tbody></table>"""
    else:
        findings_table = "<p>No findings generated.</p>"

    # Build tools table
    if pipeline_context:
        tool_rows = ""
        for r in pipeline_context:
            status = "✅" if r.get("status") == "success" else "❌"
            tool_rows += f"""<tr>
              <td>{r.get('tool_name', '')}</td>
              <td>{r.get('target', '')}</td>
              <td>{status} {r.get('status', '')}</td>
              <td>{r.get('duration_ms', 0):.0f}ms</td>
              <td>{len(r.get('findings', []))}</td>
            </tr>"""
        tools_table = f"""<table>
          <thead><tr><th>Tool</th><th>Target</th><th>Status</th><th>Duration</th><th>Findings</th></tr></thead>
          <tbody>{tool_rows}</tbody></table>"""
    else:
        tools_table = "<p>No tools were executed in this session.</p>"

    # Render HTML
    html = HTML_TEMPLATE.format(
        target=target,
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        total_findings=len(all_findings),
        critical_count=sev_counts["critical"],
        high_count=sev_counts["high"],
        medium_count=sev_counts["medium"],
        low_count=sev_counts["low"],
        tools_run=len(pipeline_context),
        findings_table=findings_table,
        tools_table=tools_table,
    )

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    return ToolResult(
        tool_name="html_report",
        target=target,
        status="success",
        data={
            "output_file": output_file,
            "total_findings": len(all_findings),
            "severity_distribution": sev_counts,
        },
    )
