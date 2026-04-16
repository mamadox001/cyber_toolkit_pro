# =============================================================================
# CyberToolkit Pro — JSON Reporter (Enhanced)
# =============================================================================
# Generates structured JSON reports from tool results with findings,
# severity scoring, timestamps, and metadata.
# =============================================================================

import json
import os
from datetime import datetime
from core.models import ToolResult

TOOL_INFO = {
    "name": "json_report",
    "category": "reporting",
    "description": "Generate structured JSON security reports",
    "author": "CyberToolkit Pro",
    "version": "2.0.0",
    "args": [
        {"name": "target", "required": False, "default": "", "description": "Target that was assessed"},
        {"name": "output_file", "required": False, "default": "",
         "description": "Output file path (auto-generated if empty)"},
    ],
    "tags": ["reporting", "json", "output"],
}


def run(args):
    target = args.get("target", "unknown")
    output_file = args.get("output_file", "")

    # Gather pipeline context if available
    pipeline_context = args.get("_pipeline_context", [])

    if not output_file:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = f"reports/report_{timestamp}.json"

    # Build report structure
    all_findings = []
    for result in pipeline_context:
        findings = result.get("findings", [])
        for f in findings:
            all_findings.append(f)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info") if isinstance(f, dict) else "info"
        if sev in severity_counts:
            severity_counts[sev] += 1

    report = {
        "report_metadata": {
            "framework": "CyberToolkit Pro v2.0",
            "generated_at": datetime.utcnow().isoformat(),
            "target": target,
        },
        "summary": {
            "total_tools_run": len(pipeline_context),
            "total_findings": len(all_findings),
            "severity_distribution": severity_counts,
        },
        "tool_results": pipeline_context,
        "findings": all_findings,
    }

    # Write report
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    return ToolResult(
        tool_name="json_report",
        target=target,
        status="success",
        data={
            "output_file": output_file,
            "total_findings": len(all_findings),
            "severity_distribution": severity_counts,
        },
    )
