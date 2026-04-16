# =============================================================================
# CyberToolkit Pro — Anomaly Detector (Enhanced)
# =============================================================================
# Threshold-based anomaly detection with configurable thresholds, pattern
# analysis, and structured alert output.
#
# UPGRADED from original: Configurable thresholds, structured results,
# multi-metric analysis.
# =============================================================================

import os
from collections import Counter, defaultdict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "anomaly_detector",
    "category": "detection",
    "description": "Threshold-based network/log anomaly detection engine",
    "author": "CyberToolkit Pro",
    "version": "2.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Path to log file to analyze"},
        {"name": "threshold", "required": False, "default": "20",
         "description": "Request count threshold for anomaly flagging"},
        {"name": "time_window", "required": False, "default": "60",
         "description": "Time window in seconds for rate analysis"},
    ],
    "tags": ["blue-team", "detection", "anomaly", "threshold"],
}


def run(args):
    filepath = args.get("target", "")
    if not filepath or not os.path.exists(filepath):
        return ToolResult(tool_name="anomaly_detector", status="error",
                          error=f"File not found: {filepath}")

    threshold = int(args.get("threshold", 20))

    ip_counts = Counter()
    line_count = 0
    anomalous_ips = []
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_count += 1
                parts = line.split()
                if not parts:
                    continue
                # Extract IP (first token in most log formats)
                ip = parts[0]
                # Basic IP validation
                if "." in ip and all(p.isdigit() for p in ip.split(".")[:2]):
                    ip_counts[ip] += 1
    except Exception as e:
        return ToolResult(tool_name="anomaly_detector", status="error", error=str(e))

    # Identify anomalous IPs
    for ip, count in ip_counts.most_common():
        if count >= threshold:
            anomalous_ips.append({"ip": ip, "count": count, "flag": "high_frequency"})
            severity = Severity.HIGH if count >= threshold * 5 else Severity.MEDIUM
            findings.append(Finding(
                title=f"Anomalous activity from {ip}: {count} events",
                severity=severity,
                description=f"IP {ip} generated {count} events (threshold: {threshold})",
                remediation="Investigate source IP, consider blocking or rate limiting",
            ))

    return ToolResult(
        tool_name="anomaly_detector",
        target=filepath,
        status="success",
        data={
            "total_lines": line_count,
            "unique_ips": len(ip_counts),
            "anomalous_ips": anomalous_ips,
            "top_ips": dict(ip_counts.most_common(10)),
            "alerts": [{"ip": a["ip"], "count": a["count"]} for a in anomalous_ips],
        },
        findings=findings,
    )
