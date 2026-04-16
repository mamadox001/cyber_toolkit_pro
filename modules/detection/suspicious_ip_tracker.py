# =============================================================================
# CyberToolkit Pro — Suspicious IP Tracker
# =============================================================================
# Tracks and profiles suspicious IPs across log sources. Aggregates
# activity, detects patterns, and maintains a watchlist.
# =============================================================================

import os
import json
from collections import Counter, defaultdict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "suspicious_ip_tracker",
    "category": "detection",
    "description": "Suspicious IP tracking and profiling across log sources",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Path to log file or directory of logs"},
        {"name": "watchlist", "required": False, "default": "",
         "description": "Path to IP watchlist file (one IP per line)"},
        {"name": "threshold", "required": False, "default": "10",
         "description": "Activity threshold for flagging"},
    ],
    "tags": ["blue-team", "detection", "ip-tracking", "watchlist"],
}

# Known suspicious IP ranges / patterns (simplified)
SUSPICIOUS_PATTERNS = [
    "10.0.0.",     # Internal but unusual in web logs
    "192.168.",    # Internal
    "172.16.",     # Internal
]


def _extract_ips(filepath):
    """Extract all IP addresses from a file."""
    import re
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    ips = Counter()

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                for ip in ip_pattern.findall(line):
                    ips[ip] += 1
    except Exception:
        pass

    return ips


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="suspicious_ip_tracker", status="error", error="No target specified")

    threshold = int(args.get("threshold", 10))
    watchlist_path = args.get("watchlist", "")

    # Load watchlist
    watchlist = set()
    if watchlist_path and os.path.exists(watchlist_path):
        with open(watchlist_path, "r") as f:
            watchlist = {line.strip() for line in f if line.strip()}

    # Collect IPs from all files
    all_ips = Counter()

    if os.path.isdir(target):
        for fname in os.listdir(target):
            fpath = os.path.join(target, fname)
            if os.path.isfile(fpath):
                all_ips.update(_extract_ips(fpath))
    elif os.path.isfile(target):
        all_ips = _extract_ips(target)
    else:
        return ToolResult(tool_name="suspicious_ip_tracker", status="error",
                          error=f"Path not found: {target}")

    # Analyze IPs
    findings = []
    suspicious_ips = []

    for ip, count in all_ips.most_common():
        reasons = []

        # Check watchlist
        if ip in watchlist:
            reasons.append("watchlist_match")

        # High frequency
        if count >= threshold:
            reasons.append("high_frequency")

        if reasons:
            suspicious_ips.append({
                "ip": ip,
                "count": count,
                "reasons": reasons,
            })

            if "watchlist_match" in reasons:
                findings.append(Finding(
                    title=f"Watchlist IP detected: {ip} ({count} events)",
                    severity=Severity.HIGH,
                    description=f"IP {ip} from watchlist appeared {count} times in logs",
                    remediation="Investigate activity from this IP immediately",
                ))
            elif count >= threshold * 5:
                findings.append(Finding(
                    title=f"High-volume IP: {ip} ({count} events)",
                    severity=Severity.MEDIUM,
                    description=f"IP {ip} has unusually high event count",
                ))

    return ToolResult(
        tool_name="suspicious_ip_tracker",
        target=target,
        status="success",
        data={
            "total_unique_ips": len(all_ips),
            "suspicious_ips": suspicious_ips,
            "watchlist_hits": [s for s in suspicious_ips if "watchlist_match" in s["reasons"]],
            "top_ips": dict(all_ips.most_common(20)),
        },
        findings=findings,
    )
