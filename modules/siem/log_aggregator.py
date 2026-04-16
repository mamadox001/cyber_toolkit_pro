# =============================================================================
# CyberToolkit Pro — Log Aggregator
# =============================================================================
# Aggregates logs from multiple sources into a unified format for
# centralized analysis. Provides normalized output and statistics.
# =============================================================================

import os
import re
import json
from datetime import datetime
from collections import Counter
from core.models import ToolResult

TOOL_INFO = {
    "name": "log_aggregator",
    "category": "siem",
    "description": "Multi-source log aggregation and normalization",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Directory containing log files"},
        {"name": "output_file", "required": False, "default": "",
         "description": "Path to save aggregated output (JSON)"},
        {"name": "max_lines", "required": False, "default": "10000",
         "description": "Maximum lines to process per file"},
    ],
    "tags": ["blue-team", "siem", "aggregation", "logs"],
}

IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
TIMESTAMP_PATTERNS = [
    re.compile(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"),  # Syslog
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"),  # ISO
    re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"),  # Apache
]


def _normalize_line(line, source_file):
    """Normalize a log line into a structured event."""
    event = {
        "source": source_file,
        "raw": line.strip()[:500],
    }

    # Extract timestamp
    for pattern in TIMESTAMP_PATTERNS:
        m = pattern.search(line)
        if m:
            event["timestamp"] = m.group(1)
            break

    # Extract IPs
    ips = IP_PATTERN.findall(line)
    if ips:
        event["ips"] = list(set(ips))

    # Detect severity from keywords
    line_lower = line.lower()
    if any(w in line_lower for w in ["error", "fail", "critical", "alert"]):
        event["severity"] = "high"
    elif any(w in line_lower for w in ["warning", "warn"]):
        event["severity"] = "medium"
    else:
        event["severity"] = "low"

    return event


def run(args):
    target = args.get("target", "")
    if not target or not os.path.exists(target):
        return ToolResult(tool_name="log_aggregator", status="error",
                          error=f"Path not found: {target}")

    max_lines = int(args.get("max_lines", 10000))
    output_file = args.get("output_file", "")

    files = []
    if os.path.isdir(target):
        for fname in sorted(os.listdir(target)):
            fpath = os.path.join(target, fname)
            if os.path.isfile(fpath):
                files.append(fpath)
    else:
        files = [target]

    all_events = []
    source_stats = {}
    severity_counts = Counter()

    for filepath in files:
        fname = os.path.basename(filepath)
        line_count = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line_count >= max_lines:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    event = _normalize_line(line, fname)
                    all_events.append(event)
                    severity_counts[event["severity"]] += 1
                    line_count += 1
        except Exception:
            pass

        source_stats[fname] = line_count

    # Save aggregated output
    if output_file:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(all_events, f, indent=2, default=str)

    return ToolResult(
        tool_name="log_aggregator",
        target=target,
        status="success",
        data={
            "total_events": len(all_events),
            "sources": source_stats,
            "severity_distribution": dict(severity_counts),
            "aggregated_at": datetime.utcnow().isoformat(),
        },
    )
