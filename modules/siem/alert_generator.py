# =============================================================================
# CyberToolkit Pro — Alert Generator
# =============================================================================
# Generates structured alerts from aggregated log data using configurable
# detection rules. Part of the lightweight SIEM system.
# =============================================================================

import os
import re
import json
from datetime import datetime
from collections import Counter
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "alert_generator",
    "category": "siem",
    "description": "Rule-based alert generation from log data",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Log file or directory to analyze"},
        {"name": "output_file", "required": False, "default": "reports/alerts.json",
         "description": "Path to save generated alerts"},
    ],
    "tags": ["blue-team", "siem", "alerts", "detection"],
}

# Detection rules for alert generation
DETECTION_RULES = [
    {
        "id": "SIEM-001",
        "name": "Multiple Failed Logins",
        "pattern": r"(?:Failed password|authentication failure|login failed)",
        "threshold": 5,
        "severity": Severity.HIGH,
        "description": "Multiple authentication failures detected",
    },
    {
        "id": "SIEM-002",
        "name": "SQL Injection Attempt",
        "pattern": r"(?:union\s+select|--\s*$|;\s*drop\s|'\s*or\s+'1)",
        "threshold": 1,
        "severity": Severity.CRITICAL,
        "description": "SQL injection attempt detected in logs",
    },
    {
        "id": "SIEM-003",
        "name": "Directory Traversal",
        "pattern": r"(?:\.\./|\.\.\\|%2e%2e)",
        "threshold": 1,
        "severity": Severity.HIGH,
        "description": "Directory traversal attempt detected",
    },
    {
        "id": "SIEM-004",
        "name": "Privilege Escalation",
        "pattern": r"(?:sudo|su\s+root|COMMAND=|privilege|escalat)",
        "threshold": 3,
        "severity": Severity.MEDIUM,
        "description": "Potential privilege escalation activity",
    },
    {
        "id": "SIEM-005",
        "name": "Service Restart",
        "pattern": r"(?:restart|stopped|started|reloaded).*(?:service|daemon|server)",
        "threshold": 5,
        "severity": Severity.LOW,
        "description": "Frequent service restarts detected",
    },
    {
        "id": "SIEM-006",
        "name": "Outbound Connection Anomaly",
        "pattern": r"(?:connect|established|outbound|outgoing).*(?:external|remote|outside)",
        "threshold": 10,
        "severity": Severity.MEDIUM,
        "description": "Unusual outbound connection pattern",
    },
]


def run(args):
    target = args.get("target", "")
    if not target or not os.path.exists(target):
        return ToolResult(tool_name="alert_generator", status="error",
                          error=f"Path not found: {target}")

    output_file = args.get("output_file", "reports/alerts.json")

    # Compile rules
    compiled_rules = []
    for rule in DETECTION_RULES:
        compiled_rules.append({
            **rule,
            "compiled": re.compile(rule["pattern"], re.IGNORECASE),
            "hits": [],
        })

    # Process files
    files = []
    if os.path.isdir(target):
        for fname in os.listdir(target):
            fpath = os.path.join(target, fname)
            if os.path.isfile(fpath):
                files.append(fpath)
    else:
        files = [target]

    total_lines = 0
    for filepath in files:
        fname = os.path.basename(filepath)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, 1):
                    total_lines += 1
                    for rule in compiled_rules:
                        if rule["compiled"].search(line):
                            rule["hits"].append({
                                "file": fname,
                                "line": line_no,
                                "content": line.strip()[:200],
                            })
        except Exception:
            pass

    # Generate alerts
    alerts = []
    findings = []

    for rule in compiled_rules:
        if len(rule["hits"]) >= rule["threshold"]:
            alert = {
                "id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"].value,
                "description": rule["description"],
                "hit_count": len(rule["hits"]),
                "threshold": rule["threshold"],
                "sample_events": rule["hits"][:5],
                "generated_at": datetime.utcnow().isoformat(),
            }
            alerts.append(alert)

            findings.append(Finding(
                title=f"[{rule['id']}] {rule['name']}",
                severity=rule["severity"],
                description=f"{rule['description']} — {len(rule['hits'])} occurrences",
                evidence=rule["hits"][0]["content"] if rule["hits"] else "",
            ))

    # Save alerts
    if output_file and alerts:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, default=str)

    return ToolResult(
        tool_name="alert_generator",
        target=target,
        status="success",
        data={
            "total_lines_processed": total_lines,
            "rules_evaluated": len(compiled_rules),
            "alerts_generated": len(alerts),
            "alerts": alerts,
            "output_file": output_file if alerts else "",
        },
        findings=findings,
    )
