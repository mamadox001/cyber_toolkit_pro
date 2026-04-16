# =============================================================================
# CyberToolkit Pro — Alert System
# =============================================================================
# Configurable alerting based on detection rules. Processes log data,
# applies rules, and generates structured alerts.
# =============================================================================

import re
import os
import json
from datetime import datetime
from collections import Counter
from core.models import ToolResult, Finding, Severity, Alert

TOOL_INFO = {
    "name": "alert_system",
    "category": "detection",
    "description": "Rule-based alert generation system for security events",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Path to log file to monitor"},
        {"name": "rules", "required": False, "default": "default",
         "description": "Alert rules: default, strict, or path to custom rules YAML"},
        {"name": "output_file", "required": False, "default": "",
         "description": "Path to save alerts JSON (optional)"},
    ],
    "tags": ["blue-team", "detection", "alerting", "rules"],
}

# Built-in alert rules
DEFAULT_RULES = [
    {
        "name": "brute_force",
        "pattern": r"Failed password|authentication failure|failed login",
        "threshold": 5,
        "severity": "high",
        "message": "Brute force attack detected",
    },
    {
        "name": "privilege_escalation",
        "pattern": r"sudo|su:|COMMAND=|root.*session opened",
        "threshold": 1,
        "severity": "medium",
        "message": "Privilege escalation event",
    },
    {
        "name": "port_scan",
        "pattern": r"scan|SYN_RECV|connection attempt|refused connect",
        "threshold": 10,
        "severity": "high",
        "message": "Possible port scan detected",
    },
    {
        "name": "web_attack",
        "pattern": r"union.*select|<script>|\.\./\.\.|cmd=|exec\(|eval\(",
        "threshold": 1,
        "severity": "critical",
        "message": "Web attack pattern detected",
    },
    {
        "name": "data_exfiltration",
        "pattern": r"large transfer|bytes sent|upload.*complete",
        "threshold": 3,
        "severity": "high",
        "message": "Possible data exfiltration",
    },
]

STRICT_RULES = DEFAULT_RULES + [
    {
        "name": "new_connection",
        "pattern": r"Accepted|connection from|session opened",
        "threshold": 20,
        "severity": "low",
        "message": "High number of new connections",
    },
    {
        "name": "error_spike",
        "pattern": r"error|Error|ERROR|exception|Exception",
        "threshold": 10,
        "severity": "medium",
        "message": "Error spike detected",
    },
]


def run(args):
    filepath = args.get("target", "")
    if not filepath or not os.path.exists(filepath):
        return ToolResult(tool_name="alert_system", status="error",
                          error=f"File not found: {filepath}")

    rules_option = args.get("rules", "default")
    output_file = args.get("output_file", "")

    # Select rules
    if rules_option == "strict":
        rules = STRICT_RULES
    else:
        rules = DEFAULT_RULES

    # Compile patterns
    compiled_rules = []
    for rule in rules:
        compiled_rules.append({
            **rule,
            "compiled": re.compile(rule["pattern"], re.IGNORECASE),
            "matches": [],
        })

    # Process log file
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                for rule in compiled_rules:
                    if rule["compiled"].search(line):
                        rule["matches"].append({
                            "line": line_no,
                            "content": line.strip()[:200],
                        })
    except Exception as e:
        return ToolResult(tool_name="alert_system", status="error", error=str(e))

    # Generate alerts
    alerts = []
    findings = []

    severity_map = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
                    "high": Severity.HIGH, "critical": Severity.CRITICAL}

    for rule in compiled_rules:
        if len(rule["matches"]) >= rule["threshold"]:
            alert = {
                "rule": rule["name"],
                "message": rule["message"],
                "severity": rule["severity"],
                "match_count": len(rule["matches"]),
                "sample": rule["matches"][:3],
                "timestamp": datetime.utcnow().isoformat(),
            }
            alerts.append(alert)

            findings.append(Finding(
                title=f"Alert: {rule['message']}",
                severity=severity_map.get(rule["severity"], Severity.MEDIUM),
                description=f"Rule '{rule['name']}' triggered {len(rule['matches'])} times (threshold: {rule['threshold']})",
                evidence=rule["matches"][0]["content"] if rule["matches"] else "",
            ))

    # Save alerts to file if requested
    if output_file and alerts:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2)

    return ToolResult(
        tool_name="alert_system",
        target=filepath,
        status="success",
        data={
            "rules_applied": len(compiled_rules),
            "alerts_generated": len(alerts),
            "alerts": alerts,
        },
        findings=findings,
    )
