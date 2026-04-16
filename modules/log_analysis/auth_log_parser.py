# =============================================================================
# CyberToolkit Pro — Auth Log Parser
# =============================================================================
# Linux auth.log / secure log parser. Detects failed login attempts,
# successful logins, sudo usage, and account changes.
# =============================================================================

import re
import os
from collections import Counter, defaultdict
from core.models import ToolResult, Finding, Severity, Alert

TOOL_INFO = {
    "name": "auth_log_parser",
    "category": "log_analysis",
    "description": "Linux auth.log parser for login analysis and threat detection",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Path to auth.log or secure log file"},
        {"name": "threshold", "required": False, "default": "5",
         "description": "Failed login threshold for alert generation"},
    ],
    "tags": ["blue-team", "log-analysis", "auth", "linux"],
}

# Regex patterns for common auth.log events
PATTERNS = {
    "failed_password": re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+)"
    ),
    "accepted_password": re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted (?:password|publickey) for (\S+) from (\S+)"
    ),
    "sudo": re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sudo:\s+(\S+)"
    ),
    "invalid_user": re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Invalid user (\S+) from (\S+)"
    ),
    "session_opened": re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+(?:sshd|systemd-logind)\[\d+\]:\s+(?:pam_unix.*session opened|New session \S+ of user) (\S+)"
    ),
}


def run(args):
    filepath = args.get("target", "")
    if not filepath:
        return ToolResult(tool_name="auth_log_parser", status="error", error="No log file specified")

    if not os.path.exists(filepath):
        return ToolResult(tool_name="auth_log_parser", status="error",
                          error=f"File not found: {filepath}")

    threshold = int(args.get("threshold", 5))

    failed_attempts = []
    successful_logins = []
    sudo_usage = []
    invalid_users = []

    failed_by_ip = Counter()
    failed_by_user = Counter()
    login_times = defaultdict(list)

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                # Failed passwords
                m = PATTERNS["failed_password"].search(line)
                if m:
                    ts, user, ip = m.groups()
                    failed_attempts.append({"timestamp": ts, "user": user, "ip": ip})
                    failed_by_ip[ip] += 1
                    failed_by_user[user] += 1
                    continue

                # Successful logins
                m = PATTERNS["accepted_password"].search(line)
                if m:
                    ts, user, ip = m.groups()
                    successful_logins.append({"timestamp": ts, "user": user, "ip": ip})
                    login_times[user].append(ts)
                    continue

                # Invalid users
                m = PATTERNS["invalid_user"].search(line)
                if m:
                    ts, user, ip = m.groups()
                    invalid_users.append({"timestamp": ts, "user": user, "ip": ip})
                    continue

                # Sudo usage
                m = PATTERNS["sudo"].search(line)
                if m:
                    ts, user = m.groups()
                    sudo_usage.append({"timestamp": ts, "user": user})

    except Exception as e:
        return ToolResult(tool_name="auth_log_parser", status="error", error=str(e))

    # Generate findings
    findings = []

    # Failed login threshold
    for ip, count in failed_by_ip.most_common(20):
        if count >= threshold:
            findings.append(Finding(
                title=f"Brute force detected from {ip}",
                severity=Severity.HIGH if count >= threshold * 3 else Severity.MEDIUM,
                description=f"{count} failed login attempts from IP {ip}",
                evidence=f"IP: {ip}, Failed attempts: {count}",
                remediation="Block IP in firewall, investigate source, enable fail2ban",
            ))

    # Invalid user enumeration
    if len(set(u["user"] for u in invalid_users)) > 10:
        findings.append(Finding(
            title="User enumeration attack detected",
            severity=Severity.MEDIUM,
            description=f"{len(invalid_users)} attempts with invalid usernames",
            remediation="Disable user enumeration, use generic authentication error messages",
        ))

    # Root login detection
    root_logins = [l for l in successful_logins if l["user"] == "root"]
    if root_logins:
        findings.append(Finding(
            title=f"Direct root login detected ({len(root_logins)} times)",
            severity=Severity.MEDIUM,
            description="Direct root SSH login should be disabled",
            remediation="Set PermitRootLogin no in sshd_config",
        ))

    return ToolResult(
        tool_name="auth_log_parser",
        target=filepath,
        status="success",
        data={
            "total_failed": len(failed_attempts),
            "total_successful": len(successful_logins),
            "total_invalid_users": len(invalid_users),
            "sudo_events": len(sudo_usage),
            "top_failed_ips": dict(failed_by_ip.most_common(10)),
            "top_failed_users": dict(failed_by_user.most_common(10)),
            "alerts": [f.to_dict() for f in findings],
        },
        findings=findings,
    )
