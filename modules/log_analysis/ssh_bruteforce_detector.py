# =============================================================================
# CyberToolkit Pro — SSH Brute Force Detector
# =============================================================================
# Specialized tool for detecting SSH brute force attacks from auth logs.
# Provides timeline analysis and attacker profiling.
# =============================================================================

import re
import os
from collections import Counter, defaultdict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "ssh_bruteforce_detector",
    "category": "log_analysis",
    "description": "SSH brute force attack detection and attacker profiling",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Path to auth.log or secure log"},
        {"name": "threshold", "required": False, "default": "5",
         "description": "Failed attempts threshold per IP"},
    ],
    "tags": ["blue-team", "ssh", "brute-force", "detection"],
}

FAILED_RE = re.compile(
    r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)"
)
ACCEPTED_RE = re.compile(
    r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted \S+ for (\S+) from (\S+)"
)


def run(args):
    filepath = args.get("target", "")
    if not filepath or not os.path.exists(filepath):
        return ToolResult(tool_name="ssh_bruteforce_detector", status="error",
                          error=f"File not found: {filepath}")

    threshold = int(args.get("threshold", 5))

    ip_failures = defaultdict(list)
    ip_usernames = defaultdict(set)
    ip_success = defaultdict(list)

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = FAILED_RE.search(line)
                if m:
                    ts, user, ip, port = m.groups()
                    ip_failures[ip].append({"timestamp": ts, "user": user})
                    ip_usernames[ip].add(user)
                    continue

                m = ACCEPTED_RE.search(line)
                if m:
                    ts, user, ip = m.groups()
                    ip_success[ip].append({"timestamp": ts, "user": user})
    except Exception as e:
        return ToolResult(tool_name="ssh_bruteforce_detector", status="error", error=str(e))

    # Identify attackers
    attackers = []
    findings = []

    for ip, failures in sorted(ip_failures.items(), key=lambda x: len(x[1]), reverse=True):
        count = len(failures)
        if count < threshold:
            continue

        usernames_tried = list(ip_usernames[ip])
        successful = ip in ip_success

        attacker = {
            "ip": ip,
            "failed_attempts": count,
            "unique_usernames": len(usernames_tried),
            "usernames_sample": usernames_tried[:10],
            "first_seen": failures[0]["timestamp"],
            "last_seen": failures[-1]["timestamp"],
            "login_succeeded": successful,
        }
        attackers.append(attacker)

        severity = Severity.CRITICAL if successful else (Severity.HIGH if count > threshold * 5 else Severity.MEDIUM)
        findings.append(Finding(
            title=f"SSH brute force from {ip}: {count} attempts" + (" ⚠ LOGIN SUCCEEDED" if successful else ""),
            severity=severity,
            description=f"IP {ip} made {count} failed SSH attempts targeting {len(usernames_tried)} unique username(s)",
            evidence=f"First: {failures[0]['timestamp']}, Last: {failures[-1]['timestamp']}, Usernames: {', '.join(usernames_tried[:5])}",
            remediation="Block IP, enable fail2ban, disable password auth, use key-based SSH",
        ))

    return ToolResult(
        tool_name="ssh_bruteforce_detector",
        target=filepath,
        status="success",
        data={
            "total_failed_attempts": sum(len(v) for v in ip_failures.values()),
            "unique_attacker_ips": len(attackers),
            "attackers": attackers,
            "compromised_ips": [a["ip"] for a in attackers if a["login_succeeded"]],
        },
        findings=findings,
    )
