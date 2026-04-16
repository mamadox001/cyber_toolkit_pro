# =============================================================================
# CyberToolkit Pro — Web Log Parser
# =============================================================================
# Apache / Nginx combined log format parser. Detects attack patterns,
# suspicious requests, high-frequency IPs, and error spikes.
# =============================================================================

import re
import os
from collections import Counter, defaultdict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "web_log_parser",
    "category": "log_analysis",
    "description": "Apache/Nginx web log parser with attack pattern detection",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Path to access.log file"},
        {"name": "threshold", "required": False, "default": "100",
         "description": "Request count threshold for suspicious IP"},
    ],
    "tags": ["blue-team", "log-analysis", "web", "apache", "nginx"],
}

# Combined Log Format regex
LOG_PATTERN = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+)\s+(\S+)\s+\S+" (\d{3}) (\d+|-)'
)

# Attack signature patterns in URLs
ATTACK_PATTERNS = {
    "sqli": re.compile(r"(?:union|select|insert|update|delete|drop|--|;|'|%27)", re.I),
    "xss": re.compile(r"(?:<script|javascript:|onerror|onload|alert\(|%3Cscript)", re.I),
    "traversal": re.compile(r"(?:\.\./|\.\.\\|%2e%2e|etc/passwd|boot\.ini)", re.I),
    "rfi": re.compile(r"(?:=https?://|=ftp://|php://input|php://filter)", re.I),
    "cmd_injection": re.compile(r"(?:;|\||`|\$\(|%7C|%60)", re.I),
    "scanner": re.compile(r"(?:nikto|sqlmap|nmap|dirbuster|gobuster|wpscan|acunetix)", re.I),
}


def run(args):
    filepath = args.get("target", "")
    if not filepath:
        return ToolResult(tool_name="web_log_parser", status="error", error="No log file specified")

    if not os.path.exists(filepath):
        return ToolResult(tool_name="web_log_parser", status="error",
                          error=f"File not found: {filepath}")

    threshold = int(args.get("threshold", 100))

    ip_counts = Counter()
    status_counts = Counter()
    path_counts = Counter()
    method_counts = Counter()
    attacks_detected = defaultdict(list)
    total_lines = 0
    parsed_lines = 0
    error_requests = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                total_lines += 1
                m = LOG_PATTERN.match(line)
                if not m:
                    continue
                parsed_lines += 1

                ip, timestamp, method, path, status, size = m.groups()
                status = int(status)

                ip_counts[ip] += 1
                status_counts[status] += 1
                path_counts[path] += 1
                method_counts[method] += 1

                # Check for attack patterns
                for attack_type, pattern in ATTACK_PATTERNS.items():
                    if pattern.search(path) or pattern.search(line):
                        attacks_detected[attack_type].append({
                            "ip": ip, "path": path[:200], "timestamp": timestamp,
                        })

                # Track server errors
                if status >= 500:
                    error_requests.append({
                        "ip": ip, "path": path[:200], "status": status,
                        "timestamp": timestamp,
                    })

    except Exception as e:
        return ToolResult(tool_name="web_log_parser", status="error", error=str(e))

    # Generate findings
    findings = []

    # High-frequency IPs
    for ip, count in ip_counts.most_common(10):
        if count >= threshold:
            findings.append(Finding(
                title=f"High-frequency IP: {ip} ({count} requests)",
                severity=Severity.MEDIUM,
                description=f"IP {ip} made {count} requests — possible scanning or DDoS",
                remediation="Investigate IP, consider rate limiting or blocking",
            ))

    # Attack patterns
    for attack_type, entries in attacks_detected.items():
        if entries:
            findings.append(Finding(
                title=f"Attack pattern detected: {attack_type.upper()} ({len(entries)} instances)",
                severity=Severity.HIGH,
                description=f"Found {len(entries)} requests matching {attack_type} patterns",
                evidence=f"Example: {entries[0]['ip']} → {entries[0]['path'][:100]}",
                remediation=f"Block source IPs, review WAF rules for {attack_type} protection",
            ))

    # High error rate
    error_count = sum(1 for s, c in status_counts.items() if s >= 500)
    if error_count > 10:
        findings.append(Finding(
            title=f"High server error rate: {sum(c for s,c in status_counts.items() if s >= 500)} 5xx responses",
            severity=Severity.MEDIUM,
            description="Elevated server error rate may indicate misconfiguration or attacks",
        ))

    return ToolResult(
        tool_name="web_log_parser",
        target=filepath,
        status="success",
        data={
            "total_lines": total_lines,
            "parsed_lines": parsed_lines,
            "unique_ips": len(ip_counts),
            "top_ips": dict(ip_counts.most_common(10)),
            "status_distribution": dict(status_counts),
            "top_paths": dict(path_counts.most_common(10)),
            "methods": dict(method_counts),
            "attacks_detected": {k: len(v) for k, v in attacks_detected.items()},
            "suspicious_ips": [ip for ip, c in ip_counts.most_common() if c >= threshold],
        },
        findings=findings,
    )
