# =============================================================================
# CyberToolkit Pro — DNS Monitor (Network Security)
# =============================================================================
# Monitors DNS traffic and detects DNS poisoning, tunneling, and
# suspicious domain lookups.
# =============================================================================

import os
import re
import subprocess
import time
from collections import Counter, defaultdict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "dns_monitor",
    "category": "network",
    "description": "DNS traffic monitoring for poisoning and tunneling detection",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": False, "default": "monitor",
         "description": "'monitor' for live, or path to DNS log file"},
        {"name": "duration", "required": False, "default": "15",
         "description": "Monitor duration in seconds"},
    ],
    "tags": ["network", "dns", "monitoring", "security"],
}

# Known suspicious TLDs and patterns
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".icu"}
DGA_PATTERN = re.compile(r'^[a-z0-9]{15,}\.', re.IGNORECASE)  # Random-looking domains


def run(args):
    target = args.get("target", "monitor")
    duration = int(args.get("duration", "15"))

    if target != "monitor" and os.path.exists(target):
        return _analyze_dns_log(target)

    return _monitor_live(duration)


def _monitor_live(duration):
    """Monitor DNS queries using system cache or tshark."""
    queries = []

    # Method 1: tshark DNS capture
    try:
        result = subprocess.run(
            ["tshark", "-a", f"duration:{duration}", "-f", "port 53",
             "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name",
             "-e", "dns.qry.type", "-e", "dns.a",
             "-E", "separator=|"],
            capture_output=True, text=True, timeout=duration + 5
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 2 and parts[1]:
                queries.append({
                    "src": parts[0],
                    "domain": parts[1],
                    "type": parts[2] if len(parts) > 2 else "",
                    "answer": parts[3] if len(parts) > 3 else "",
                })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Method 2: Windows DNS cache
    if not queries and os.name == "nt":
        try:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True, text=True, timeout=10
            )
            current_domain = ""
            for line in result.stdout.splitlines():
                line = line.strip()
                if "Record Name" in line and ":" in line:
                    current_domain = line.split(":", 1)[1].strip()
                elif "A (Host)" in line and ":" in line:
                    ip = line.split(":", 1)[1].strip()
                    queries.append({
                        "domain": current_domain,
                        "answer": ip,
                        "src": "cache",
                        "type": "A",
                    })
        except Exception:
            pass

    # Method 3: /etc/resolv.conf based queries (Linux)
    if not queries and os.name != "nt":
        try:
            result = subprocess.run(
                ["journalctl", "-u", "systemd-resolved", "-n", "100", "--no-pager"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                match = re.search(r'query\[(\w+)\]\s+(\S+)', line)
                if match:
                    queries.append({
                        "type": match.group(1),
                        "domain": match.group(2),
                        "src": "resolver",
                    })
        except Exception:
            pass

    return _analyze_queries(queries)


def _analyze_dns_log(log_path):
    """Analyze a DNS log file."""
    queries = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                # Parse common DNS log formats
                match = re.search(r'query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)', line)
                if match:
                    queries.append({
                        "type": match.group(1),
                        "domain": match.group(2),
                        "src": match.group(3),
                    })
                    continue
                # Generic format
                match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?query.*?(\S+\.\S+)', line)
                if match:
                    queries.append({
                        "src": match.group(1),
                        "domain": match.group(2),
                    })
    except Exception:
        pass

    return _analyze_queries(queries)


def _analyze_queries(queries):
    """Analyze DNS queries for suspicious patterns."""
    findings = []
    domain_counts = Counter(q.get("domain", "") for q in queries)
    source_counts = Counter(q.get("src", "") for q in queries)

    # Detection 1: Suspicious TLDs
    sus_domains = set()
    for q in queries:
        domain = q.get("domain", "")
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                sus_domains.add(domain)

    if sus_domains:
        findings.append(Finding(
            title=f"Queries to {len(sus_domains)} suspicious TLD domain(s)",
            severity=Severity.MEDIUM,
            description=f"Domains: {', '.join(list(sus_domains)[:10])}",
            evidence=str(list(sus_domains)[:20]),
            remediation="Investigate these domains — commonly used by malware"
        ))

    # Detection 2: DGA-like domains (algorithmically generated)
    dga_domains = set()
    for q in queries:
        domain = q.get("domain", "")
        if DGA_PATTERN.match(domain):
            dga_domains.add(domain)

    if dga_domains:
        findings.append(Finding(
            title=f"Detected {len(dga_domains)} DGA-like domain(s)",
            severity=Severity.HIGH,
            description="These domains appear algorithmically generated — typical of malware C2",
            evidence=", ".join(list(dga_domains)[:10]),
            remediation="Block these domains and scan the source machine for malware"
        ))

    # Detection 3: DNS tunneling (very long subdomains)
    tunneling = set()
    for q in queries:
        domain = q.get("domain", "")
        parts = domain.split(".")
        if any(len(p) > 50 for p in parts):
            tunneling.add(domain)

    if tunneling:
        findings.append(Finding(
            title=f"Possible DNS tunneling detected ({len(tunneling)} queries)",
            severity=Severity.CRITICAL,
            description="Extremely long subdomain labels suggest DNS tunneling (data exfiltration)",
            evidence=", ".join(list(tunneling)[:5]),
            remediation="Block tunneling domains and investigate the source"
        ))

    # Detection 4: High query volume from single source
    for src, count in source_counts.most_common(3):
        if count > 100:
            findings.append(Finding(
                title=f"High DNS query volume from {src} ({count} queries)",
                severity=Severity.MEDIUM,
                description="Could indicate DNS-based reconnaissance or tunneling"
            ))

    if not findings:
        findings.append(Finding(
            title="No suspicious DNS activity detected",
            severity=Severity.INFO,
            description=f"Analyzed {len(queries)} DNS queries"
        ))

    return ToolResult(
        tool_name="dns_monitor",
        target="monitor",
        status="success",
        data={
            "total_queries": len(queries),
            "unique_domains": len(domain_counts),
            "top_domains": dict(domain_counts.most_common(20)),
            "top_sources": dict(source_counts.most_common(10)),
            "suspicious_tld_domains": list(sus_domains),
            "dga_domains": list(dga_domains),
            "tunneling_domains": list(tunneling) if 'tunneling' in dir() else [],
        },
        findings=findings,
    )
