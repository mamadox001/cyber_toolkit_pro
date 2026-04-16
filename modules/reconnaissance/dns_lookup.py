# =============================================================================
# CyberToolkit Pro — DNS Lookup
# =============================================================================
# Performs comprehensive DNS record enumeration (A, AAAA, MX, NS, TXT, SOA,
# CNAME). Uses the socket module with fallback to nslookup for systems
# without the dns.resolver library.
# =============================================================================

import socket
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "dns_lookup",
    "category": "reconnaissance",
    "description": "DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Domain name to query"},
    ],
    "tags": ["dns", "recon", "enumeration"],
}


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="dns_lookup", status="error", error="No target specified")

    records = {}
    findings = []

    # --- A records (IPv4) ---
    try:
        a_records = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(set(addr[4][0] for addr in a_records))
        records["A"] = ips
    except socket.gaierror:
        records["A"] = []

    # --- AAAA records (IPv6) ---
    try:
        aaaa_records = socket.getaddrinfo(target, None, socket.AF_INET6, socket.SOCK_STREAM)
        ipv6 = list(set(addr[4][0] for addr in aaaa_records))
        records["AAAA"] = ipv6
    except socket.gaierror:
        records["AAAA"] = []

    # --- Try dns.resolver for advanced records ---
    try:
        import dns.resolver

        for rtype in ["MX", "NS", "TXT", "SOA", "CNAME"]:
            try:
                answers = dns.resolver.resolve(target, rtype)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                records[rtype] = []
            except Exception:
                records[rtype] = []

    except ImportError:
        # Fallback: use nslookup subprocess
        import subprocess
        for rtype in ["MX", "NS", "TXT"]:
            try:
                result = subprocess.run(
                    ["nslookup", "-type=" + rtype, target],
                    capture_output=True, text=True, timeout=10
                )
                records[rtype] = [
                    line.strip() for line in result.stdout.split("\n")
                    if line.strip() and not line.startswith("Server") and not line.startswith("Address")
                ]
            except Exception:
                records[rtype] = []

    # --- Analysis ---
    if not records.get("A"):
        findings.append(Finding(
            title=f"No A records found for {target}",
            severity=Severity.INFO,
            description="Domain may not resolve or may be misconfigured",
        ))

    # Check for mail records without SPF
    if records.get("MX"):
        txt_records = " ".join(records.get("TXT", []))
        if "v=spf1" not in txt_records.lower():
            findings.append(Finding(
                title="MX records present but no SPF record detected",
                severity=Severity.MEDIUM,
                description="Domain accepts email but lacks SPF, making it vulnerable to email spoofing",
                remediation="Add an SPF TXT record to specify authorized mail servers",
            ))
        if "v=dmarc1" not in txt_records.lower():
            findings.append(Finding(
                title="No DMARC record detected",
                severity=Severity.LOW,
                description="DMARC helps prevent email spoofing and phishing",
                remediation="Add a DMARC TXT record at _dmarc.{domain}",
            ))

    return ToolResult(
        tool_name="dns_lookup",
        target=target,
        status="success",
        data={"dns_records": records, "record_count": sum(len(v) for v in records.values())},
        findings=findings,
    )
