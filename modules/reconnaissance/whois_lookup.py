# =============================================================================
# CyberToolkit Pro — WHOIS Lookup
# =============================================================================
# Domain registration info lookup using the whois protocol (socket-based,
# no external dependencies required).
# =============================================================================

import socket
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "whois_lookup",
    "category": "reconnaissance",
    "description": "WHOIS domain registration information lookup",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Domain name to query"},
    ],
    "tags": ["whois", "recon", "domain"],
}

# WHOIS servers for common TLDs
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io":  "whois.nic.io",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "co":  "whois.nic.co",
    "uk":  "whois.nic.uk",
    "de":  "whois.denic.de",
    "fr":  "whois.nic.fr",
    "eu":  "whois.eu",
    "info": "whois.afilias.net",
}


def _whois_query(domain, server="whois.iana.org", port=43, timeout=10):
    """Perform a raw WHOIS query."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, port))
        s.send((domain + "\r\n").encode())

        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        return response.decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error: {e}"


def _parse_whois(raw_text):
    """Extract key fields from raw WHOIS output."""
    parsed = {}
    key_fields = [
        "domain name", "registrar", "creation date", "updated date",
        "registry expiry date", "registrant organization", "registrant country",
        "name server", "dnssec", "status",
    ]

    for line in raw_text.split("\n"):
        line = line.strip()
        if ":" in line:
            key, _, value = line.partition(":")
            key_lower = key.strip().lower()
            value = value.strip()
            for field in key_fields:
                if field in key_lower:
                    if field in parsed:
                        if isinstance(parsed[field], list):
                            parsed[field].append(value)
                        else:
                            parsed[field] = [parsed[field], value]
                    else:
                        parsed[field] = value

    return parsed


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="whois_lookup", status="error", error="No target specified")

    # Determine WHOIS server
    tld = target.rsplit(".", 1)[-1].lower()
    whois_server = WHOIS_SERVERS.get(tld, "whois.iana.org")

    # Query WHOIS
    raw = _whois_query(target, whois_server)

    # If IANA response contains a referral, follow it
    if "refer:" in raw.lower() or "whois:" in raw.lower():
        for line in raw.split("\n"):
            if line.strip().lower().startswith(("refer:", "whois:")):
                referral_server = line.split(":", 1)[1].strip()
                if referral_server:
                    raw = _whois_query(target, referral_server)
                    break

    parsed = _parse_whois(raw)
    findings = []

    # Check for privacy protection
    if any("privacy" in str(v).lower() or "redacted" in str(v).lower()
           for v in parsed.values()):
        findings.append(Finding(
            title="WHOIS privacy protection enabled",
            severity=Severity.INFO,
            description="Registrant information is redacted through a privacy service",
        ))

    return ToolResult(
        tool_name="whois_lookup",
        target=target,
        status="success",
        data={
            "whois_parsed": parsed,
            "whois_server": whois_server,
            "raw_length": len(raw),
        },
        findings=findings,
    )
