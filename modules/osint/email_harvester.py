# =============================================================================
# CyberToolkit Pro — Email Harvester (OSINT)
# =============================================================================
# Scrapes emails from public web pages, search engine results, and DNS
# records for a given domain. Useful for phishing campaign preparation.
# =============================================================================

import re
import socket
import urllib.request
import urllib.parse
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "email_harvester",
    "category": "osint",
    "description": "Harvest email addresses from web pages and DNS for a domain",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target domain"},
        {"name": "depth", "required": False, "default": "2",
         "description": "Crawl depth (pages to check)"},
    ],
    "tags": ["osint", "reconnaissance", "email", "harvesting"],
}


def run(args):
    target = args.get("target", "")
    depth = int(args.get("depth", "2"))

    emails = set()
    sources = {}   # email → where it was found

    # --- Strategy 1: Scrape the main website ---
    urls_to_check = [
        f"http://{target}",
        f"http://{target}/contact",
        f"http://{target}/about",
        f"http://{target}/team",
        f"http://www.{target}",
    ]

    email_pattern = re.compile(
        rf'[a-zA-Z0-9._%+\-]+@(?:{re.escape(target)}|[a-zA-Z0-9.\-]+\.[a-zA-Z]{{2,}})',
        re.IGNORECASE
    )

    for url in urls_to_check[:depth * 3]:
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
                found = email_pattern.findall(html)
                for e in found:
                    e_lower = e.lower()
                    emails.add(e_lower)
                    sources[e_lower] = url
        except Exception:
            continue

    # --- Strategy 2: Check DNS TXT / SOA records ---
    try:
        import subprocess
        dns_out = subprocess.run(
            ["nslookup", "-type=TXT", target],
            capture_output=True, text=True, timeout=10
        )
        txt_emails = email_pattern.findall(dns_out.stdout)
        for e in txt_emails:
            emails.add(e.lower())
            sources[e.lower()] = "DNS TXT record"

        soa_out = subprocess.run(
            ["nslookup", "-type=SOA", target],
            capture_output=True, text=True, timeout=10
        )
        soa_emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+', soa_out.stdout)
        for e in soa_emails:
            emails.add(e.lower())
            sources[e.lower()] = "DNS SOA record"
    except Exception:
        pass

    # --- Strategy 3: Check common email prefixes ---
    common_prefixes = [
        "info", "admin", "contact", "support", "sales", "hr",
        "webmaster", "security", "abuse", "postmaster"
    ]
    guessed = []
    for prefix in common_prefixes:
        email = f"{prefix}@{target}"
        try:
            # Try MX lookup to see if domain accepts mail
            import subprocess
            mx_out = subprocess.run(
                ["nslookup", "-type=MX", target],
                capture_output=True, text=True, timeout=5
            )
            if "mail exchanger" in mx_out.stdout.lower():
                guessed.append(email)
        except Exception:
            break

    # Build findings
    findings = []
    if emails:
        findings.append(Finding(
            title=f"Found {len(emails)} email address(es) for {target}",
            severity=Severity.INFO,
            description="Emails scraped from public sources",
            evidence=", ".join(sorted(emails)[:20])
        ))

    email_list = [{"email": e, "source": sources.get(e, "guessed")} for e in sorted(emails)]

    return ToolResult(
        tool_name="email_harvester",
        target=target,
        status="success",
        data={
            "domain": target,
            "emails_found": sorted(emails),
            "email_details": email_list,
            "guessed_emails": guessed[:10],
            "total": len(emails),
            "sources_checked": len(urls_to_check[:depth * 3]),
        },
        findings=findings,
    )
