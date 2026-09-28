# modules/reconnaissance/ct_search.py
# =============================================================================
# CyberToolkit Pro — Certificate Transparency Search
# =============================================================================
# Query crt.sh for subdomains via Certificate Transparency logs.
# =============================================================================

import json
import urllib.request
import urllib.error
import urllib.parse
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "ct_search",
    "category": "reconnaissance",
    "description": "Search Certificate Transparency logs (crt.sh) for subdomains",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Domain to search"},
    ],
    "tags": ["recon", "subdomain", "ct", "certificate"],
}


def run(args):
    domain = args.get("target", "")
    if not domain:
        return ToolResult(tool_name="ct_search", status="error", error="No domain specified")

    # Strip protocol if present
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

    data = {"target": domain, "subdomains": [], "total_certs": 0}
    findings = []

    try:
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        req = urllib.request.Request(url, headers={
            "User-Agent": "CyberToolkit Pro/2.5",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            certs = json.loads(resp.read().decode("utf-8"))

        # Extract unique subdomains
        subdomains = set()
        for cert in certs:
            name = cert.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and sub.endswith(domain) and "*" not in sub:
                    subdomains.add(sub)

        data["subdomains"] = sorted(subdomains)
        data["total_certs"] = len(certs)

        if subdomains:
            findings.append(Finding(
                title=f"Found {len(subdomains)} subdomains via CT logs",
                severity=Severity.INFO,
                description=f"Certificate Transparency reveals {len(subdomains)} subdomains for {domain}",
                remediation="Review exposed subdomains for sensitive services"
            ))

    except urllib.error.URLError as e:
        return ToolResult(tool_name="ct_search", target=domain, status="error", error=str(e))
    except Exception as e:
        return ToolResult(tool_name="ct_search", target=domain, status="error", error=str(e))

    return ToolResult(
        tool_name="ct_search", target=domain,
        status="success", data=data, findings=findings
    )
