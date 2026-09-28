# modules/osint/domain_reputation.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "domain_reputation",
    "category": "osint",
    "description": "Check domain reputation across threat intelligence feeds",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['osint', 'reputation', 'threat_intel'],
}


def run(args):

    import json, urllib.request, urllib.parse
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="domain_reputation", status="error", error="No target specified")
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    data = {"target": domain, "checks": [], "reputation_score": "unknown"}
    findings = []
    # Check Google Safe Browsing via transparency report
    try:
        url = f"https://transparencyreport.google.com/safe-browsing/search?url={urllib.parse.quote(domain)}"
        data["checks"].append({"provider": "Google Safe Browsing", "check_url": url, "status": "manual_check"})
    except Exception:
        pass
    # Check URLhaus
    try:
        req = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data=f"host={domain}".encode("utf-8"),
            headers={"User-Agent": "CyberToolkit Pro/2.5"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        status = result.get("query_status", "")
        urls_count = result.get("urls_count", 0)
        data["checks"].append({"provider": "URLhaus", "status": status, "malicious_urls": urls_count})
        if urls_count and urls_count > 0:
            findings.append(Finding(
                title=f"Domain found in URLhaus ({urls_count} malicious URLs)",
                severity=Severity.HIGH,
                description=f"{domain} has {urls_count} malicious URL(s) reported in URLhaus",
                remediation="Investigate the reported URLs and block if necessary"
            ))
    except Exception:
        data["checks"].append({"provider": "URLhaus", "status": "check_failed"})
    findings.append(Finding(title=f"Domain reputation check for {domain}", severity=Severity.INFO,
        description=f"Checked {len(data['checks'])} reputation providers"))
    return ToolResult(tool_name="domain_reputation", target=domain, status="success", data=data, findings=findings)

