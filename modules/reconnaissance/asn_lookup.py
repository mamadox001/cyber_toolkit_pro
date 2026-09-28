# modules/reconnaissance/asn_lookup.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "asn_lookup",
    "category": "reconnaissance",
    "description": "BGP/ASN enumeration for IP range discovery",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['recon', 'asn', 'bgp', 'network'],
}


def run(args):

    import json, urllib.request, urllib.parse
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="asn_lookup", status="error", error="No target specified")
    data = {"target": target, "asn_info": {}, "ip_ranges": []}
    findings = []
    try:
        url = f"https://api.hackertarget.com/aslookup/?q={urllib.parse.quote(target)}"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberToolkit Pro/2.5"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = resp.read().decode("utf-8")
        lines = result.strip().split("\n")
        if lines:
            data["asn_info"]["raw"] = lines
            for line in lines:
                if "/" in line:
                    data["ip_ranges"].append(line.strip())
        if data["ip_ranges"]:
            findings.append(Finding(title=f"Found {len(data['ip_ranges'])} IP range(s) for ASN", severity=Severity.INFO))
    except Exception as e:
        return ToolResult(tool_name="asn_lookup", target=target, status="error", error=str(e))
    return ToolResult(tool_name="asn_lookup", target=target, status="success", data=data, findings=findings)

