# modules/osint/wayback_machine.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "wayback_machine",
    "category": "osint",
    "description": "Retrieve historical versions of web pages from the Wayback Machine",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['osint', 'wayback', 'archive', 'history'],
}


def run(args):

    import json, urllib.request, urllib.parse
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="wayback_machine", status="error", error="No target specified")
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    data = {"target": domain, "snapshots": [], "total_snapshots": 0, "oldest": "", "newest": ""}
    findings = []
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(domain)}/*&output=json&limit=100&fl=timestamp,original,statuscode,mimetype"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberToolkit Pro/2.5"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            results = json.loads(resp.read().decode("utf-8"))
        if len(results) > 1:
            headers_row = results[0]
            for row in results[1:]:
                snapshot = dict(zip(headers_row, row))
                snapshot["archive_url"] = f"https://web.archive.org/web/{snapshot.get('timestamp', '')}/{snapshot.get('original', '')}"
                data["snapshots"].append(snapshot)
            data["total_snapshots"] = len(data["snapshots"])
            if data["snapshots"]:
                data["oldest"] = data["snapshots"][-1].get("timestamp", "")
                data["newest"] = data["snapshots"][0].get("timestamp", "")
            findings.append(Finding(
                title=f"Found {data['total_snapshots']} Wayback Machine snapshots",
                severity=Severity.INFO,
                description=f"Historical web pages available for {domain} from {data['oldest'][:8]} to {data['newest'][:8]}"
            ))
    except Exception as e:
        return ToolResult(tool_name="wayback_machine", target=domain, status="error", error=str(e))
    return ToolResult(tool_name="wayback_machine", target=domain, status="success", data=data, findings=findings)

