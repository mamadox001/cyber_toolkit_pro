# modules/forensics/timeline_generator.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "timeline_generator",
    "category": "forensics",
    "description": "Generate forensic timeline from file system metadata",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['forensics', 'timeline', 'filesystem'],
}


def run(args):

    import os, json
    from datetime import datetime
    target = args.get("target", "")
    if not target or not os.path.exists(target):
        return ToolResult(tool_name="timeline_generator", status="error", error="Path not found or no target specified")
    data = {"target": target, "entries": [], "total_files": 0, "date_range": {}}
    findings = []
    entries = []
    try:
        for root, dirs, files in os.walk(target):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    stat = os.stat(fpath)
                    entries.append({
                        "path": fpath,
                        "size": stat.st_size,
                        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                    })
                except (OSError, PermissionError):
                    pass
            if len(entries) >= 5000:
                break
        entries.sort(key=lambda x: x["modified"], reverse=True)
        data["entries"] = entries[:500]
        data["total_files"] = len(entries)
        if entries:
            data["date_range"] = {
                "earliest_modified": entries[-1]["modified"],
                "latest_modified": entries[0]["modified"],
            }
        findings.append(Finding(
            title=f"Timeline generated: {len(entries)} files",
            severity=Severity.INFO,
            description=f"Filesystem timeline for {target}"
        ))
    except Exception as e:
        return ToolResult(tool_name="timeline_generator", target=target, status="error", error=str(e))
    return ToolResult(tool_name="timeline_generator", target=target, status="success", data=data, findings=findings)

