# modules/osint/metadata_extractor.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "metadata_extractor",
    "category": "osint",
    "description": "Extract metadata from files (EXIF, PDF properties, Office document info)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['osint', 'metadata', 'exif', 'forensics'],
}


def run(args):

    import os, struct, json
    target = args.get("target", "")
    if not target or not os.path.exists(target):
        return ToolResult(tool_name="metadata_extractor", status="error", error="File not found or no target specified")
    data = {"target": target, "file_size": os.path.getsize(target), "metadata": {}}
    findings = []
    filename = os.path.basename(target).lower()
    try:
        with open(target, "rb") as f:
            header = f.read(16)
        # Detect file type
        if header[:4] == b"%PDF":
            data["file_type"] = "PDF"
            with open(target, "rb") as f:
                content = f.read()
            import re
            for match in re.finditer(rb"/([A-Za-z]+)\s*\(([^)]+)\)", content):
                key = match.group(1).decode("utf-8", errors="replace")
                value = match.group(2).decode("utf-8", errors="replace")
                if key.lower() in ("author", "creator", "producer", "title", "subject", "creationdate", "moddate"):
                    data["metadata"][key] = value
        elif header[:2] == b"PK":
            data["file_type"] = "ZIP/Office"
            import zipfile
            if zipfile.is_zipfile(target):
                with zipfile.ZipFile(target) as zf:
                    data["metadata"]["contents"] = zf.namelist()[:20]
                    if "docProps/core.xml" in zf.namelist():
                        core = zf.read("docProps/core.xml").decode("utf-8", errors="replace")
                        data["metadata"]["office_metadata_raw"] = core[:500]
        else:
            data["file_type"] = "Binary/Unknown"
            data["metadata"]["magic_bytes"] = header[:8].hex()
        if data["metadata"]:
            sensitive = [k for k in data["metadata"] if k.lower() in ("author", "creator")]
            if sensitive:
                findings.append(Finding(
                    title="Author/creator metadata found",
                    severity=Severity.LOW,
                    description=f"File contains identifying metadata: {', '.join(sensitive)}",
                    remediation="Strip metadata before publishing files"
                ))
    except Exception as e:
        data["error"] = str(e)
    return ToolResult(tool_name="metadata_extractor", target=target, status="success", data=data, findings=findings)

