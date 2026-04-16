# =============================================================================
# CyberToolkit Pro — File Type Detector
# =============================================================================
# Identifies file types using magic bytes regardless of file extension.
# Detects mismatches between extension and actual content.
# =============================================================================

import os
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "file_type_detector",
    "category": "forensics",
    "description": "File type detection via magic bytes (identifies extension mismatches)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "File or directory to analyze"},
    ],
    "tags": ["blue-team", "forensics", "file-type", "magic-bytes"],
}

# Extended magic byte table with expected extensions
SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG Image",       [".png"]),
    (b"\xff\xd8\xff",       "JPEG Image",      [".jpg", ".jpeg"]),
    (b"GIF89a",             "GIF Image",       [".gif"]),
    (b"GIF87a",             "GIF Image",       [".gif"]),
    (b"PK\x03\x04",        "ZIP/Office",      [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]),
    (b"\x1f\x8b",          "GZIP",            [".gz", ".tgz"]),
    (b"\x7fELF",           "ELF Binary",      [".elf", ".so", ".o", ""]),
    (b"MZ",                "PE Executable",   [".exe", ".dll", ".sys"]),
    (b"%PDF",              "PDF Document",    [".pdf"]),
    (b"\xd0\xcf\x11",     "MS Office Legacy", [".doc", ".xls", ".ppt"]),
    (b"Rar!\x1a\x07",     "RAR Archive",     [".rar"]),
    (b"\xca\xfe\xba\xbe", "Mach-O/Java",     [".class", ""]),
    (b"RIFF",              "RIFF Container",  [".avi", ".wav"]),
    (b"SQLite format 3",   "SQLite DB",       [".db", ".sqlite", ".sqlite3"]),
    (b"\x00\x00\x00\x1c\x66\x74\x79\x70", "MP4 Video", [".mp4", ".m4v"]),
    (b"\x00\x00\x00\x14\x66\x74\x79\x70", "MP4 Video", [".mp4"]),
    (b"\x49\x44\x33",     "MP3 Audio",       [".mp3"]),
    (b"BM",               "BMP Image",       [".bmp"]),
    (b"\x50\x4b\x03\x04\x14\x00\x06\x00", "MS Office (OOXML)", [".docx", ".xlsx"]),
]


def _detect_type(data):
    """Identify file type from first N bytes."""
    for magic, filetype, exts in SIGNATURES:
        if data.startswith(magic):
            return filetype, exts
    try:
        data[:512].decode("utf-8")
        return "Text/ASCII", [".txt", ".log", ".csv", ".json", ".xml", ".html", ".py", ".js"]
    except (UnicodeDecodeError, AttributeError):
        return "Unknown Binary", []


def _analyze_file(filepath):
    """Analyze a single file for type mismatch."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(32)
            size = f.seek(0, 2)
    except Exception as e:
        return {"path": filepath, "error": str(e)}

    detected_type, expected_exts = _detect_type(header)
    actual_ext = os.path.splitext(filepath)[1].lower()

    mismatch = bool(expected_exts and actual_ext and actual_ext not in expected_exts)

    return {
        "path": filepath,
        "filename": os.path.basename(filepath),
        "size": size,
        "extension": actual_ext,
        "detected_type": detected_type,
        "expected_extensions": expected_exts,
        "extension_mismatch": mismatch,
    }


def run(args):
    target = args.get("target", "")
    if not target or not os.path.exists(target):
        return ToolResult(tool_name="file_type_detector", status="error",
                          error=f"Path not found: {target}")

    results = []
    findings = []

    if os.path.isfile(target):
        files = [target]
    else:
        files = [
            os.path.join(target, f) for f in os.listdir(target)
            if os.path.isfile(os.path.join(target, f))
        ]

    for filepath in files:
        info = _analyze_file(filepath)
        results.append(info)

        if info.get("extension_mismatch"):
            findings.append(Finding(
                title=f"Extension mismatch: {info['filename']}",
                severity=Severity.MEDIUM,
                description=f"File '{info['filename']}' has extension '{info['extension']}' "
                            f"but content is '{info['detected_type']}'",
                evidence=f"Expected extensions: {', '.join(info['expected_extensions'])}",
                remediation="Investigate file — extension mismatch may indicate concealed content",
            ))

    mismatch_count = sum(1 for r in results if r.get("extension_mismatch"))

    return ToolResult(
        tool_name="file_type_detector",
        target=target,
        status="success",
        data={
            "files_analyzed": len(results),
            "extension_mismatches": mismatch_count,
            "results": results,
        },
        findings=findings,
    )
