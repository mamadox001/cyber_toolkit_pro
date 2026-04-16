# =============================================================================
# CyberToolkit Pro — File Analyzer (Enhanced)
# =============================================================================
# Multi-hash file analysis with magic byte detection, string extraction,
# and entropy calculation. Replaces original basic version.
# =============================================================================

import hashlib
import os
import math
from collections import Counter
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "file_analyzer",
    "category": "forensics",
    "description": "File hash analysis, magic byte detection, and entropy calculation",
    "author": "CyberToolkit Pro",
    "version": "2.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Path to file to analyze"},
    ],
    "tags": ["blue-team", "forensics", "hash", "analysis"],
}

# Magic byte signatures for file type identification
MAGIC_BYTES = {
    b"\x89PNG":       "PNG Image",
    b"\xff\xd8\xff":  "JPEG Image",
    b"GIF87a":        "GIF Image (87a)",
    b"GIF89a":        "GIF Image (89a)",
    b"PK\x03\x04":   "ZIP Archive / Office Document",
    b"PK\x05\x06":   "ZIP Archive (empty)",
    b"\x50\x4b\x07": "ZIP Archive (spanned)",
    b"\x1f\x8b":     "GZIP Archive",
    b"BZ":           "BZIP2 Archive",
    b"\x7fELF":      "ELF Executable (Linux)",
    b"MZ":           "PE Executable (Windows)",
    b"%PDF":         "PDF Document",
    b"\xd0\xcf\x11": "MS Office Legacy (DOC/XLS/PPT)",
    b"Rar!":         "RAR Archive",
    b"\xca\xfe\xba": "Mach-O Executable (macOS)",
    b"\x00\x00\x01\x00": "ICO Icon",
    b"RIFF":         "RIFF (AVI/WAV)",
    b"SQLite":       "SQLite Database",
    b"<!DOCTYPE":    "HTML Document",
    b"<?xml":        "XML Document",
    b"#!/":          "Script (shebang)",
}


def _calculate_entropy(data):
    """Calculate Shannon entropy of data (0-8 scale for bytes)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy, 4)


def _detect_file_type(data):
    """Detect file type by magic bytes."""
    for magic, filetype in MAGIC_BYTES.items():
        if data.startswith(magic):
            return filetype
    # Check for text
    try:
        data[:1024].decode("utf-8")
        return "Text/ASCII"
    except (UnicodeDecodeError, AttributeError):
        return "Unknown Binary"


def run(args):
    filepath = args.get("target", "")
    if not filepath:
        return ToolResult(tool_name="file_analyzer", status="error", error="No file specified")

    if not os.path.exists(filepath):
        return ToolResult(tool_name="file_analyzer", status="error",
                          error=f"File not found: {filepath}")

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        return ToolResult(tool_name="file_analyzer", status="error", error=str(e))

    file_size = len(data)
    file_type = _detect_file_type(data)
    entropy = _calculate_entropy(data)

    hashes = {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    findings = []

    # High entropy indicates encryption or packing
    if entropy > 7.5:
        findings.append(Finding(
            title="High entropy detected",
            severity=Severity.MEDIUM,
            description=f"File entropy is {entropy}/8.0 — may be encrypted, compressed, or packed",
            remediation="Investigate file contents — high entropy is common in malware",
        ))

    # Executable detection
    if file_type in ("PE Executable (Windows)", "ELF Executable (Linux)", "Mach-O Executable (macOS)"):
        findings.append(Finding(
            title=f"Executable file detected: {file_type}",
            severity=Severity.MEDIUM,
            description=f"File is an executable ({file_type}). Verify the hash against malware databases.",
            evidence=f"SHA256: {hashes['sha256']}",
            remediation="Submit hash to VirusTotal for analysis",
        ))

    return ToolResult(
        tool_name="file_analyzer",
        target=filepath,
        status="success",
        data={
            "filename": os.path.basename(filepath),
            "file_path": filepath,
            "file_size": file_size,
            "file_type": file_type,
            "entropy": entropy,
            "hashes": hashes,
        },
        findings=findings,
    )
