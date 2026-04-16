# =============================================================================
# CyberToolkit Pro — String Extractor
# =============================================================================
# Extracts printable strings from binary files. Similar to the `strings`
# Unix utility. Useful for malware analysis and forensic investigation.
# =============================================================================

import os
import re
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "string_extractor",
    "category": "forensics",
    "description": "Extract printable strings from binary files for analysis",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Path to binary file"},
        {"name": "min_length", "required": False, "default": "4", "description": "Minimum string length"},
        {"name": "encoding", "required": False, "default": "ascii",
         "description": "Encoding: ascii, utf-16, both"},
    ],
    "tags": ["blue-team", "forensics", "strings", "malware-analysis"],
}

# Patterns that are interesting from a security perspective
SUSPICIOUS_PATTERNS = [
    (re.compile(r"https?://\S+", re.I), "URL"),
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "IP Address"),
    (re.compile(r"password|passwd|pwd|credentials", re.I), "Password reference"),
    (re.compile(r"api[_-]?key|secret[_-]?key|access[_-]?token", re.I), "API key reference"),
    (re.compile(r"cmd\.exe|/bin/sh|/bin/bash|powershell", re.I), "Shell reference"),
    (re.compile(r"HKEY_|HKLM\\|HKCU\\", re.I), "Windows registry key"),
    (re.compile(r"\\windows\\|\\system32\\", re.I), "Windows system path"),
    (re.compile(r"/etc/passwd|/etc/shadow|/proc/", re.I), "Linux system path"),
    (re.compile(r"socket|connect|bind|listen|recv|send", re.I), "Network function"),
    (re.compile(r"CreateProcess|ShellExecute|WinExec", re.I), "Process execution (Win API)"),
    (re.compile(r"admin|root|administrator", re.I), "Privileged user reference"),
]


def _extract_ascii_strings(data, min_length):
    """Extract ASCII printable strings."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    return [m.group().decode("ascii", errors="replace") for m in pattern.finditer(data)]


def _extract_utf16_strings(data, min_length):
    """Extract UTF-16 (wide) strings — common in Windows binaries."""
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    results = []
    for m in pattern.finditer(data):
        try:
            decoded = m.group().decode("utf-16-le", errors="replace").strip("\x00")
            if decoded:
                results.append(decoded)
        except Exception:
            pass
    return results


def run(args):
    filepath = args.get("target", "")
    if not filepath or not os.path.exists(filepath):
        return ToolResult(tool_name="string_extractor", status="error",
                          error=f"File not found: {filepath}")

    min_length = int(args.get("min_length", 4))
    encoding = args.get("encoding", "ascii").lower()

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        return ToolResult(tool_name="string_extractor", status="error", error=str(e))

    strings = []
    if encoding in ("ascii", "both"):
        strings.extend(_extract_ascii_strings(data, min_length))
    if encoding in ("utf-16", "both"):
        strings.extend(_extract_utf16_strings(data, min_length))

    # Deduplicate while preserving order
    seen = set()
    unique_strings = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append(s)

    # Analyze for suspicious patterns
    findings = []
    suspicious_strings = []

    for s in unique_strings:
        for pattern, category in SUSPICIOUS_PATTERNS:
            if pattern.search(s):
                suspicious_strings.append({"string": s[:200], "category": category})
                break

    if suspicious_strings:
        categories = set(s["category"] for s in suspicious_strings)
        findings.append(Finding(
            title=f"Suspicious strings found: {', '.join(categories)}",
            severity=Severity.MEDIUM,
            description=f"Found {len(suspicious_strings)} strings matching suspicious patterns",
            evidence="\n".join(f"[{s['category']}] {s['string'][:100]}" for s in suspicious_strings[:10]),
        ))

    return ToolResult(
        tool_name="string_extractor",
        target=filepath,
        status="success",
        data={
            "total_strings": len(unique_strings),
            "strings": unique_strings[:500],  # First 500
            "suspicious_strings": suspicious_strings,
            "suspicious_count": len(suspicious_strings),
        },
        findings=findings,
    )
