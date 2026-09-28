# modules/forensics/yara_scanner.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "yara_scanner",
    "category": "forensics",
    "description": "YARA rule-based malware pattern scanning for files",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['forensics', 'yara', 'malware', 'scanning'],
}


def run(args):

    import os, re
    target = args.get("target", "")
    if not target or not os.path.exists(target):
        return ToolResult(tool_name="yara_scanner", status="error", error="File not found or no target specified")
    rules_path = args.get("rules", "")
    data = {"target": target, "file_size": os.path.getsize(target), "matches": [], "patterns_checked": 0}
    findings = []
    # Built-in suspicious patterns (simplified YARA-like)
    builtin_patterns = [
        ("Suspicious_PE_Header", rb"MZ.*This program"),
        ("Suspicious_Shell_Script", rb"#!/bin/(bash|sh).*rm -rf"),
        ("Base64_Encoded_PE", rb"TVqQAAMAAAA"),
        ("PowerShell_Download", rb"(Invoke-WebRequest|wget|curl|DownloadFile|DownloadString)"),
        ("Reverse_Shell_Pattern", rb"(socket|connect|SOCK_STREAM|/dev/tcp|bash -i)"),
        ("Crypto_Mining", rb"(stratum\+tcp|xmrig|cryptonight|monero)"),
        ("Webshell_Indicator", rb"(eval\s*\(|base64_decode|system\s*\(|exec\s*\(|passthru)"),
        ("Credential_Harvesting", rb"(mimikatz|lsadump|sekurlsa|wdigest|kerberos)"),
        ("Ransomware_Indicator", rb"(encrypt|ransom|bitcoin|btc|decrypt.*key|YOUR FILES)"),
        ("Packed_Binary", rb"(UPX0|UPX1|\.aspack|\.mpress)"),
    ]
    try:
        with open(target, "rb") as f:
            content = f.read(5000000)  # Read up to 5MB
        data["patterns_checked"] = len(builtin_patterns)
        for name, pattern in builtin_patterns:
            matches_found = re.findall(pattern, content, re.IGNORECASE)
            if matches_found:
                data["matches"].append({
                    "rule": name,
                    "count": len(matches_found),
                    "preview": matches_found[0][:50].decode("utf-8", errors="replace"),
                })
                findings.append(Finding(
                    title=f"YARA match: {name}",
                    severity=Severity.HIGH,
                    description=f"Pattern '{name}' matched {len(matches_found)} time(s)",
                    evidence=matches_found[0][:100].decode("utf-8", errors="replace"),
                    remediation="Investigate this file for potential malware"
                ))
    except Exception as e:
        return ToolResult(tool_name="yara_scanner", target=target, status="error", error=str(e))
    return ToolResult(tool_name="yara_scanner", target=target, status="success", data=data, findings=findings)

