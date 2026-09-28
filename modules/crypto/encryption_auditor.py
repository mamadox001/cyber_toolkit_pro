# modules/crypto/encryption_auditor.py
# =============================================================================
# CyberToolkit Pro — Encryption & Cryptographic Primitive Auditor
# =============================================================================

import os
import re
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "encryption_auditor",
    "category": "crypto",
    "description": "Audits source files or configurations for weak cryptographic algorithms and hardcoded keys",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "File or directory path to audit", "arg_type": "file", "required": True},
    ],
    "tags": ["crypto", "encryption", "hash", "md5", "des", "keys"],
}

WEAK_CRYPTO_RULES = [
    {
        "pattern": r"(?i)\b(md5|sha1|des|3des|blowfish|rc4)\b",
        "title": "Broken or Deprecated Cryptographic Algorithm In Use",
        "severity": Severity.HIGH,
        "description": "Broken hash or cipher algorithm detected. MD5, SHA1, DES, and RC4 are vulnerable to collisions or key recovery.",
        "remediation": "Upgrade to modern algorithms: SHA-256/SHA-3 for hashing; AES-256-GCM or ChaCha20-Poly1305 for ciphers."
    },
    {
        "pattern": r"(?i)\bAES.*MODE_ECB\b",
        "title": "Insecure AES-ECB Mode In Use",
        "severity": Severity.HIGH,
        "description": "Electronic Codebook (ECB) mode does not use an initialization vector, leaking pattern information.",
        "remediation": "Use authenticated encryption modes such as AES-GCM."
    },
    {
        "pattern": r"(?i)(-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)",
        "title": "Hardcoded Private Key Found in File",
        "severity": Severity.CRITICAL,
        "description": "Plaintext cryptographic private key embedded in source or configuration file.",
        "remediation": "Remove private key from source control immediately and rotate the key."
    },
    {
        "pattern": r"(?i)(Math\.random\(\)|random\.random\(\)|rand\(\))",
        "title": "Use of Cryptographically Insecure Pseudo-Random Number Generator",
        "severity": Severity.MEDIUM,
        "description": "Standard pseudo-random number generators are predictable and unsafe for security tokens or crypto keys.",
        "remediation": "Use CSPRNG such as secrets module (Python), crypto.randomBytes (Node.js), or SecureRandom (Java)."
    }
]

def run(args: Dict[str, Any]) -> ToolResult:
    target_path = args.get("target", "").strip()
    if not target_path:
        return ToolResult(tool_name="encryption_auditor", status="error", error="No target specified")

    files_to_check = []
    if os.path.isfile(target_path):
        files_to_check.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for f in files:
                if f.endswith((".py", ".js", ".ts", ".go", ".java", ".c", ".cpp", ".php", ".rb", ".yaml", ".json", ".env")):
                    files_to_check.append(os.path.join(root, f))
    else:
        return ToolResult(tool_name="encryption_auditor", status="error", error=f"Target path '{target_path}' not found")

    data = {"files_scanned": len(files_to_check), "matches": []}
    findings = []

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for line_idx, line in enumerate(content.splitlines(), 1):
                for rule in WEAK_CRYPTO_RULES:
                    match = re.search(rule["pattern"], line)
                    if match:
                        data["matches"].append({
                            "file": fpath,
                            "line": line_idx,
                            "matched": match.group(0),
                            "rule": rule["title"]
                        })
                        findings.append(Finding(
                            title=rule["title"],
                            severity=rule["severity"],
                            description=f"{rule['description']} ({match.group(0)} at {os.path.basename(fpath)}:L{line_idx})",
                            remediation=rule["remediation"],
                            target=f"{fpath}:{line_idx}"
                        ))
        except Exception:
            pass

    return ToolResult(
        tool_name="encryption_auditor",
        target=target_path,
        status="success",
        data=data,
        findings=findings
    )
