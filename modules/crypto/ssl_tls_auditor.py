# modules/crypto/ssl_tls_auditor.py
# =============================================================================
# CyberToolkit Pro — Deep SSL/TLS Configuration Auditor
# =============================================================================

import socket
import ssl
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "ssl_tls_auditor",
    "category": "crypto",
    "description": "Performs deep SSL/TLS configuration analysis, protocol versions, and cipher audits",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "Target hostname or IP", "arg_type": "str", "required": True},
        {"name": "port", "description": "Target port (default 443)", "arg_type": "int", "default": 443},
    ],
    "tags": ["crypto", "ssl", "tls", "ciphers", "security"],
}

WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]

def run(args: Dict[str, Any]) -> ToolResult:
    target = args.get("target", "").strip()
    port = int(args.get("port", 443))

    if not target:
        return ToolResult(tool_name="ssl_tls_auditor", status="error", error="No target specified")
    
    # Strip protocol prefix if present
    for prefix in ["https://", "http://"]:
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0].split(":")[0]

    data = {
        "target": target,
        "port": port,
        "tls_version": None,
        "cipher": None,
        "weak_ciphers_detected": [],
        "warnings": [],
    }
    findings = []

    # Test standard modern connection
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                data["tls_version"] = version
                data["cipher"] = cipher

                # Check if TLS 1.0 or 1.1 used
                if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(Finding(
                        title=f"Deprecated TLS Protocol in Use: {version}",
                        severity=Severity.HIGH,
                        description=f"Server negotiates deprecated protocol {version}. Deprecated protocols are vulnerable to POODLE, BEAST, and lack modern security guarantees.",
                        remediation="Disable SSLv3, TLS 1.0, and TLS 1.1. Enforce TLS 1.2 and TLS 1.3 only.",
                        target=f"{target}:{port}"
                    ))

                if cipher:
                    cipher_name = cipher[0]
                    for weak in WEAK_CIPHERS:
                        if weak.lower() in cipher_name.lower():
                            data["weak_ciphers_detected"].append(cipher_name)
                            findings.append(Finding(
                                title=f"Weak Cipher Suite Negotiated: {cipher_name}",
                                severity=Severity.HIGH,
                                description=f"Cipher suite {cipher_name} contains weak primitive ({weak}).",
                                remediation="Disable weak ciphers and configure strong AEAD suites (AES-GCM, CHACHA20-POLY1305).",
                                target=f"{target}:{port}"
                            ))

                    if "CBC" in cipher_name and version == "TLSv1.2":
                        findings.append(Finding(
                            title=f"CBC Mode Cipher Suite in Use: {cipher_name}",
                            severity=Severity.LOW,
                            description=f"Cipher suite uses CBC mode which is vulnerable to padding oracle attacks in certain implementations.",
                            remediation="Prioritize GCM or Poly1305 cipher suites.",
                            target=f"{target}:{port}"
                        ))
    except Exception as e:
        return ToolResult(
            tool_name="ssl_tls_auditor",
            target=target,
            status="error",
            error=f"Connection failed: {e}"
        )

    return ToolResult(
        tool_name="ssl_tls_auditor",
        target=target,
        status="success",
        data=data,
        findings=findings
    )
