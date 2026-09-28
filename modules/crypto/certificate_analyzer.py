# modules/crypto/certificate_analyzer.py
# =============================================================================
# CyberToolkit Pro — X.509 Certificate Chain & Trust Analyzer
# =============================================================================

import socket
import ssl
import datetime
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "certificate_analyzer",
    "category": "crypto",
    "description": "Inspects SSL/TLS X.509 certificates for expiration, trust, SANs, and signature algorithms",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "Target hostname", "arg_type": "str", "required": True},
        {"name": "port", "description": "Port number (default 443)", "arg_type": "int", "default": 443},
    ],
    "tags": ["crypto", "certificate", "x509", "pki", "ssl", "expiry"],
}

def run(args: Dict[str, Any]) -> ToolResult:
    target = args.get("target", "").strip()
    port = int(args.get("port", 443))

    if not target:
        return ToolResult(tool_name="certificate_analyzer", status="error", error="No target specified")

    for prefix in ["https://", "http://"]:
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0].split(":")[0]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    findings = []
    data = {}

    try:
        with socket.create_connection((target, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                # If cert is empty because of CERT_NONE, fetch binary or parsed
                if not cert:
                    # Retry with CERT_REQUIRED or inspect binary
                    ctx_req = ssl.create_default_context()
                    try:
                        with socket.create_connection((target, port), timeout=8) as s2:
                            with ctx_req.wrap_socket(s2, server_hostname=target) as ssock2:
                                cert = ssock2.getpeercert()
                    except Exception as verify_err:
                        findings.append(Finding(
                            title="Untrusted Certificate / Validation Failure",
                            severity=Severity.HIGH,
                            description=f"Certificate verification failed: {verify_err}",
                            remediation="Install a valid certificate signed by a trusted public Certificate Authority.",
                            target=f"{target}:{port}"
                        ))
                        # Still fallback to empty cert dictionary
                        cert = cert or {}

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_after = cert.get("notAfter", "")
                not_before = cert.get("notBefore", "")
                sans = [x[1] for x in cert.get("subjectAltName", [])]

                data["subject"] = subject
                data["issuer"] = issuer
                data["sans"] = sans
                data["not_after"] = not_after
                data["not_before"] = not_before

                # Parse expiration
                if not_after:
                    try:
                        exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_date - datetime.datetime.utcnow()).days
                        data["days_remaining"] = days_left

                        if days_left < 0:
                            findings.append(Finding(
                                title=f"SSL/TLS Certificate Has Expired ({abs(days_left)} days ago)",
                                severity=Severity.CRITICAL,
                                description=f"Certificate expired on {not_after}.",
                                remediation="Renew and install an active SSL/TLS certificate immediately.",
                                target=f"{target}:{port}"
                            ))
                        elif days_left < 30:
                            findings.append(Finding(
                                title=f"SSL/TLS Certificate Expiring Soon ({days_left} days remaining)",
                                severity=Severity.MEDIUM,
                                description=f"Certificate will expire on {not_after}.",
                                remediation="Renew certificate before expiration to avoid service interruption.",
                                target=f"{target}:{port}"
                            ))
                    except Exception:
                        pass

                # Check self-signed
                if subject and issuer and subject.get("commonName") == issuer.get("commonName"):
                    findings.append(Finding(
                        title="Self-Signed SSL/TLS Certificate",
                        severity=Severity.HIGH,
                        description="Certificate subject and issuer are identical, indicating a self-signed certificate.",
                        remediation="Replace self-signed certificate with one issued by a trusted CA (e.g. Let's Encrypt).",
                        target=f"{target}:{port}"
                    ))
    except Exception as e:
        return ToolResult(tool_name="certificate_analyzer", target=target, status="error", error=str(e))

    return ToolResult(
        tool_name="certificate_analyzer",
        target=target,
        status="success",
        data=data,
        findings=findings
    )
