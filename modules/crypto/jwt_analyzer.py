# modules/crypto/jwt_analyzer.py
# =============================================================================
# CyberToolkit Pro — JSON Web Token (JWT) Security Analyzer
# =============================================================================

import base64
import json
import time
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "jwt_analyzer",
    "category": "crypto",
    "description": "Analyzes JWT tokens for common vulnerabilities: 'none' algorithm, expiration, and sensitive claims",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "token", "description": "JWT string to inspect", "arg_type": "str", "required": True},
    ],
    "tags": ["crypto", "jwt", "tokens", "auth", "header", "none-alg"],
}

def _b64_decode(s: str) -> bytes:
    padding = "=" * (4 - (len(s) % 4))
    return base64.urlsafe_b64decode(s + padding)

def run(args: Dict[str, Any]) -> ToolResult:
    token = args.get("token", "") or args.get("target", "")
    token = token.strip()
    if not token:
        return ToolResult(tool_name="jwt_analyzer", status="error", error="No JWT token provided")

    parts = token.split(".")
    if len(parts) != 3:
        return ToolResult(tool_name="jwt_analyzer", status="error", error="Invalid JWT format: expected 3 dot-separated segments")

    findings = []
    data = {}

    try:
        header_raw = _b64_decode(parts[0]).decode("utf-8", errors="replace")
        header = json.loads(header_raw)
        data["header"] = header

        payload_raw = _b64_decode(parts[1]).decode("utf-8", errors="replace")
        payload = json.loads(payload_raw)
        data["payload"] = payload
    except Exception as e:
        return ToolResult(tool_name="jwt_analyzer", status="error", error=f"Failed to decode JWT segments: {e}")

    # Vulnerability 1: alg == none
    alg = header.get("alg", "").lower()
    if alg in ("none", "none_strict"):
        findings.append(Finding(
            title="JWT 'none' Algorithm Vulnerability",
            severity=Severity.CRITICAL,
            description="The JWT header specifies 'none' as algorithm. If accepted by server, signatures can be forged.",
            remediation="Enforce strict asymmetric (RS256/ES256) or symmetric (HS256) signature verification on server."
        ))

    # Vulnerability 2: Missing or expired 'exp'
    if "exp" not in payload:
        findings.append(Finding(
            title="JWT Missing Expiration Claim ('exp')",
            severity=Severity.MEDIUM,
            description="Token lacks an 'exp' claim and never expires, allowing indefinite replay attacks.",
            remediation="Add an 'exp' timestamp claim to limit token lifespan."
        ))
    else:
        exp_time = payload["exp"]
        if isinstance(exp_time, (int, float)):
            now = time.time()
            if exp_time < now:
                findings.append(Finding(
                    title="JWT Token Is Expired",
                    severity=Severity.LOW,
                    description=f"Token expiration time ({exp_time}) is in the past.",
                    remediation="Generate a fresh token."
                ))

    # Vulnerability 3: Sensitive claims exposed in plaintext payload
    sensitive_keys = ["password", "passwd", "secret", "private_key", "ssn", "credit_card"]
    for k in payload.keys():
        if any(s in k.lower() for s in sensitive_keys):
            findings.append(Finding(
                title=f"Sensitive Data Exposed in JWT Payload: '{k}'",
                severity=Severity.HIGH,
                description=f"JWT payload contains sensitive key '{k}'. JWT payloads are base64 encoded and readable by anyone.",
                remediation="Never store passwords, secrets, or sensitive PII in client-facing JWT tokens."
            ))

    return ToolResult(
        tool_name="jwt_analyzer",
        status="success",
        data=data,
        findings=findings
    )
