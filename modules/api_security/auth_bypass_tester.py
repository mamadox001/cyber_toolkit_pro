# modules/api_security/auth_bypass_tester.py
# =============================================================================
# CyberToolkit Pro — API Authorization & BOLA/BFLA Tester
# =============================================================================

import urllib.request
import urllib.error
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "auth_bypass_tester",
    "category": "api_security",
    "description": "Tests API endpoints for Broken Object Level Authorization (BOLA) and method tampering",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "API URL (e.g. https://api.example.com/v1/users/100)", "arg_type": "str", "required": True},
    ],
    "tags": ["api", "bola", "idor", "auth", "bypass", "owasp-top10"],
}

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
]

def run(args: Dict[str, Any]) -> ToolResult:
    target = args.get("target", "").strip()
    if not target:
        return ToolResult(tool_name="auth_bypass_tester", status="error", error="No target specified")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    data = {"target": target, "tested_methods": [], "tested_headers": []}
    findings = []

    # 1. Method tampering test
    for m in METHODS:
        req = urllib.request.Request(target, method=m, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data["tested_methods"].append({"method": m, "code": resp.status})
                if resp.status == 200 and m in ("PUT", "DELETE", "PATCH"):
                    findings.append(Finding(
                        title=f"Unauthenticated {m} Method Allowed on Endpoint",
                        severity=Severity.HIGH,
                        description=f"HTTP method {m} returned status 200 OK without authentication.",
                        remediation="Ensure all state-modifying HTTP methods enforce proper authorization checks.",
                        target=target
                    ))
        except urllib.error.HTTPError as e:
            data["tested_methods"].append({"method": m, "code": e.code})
        except Exception:
            pass

    # 2. Header-based bypass test
    for h in BYPASS_HEADERS:
        req = urllib.request.Request(target, headers={**h, "User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data["tested_headers"].append({"headers": h, "status": 200})
                    header_name = list(h.keys())[0]
                    findings.append(Finding(
                        title=f"Potential Reverse-Proxy Bypass via {header_name}",
                        severity=Severity.HIGH,
                        description=f"Request with header {h} succeeded with HTTP 200.",
                        remediation=f"Sanitize or strip {header_name} at the edge reverse-proxy before routing to application.",
                        target=target
                    ))
        except urllib.error.HTTPError as e:
            data["tested_headers"].append({"headers": h, "status": e.code})
        except Exception:
            pass

    return ToolResult(
        tool_name="auth_bypass_tester",
        target=target,
        status="success",
        data=data,
        findings=findings
    )
