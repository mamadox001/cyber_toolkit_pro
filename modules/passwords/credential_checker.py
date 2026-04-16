# =============================================================================
# CyberToolkit Pro — Credential Reuse Checker
# =============================================================================
# Tests a set of credentials across multiple services on a target to
# detect credential reuse. LAB USE ONLY.
# =============================================================================

import socket
import urllib.request
import urllib.error
import ssl
import base64
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "credential_checker",
    "category": "passwords",
    "description": "Credential reuse detection across multiple services (LAB ONLY)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target IP or hostname"},
        {"name": "username", "required": False, "default": "admin", "description": "Username to test"},
        {"name": "password", "required": False, "default": "admin", "description": "Password to test"},
        {"name": "services", "required": False, "default": "http,ftp",
         "description": "Comma-separated services to check (http, ftp)"},
    ],
    "tags": ["passwords", "credential-reuse", "lateral-movement", "lab-only"],
}


def _check_http(target, username, password, port=80):
    """Test HTTP Basic Auth."""
    try:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{target}:{port}/"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {creds}")
        resp = urllib.request.urlopen(req, timeout=5, context=ctx)
        return resp.status != 401, resp.status
    except urllib.error.HTTPError as e:
        return e.code != 401, e.code
    except Exception as e:
        return False, str(e)


def _check_ftp(target, username, password, port=21):
    """Test FTP login."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        s.recv(1024)
        s.send(f"USER {username}\r\n".encode())
        s.recv(1024)
        s.send(f"PASS {password}\r\n".encode())
        resp = s.recv(1024).decode("utf-8", errors="replace")
        s.send(b"QUIT\r\n")
        s.close()
        return "230" in resp, resp.strip()
    except Exception as e:
        return False, str(e)


SERVICE_CHECKS = {
    "http":  (_check_http, 80),
    "https": (_check_http, 443),
    "ftp":   (_check_ftp, 21),
}


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="credential_checker", status="error", error="No target specified")

    username = args.get("username", "admin")
    password = args.get("password", "admin")
    services_str = args.get("services", "http,ftp")
    services = [s.strip() for s in services_str.split(",") if s.strip()]

    results = []
    findings = []
    successful = []

    for service in services:
        if service not in SERVICE_CHECKS:
            results.append({"service": service, "status": "unsupported"})
            continue

        check_fn, default_port = SERVICE_CHECKS[service]
        success, detail = check_fn(target, username, password, default_port)

        results.append({
            "service": service,
            "port": default_port,
            "success": success,
            "detail": str(detail)[:200],
        })

        if success:
            successful.append(service)

    if len(successful) > 1:
        findings.append(Finding(
            title=f"Credential reuse detected across {len(successful)} services",
            severity=Severity.HIGH,
            description=f"Username '{username}' with the same password works on: {', '.join(successful)}",
            evidence=f"Services: {', '.join(successful)}",
            remediation="Use unique passwords per service. Implement a password manager.",
        ))
    elif len(successful) == 1:
        findings.append(Finding(
            title=f"Valid credentials on {successful[0]}",
            severity=Severity.MEDIUM,
            description=f"Credentials '{username}' accepted on {successful[0]}",
        ))

    return ToolResult(
        tool_name="credential_checker",
        target=target,
        status="success",
        data={
            "username": username,
            "services_tested": services,
            "results": results,
            "successful_services": successful,
        },
        findings=findings,
    )
