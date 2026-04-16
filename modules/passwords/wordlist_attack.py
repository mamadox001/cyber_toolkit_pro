# =============================================================================
# CyberToolkit Pro — Wordlist Attack
# =============================================================================
# Dictionary-based login testing for common protocols (HTTP Basic Auth,
# FTP, SSH via socket-based testing). LAB USE ONLY.
# =============================================================================

import urllib.request
import urllib.error
import ssl
import base64
import socket
import time
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "wordlist_attack",
    "category": "passwords",
    "description": "Dictionary-based login testing for HTTP/FTP/SSH (LAB ONLY)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target IP or URL"},
        {"name": "protocol", "required": False, "default": "http",
         "description": "Protocol: http, ftp"},
        {"name": "username", "required": False, "default": "admin", "description": "Username to test"},
        {"name": "wordlist", "required": False, "default": "",
         "description": "Path to password wordlist"},
        {"name": "port", "required": False, "default": "", "description": "Target port"},
        {"name": "rate_limit", "required": False, "default": "200", "description": "Delay between attempts (ms)"},
    ],
    "tags": ["passwords", "brute-force", "dictionary", "lab-only"],
}

DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "admin123", "letmein", "welcome", "monkey", "dragon",
    "master", "login", "princess", "passw0rd", "shadow", "sunshine",
    "trustno1", "iloveyou", "batman", "access", "hello", "charlie",
    "root", "toor", "test", "guest", "administrator", "changeme",
]


def _test_http_basic(target, port, username, password):
    """Test HTTP Basic Authentication."""
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
        return resp.status != 401
    except urllib.error.HTTPError as e:
        return e.code != 401
    except Exception:
        return False


def _test_ftp(target, port, username, password):
    """Test FTP login."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        s.recv(1024)  # Banner
        s.send(f"USER {username}\r\n".encode())
        s.recv(1024)
        s.send(f"PASS {password}\r\n".encode())
        resp = s.recv(1024).decode("utf-8", errors="replace")
        s.send(b"QUIT\r\n")
        s.close()
        return "230" in resp  # 230 = Login successful
    except Exception:
        return False


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="wordlist_attack", status="error", error="No target specified")

    protocol = args.get("protocol", "http").lower()
    username = args.get("username", "admin")
    rate_limit = int(args.get("rate_limit", 200)) / 1000.0

    # Determine port
    default_ports = {"http": 80, "ftp": 21}
    port = int(args.get("port", "")) if args.get("port", "") else default_ports.get(protocol, 80)

    # Load wordlist
    passwords = DEFAULT_PASSWORDS[:]
    wordlist_path = args.get("wordlist", "")
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="replace") as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            pass

    # Select test function
    test_functions = {
        "http": _test_http_basic,
        "ftp": _test_ftp,
    }
    test_fn = test_functions.get(protocol)
    if not test_fn:
        return ToolResult(
            tool_name="wordlist_attack", status="error",
            error=f"Protocol '{protocol}' not supported. Use: {', '.join(test_functions.keys())}",
        )

    # Run attack
    found_creds = []
    attempts = 0

    for password in passwords:
        attempts += 1
        success = test_fn(target, port, username, password)
        if success:
            found_creds.append({"username": username, "password": password})
            break  # Stop after first success
        if rate_limit > 0:
            time.sleep(rate_limit)

    findings = []
    if found_creds:
        findings.append(Finding(
            title=f"Valid credentials found: {username}:{found_creds[0]['password']}",
            severity=Severity.CRITICAL,
            description=f"Weak password detected for {protocol.upper()} on {target}:{port}",
            evidence=f"Username: {username}, Password: {found_creds[0]['password']}",
            remediation="Change password immediately and enforce strong password policy",
        ))

    return ToolResult(
        tool_name="wordlist_attack",
        target=target,
        status="success",
        data={
            "protocol": protocol,
            "username": username,
            "attempts": attempts,
            "credentials_found": found_creds,
        },
        findings=findings,
    )
