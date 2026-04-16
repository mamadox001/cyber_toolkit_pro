# =============================================================================
# CyberToolkit Pro — HTTP Fingerprinting
# =============================================================================
# Identifies server technology, headers, security posture, and common
# web technologies by analyzing HTTP response headers and content.
# =============================================================================

import urllib.request
import urllib.error
import ssl
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "http_fingerprint",
    "category": "reconnaissance",
    "description": "HTTP server fingerprinting and technology detection",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target URL or hostname"},
        {"name": "port", "required": False, "default": "80", "description": "Target port"},
    ],
    "tags": ["http", "recon", "fingerprint", "headers"],
}

# Security headers that should be present
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HSTS not set — vulnerable to SSL stripping attacks", Severity.MEDIUM),
    "Content-Security-Policy": ("CSP not set — vulnerable to XSS and injection attacks", Severity.MEDIUM),
    "X-Frame-Options": ("X-Frame-Options not set — vulnerable to clickjacking", Severity.LOW),
    "X-Content-Type-Options": ("X-Content-Type-Options not set — MIME-type sniffing risk", Severity.LOW),
    "X-XSS-Protection": ("X-XSS-Protection not set — browser XSS filter not enabled", Severity.LOW),
    "Referrer-Policy": ("Referrer-Policy not set — referrer info may leak", Severity.INFO),
    "Permissions-Policy": ("Permissions-Policy not set — browser features not restricted", Severity.INFO),
}

# Headers that reveal sensitive info
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="http_fingerprint", status="error", error="No target specified")

    port = args.get("port", "80")

    # Normalize URL
    if not target.startswith(("http://", "https://")):
        scheme = "https" if port == "443" else "http"
        url = f"{scheme}://{target}:{port}" if port not in ("80", "443") else f"{scheme}://{target}"
    else:
        url = target

    findings = []
    headers_dict = {}
    technologies = []

    try:
        # Create SSL context that doesn't verify (for testing purposes)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "CyberToolkitPro/2.0 SecurityScanner")

        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            headers_dict = dict(resp.headers)
            status_code = resp.status
            body = resp.read(8192).decode("utf-8", errors="replace")

    except urllib.error.HTTPError as e:
        headers_dict = dict(e.headers) if e.headers else {}
        status_code = e.code
        body = ""
    except Exception as e:
        return ToolResult(
            tool_name="http_fingerprint",
            target=target,
            status="error",
            error=str(e),
        )

    # --- Analyze security headers ---
    headers_lower = {k.lower(): v for k, v in headers_dict.items()}

    for header, (message, severity) in SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            findings.append(Finding(
                title=f"Missing header: {header}",
                description=message,
                severity=severity,
                remediation=f"Add {header} header to HTTP responses",
            ))

    # --- Check for leaky headers ---
    for header in LEAKY_HEADERS:
        if header.lower() in headers_lower:
            value = headers_lower[header.lower()]
            findings.append(Finding(
                title=f"Information disclosure: {header}",
                description=f"{header} header reveals: {value}",
                severity=Severity.LOW,
                evidence=f"{header}: {value}",
                remediation=f"Remove or obfuscate the {header} header",
            ))
            technologies.append(f"{header}: {value}")

    # --- Technology detection from HTML ---
    tech_signatures = {
        "WordPress": ["wp-content", "wp-includes", "WordPress"],
        "jQuery": ["jquery", "jQuery"],
        "React": ["react", "_reactRoot", "__NEXT_DATA__"],
        "Angular": ["ng-app", "angular"],
        "Vue.js": ["vue.js", "__vue__"],
        "Bootstrap": ["bootstrap"],
        "PHP": [".php"],
        "ASP.NET": ["__VIEWSTATE", "aspnet"],
    }

    for tech, signatures in tech_signatures.items():
        if any(sig.lower() in body.lower() for sig in signatures):
            technologies.append(tech)

    return ToolResult(
        tool_name="http_fingerprint",
        target=target,
        status="success",
        data={
            "url": url,
            "status_code": status_code,
            "headers": headers_dict,
            "technologies": technologies,
            "security_headers_missing": [
                h for h in SECURITY_HEADERS if h.lower() not in headers_lower
            ],
        },
        findings=findings,
    )
