# =============================================================================
# CyberToolkit Pro — HTTP Fuzzer
# =============================================================================
# Parameter fuzzing engine for web applications. Tests URL parameters,
# headers, and POST data with various payloads to detect injection points.
# =============================================================================

import urllib.request
import urllib.error
import urllib.parse
import ssl
import time
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "http_fuzzer",
    "category": "web",
    "description": "HTTP parameter fuzzing engine for injection point detection",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target URL with FUZZ marker (e.g. http://example.com/page?id=FUZZ)"},
        {"name": "wordlist", "required": False, "default": "", "description": "Custom payload wordlist path"},
        {"name": "method", "required": False, "default": "GET", "description": "HTTP method (GET or POST)"},
        {"name": "rate_limit", "required": False, "default": "100", "description": "Delay between requests in ms"},
    ],
    "tags": ["web", "fuzzing", "injection", "parameter"],
}

# Built-in fuzzing payloads covering common injection patterns
DEFAULT_PAYLOADS = [
    # Basic tests
    "", "1", "0", "-1", "99999", "null", "undefined", "true", "false",
    # String boundary
    "A" * 100, "A" * 1000,
    # SQL injection probes
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1' OR '1'='1'--", "1; DROP TABLE--",
    "' UNION SELECT NULL--", "admin'--",
    # XSS probes
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>", "javascript:alert(1)",
    # Path traversal
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
    # Command injection
    "; ls", "| cat /etc/passwd", "`id`", "$(whoami)",
    # LDAP injection
    "*)(objectClass=*", "*)(&",
    # Format string
    "%s%s%s%s%s", "%x%x%x%x",
    # Special characters
    "{{7*7}}", "${7*7}", "#{7*7}",  # SSTI probes
]


def _send_request(url, method, timeout=10):
    """Send a request and return status, length, response time."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "CyberToolkitPro/2.0 Fuzzer")

        start = time.time()
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        elapsed = (time.time() - start) * 1000

        body = resp.read().decode("utf-8", errors="replace")
        return {
            "status": resp.status,
            "length": len(body),
            "time_ms": round(elapsed),
            "body_preview": body[:200],
        }
    except urllib.error.HTTPError as e:
        elapsed = 0
        return {"status": e.code, "length": 0, "time_ms": 0, "body_preview": ""}
    except Exception as e:
        return {"status": 0, "length": 0, "time_ms": 0, "body_preview": "", "error": str(e)}


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="http_fuzzer", status="error", error="No target specified")

    method = args.get("method", "GET").upper()
    rate_limit = int(args.get("rate_limit", 100)) / 1000.0  # Convert to seconds

    # Load payloads
    payloads = DEFAULT_PAYLOADS[:]
    wordlist_path = args.get("wordlist", "")
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8") as f:
                payloads = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            pass

    # Check for FUZZ marker
    if "FUZZ" not in target:
        return ToolResult(
            tool_name="http_fuzzer", target=target, status="error",
            error="Target URL must contain 'FUZZ' marker (e.g. http://example.com/?id=FUZZ)",
        )

    # Get baseline response
    baseline_url = target.replace("FUZZ", "1")
    baseline = _send_request(baseline_url, method)

    results = []
    anomalies = []
    findings = []

    for payload in payloads:
        fuzzed_url = target.replace("FUZZ", urllib.parse.quote(str(payload), safe=""))
        resp = _send_request(fuzzed_url, method)

        entry = {
            "payload": payload[:100],
            "status": resp["status"],
            "length": resp["length"],
            "time_ms": resp["time_ms"],
        }
        results.append(entry)

        # Detect anomalies (different from baseline)
        if resp["status"] != baseline["status"] or abs(resp["length"] - baseline["length"]) > 100:
            anomalies.append(entry)

        # Look for error messages indicating injection
        body = resp.get("body_preview", "").lower()
        error_indicators = [
            ("sql", "Possible SQL injection"),
            ("syntax error", "Server-side error triggered"),
            ("warning:", "PHP warning triggered"),
            ("exception", "Exception triggered"),
            ("stack trace", "Stack trace exposed"),
            ("root:", "System file disclosure"),
        ]
        for indicator, description in error_indicators:
            if indicator in body:
                findings.append(Finding(
                    title=f"Injection indicator: {description}",
                    severity=Severity.HIGH,
                    evidence=f"Payload: {payload[:50]}, Response contained: {indicator}",
                    description=f"The server response suggests potential vulnerability when payload '{payload[:50]}' was sent",
                ))
                break

        if rate_limit > 0:
            time.sleep(rate_limit)

    return ToolResult(
        tool_name="http_fuzzer",
        target=target,
        status="success",
        data={
            "total_payloads": len(payloads),
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "baseline_status": baseline["status"],
            "baseline_length": baseline["length"],
        },
        findings=findings,
    )
