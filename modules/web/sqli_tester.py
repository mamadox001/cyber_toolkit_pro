# =============================================================================
# CyberToolkit Pro — SQL Injection Tester
# =============================================================================
# Safe SQL injection detection mode. Tests URL parameters for common SQLi
# patterns by analyzing server responses for error-based indicators.
# Does NOT attempt actual data extraction — detection only.
# =============================================================================

import urllib.request
import urllib.error
import urllib.parse
import ssl
import time
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "sqli_tester",
    "category": "web",
    "description": "Safe SQL injection detection tester (detection mode only)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target URL with parameter (e.g. http://example.com/page?id=1)"},
        {"name": "param", "required": False, "default": "", "description": "Parameter to test (auto-detected if empty)"},
        {"name": "rate_limit", "required": False, "default": "200", "description": "Delay between requests in ms"},
    ],
    "tags": ["web", "sqli", "sql-injection", "vulnerability"],
}

# Safe SQLi test payloads — designed to trigger errors without causing damage
SQLI_PAYLOADS = [
    # Error-based detection
    ("'", "Single quote"),
    ("\"", "Double quote"),
    ("' OR '1'='1", "Boolean tautology (single quote)"),
    ("\" OR \"1\"=\"1", "Boolean tautology (double quote)"),
    ("' OR '1'='2", "Boolean false condition"),
    ("1' AND '1'='1", "AND tautology"),
    ("1' AND '1'='2", "AND false"),
    ("1 OR 1=1", "Numeric boolean"),
    ("1 OR 1=2", "Numeric boolean false"),
    # Syntax probing
    ("' OR ''='", "Empty string comparison"),
    ("1'1", "Syntax break"),
    ("1 UNION SELECT NULL--", "UNION probe"),
    ("' UNION SELECT NULL--", "Quoted UNION probe"),
    # Time-based (safe, just adds delay)
    ("1' AND SLEEP(0)--", "Time-based probe (0 delay)"),
    ("1; WAITFOR DELAY '0:0:0'--", "MSSQL time probe (0 delay)"),
    # Comment termination
    ("admin'--", "Comment termination"),
    ("admin'#", "MySQL comment termination"),
]

# Error patterns in responses that indicate SQL injection vulnerability
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "microsoft ole db provider for odbc drivers",
    "syntax error",
    "pg_query",
    "pg_exec",
    "postgresql",
    "ora-01756",
    "ora-00933",
    "sqlite3.operationalerror",
    "sqlexception",
    "sql server",
    "mysql_fetch",
    "mysql_num_rows",
    "mysqli_",
    "invalid query",
    "sql command not properly ended",
    "division by zero",
    "supplied argument is not a valid mysql",
    "unterminated string",
    "jdbc.sqle",
]


def _make_request(url, timeout=10):
    """Make HTTP request and return response body + status."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "CyberToolkitPro/2.0 SecurityScanner")

        start = time.time()
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        elapsed = (time.time() - start) * 1000
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body, elapsed
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body, 0
    except Exception as e:
        return 0, str(e), 0


def _detect_sqli_in_response(body):
    """Check response body for SQL error indicators."""
    body_lower = body.lower()
    detected = []
    for pattern in SQL_ERROR_PATTERNS:
        if pattern in body_lower:
            detected.append(pattern)
    return detected


def _extract_params(url):
    """Extract query parameters from URL."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return {k: v[0] for k, v in params.items()}


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="sqli_tester", status="error", error="No target specified")

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    rate_limit = int(args.get("rate_limit", 200)) / 1000.0
    param_to_test = args.get("param", "")

    # Extract parameters from URL
    parsed_url = urllib.parse.urlparse(target)
    params = _extract_params(target)

    if not params:
        return ToolResult(
            tool_name="sqli_tester", target=target, status="error",
            error="No query parameters found in URL. Provide URL like: http://example.com/page?id=1",
        )

    # Determine which parameters to test
    test_params = [param_to_test] if param_to_test and param_to_test in params else list(params.keys())

    # Get baseline response
    baseline_status, baseline_body, baseline_time = _make_request(target)
    baseline_length = len(baseline_body)

    vulnerabilities = []
    test_results = []
    findings = []

    for param in test_params:
        original_value = params[param]

        for payload, description in SQLI_PAYLOADS:
            # Build test URL
            test_params_dict = params.copy()
            test_params_dict[param] = payload
            query_string = urllib.parse.urlencode(test_params_dict)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"

            status, body, elapsed = _make_request(test_url)
            sql_errors = _detect_sqli_in_response(body)

            entry = {
                "param": param,
                "payload": payload,
                "description": description,
                "status": status,
                "length": len(body),
                "time_ms": round(elapsed),
                "sql_errors": sql_errors,
            }
            test_results.append(entry)

            if sql_errors:
                vuln = {
                    "param": param,
                    "payload": payload,
                    "type": description,
                    "errors": sql_errors,
                }
                vulnerabilities.append(vuln)
                findings.append(Finding(
                    title=f"Potential SQLi in parameter '{param}'",
                    severity=Severity.CRITICAL,
                    description=f"Payload '{payload}' ({description}) triggered SQL error: {sql_errors[0]}",
                    evidence=f"URL: {test_url}\nError pattern: {', '.join(sql_errors)}",
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                ))

            # Boolean-based detection: compare response lengths
            if "tautology" in description.lower():
                length_diff = abs(len(body) - baseline_length)
                if length_diff > 100 and status == baseline_status:
                    # Check if false condition gives different result
                    pass  # Already captured above if errors found

            if rate_limit > 0:
                time.sleep(rate_limit)

    return ToolResult(
        tool_name="sqli_tester",
        target=target,
        status="success",
        data={
            "parameters_tested": test_params,
            "total_payloads": len(SQLI_PAYLOADS),
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
        },
        findings=findings,
    )
