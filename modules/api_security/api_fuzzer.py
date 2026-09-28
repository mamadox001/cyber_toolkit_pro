# modules/api_security/api_fuzzer.py
# =============================================================================
# CyberToolkit Pro — REST API Fuzzer & Boundary Tester
# =============================================================================

import urllib.request
import urllib.error
import urllib.parse
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "api_fuzzer",
    "category": "api_security",
    "description": "Fuzzes API endpoints with malformed parameters, type confusion, and boundary values",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "Target API endpoint URL", "arg_type": "str", "required": True},
        {"name": "method", "description": "HTTP method (GET/POST)", "arg_type": "str", "default": "GET"},
    ],
    "tags": ["api", "fuzzer", "rest", "injection", "validation"],
}

FUZZ_PAYLOADS = [
    ("null_byte", "%00"),
    ("type_confusion_array", "[]"),
    ("type_confusion_dict", "{}"),
    ("oversized_string", "A" * 1024),
    ("format_string", "%s%s%s%s%n"),
    ("negative_id", "-1"),
    ("max_int", "9223372036854775807"),
    ("boolean_injection", "true"),
    ("sql_probe", "' OR 1=1--"),
    ("path_traversal", "../../../etc/passwd"),
]

def run(args: Dict[str, Any]) -> ToolResult:
    target = args.get("target", "").strip()
    method = args.get("method", "GET").upper()

    if not target:
        return ToolResult(tool_name="api_fuzzer", status="error", error="No target URL specified")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    data = {"target": target, "tests_run": 0, "anomalies": []}
    findings = []

    parsed = urllib.parse.urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query = urllib.parse.parse_qs(parsed.query)

    params = query if query else {"id": ["1"]}

    for param_name in params.keys():
        for payload_name, payload_val in FUZZ_PAYLOADS:
            data["tests_run"] += 1
            test_params = dict(params)
            test_params[param_name] = [payload_val]
            qs = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{base_url}?{qs}"

            req = urllib.request.Request(test_url, method=method, headers={"User-Agent": "CyberToolkitPro-APIFuzzer"})
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    pass
            except urllib.error.HTTPError as e:
                # 500 status code indicates unhandled exception/crash
                if e.code == 500:
                    body = e.read(1000).decode("utf-8", errors="ignore")
                    anomaly = {
                        "param": param_name,
                        "payload": payload_name,
                        "status": 500,
                        "sample": body[:150]
                    }
                    data["anomalies"].append(anomaly)
                    findings.append(Finding(
                        title=f"Unhandled Server Exception (HTTP 500) Triggered via '{param_name}'",
                        severity=Severity.HIGH,
                        description=f"Fuzz payload '{payload_name}' on parameter '{param_name}' triggered a 500 error. Server may leak stack traces or crash.",
                        remediation="Implement robust input validation and return sanitized 400 Bad Request responses.",
                        target=test_url
                    ))
            except Exception:
                pass

    return ToolResult(
        tool_name="api_fuzzer",
        target=target,
        status="success",
        data=data,
        findings=findings
    )
