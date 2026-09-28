# modules/api_security/rate_limit_tester.py
# =============================================================================
# CyberToolkit Pro — API Rate Limiting & DoS Resilience Tester
# =============================================================================

import urllib.request
import urllib.error
import time
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "rate_limit_tester",
    "category": "api_security",
    "description": "Tests if API endpoints enforce rate limits against burst requests",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "Target API URL", "arg_type": "str", "required": True},
        {"name": "burst", "description": "Number of rapid requests to send (default 20)", "arg_type": "int", "default": 20},
    ],
    "tags": ["api", "rate-limit", "dos", "throttling", "protection"],
}

def run(args: Dict[str, Any]) -> ToolResult:
    target = args.get("target", "").strip()
    burst = min(int(args.get("burst", 20)), 50)

    if not target:
        return ToolResult(tool_name="rate_limit_tester", status="error", error="No target specified")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    data = {
        "target": target,
        "burst_count": burst,
        "status_codes": {},
        "rate_limited": False,
        "rate_limit_headers": {}
    }
    findings = []

    rate_limited = False

    for i in range(burst):
        req = urllib.request.Request(target, headers={"User-Agent": "CyberToolkitPro-RateTester"})
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                code = resp.status
                data["status_codes"][code] = data["status_codes"].get(code, 0) + 1
                for h, v in resp.headers.items():
                    if "ratelimit" in h.lower() or "retry-after" in h.lower():
                        data["rate_limit_headers"][h] = v
        except urllib.error.HTTPError as e:
            code = e.code
            data["status_codes"][code] = data["status_codes"].get(code, 0) + 1
            if code == 429:
                rate_limited = True
                data["rate_limited"] = True
                for h, v in e.headers.items():
                    if "ratelimit" in h.lower() or "retry-after" in h.lower():
                        data["rate_limit_headers"][h] = v
                break
        except Exception:
            pass

    if not rate_limited and burst >= 15:
        findings.append(Finding(
            title="Missing Rate Limiting Protection on API Endpoint",
            severity=Severity.MEDIUM,
            description=f"Sent {burst} rapid consecutive requests to {target} without encountering HTTP 429 (Too Many Requests).",
            remediation="Implement rate limiting (e.g. token bucket or leaky bucket algorithm) using an API gateway or reverse proxy.",
            target=target
        ))

    return ToolResult(
        tool_name="rate_limit_tester",
        target=target,
        status="success",
        data=data,
        findings=findings
    )
