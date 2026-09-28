# modules/web/crlf_injection_tester.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "crlf_injection_tester",
    "category": "web",
    "description": "HTTP header injection / CRLF injection detection",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['web', 'crlf', 'header', 'injection'],
}


def run(args):

    import urllib.request, urllib.error, urllib.parse
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="crlf_injection_tester", status="error", error="No target specified")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    data = {"target": target, "tests": [], "vulnerabilities": []}
    findings = []
    crlf_payloads = [
        "%0d%0aInjected-Header:CyberToolkit", "%0aInjected-Header:CyberToolkit",
        "%0d%0a%0d%0a<html>injected</html>", "\r\nInjected-Header:CyberToolkit",
        "%E5%98%8A%E5%98%8DInjected-Header:CyberToolkit",
    ]
    for payload in crlf_payloads:
        test_url = f"{target}/{payload}"
        try:
            req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                headers = dict(resp.getheaders())
                if "Injected-Header" in headers:
                    data["vulnerabilities"].append({"payload": payload, "type": "header_injection"})
                    findings.append(Finding(
                        title="CRLF injection / HTTP header injection",
                        severity=Severity.HIGH,
                        description="Server reflects injected headers via CRLF sequences",
                        remediation="Sanitize all user input in URL paths and parameters; encode CR/LF characters"
                    ))
        except Exception:
            pass
        data["tests"].append({"payload": payload})
    return ToolResult(tool_name="crlf_injection_tester", target=target, status="success", data=data, findings=findings)

