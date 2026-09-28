# modules/web/cors_tester.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "cors_tester",
    "category": "web",
    "description": "Test for CORS misconfigurations (wildcard origins, credential leaks)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['web', 'cors', 'misconfiguration'],
}


def run(args):

    import urllib.request, urllib.error
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="cors_tester", status="error", error="No target specified")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    data = {"target": target, "cors_tests": [], "vulnerable": False}
    findings = []
    test_origins = [
        "https://evil.com", "https://attacker.com",
        "null", f"{target}.evil.com",
    ]
    for origin in test_origins:
        try:
            req = urllib.request.Request(target, headers={
                "User-Agent": "Mozilla/5.0", "Origin": origin,
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                acao = dict(resp.getheaders()).get("Access-Control-Allow-Origin", "")
                acac = dict(resp.getheaders()).get("Access-Control-Allow-Credentials", "")
                result = {"origin_tested": origin, "acao": acao, "acac": acac, "reflected": acao == origin}
                data["cors_tests"].append(result)
                if acao == origin or acao == "*":
                    data["vulnerable"] = True
                    sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                    findings.append(Finding(
                        title=f"CORS misconfiguration: origin '{origin}' reflected",
                        severity=sev,
                        description=f"Access-Control-Allow-Origin reflects '{origin}'" + (" with credentials" if acac else ""),
                        remediation="Restrict CORS origins to trusted domains only"
                    ))
        except Exception:
            data["cors_tests"].append({"origin_tested": origin, "error": "Request failed"})
    return ToolResult(tool_name="cors_tester", target=target, status="success", data=data, findings=findings)

