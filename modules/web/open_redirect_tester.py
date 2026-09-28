# modules/web/open_redirect_tester.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "open_redirect_tester",
    "category": "web",
    "description": "Open redirect vulnerability detection in URL parameters",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['web', 'redirect', 'vulnerability'],
}


def run(args):

    import urllib.request, urllib.error, urllib.parse
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="open_redirect_tester", status="error", error="No target specified")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    data = {"target": target, "tests": [], "vulnerable_params": []}
    findings = []
    redirect_payloads = [
        "https://evil.com", "//evil.com", "https://evil.com%00.target.com",
        "https://evil.com%2F%2F", "/\\evil.com", "https:evil.com",
    ]
    redirect_params = ["url", "redirect", "next", "return", "returnTo", "goto", "redir", "redirect_uri", "continue", "target"]
    for param in redirect_params:
        for payload in redirect_payloads[:3]:
            test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
                resp = opener.open(req, timeout=8)
                final_url = resp.url
                if "evil.com" in final_url:
                    data["vulnerable_params"].append({"param": param, "payload": payload, "redirected_to": final_url})
                    findings.append(Finding(
                        title=f"Open redirect via '{param}' parameter",
                        severity=Severity.MEDIUM,
                        description=f"Parameter '{param}' redirects to external domain",
                        remediation="Validate redirect URLs against a whitelist of allowed domains"
                    ))
            except Exception:
                pass
            data["tests"].append({"param": param, "payload": payload})
    return ToolResult(tool_name="open_redirect_tester", target=target, status="success", data=data, findings=findings)

