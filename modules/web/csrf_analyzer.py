# modules/web/csrf_analyzer.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "csrf_analyzer",
    "category": "web",
    "description": "Analyze CSRF token presence and effectiveness on forms",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['web', 'csrf', 'vulnerability'],
}


def run(args):

    import urllib.request, urllib.error, re
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="csrf_analyzer", status="error", error="No target specified")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    data = {"target": target, "forms_found": 0, "forms_without_csrf": 0, "details": []}
    findings = []
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(200000).decode("utf-8", errors="replace")
        forms = re.findall(r"<form[^>]*>(.*?)</form>", body, re.DOTALL | re.IGNORECASE)
        data["forms_found"] = len(forms)
        csrf_patterns = ["csrf", "token", "_token", "authenticity_token", "csrfmiddlewaretoken", "anti-forgery", "__RequestVerificationToken"]
        for i, form in enumerate(forms):
            has_csrf = any(p.lower() in form.lower() for p in csrf_patterns)
            method_match = re.search(r'method=["\']?(POST|PUT|DELETE)', form, re.IGNORECASE)
            method = method_match.group(1) if method_match else "GET"
            action_match = re.search(r'action=["\']?([^"\'\s>]+)', form, re.IGNORECASE)
            action = action_match.group(1) if action_match else "(same page)"
            detail = {"form_index": i, "method": method, "action": action, "has_csrf_token": has_csrf}
            data["details"].append(detail)
            if method.upper() in ("POST", "PUT", "DELETE") and not has_csrf:
                data["forms_without_csrf"] += 1
                findings.append(Finding(
                    title=f"Form without CSRF protection (#{i})",
                    severity=Severity.MEDIUM,
                    description=f"{method} form to '{action}' lacks CSRF token",
                    remediation="Add anti-CSRF tokens to all state-changing forms"
                ))
    except Exception as e:
        return ToolResult(tool_name="csrf_analyzer", target=target, status="error", error=str(e))
    return ToolResult(tool_name="csrf_analyzer", target=target, status="success", data=data, findings=findings)

