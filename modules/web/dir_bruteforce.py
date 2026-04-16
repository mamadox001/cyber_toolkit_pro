# =============================================================================
# CyberToolkit Pro — Directory Brute Force
# =============================================================================
# Multi-threaded web directory/file discovery using wordlists.
# Supports custom wordlists, status code filtering, and extension appending.
# =============================================================================

import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "dir_bruteforce",
    "category": "web",
    "description": "Web directory brute force discovery with wordlist support",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target base URL (e.g. http://example.com)"},
        {"name": "wordlist", "required": False, "default": "wordlists/common_dirs.txt",
         "description": "Path to directory wordlist"},
        {"name": "extensions", "required": False, "default": "",
         "description": "File extensions to append (comma-separated, e.g. php,html,txt)"},
        {"name": "threads", "required": False, "default": "10", "description": "Number of threads"},
        {"name": "status_codes", "required": False, "default": "200,201,301,302,403",
         "description": "Status codes to report (comma-separated)"},
    ],
    "tags": ["web", "directory", "brute-force", "discovery"],
}

# Built-in minimal wordlist
DEFAULT_DIRS = [
    "admin", "login", "wp-admin", "wp-login.php", "administrator", "phpmyadmin",
    "dashboard", "cpanel", "config", "backup", "api", "api/v1", "robots.txt",
    "sitemap.xml", ".env", ".git", ".git/config", "debug", "test", "staging",
    "uploads", "images", "css", "js", "includes", "assets", "static", "media",
    "docs", "documentation", "swagger", "graphql", "status", "health",
    "server-status", "server-info", "info.php", "phpinfo.php", ".htaccess",
    "web.config", "crossdomain.xml", ".well-known", "favicon.ico",
    "wp-content", "wp-includes", "xmlrpc.php", "readme.html",
    "console", "manager", "portal", "secure", "private", "internal",
]


def _check_path(base_url, path, timeout, valid_codes):
    """Check if a path exists on the target."""
    url = f"{base_url.rstrip('/')}/{path}"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "CyberToolkitPro/2.0")

        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status = resp.status
        length = len(resp.read(1024))
        resp.close()

        if status in valid_codes:
            return {"path": f"/{path}", "status": status, "size": length, "url": url}
    except urllib.error.HTTPError as e:
        if e.code in valid_codes:
            return {"path": f"/{path}", "status": e.code, "size": 0, "url": url}
    except Exception:
        pass
    return None


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="dir_bruteforce", status="error", error="No target specified")

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    wordlist_path = args.get("wordlist", "wordlists/common_dirs.txt")
    threads = int(args.get("threads", 10))
    ext_str = args.get("extensions", "")
    status_str = args.get("status_codes", "200,201,301,302,403")

    valid_codes = {int(c.strip()) for c in status_str.split(",") if c.strip()}

    # Load wordlist
    paths = DEFAULT_DIRS[:]
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        pass

    # Append extensions if specified
    if ext_str:
        extensions = [e.strip().lstrip(".") for e in ext_str.split(",") if e.strip()]
        extended = []
        for path in paths:
            extended.append(path)
            for ext in extensions:
                extended.append(f"{path}.{ext}")
        paths = extended

    found = []
    timeout = 5

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_check_path, target, p, timeout, valid_codes): p for p in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: x["path"])

    # Generate findings
    findings = []
    sensitive_paths = [".env", ".git", "config", "backup", "phpinfo", "debug", "server-status"]
    for item in found:
        if any(s in item["path"].lower() for s in sensitive_paths):
            findings.append(Finding(
                title=f"Sensitive path discovered: {item['path']}",
                severity=Severity.HIGH,
                description=f"Path {item['path']} (HTTP {item['status']}) may expose sensitive information",
                remediation="Restrict access or remove this path from the public web server",
            ))
        elif item["status"] == 403:
            findings.append(Finding(
                title=f"Forbidden path: {item['path']}",
                severity=Severity.LOW,
                description=f"Path exists but returns 403 Forbidden — may indicate restricted content",
            ))

    return ToolResult(
        tool_name="dir_bruteforce",
        target=target,
        status="success",
        data={
            "found_paths": found,
            "total_tested": len(paths),
            "total_found": len(found),
        },
        findings=findings,
    )
