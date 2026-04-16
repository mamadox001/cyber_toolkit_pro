# =============================================================================
# CyberToolkit Pro — AI / Smart Reasoning Engine
# =============================================================================
# Analyzes tool outputs and suggests next steps. Uses a rule-based engine
# with 50+ pattern rules, plus optional LLM API integration for natural
# language analysis.
#
# Architecture: Rules are functions decorated with @suggestion_rule that
# match against ToolResult data and produce recommendations.
# =============================================================================

import json
from typing import Any, Dict, List, Optional

from core.models import ToolResult
from core.config import Config
from core import output
from core.logger import get_logger

logger = get_logger("ai")


# =============================================================================
# Rule-based suggestion engine
# =============================================================================

# Port → service / next-step mappings
PORT_SERVICE_MAP = {
    21:   ("FTP",        ["Check for anonymous FTP access", "Run FTP brute force"]),
    22:   ("SSH",        ["Run SSH brute force detector", "Check SSH key auth"]),
    23:   ("Telnet",     ["Telnet is insecure — check for cleartext creds"]),
    25:   ("SMTP",       ["Check for open relay", "Enumerate SMTP users"]),
    53:   ("DNS",        ["Run DNS enumeration", "Check for zone transfer"]),
    80:   ("HTTP",       ["Run directory brute force", "Run HTTP fingerprinting", "Test for SQLi/XSS"]),
    110:  ("POP3",       ["Check for cleartext auth"]),
    135:  ("MSRPC",      ["Enumerate RPC endpoints"]),
    139:  ("NetBIOS",    ["Enumerate SMB shares"]),
    143:  ("IMAP",       ["Check IMAP auth security"]),
    443:  ("HTTPS",      ["Run web audit pipeline", "Check SSL/TLS configuration", "Test for SQLi/XSS"]),
    445:  ("SMB",        ["Enumerate SMB shares", "Check for EternalBlue"]),
    993:  ("IMAPS",      ["Verify certificate validity"]),
    995:  ("POP3S",      ["Verify certificate validity"]),
    1433: ("MSSQL",      ["Test default credentials", "Run SQLi tester"]),
    1521: ("Oracle",     ["Test default credentials"]),
    3306: ("MySQL",      ["Test default credentials", "Run SQLi tester"]),
    3389: ("RDP",        ["Check NLA configuration", "Test default credentials"]),
    5432: ("PostgreSQL", ["Test default credentials", "Run SQLi tester"]),
    5900: ("VNC",        ["Test VNC authentication bypass"]),
    6379: ("Redis",      ["Check for unauthenticated access"]),
    8080: ("HTTP-Alt",   ["Run directory brute force", "HTTP fingerprinting"]),
    8443: ("HTTPS-Alt",  ["Run web audit pipeline"]),
    8888: ("HTTP-Alt",   ["Run HTTP fingerprinting"]),
    27017:("MongoDB",    ["Check for unauthenticated access"]),
}

# HTTP header → security concern mappings
HEADER_RULES = {
    "x-powered-by":              "Server technology exposed via X-Powered-By header — consider removing",
    "server":                    "Server header reveals software version — consider removing or hardening",
    "x-aspnet-version":          "ASP.NET version exposed — high-value info for attackers",
    "x-frame-options":           None,  # Presence is GOOD, absence is bad
    "strict-transport-security": None,  # Presence is GOOD
    "content-security-policy":   None,  # Presence is GOOD
    "x-content-type-options":    None,  # Presence is GOOD
}

MISSING_HEADER_WARNINGS = {
    "x-frame-options":           "Missing X-Frame-Options — vulnerable to clickjacking",
    "strict-transport-security": "Missing HSTS — vulnerable to SSL stripping",
    "content-security-policy":   "Missing CSP — vulnerable to XSS/injection",
    "x-content-type-options":    "Missing X-Content-Type-Options — MIME sniffing risk",
}


def analyze_result(result: ToolResult) -> List[str]:
    """
    Analyze a ToolResult and return a list of actionable suggestions.
    This is the main entry point for the rule engine.
    """
    suggestions = []

    data = result.data if result.data else {}
    tool_name = result.tool_name.lower()

    # --- Port scan analysis ---
    open_ports = data.get("open_ports", [])
    if open_ports:
        suggestions.append(f"Found {len(open_ports)} open port(s)")
        for port_info in open_ports:
            port = port_info if isinstance(port_info, int) else port_info.get("port", 0)
            if port in PORT_SERVICE_MAP:
                service, tips = PORT_SERVICE_MAP[port][0], PORT_SERVICE_MAP[port][1]
                suggestions.append(f"  Port {port} ({service}):")
                for tip in tips:
                    suggestions.append(f"    → {tip}")

    # --- HTTP fingerprint analysis ---
    headers = data.get("headers", {})
    if headers:
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Flag exposed headers
        for header, warning in HEADER_RULES.items():
            if header in headers_lower and warning:
                suggestions.append(f"⚠ {warning}: {headers_lower[header]}")

        # Flag missing security headers
        for header, warning in MISSING_HEADER_WARNINGS.items():
            if header not in headers_lower:
                suggestions.append(f"⚠ {warning}")

    # --- DNS analysis ---
    if "dns_records" in data or "subdomains" in data:
        records = data.get("dns_records", {})
        subdomains = data.get("subdomains", [])
        if subdomains:
            suggestions.append(f"Found {len(subdomains)} subdomain(s) — scan each for open ports")
        if records.get("mx"):
            suggestions.append("MX records found — check for email security (SPF/DKIM/DMARC)")
        if records.get("txt"):
            suggestions.append("TXT records found — review for sensitive information")

    # --- Web exploitation suggestions ---
    if "sqli" in tool_name or "sql" in tool_name:
        vulns = data.get("vulnerabilities", [])
        if vulns:
            suggestions.append(f"🔴 Found {len(vulns)} potential SQL injection point(s)!")
            suggestions.append("  → Verify manually and check for data exfiltration risk")

    if "xss" in tool_name:
        vulns = data.get("vulnerabilities", [])
        if vulns:
            suggestions.append(f"🟡 Found {len(vulns)} potential XSS point(s)")
            suggestions.append("  → Test with DOM-based and stored XSS payloads")

    if "dir" in tool_name and "brute" in tool_name:
        found = data.get("found_paths", [])
        if found:
            suggestions.append(f"Found {len(found)} accessible path(s)")
            interesting = [p for p in found if any(
                kw in str(p).lower() for kw in ["admin", "config", "backup", "api", ".env", "debug"]
            )]
            if interesting:
                suggestions.append(f"  🔴 High-interest paths: {', '.join(str(p) for p in interesting)}")

    # --- Detection / blue team suggestions ---
    alerts = data.get("alerts", [])
    if alerts:
        suggestions.append(f"⚠ {len(alerts)} alert(s) generated — review immediately")

    suspicious_ips = data.get("suspicious_ips", [])
    if suspicious_ips:
        suggestions.append(f"⚠ {len(suspicious_ips)} suspicious IP(s) detected")
        suggestions.append("  → Cross-reference with threat intelligence feeds")
        suggestions.append("  → Check firewall logs for these IPs")

    # --- Forensics ---
    if "hashes" in data:
        suggestions.append("File hash computed — check against VirusTotal or malware hash databases")

    if "strings" in data:
        strings = data.get("strings", [])
        suspicious_strings = [s for s in strings if any(
            kw in s.lower() for kw in ["password", "secret", "api_key", "token", "admin", "root"]
        )]
        if suspicious_strings:
            suggestions.append(f"⚠ Found {len(suspicious_strings)} suspicious string(s) in binary")

    # --- General severity-based suggestions ---
    if result.findings:
        crit_count = sum(1 for f in result.findings if hasattr(f, 'severity') and f.severity.value in ("critical", "high"))
        if crit_count:
            suggestions.append(f"🔴 {crit_count} HIGH/CRITICAL finding(s) — prioritize remediation")

    return suggestions


def suggest(category: str = "", result: ToolResult = None, results: List[ToolResult] = None):
    """
    Print AI suggestions for one or more tool results.
    Backward-compatible: supports old-style (category, result) calls.
    """
    all_suggestions = []

    if result:
        all_suggestions.extend(analyze_result(result))
    if results:
        for r in results:
            all_suggestions.extend(analyze_result(r))

    # Fallback for old-style category-only calls
    if not all_suggestions and category:
        if category == "scanning":
            all_suggestions.append("Run vulnerability assessment on discovered services")
        elif category in ("web", "exploitation"):
            all_suggestions.append("Try SQLi tester or directory brute force")
        elif category == "reconnaissance":
            all_suggestions.append("Proceed with port scanning on discovered targets")

    if all_suggestions:
        output.section("AI Analysis & Suggestions")
        for s in all_suggestions:
            if s.startswith("🔴") or s.startswith("⚠"):
                output.warning(s)
            elif s.startswith("  "):
                print(f"       {s}")
            else:
                output.info(s)


# =============================================================================
# Optional LLM integration
# =============================================================================

def llm_analyze(result: ToolResult) -> Optional[str]:
    """
    Send result data to an LLM API for natural language analysis.
    Returns None if LLM is not configured or unavailable.
    """
    cfg = Config()
    if not cfg.get("ai.llm_enabled", False):
        return None

    api_key = cfg.get("ai.llm_api_key", "")
    if not api_key:
        logger.warning("LLM enabled but no API key configured")
        return None

    try:
        import urllib.request
        import urllib.error

        endpoint = cfg.get("ai.llm_endpoint", "https://api.openai.com/v1/chat/completions")
        model = cfg.get("ai.llm_model", "gpt-4")

        prompt = (
            "You are a cybersecurity analyst. Analyze the following tool output "
            "and provide actionable next steps. Be concise and specific.\n\n"
            f"Tool: {result.tool_name}\n"
            f"Target: {result.target}\n"
            f"Data: {json.dumps(result.data, indent=2, default=str)}\n"
        )

        payload = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 500,
        }).encode("utf-8")

        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            return resp_data["choices"][0]["message"]["content"]

    except Exception as e:
        logger.error(f"LLM analysis failed: {e}")
        return None
