# =============================================================================
# CyberToolkit Pro — CVE & Vulnerability Lookup Module
# =============================================================================

from typing import Dict, Any
from core.models import ToolResult, Finding, Severity
from core.cve_lookup import get_cve_engine

TOOL_INFO = {
    "name": "cve_search",
    "category": "scanning",
    "description": "Offline CVE database search and software banner vulnerability matching",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "query", "description": "Search keyword or CVE ID (e.g. Apache, Log4j, CVE-2021-44228)", "arg_type": "str", "default": ""},
        {"name": "banner", "description": "Service banner to match (e.g. Apache/2.4.49, OpenSSH_8.5p1)", "arg_type": "str", "default": ""},
        {"name": "target", "description": "Target hostname or service identifier", "arg_type": "str", "default": "local"},
    ],
    "tags": ["cve", "vulnerability", "cvss", "nvd", "offline", "banner"],
}


def run(args: Dict[str, Any]) -> ToolResult:
    query = args.get("query", "")
    banner = args.get("banner", "")
    target = args.get("target", "service")

    # If banner is provided via target
    if not query and not banner and target and target != "local":
        banner = target

    engine = get_cve_engine()
    findings = []
    results = []

    if banner:
        results = engine.match_banner(banner)
    elif query:
        results = engine.search(query)
    else:
        results = engine.search("")

    for item in results:
        sev_str = item.get("severity", "MEDIUM").upper()
        if sev_str == "CRITICAL":
            severity = Severity.CRITICAL
        elif sev_str == "HIGH":
            severity = Severity.HIGH
        elif sev_str == "LOW":
            severity = Severity.LOW
        else:
            severity = Severity.MEDIUM

        findings.append(Finding(
            title=f"Known CVE Match: {item.get('cve')} - {item.get('title')}",
            severity=severity,
            description=f"CVSS: {item.get('base_score')} ({sev_str})\n\n{item.get('description')}\nVector: {item.get('vector')}",
            remediation=item.get("remediation", "Update software to the latest secure version."),
            target=banner or query or target,
            evidence={
                "cve": item.get("cve"),
                "product": item.get("product"),
                "cwe": item.get("cwe"),
                "vector": item.get("vector"),
                "base_score": item.get("base_score"),
            }
        ))

    return ToolResult(
        tool_name="cve_search",
        status="success",
        data={
            "query": query,
            "banner": banner,
            "total_matches": len(results),
            "matches": results,
        },
        findings=findings
    )
