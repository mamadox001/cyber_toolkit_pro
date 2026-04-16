# =============================================================================
# CyberToolkit Pro — Compliance Report Generator
# =============================================================================
# Generates compliance-specific security assessment reports for
# PCI-DSS, HIPAA, SOC2, and OWASP frameworks.
# =============================================================================

import json
import os
from datetime import datetime
from core.models import ToolResult, Finding, Severity
from core.database import get_db

TOOL_INFO = {
    "name": "compliance_report",
    "category": "reporting",
    "description": "Generate compliance-mapped reports (PCI-DSS, HIPAA, SOC2, OWASP)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": False, "default": "",
         "description": "Target to filter report (empty = all)"},
        {"name": "framework", "required": False, "default": "owasp",
         "description": "Compliance framework: pci-dss, hipaa, soc2, owasp"},
        {"name": "output", "required": False, "default": "",
         "description": "Output file path"},
    ],
    "tags": ["reporting", "compliance", "pci-dss", "hipaa", "soc2", "owasp"],
}

COMPLIANCE_MAPPINGS = {
    "pci-dss": {
        "name": "PCI-DSS v4.0",
        "controls": {
            "1": {"name": "Install and maintain network security controls", "keywords": ["firewall", "network", "port", "arp"]},
            "2": {"name": "Apply secure configurations", "keywords": ["config", "default", "header", "server"]},
            "3": {"name": "Protect stored account data", "keywords": ["encryption", "hash", "credential", "password"]},
            "4": {"name": "Protect with strong cryptography", "keywords": ["ssl", "tls", "certificate", "cipher", "crypto"]},
            "5": {"name": "Protect against malicious software", "keywords": ["malware", "virus", "backdoor", "trojan"]},
            "6": {"name": "Develop and maintain secure systems", "keywords": ["vuln", "sql", "xss", "injection", "cve"]},
            "7": {"name": "Restrict access", "keywords": ["auth", "login", "access", "admin", "privilege"]},
            "8": {"name": "Identify users and authenticate access", "keywords": ["auth", "mfa", "password", "brute"]},
            "9": {"name": "Restrict physical access", "keywords": ["physical", "badge"]},
            "10": {"name": "Log and monitor activity", "keywords": ["log", "monitor", "audit", "siem"]},
            "11": {"name": "Test security regularly", "keywords": ["scan", "pentest", "vulnerability"]},
            "12": {"name": "Support with organizational policies", "keywords": ["policy", "procedure"]},
        }
    },
    "owasp": {
        "name": "OWASP Top 10 (2021)",
        "controls": {
            "A01": {"name": "Broken Access Control", "keywords": ["access", "auth", "admin", "privilege", "idor"]},
            "A02": {"name": "Cryptographic Failures", "keywords": ["ssl", "tls", "encrypt", "hash", "crypto", "clear-text"]},
            "A03": {"name": "Injection", "keywords": ["sql", "xss", "inject", "command", "ldap"]},
            "A04": {"name": "Insecure Design", "keywords": ["design", "architecture", "logic"]},
            "A05": {"name": "Security Misconfiguration", "keywords": ["config", "default", "header", "permission", "directory"]},
            "A06": {"name": "Vulnerable Components", "keywords": ["cve", "version", "outdated", "component"]},
            "A07": {"name": "Authentication Failures", "keywords": ["login", "password", "brute", "session", "credential"]},
            "A08": {"name": "Software and Data Integrity", "keywords": ["integrity", "update", "pipeline"]},
            "A09": {"name": "Security Logging Failures", "keywords": ["log", "monitor", "alert", "audit"]},
            "A10": {"name": "Server-Side Request Forgery", "keywords": ["ssrf", "request", "internal"]},
        }
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "controls": {
            "164.308(a)(1)": {"name": "Security Management Process", "keywords": ["risk", "vulnerability", "policy"]},
            "164.308(a)(3)": {"name": "Workforce Security", "keywords": ["access", "auth", "privilege"]},
            "164.308(a)(4)": {"name": "Information Access Management", "keywords": ["access", "permission", "admin"]},
            "164.308(a)(5)": {"name": "Security Awareness Training", "keywords": ["phishing", "social", "training"]},
            "164.312(a)(1)": {"name": "Access Control", "keywords": ["auth", "login", "session", "brute"]},
            "164.312(a)(2)": {"name": "Audit Controls", "keywords": ["log", "audit", "monitor"]},
            "164.312(c)(1)": {"name": "Integrity Controls", "keywords": ["integrity", "hash", "checksum"]},
            "164.312(e)(1)": {"name": "Transmission Security", "keywords": ["ssl", "tls", "encrypt", "transport"]},
        }
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "controls": {
            "CC6.1": {"name": "Logical and Physical Access Controls", "keywords": ["access", "auth", "firewall", "port"]},
            "CC6.6": {"name": "Security Against Threats", "keywords": ["vuln", "malware", "scan", "ids"]},
            "CC6.7": {"name": "Data Transmission Protection", "keywords": ["ssl", "tls", "encrypt"]},
            "CC7.1": {"name": "Monitoring Activities", "keywords": ["monitor", "log", "alert", "siem"]},
            "CC7.2": {"name": "Anomaly Detection", "keywords": ["anomaly", "detection", "intrusion"]},
            "CC7.3": {"name": "Security Incident Response", "keywords": ["incident", "alert", "breach"]},
            "CC8.1": {"name": "Change Management", "keywords": ["change", "update", "patch", "version"]},
        }
    },
}


def run(args):
    target = args.get("target", "")
    framework = args.get("framework", "owasp").lower()
    output_path = args.get("output", "")

    if framework not in COMPLIANCE_MAPPINGS:
        return ToolResult(
            tool_name="compliance_report", target=target, status="error",
            error=f"Unknown framework: {framework}. Use: {', '.join(COMPLIANCE_MAPPINGS.keys())}"
        )

    # Get findings from database
    db = get_db()
    if target:
        scans = db.get_scans(target=target, limit=1000)
    else:
        scans = db.get_scans(limit=1000)

    all_findings = []
    for scan in scans:
        all_findings.extend(db.get_findings(scan_id=scan.get("scan_id", "")))

    # Map findings to compliance controls
    mapping = COMPLIANCE_MAPPINGS[framework]
    control_results = {}

    for ctrl_id, ctrl_info in mapping["controls"].items():
        matched = []
        for finding in all_findings:
            title = finding.get("title", "").lower()
            desc = finding.get("description", "").lower()
            combined = title + " " + desc
            if any(kw in combined for kw in ctrl_info["keywords"]):
                matched.append(finding)

        status = "pass" if not matched else "fail"
        sev_counts = {}
        for f in matched:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        control_results[ctrl_id] = {
            "name": ctrl_info["name"],
            "status": status,
            "findings_count": len(matched),
            "severity_breakdown": sev_counts,
            "findings": matched[:10],
        }

    # Calculate compliance score
    total = len(control_results)
    passing = sum(1 for c in control_results.values() if c["status"] == "pass")
    score = (passing / total * 100) if total > 0 else 0

    report = {
        "framework": mapping["name"],
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": target or "all",
        "compliance_score": round(score, 1),
        "controls_total": total,
        "controls_passing": passing,
        "controls_failing": total - passing,
        "control_results": control_results,
        "total_findings_analyzed": len(all_findings),
    }

    # Save if output specified
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

    findings = [
        Finding(
            title=f"{mapping['name']} Compliance: {score:.0f}% ({passing}/{total} controls passing)",
            severity=Severity.CRITICAL if score < 50 else Severity.HIGH if score < 75 else Severity.MEDIUM if score < 90 else Severity.INFO,
            description=f"Failing controls: {total - passing}",
        )
    ]

    return ToolResult(
        tool_name="compliance_report",
        target=target,
        status="success",
        data=report,
        findings=findings,
    )
