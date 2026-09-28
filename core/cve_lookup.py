# =============================================================================
# CyberToolkit Pro — Offline CVE Database & CVSS v3.1 Calculator
# =============================================================================
# Provides offline CVE search, banner matching, and standard CVSS v3.1
# base score computation from vector strings.
# =============================================================================

import math
import re
from typing import Dict, Any, List, Optional
from core.models import Severity


# -----------------------------------------------------------------------------
# CVSS v3.1 Calculator
# -----------------------------------------------------------------------------
def round_up(val: float) -> float:
    """Standard CVSS v3.1 Roundup function (round up to nearest 0.1)."""
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    else:
        return (math.floor(int_val / 10000) + 1) / 10.0


def calculate_cvss31(vector_string: str) -> Dict[str, Any]:
    """
    Calculate CVSS v3.1 base score from a vector string.
    Example vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    Returns score (float), severity (str), and breakdown dict.
    """
    # Weights and metric mapping
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_weights = {"L": 0.77, "H": 0.44}
    pr_weights_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_weights_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_weights = {"N": 0.85, "R": 0.62}
    cia_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

    metrics = {}
    parts = vector_string.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/")
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            metrics[k.upper()] = v.upper()

    # Extract required base metrics with defaults
    av = metrics.get("AV", "N")
    ac = metrics.get("AC", "L")
    pr = metrics.get("PR", "N")
    ui = metrics.get("UI", "N")
    scope = metrics.get("S", "U")
    c = metrics.get("C", "H")
    i = metrics.get("I", "H")
    a = metrics.get("A", "H")

    # Exploitability sub-score
    av_val = av_weights.get(av, 0.85)
    ac_val = ac_weights.get(ac, 0.77)
    if scope == "C":
        pr_val = pr_weights_changed.get(pr, 0.85)
    else:
        pr_val = pr_weights_unchanged.get(pr, 0.85)
    ui_val = ui_weights.get(ui, 0.85)

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    # Impact sub-score (ISS)
    c_val = cia_weights.get(c, 0.56)
    i_val = cia_weights.get(i, 0.56)
    a_val = cia_weights.get(a, 0.56)

    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        base_score = 0.0
    else:
        if scope == "U":
            base_score = round_up(min(impact + exploitability, 10.0))
        else:
            base_score = round_up(min(1.08 * (impact + exploitability), 10.0))

    base_score = max(0.0, min(10.0, base_score))

    # Determine qualitative rating
    if base_score == 0.0:
        sev = "NONE"
    elif base_score < 4.0:
        sev = "LOW"
    elif base_score < 7.0:
        sev = "MEDIUM"
    elif base_score < 9.0:
        sev = "HIGH"
    else:
        sev = "CRITICAL"

    return {
        "vector": vector_string,
        "base_score": base_score,
        "severity": sev,
        "impact": round(impact, 2),
        "exploitability": round(exploitability, 2),
        "metrics": metrics
    }


# -----------------------------------------------------------------------------
# Curated Offline Vulnerability Knowledgebase
# -----------------------------------------------------------------------------
OFFLINE_CVE_DATABASE: List[Dict[str, Any]] = [
    {
        "cve": "CVE-2021-44228",
        "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "product": "Log4j",
        "affected_versions": ["2.0-beta9", "2.14.1"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "remediation": "Upgrade to Log4j 2.17.1 or newer. Set log4j2.formatMsgNoLookups=true as temporary mitigation.",
        "cwe": "CWE-502",
    },
    {
        "cve": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal and File Disclosure",
        "product": "Apache",
        "affected_versions": ["2.4.49"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49, allowing mapped document root directory traversal.",
        "remediation": "Update Apache HTTP Server to version 2.4.51 or later.",
        "cwe": "CWE-22",
    },
    {
        "cve": "CVE-2021-42013",
        "title": "Apache HTTP Server Path Traversal and RCE (Incomplete fix for CVE-2021-41773)",
        "product": "Apache",
        "affected_versions": ["2.4.49", "2.4.50"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives and execute CGI scripts.",
        "remediation": "Update Apache HTTP Server to version 2.4.51 or later.",
        "cwe": "CWE-22",
    },
    {
        "cve": "CVE-2023-38606",
        "title": "OpenSSH Pre-Authentication Privilege Escalation (PKCS#11)",
        "product": "OpenSSH",
        "affected_versions": ["8.5p1", "9.3p1"],
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "OpenSSH PKCS#11 provider loading flaw allowing execution of arbitrary shared libraries via ssh-agent.",
        "remediation": "Upgrade OpenSSH to version 9.3p2 or newer.",
        "cwe": "CWE-426",
    },
    {
        "cve": "CVE-2024-6387",
        "title": "OpenSSH Server Signal Handler Race Condition (regreSSHion)",
        "product": "OpenSSH",
        "affected_versions": ["8.5p1", "9.7p1"],
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "A signal handler race condition in OpenSSH server (sshd) in glibc-based Linux systems allows remote code execution as root.",
        "remediation": "Update OpenSSH to 9.8p1 or newer. Set LoginGraceTime 0 in sshd_config as immediate workaround.",
        "cwe": "CWE-362",
    },
    {
        "cve": "CVE-2022-22965",
        "title": "Spring Framework RCE via Data Binding (Spring4Shell)",
        "product": "Spring",
        "affected_versions": ["5.3.0", "5.3.17", "5.2.0", "5.2.19"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Spring Framework vulnerable to remote code execution via DataBinder access to ClassLoader on Tomcat.",
        "remediation": "Upgrade to Spring Framework 5.3.18+, 5.2.20+ or upgrade to Tomcat 10.0.20+.",
        "cwe": "CWE-94",
    },
    {
        "cve": "CVE-2021-26855",
        "title": "Microsoft Exchange Server SSRF (ProxyLogon)",
        "product": "Exchange",
        "affected_versions": ["2013", "2016", "2019"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Pre-authentication server-side request forgery (SSRF) allowing authentication bypass and arbitrary mailbox access.",
        "remediation": "Apply Microsoft Security Update KB5000871 or latest Cumulative Update.",
        "cwe": "CWE-918",
    },
    {
        "cve": "CVE-2022-40684",
        "title": "Fortinet FortiOS Authentication Bypass on Administrative Interface",
        "product": "FortiOS",
        "affected_versions": ["7.0.0", "7.0.6", "7.2.0", "7.2.1"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "An authentication bypass using an alternate path or channel in FortiOS and FortiProxy allows an unauthenticated attacker to perform operations on the administrative interface.",
        "remediation": "Upgrade to FortiOS 7.0.7+, 7.2.2+ or disable HTTP/HTTPS administrative interface on public-facing ports.",
        "cwe": "CWE-287",
    },
    {
        "cve": "CVE-2023-22515",
        "title": "Atlassian Confluence Server Broken Access Control",
        "product": "Confluence",
        "affected_versions": ["8.0.0", "8.5.1"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Broken Access Control vulnerability in Atlassian Confluence Data Center and Server allowing unauthenticated attackers to create administrator accounts.",
        "remediation": "Upgrade Confluence to versions 8.3.3+, 8.4.3+, or 8.5.2+.",
        "cwe": "CWE-284",
    },
    {
        "cve": "CVE-2022-26134",
        "title": "Atlassian Confluence OGNL Injection Remote Code Execution",
        "product": "Confluence",
        "affected_versions": ["7.4.0", "7.18.0"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "OGNL injection vulnerability in Confluence Server and Data Center leading to arbitrary code execution in the context of the Confluence user.",
        "remediation": "Upgrade Confluence to 7.18.1+, 7.17.4+, 7.16.5+, or 7.15.3+.",
        "cwe": "CWE-917",
    },
    {
        "cve": "CVE-2024-21626",
        "title": "runc Leaky File Descriptor Container Escape",
        "product": "Docker/runc",
        "affected_versions": ["1.0.0", "1.1.11"],
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "In runc through 1.1.11, as used in Docker and Kubernetes, internal file descriptors to the host filesystem can be leaked to newly started container processes.",
        "remediation": "Upgrade runc to version 1.1.12 or newer. Update Docker Engine to 25.0.2+.",
        "cwe": "CWE-403",
    },
    {
        "cve": "CVE-2023-44487",
        "title": "HTTP/2 Rapid Reset Denial of Service",
        "product": "HTTP/2",
        "affected_versions": ["all HTTP/2 implementations"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "description": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly.",
        "remediation": "Apply web server / load balancer patches limiting RST_STREAM frame rates (Nginx, Envoy, Apache).",
        "cwe": "CWE-400",
    }
]


class CveLookupEngine:
    """Search and correlate software banners with known CVEs."""

    def __init__(self, database: Optional[List[Dict[str, Any]]] = None):
        self.db = database or OFFLINE_CVE_DATABASE
        # Precompute calculated CVSS scores
        for entry in self.db:
            if "vector" in entry:
                calc = calculate_cvss31(entry["vector"])
                entry["base_score"] = calc["base_score"]
                entry["severity"] = calc["severity"]

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search CVEs by query string across CVE ID, product, title, description, and affected versions."""
        query_lower = query.lower().strip()
        if not query_lower:
            return self.db

        words = query_lower.split()
        results = []
        for entry in self.db:
            cve_id = entry.get("cve", "").lower()
            product = entry.get("product", "").lower()
            title = entry.get("title", "").lower()
            desc = entry.get("description", "").lower()
            versions = " ".join(v.lower() for v in entry.get("affected_versions", []))

            combined = f"{cve_id} {product} {title} {desc} {versions}"
            if all(w in combined for w in words):
                results.append(entry)

        return results

    def match_banner(self, banner: str) -> List[Dict[str, Any]]:
        """
        Analyze a service banner or version string and return matching known vulnerabilities.
        Example: 'Apache/2.4.49 (Unix)' -> returns CVE-2021-41773 & CVE-2021-42013.
        """
        matches = []
        banner_clean = banner.lower()

        for entry in self.db:
            product = entry.get("product", "").lower()
            if product and product in banner_clean:
                # Check version matches
                for ver in entry.get("affected_versions", []):
                    if ver.lower() in banner_clean:
                        matches.append(entry)
                        break

        return matches


# Global instance
_cve_engine = None

def get_cve_engine() -> CveLookupEngine:
    global _cve_engine
    if _cve_engine is None:
        _cve_engine = CveLookupEngine()
    return _cve_engine
