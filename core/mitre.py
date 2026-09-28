# =============================================================================
# CyberToolkit Pro — MITRE ATT&CK Matrix & Coverage Engine
# =============================================================================
# Maps framework tools, findings, and assessment workflows directly to
# MITRE Enterprise ATT&CK tactics and techniques.
# =============================================================================

from typing import Dict, List, Any, Optional

# Standard MITRE ATT&CK Enterprise Tactics
TACTICS: Dict[str, Dict[str, str]] = {
    "TA0043": {"name": "Reconnaissance", "description": "Gathering information to plan future adversary operations"},
    "TA0042": {"name": "Resource Development", "description": "Establishing resources to support operations"},
    "TA0001": {"name": "Initial Access", "description": "Techniques that use various entry vectors to gain a foothold"},
    "TA0002": {"name": "Execution", "description": "Techniques that result in adversary-controlled code running"},
    "TA0003": {"name": "Persistence", "description": "Maintaining foothold across restarts and credential changes"},
    "TA0004": {"name": "Privilege Escalation", "description": "Techniques used to gain higher-level permissions"},
    "TA0005": {"name": "Defense Evasion", "description": "Techniques used to avoid detection throughout their compromise"},
    "TA0006": {"name": "Credential Access", "description": "Techniques for stealing credentials like passwords and hashes"},
    "TA0007": {"name": "Discovery", "description": "Techniques used to gain knowledge of system and internal network"},
    "TA0008": {"name": "Lateral Movement", "description": "Techniques used to extend access across remote systems"},
    "TA0009": {"name": "Collection", "description": "Techniques used to gather data of interest prior to exfiltration"},
    "TA0011": {"name": "Command & Control", "description": "Communicating with systems under their control"},
    "TA0010": {"name": "Exfiltration", "description": "Techniques used to steal data from the target network"},
    "TA0040": {"name": "Impact", "description": "Techniques to disrupt availability or compromise integrity"},
}

# Mapping of CyberToolkit Pro tools to MITRE ATT&CK Techniques
TOOL_TECHNIQUE_MAP: Dict[str, List[Dict[str, str]]] = {
    # Reconnaissance & OSINT
    "reconnaissance.whois_lookup": [{"id": "T1596.002", "name": "Search Open Technical Databases: WHOIS", "tactic": "TA0043"}],
    "reconnaissance.dns_lookup": [{"id": "T1590.002", "name": "Gather Victim Network Information: DNS", "tactic": "TA0043"}],
    "reconnaissance.subdomain_discovery": [{"id": "T1596.001", "name": "Search Open Technical Databases: DNS/Certificates", "tactic": "TA0043"}],
    "reconnaissance.ct_search": [{"id": "T1596.003", "name": "Search Open Technical Databases: Certificate Transparency", "tactic": "TA0043"}],
    "reconnaissance.asn_lookup": [{"id": "T1590.005", "name": "Gather Victim Network Information: IP Addresses/BGP", "tactic": "TA0043"}],
    "reconnaissance.http_fingerprint": [{"id": "T1592.002", "name": "Gather Victim Host Information: Software", "tactic": "TA0043"}],
    "reconnaissance.tech_stack_detector": [{"id": "T1592.002", "name": "Gather Victim Host Information: Software Stack", "tactic": "TA0043"}],
    "osint.email_harvester": [{"id": "T1589.002", "name": "Gather Victim Identity Information: Email Addresses", "tactic": "TA0043"}],
    "osint.social_recon": [{"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials/Profiles", "tactic": "TA0043"}],
    "osint.breach_checker": [{"id": "T1589.001", "name": "Credentials in Compromised Accounts", "tactic": "TA0043"}],
    "osint.github_dorker": [{"id": "T1593.003", "name": "Search Open Websites: Code Repositories", "tactic": "TA0043"}],
    "osint.domain_reputation": [{"id": "T1596", "name": "Search Open Technical Databases", "tactic": "TA0043"}],
    "osint.wayback_machine": [{"id": "T1593.002", "name": "Search Open Websites: Search Engines & Archives", "tactic": "TA0043"}],
    "osint.metadata_extractor": [{"id": "T1592.004", "name": "Gather Victim Host Information: Client Configurations", "tactic": "TA0043"}],

    # Scanning & Network Discovery
    "scanning.port_scanner": [{"id": "T1046", "name": "Network Service Discovery", "tactic": "TA0007"}],
    "scanning.service_detector": [{"id": "T1046", "name": "Network Service Discovery: Port/Service", "tactic": "TA0007"}],
    "scanning.nmap_advanced": [{"id": "T1046", "name": "Network Service Discovery", "tactic": "TA0007"}],
    "scanning.nse_runner": [{"id": "T1046", "name": "Network Service Discovery: Vulnerability Scripting", "tactic": "TA0007"}],
    "network.traceroute_mapper": [{"id": "T1018", "name": "Remote System Discovery", "tactic": "TA0007"}],
    "network.packet_sniffer": [{"id": "T1040", "name": "Network Sniffing", "tactic": "TA0006"}],
    "network.arp_detector": [{"id": "T1049", "name": "System Network Connections Discovery", "tactic": "TA0007"}],
    "network.dns_monitor": [{"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "TA0011"}],

    # Web & API Security
    "web.dir_bruteforce": [{"id": "T1083", "name": "File and Directory Discovery", "tactic": "TA0007"}],
    "web.http_fuzzer": [{"id": "T1190", "name": "Exploit Public-Facing Application: Parameter Fuzzing", "tactic": "TA0001"}],
    "web.sqli_tester": [{"id": "T1190", "name": "Exploit Public-Facing Application: SQL Injection", "tactic": "TA0001"}],
    "web.xss_tester": [{"id": "T1189", "name": "Drive-by Compromise: Cross-Site Scripting", "tactic": "TA0001"}],
    "web.ssrf_tester": [{"id": "T1190", "name": "Exploit Public-Facing Application: SSRF", "tactic": "TA0001"}],
    "web.cors_tester": [{"id": "T1189", "name": "Drive-by Compromise: Cross-Origin Misconfiguration", "tactic": "TA0001"}],
    "web.csrf_analyzer": [{"id": "T1189", "name": "Drive-by Compromise: Cross-Site Request Forgery", "tactic": "TA0001"}],
    "web.command_injection_tester": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "TA0002"}],
    "web.lfi_rfi_tester": [{"id": "T1005", "name": "Data from Local System / Remote Inclusion", "tactic": "TA0009"}],
    "web.open_redirect_tester": [{"id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "TA0001"}],
    "api_security.api_fuzzer": [{"id": "T1190", "name": "Exploit Public-Facing Application: API Fuzzing", "tactic": "TA0001"}],
    "api_security.auth_bypass_tester": [{"id": "T1078", "name": "Valid Accounts: Authentication Bypass", "tactic": "TA0001"}],
    "api_security.graphql_introspector": [{"id": "T1083", "name": "File and Directory Discovery: Schema Introspection", "tactic": "TA0007"}],
    "api_security.rate_limit_tester": [{"id": "T1499", "name": "Endpoint Denial of Service: Resource Exhaustion", "tactic": "TA0040"}],

    # Cloud & Virtualization
    "cloud.s3_bucket_scanner": [{"id": "T1530", "name": "Data from Cloud Storage", "tactic": "TA0009"}],
    "cloud.azure_blob_checker": [{"id": "T1530", "name": "Data from Cloud Storage: Azure Blob", "tactic": "TA0009"}],
    "cloud.cloud_metadata_exploiter": [{"id": "T1552.005", "name": "Unsecured Credentials: Cloud Instance Metadata API", "tactic": "TA0006"}],
    "cloud.container_scanner": [{"id": "T1610", "name": "Deploy Container / Insecure Image Configuration", "tactic": "TA0002"}],
    "cloud.kubernetes_auditor": [{"id": "T1609", "name": "Container Administration Command / K8s Misconfiguration", "tactic": "TA0002"}],

    # Credential & Password Assessment
    "passwords.wordlist_attack": [{"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "TA0006"}],
    "passwords.hash_cracker": [{"id": "T1110.002", "name": "Brute Force: Password Cracking", "tactic": "TA0006"}],
    "passwords.cred_checker": [{"id": "T1078", "name": "Valid Accounts: Default Credentials", "tactic": "TA0001"}],

    # Cryptography & Certificates
    "crypto.ssl_tls_auditor": [{"id": "T1573.002", "name": "Encrypted Channel: Asymmetric Cryptography Weakness", "tactic": "TA0011"}],
    "crypto.certificate_analyzer": [{"id": "T1588.004", "name": "Obtain Capabilities: Digital Certificates", "tactic": "TA0042"}],
    "crypto.jwt_analyzer": [{"id": "T1552.001", "name": "Unsecured Credentials: Insecure Web Tokens", "tactic": "TA0006"}],
    "crypto.encryption_auditor": [{"id": "T1552", "name": "Unsecured Credentials: Weak Cryptographic Algorithms", "tactic": "TA0006"}],

    # Detection & Forensics (Blue Team / Defensive)
    "detection.anomaly_detector": [{"id": "T1070", "name": "Indicator Removal / Detection Evasion Validation", "tactic": "TA0005"}],
    "detection.ip_tracker": [{"id": "T1049", "name": "System Network Connections Discovery: Threat IP", "tactic": "TA0007"}],
    "forensics.yara_scanner": [{"id": "T1027", "name": "Obfuscated Files or Information: Malware Scanning", "tactic": "TA0005"}],
    "forensics.timeline_generator": [{"id": "T1070.006", "name": "Timestomp / Forensic Timeline Generation", "tactic": "TA0005"}],
    "forensics.file_analyzer": [{"id": "T1005", "name": "Data from Local System: Artifact Analysis", "tactic": "TA0009"}],
    "forensics.string_extractor": [{"id": "T1005", "name": "Data from Local System: String Carving", "tactic": "TA0009"}],
    "log_analysis.auth_log_parser": [{"id": "T1078", "name": "Valid Accounts: Logon Session Audit", "tactic": "TA0001"}],
    "log_analysis.web_log_analyzer": [{"id": "T1190", "name": "Exploit Public-Facing Application: Web Attack Logs", "tactic": "TA0001"}],
    "log_analysis.ssh_brute_detector": [{"id": "T1110.001", "name": "Brute Force: SSH Password Spray Detection", "tactic": "TA0006"}],
    "siem.alert_generator": [{"id": "T1070", "name": "Security Monitoring: Rule-Based Alert Trigger", "tactic": "TA0005"}],
    "siem.log_aggregator": [{"id": "T1005", "name": "Log Aggregation & Centralization", "tactic": "TA0009"}],

    # Mobile Security
    "mobile.apk_analyzer": [{"id": "T1407", "name": "Download New Code at Runtime / Android Insecure Permissions", "tactic": "TA0002"}],
    "mobile.ios_plist_parser": [{"id": "T1476", "name": "Insecure App Transport Security / Insecure Storage", "tactic": "TA0005"}],
}


class MitreCoverageEngine:
    """Computes MITRE ATT&CK matrix coverage and posture metrics."""

    def __init__(self):
        self.tactics = TACTICS
        self.tool_map = TOOL_TECHNIQUE_MAP

    def get_techniques_for_tool(self, tool_path: str) -> List[Dict[str, str]]:
        """Retrieve all MITRE ATT&CK techniques associated with a given tool."""
        return self.tool_map.get(tool_path, [])

    def get_matrix_view(self) -> Dict[str, Any]:
        """
        Build an enterprise-grade visual representation of the ATT&CK Matrix,
        showing tactics as columns and mapped techniques with associated toolkit tools.
        """
        columns = []
        for tactic_id, tactic_info in self.tactics.items():
            techniques_in_tactic = {}
            for tool_path, tech_list in self.tool_map.items():
                for tech in tech_list:
                    if tech.get("tactic") == tactic_id:
                        tid = tech["id"]
                        if tid not in techniques_in_tactic:
                            techniques_in_tactic[tid] = {
                                "id": tid,
                                "name": tech["name"],
                                "tools": [tool_path]
                            }
                        else:
                            if tool_path not in techniques_in_tactic[tid]["tools"]:
                                techniques_in_tactic[tid]["tools"].append(tool_path)

            columns.append({
                "tactic_id": tactic_id,
                "tactic_name": tactic_info["name"],
                "description": tactic_info["description"],
                "technique_count": len(techniques_in_tactic),
                "techniques": sorted(list(techniques_in_tactic.values()), key=lambda x: x["id"])
            })

        total_techniques = sum(col["technique_count"] for col in columns)
        total_tools_mapped = len(self.tool_map)

        return {
            "tactics_count": len(columns),
            "total_techniques": total_techniques,
            "total_tools_mapped": total_tools_mapped,
            "columns": columns
        }

    def correlate_findings(self, findings: List[Any]) -> Dict[str, Any]:
        """
        Correlate a list of scan findings with MITRE ATT&CK tactics and generate
        a risk heatmap by tactic.
        """
        tactic_stats = {tid: {"name": info["name"], "findings_count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
                        for tid, info in self.tactics.items()}

        for f in findings:
            tool_name = getattr(f, "tool_name", "") or getattr(f, "source_tool", "")
            # Look up techniques for this tool
            techniques = self.get_techniques_for_tool(tool_name)
            sev = getattr(f, "severity", "INFO")
            sev_str = (sev.value if hasattr(sev, "value") else str(sev)).lower()

            matched_tactics = set()
            for tech in techniques:
                matched_tactics.add(tech.get("tactic"))

            if not matched_tactics:
                # Default heuristic based on finding title/type if tool not directly mapped
                matched_tactics.add("TA0001")  # Initial Access

            for tid in matched_tactics:
                if tid in tactic_stats:
                    tactic_stats[tid]["findings_count"] += 1
                    if sev_str == "critical":
                        tactic_stats[tid]["critical"] += 1
                    elif sev_str == "high":
                        tactic_stats[tid]["high"] += 1
                    elif sev_str == "medium":
                        tactic_stats[tid]["medium"] += 1
                    elif sev_str == "low":
                        tactic_stats[tid]["low"] += 1

        return {
            "heatmap": tactic_stats,
            "top_threat_tactics": sorted(
                [t for t in tactic_stats.values() if t["findings_count"] > 0],
                key=lambda x: (x["critical"] * 4 + x["high"] * 3 + x["medium"] * 2 + x["low"]),
                reverse=True
            )
        }


# Global singleton
_mitre_engine = None

def get_mitre_engine() -> MitreCoverageEngine:
    global _mitre_engine
    if _mitre_engine is None:
        _mitre_engine = MitreCoverageEngine()
    return _mitre_engine
