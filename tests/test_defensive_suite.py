# =============================================================================
# CyberToolkit Pro — Defensive & Posture Architecture Test Suite
# =============================================================================

import os
import sys
import tempfile
import pytest

# Ensure root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import ToolResult, Finding, Severity
from core.mitre import get_mitre_engine
from core.cve_lookup import get_cve_engine, calculate_cvss31
from core.canary import CanaryManager


# -----------------------------------------------------------------------------
# Test MITRE ATT&CK Matrix & Coverage
# -----------------------------------------------------------------------------
class TestMitreEngine:
    def test_mitre_matrix_structure(self):
        engine = get_mitre_engine()
        view = engine.get_matrix_view()
        assert view["tactics_count"] == 14
        assert view["total_techniques"] > 20
        assert len(view["columns"]) == 14
        assert any(col["tactic_name"] == "Reconnaissance" for col in view["columns"])

    def test_tool_technique_mapping(self):
        engine = get_mitre_engine()
        techs = engine.get_techniques_for_tool("scanning.port_scanner")
        assert len(techs) > 0
        assert techs[0]["id"] == "T1046"

    def test_correlate_findings(self):
        engine = get_mitre_engine()
        findings = [
            Finding(
                title="Open Port 22",
                severity=Severity.INFO,
                description="SSH port open",
                remediation="N/A",
                target="10.0.0.1"
            )
        ]
        # Attach tool_name dynamically
        findings[0].tool_name = "scanning.port_scanner"
        corr = engine.correlate_findings(findings)
        assert "heatmap" in corr
        assert "TA0007" in corr["heatmap"]  # Discovery tactic
        assert corr["heatmap"]["TA0007"]["findings_count"] >= 1


# -----------------------------------------------------------------------------
# Test CVSS v3.1 & Offline CVE Lookup
# -----------------------------------------------------------------------------
class TestCveAndCvss:
    def test_cvss_log4shell_vector(self):
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H is 10.0 Critical
        res = calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert res["base_score"] == 10.0
        assert res["severity"] == "CRITICAL"

    def test_cvss_standard_vector(self):
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H is 9.8 Critical
        res = calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert res["base_score"] == 9.8
        assert res["severity"] == "CRITICAL"

    def test_cve_search_query(self):
        engine = get_cve_engine()
        results = engine.search("Log4j")
        assert len(results) >= 1
        assert any(r["cve"] == "CVE-2021-44228" for r in results)

    def test_cve_banner_matching(self):
        engine = get_cve_engine()
        matches = engine.match_banner("Apache/2.4.49 (Unix)")
        assert len(matches) >= 1
        cve_ids = [m["cve"] for m in matches]
        assert "CVE-2021-41773" in cve_ids

    def test_cve_tool_execution(self):
        from modules.scanning.cve_search import run
        res = run({"query": "Fortinet"})
        assert res.status == "success"
        assert len(res.findings) >= 1
        assert "CVE-2022-40684" in res.findings[0].title


# -----------------------------------------------------------------------------
# Test Active Defense & Canary Tokens
# -----------------------------------------------------------------------------
class TestActiveDefenseCanaries:
    def test_canary_token_lifecycle(self, tmp_path):
        db_file = str(tmp_path / "test_canaries.db")
        manager = CanaryManager(db_path=db_file)

        # 1. Generate AWS token
        tok = manager.generate_token(token_type="aws_keys", memo="Test Honeypot")
        assert tok["token_type"] == "aws_keys"
        assert tok["payload"]["aws_access_key_id"].startswith("AKIA")
        tid = tok["token_id"]

        # 2. List canaries
        all_tokens = manager.list_canaries()
        assert len(all_tokens) == 1
        assert all_tokens[0]["token_id"] == tid

        # 3. Simulate tripwire trigger
        hit = manager.trigger(token_id=tid, client_ip="192.168.1.100", user_agent="curl/7.68.0")
        assert hit is not None
        assert hit["triggered_count"] == 1

        # 4. Check hit logs
        hits = manager.get_hits(token_id=tid)
        assert len(hits) == 1
        assert hits[0]["client_ip"] == "192.168.1.100"

    def test_canary_generator_tool(self):
        from modules.detection.canary_generator import run
        res = run({"token_type": "git_token", "memo": "Repo Secret"})
        assert res.status == "success"
        assert "payload" in res.data
        assert res.data["payload"]["github_pat"].startswith("ghp_")


# -----------------------------------------------------------------------------
# Test Smart Contract Solidity Static Auditor
# -----------------------------------------------------------------------------
class TestSolidityAuditor:
    def test_reentrancy_and_tx_origin_detection(self):
        from modules.crypto.solidity_auditor import run
        vulnerable_code = """
        pragma solidity ^0.7.0;
        contract VulnerableBank {
            mapping(address => uint) public balances;
            address public owner;

            function withdraw() public {
                (bool s, ) = msg.sender.call{value: balances[msg.sender]}("");
                balances[msg.sender] = 0;
            }

            function transferOwnership(address newOwner) public {
                require(tx.origin == owner);
                owner = newOwner;
            }
        }
        """
        res = run({"code": vulnerable_code})
        assert res.status == "success"
        titles = [f.title for f in res.findings]
        assert any("tx.origin" in t for t in titles)
        assert any("Reentrancy" in t for t in titles)
        assert any("Integer Overflow" in t for t in titles)

    def test_clean_contract(self):
        from modules.crypto.solidity_auditor import run
        secure_code = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        contract CleanContract {
            address public owner;
            constructor() { owner = msg.sender; }
            function getOwner() external view returns (address) { return owner; }
        }
        """
        res = run({"code": secure_code})
        assert res.status == "success"
        # No critical or high severity findings on clean contract
        severe = [f for f in res.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(severe) == 0
