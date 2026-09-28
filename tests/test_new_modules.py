# =============================================================================
# CyberToolkit Pro — Unit Tests for New Modules & Capabilities
# =============================================================================

import os
import sys
import json
import base64
import tempfile
import plistlib
import pytest

# Ensure root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import ToolResult, Finding, Severity
from core.differ import ScanDiffer
from core.stix_exporter import STIXExporter
from core.threat_intel import ThreatIntel
from core.notifier import Notifier
from core.scheduler import ScanScheduler, ScheduledTask
from core.loader import load_all
from core.registry import get_registry


# -----------------------------------------------------------------------------
# Test Core Differ
# -----------------------------------------------------------------------------
class TestDiffer:
    def test_differ_initialization(self):
        differ = ScanDiffer()
        assert differ is not None

    def test_compare_nonexistent_scans(self):
        differ = ScanDiffer()
        res = differ.compare_scans("fake_old", "fake_new")
        assert "error" in res


# -----------------------------------------------------------------------------
# Test STIX Exporter
# -----------------------------------------------------------------------------
class TestSTIXExporter:
    def test_stix_id_format(self):
        exporter = STIXExporter()
        sid = exporter._stix_id("indicator")
        assert sid.startswith("indicator--")

    def test_stix_export_missing_scan(self):
        exporter = STIXExporter()
        res = exporter.export_scan("non_existent_scan_id")
        assert "error" in res


# -----------------------------------------------------------------------------
# Test Threat Intel
# -----------------------------------------------------------------------------
class TestThreatIntel:
    def test_unconfigured_api_keys(self):
        ti = ThreatIntel()
        res = ti.virustotal_ip("8.8.8.8")
        assert "error" in res or res is None


# -----------------------------------------------------------------------------
# Test Notifier
# -----------------------------------------------------------------------------
class TestNotifier:
    def test_singleton(self):
        n1 = Notifier()
        n2 = Notifier()
        assert n1 is n2

    def test_format_message(self):
        n = Notifier()
        # Test notify with mock or empty channels
        notified = n.notify("Test Alert", "This is a test notification", "info")
        assert isinstance(notified, list)


# -----------------------------------------------------------------------------
# Test Scheduler
# -----------------------------------------------------------------------------
class TestScheduler:
    def test_scheduled_task_model(self):
        task = ScheduledTask(
            task_id="t-123",
            tool_path="scanning.port_scanner",
            args={"target": "127.0.0.1"},
            description="Test scheduled port scan"
        )
        d = task.to_dict()
        assert d["task_id"] == "t-123"
        assert d["tool_path"] == "scanning.port_scanner"
        assert d["status"] == "pending"


# -----------------------------------------------------------------------------
# Test Crypto Tools
# -----------------------------------------------------------------------------
class TestCryptoTools:
    def test_jwt_analyzer_none_algorithm(self):
        from modules.crypto.jwt_analyzer import run
        # header: {"alg":"none","typ":"JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
        # payload: {"user":"admin"} -> eyJ1c2VyIjoiYWRtaW4ifQ
        token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
        result = run({"token": token})
        assert result.status == "success"
        vulnerabilities = [f.title for f in result.findings]
        assert any("none" in title.lower() for title in vulnerabilities)

    def test_encryption_auditor(self, tmp_path):
        from modules.crypto.encryption_auditor import run
        code_file = tmp_path / "insecure_crypto.py"
        code_file.write_text(
            "import hashlib\nh = hashlib.md5(b'secret').hexdigest()\nkey = '-----BEGIN RSA PRIVATE KEY-----'\n",
            encoding="utf-8"
        )
        result = run({"target": str(code_file)})
        assert result.status == "success"
        titles = [f.title for f in result.findings]
        assert any("Cryptographic Algorithm" in t for t in titles)
        assert any("Private Key" in t for t in titles)


# -----------------------------------------------------------------------------
# Test Cloud Tools
# -----------------------------------------------------------------------------
class TestCloudTools:
    def test_container_scanner(self, tmp_path):
        from modules.cloud.container_scanner import run
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "FROM ubuntu:latest\nUSER root\nENV API_KEY=secret123\n",
            encoding="utf-8"
        )
        result = run({"target": str(dockerfile)})
        assert result.status == "success"
        titles = [f.title for f in result.findings]
        assert any("USER root" in t or "root" in t.lower() for t in titles)
        assert any("latest" in t.lower() for t in titles)
        assert any("secret" in t.lower() for t in titles)

    def test_kubernetes_auditor(self, tmp_path):
        from modules.cloud.kubernetes_auditor import run
        manifest = tmp_path / "pod.yaml"
        manifest.write_text(
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: test\n    securityContext:\n      privileged: true\n",
            encoding="utf-8"
        )
        result = run({"target": str(manifest)})
        assert result.status == "success"
        titles = [f.title for f in result.findings]
        assert any("Privileged" in t for t in titles)


# -----------------------------------------------------------------------------
# Test Mobile Tools
# -----------------------------------------------------------------------------
class TestMobileTools:
    def test_ios_plist_parser(self, tmp_path):
        from modules.mobile.ios_plist_parser import run
        plist_path = tmp_path / "Info.plist"
        plist_content = {
            "CFBundleIdentifier": "com.example.app",
            "CFBundleShortVersionString": "1.0.0",
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoads": True
            }
        }
        with open(plist_path, "wb") as f:
            plistlib.dump(plist_content, f)

        result = run({"target": str(plist_path)})
        assert result.status == "success"
        titles = [f.title for f in result.findings]
        assert any("App Transport Security" in t for t in titles)


# -----------------------------------------------------------------------------
# Test Reporting: PDF Report
# -----------------------------------------------------------------------------
class TestReportingPDF:
    def test_pdf_report_generation(self, tmp_path):
        from modules.reporting.pdf_report import run
        out_pdf = str(tmp_path / "test_report.pdf")
        findings = [
            Finding(
                title="Critical SQL Injection",
                severity=Severity.CRITICAL,
                description="Unsanitized input in /login parameter",
                remediation="Use parameterized queries",
                target="https://example.com/login"
            )
        ]
        result = run({"output_file": out_pdf, "findings": findings})
        assert result.status == "success"
        assert os.path.exists(out_pdf)
        assert os.path.getsize(out_pdf) > 100
