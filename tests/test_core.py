# =============================================================================
# CyberToolkit Pro — Unit Tests
# =============================================================================
# pytest test suite covering core modules: models, registry, executor,
# pipeline, scope, vault, audit, database, and campaign.
# Run: pytest tests/ -v
# =============================================================================

import os
import sys
import json
import shutil
import tempfile
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# Test: core/models.py
# ============================================================
class TestModels:
    def test_tool_result_creation(self):
        from core.models import ToolResult, Finding, Severity
        result = ToolResult(
            tool_name="test_tool",
            target="10.0.0.1",
            status="success",
            data={"key": "value"}
        )
        assert result.tool_name == "test_tool"
        assert result.target == "10.0.0.1"
        assert result.status == "success"
        assert result.data["key"] == "value"

    def test_tool_result_json(self):
        from core.models import ToolResult
        result = ToolResult(tool_name="test", target="t", status="ok", data={"x": 1})
        j = result.to_json()
        parsed = json.loads(j)
        assert parsed["tool_name"] == "test"
        assert parsed["data"]["x"] == 1

    def test_finding_creation(self):
        from core.models import Finding, Severity
        f = Finding(title="Test finding", severity=Severity.HIGH,
                    description="Test desc", remediation="Fix it")
        assert f.title == "Test finding"
        assert f.severity == Severity.HIGH
        assert f.remediation == "Fix it"

    def test_severity_ordering(self):
        from core.models import Severity
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"

    def test_tool_result_with_findings(self):
        from core.models import ToolResult, Finding, Severity
        result = ToolResult(
            tool_name="test", target="x", status="success",
            data={}, findings=[
                Finding(title="F1", severity=Severity.LOW),
                Finding(title="F2", severity=Severity.HIGH),
            ]
        )
        assert len(result.findings) == 2


# ============================================================
# Test: core/registry.py
# ============================================================
class TestRegistry:
    def test_singleton(self):
        from core.registry import ToolRegistry
        r1 = ToolRegistry()
        r2 = ToolRegistry()
        assert r1 is r2

    def test_register_and_get(self):
        from core.registry import ToolRegistry
        registry = ToolRegistry()
        # Create a mock tool info
        info = type("ToolInfo", (), {
            "name": "test_tool", "category": "test_category",
            "description": "A test tool"
        })()
        module = type("Module", (), {"TOOL_INFO": {"name": "test_tool", "category": "test_category"}})()
        registry.register(info, module)
        tool = registry.get("test_category.test_tool")
        assert tool is not None

    def test_search(self):
        from core.registry import ToolRegistry
        registry = ToolRegistry()
        results = registry.search("test")
        assert isinstance(results, list)

    def test_categories(self):
        from core.registry import ToolRegistry
        registry = ToolRegistry()
        cats = registry.categories()
        assert isinstance(cats, list)


# ============================================================
# Test: core/scope.py
# ============================================================
class TestScope:
    def test_disabled_scope_allows_all(self):
        from core.scope import ScopeEnforcer
        enforcer = ScopeEnforcer.__new__(ScopeEnforcer)
        enforcer._initialized = False
        enforcer.__init__("nonexistent_file.yaml")
        enforcer.enabled = False
        allowed, reason = enforcer.check_target("anything.com")
        assert allowed is True

    def test_ip_in_range(self):
        import ipaddress
        from core.scope import ScopeEnforcer
        enforcer = ScopeEnforcer.__new__(ScopeEnforcer)
        enforcer._initialized = False
        enforcer.__init__("nonexistent_file.yaml")
        enforcer.enabled = True
        enforcer.allowed_ips = [ipaddress.ip_network("192.168.1.0/24")]
        enforcer.allowed_domains = []
        enforcer.excluded_ips = []
        enforcer.excluded_domains = []
        enforcer.allowed_ports = []

        allowed, _ = enforcer.check_target("192.168.1.50")
        assert allowed is True

        allowed, _ = enforcer.check_target("10.0.0.1")
        assert allowed is False

    def test_scope_violation(self):
        import ipaddress
        from core.scope import ScopeEnforcer, ScopeViolation
        enforcer = ScopeEnforcer.__new__(ScopeEnforcer)
        enforcer._initialized = False
        enforcer.__init__("nonexistent_file.yaml")
        enforcer.enabled = True
        enforcer.allowed_ips = [ipaddress.ip_network("10.0.0.0/8")]
        enforcer.allowed_domains = []
        enforcer.excluded_ips = []
        enforcer.excluded_domains = []
        enforcer.allowed_ports = []

        with pytest.raises(ScopeViolation):
            enforcer.enforce("1.2.3.4")


# ============================================================
# Test: core/vault.py
# ============================================================
class TestVault:
    def test_store_and_retrieve(self, tmp_path):
        from core.vault import CredentialVault
        vault = CredentialVault(
            vault_path=str(tmp_path / "test_vault"),
            master_key="test_key_123"
        )
        vault.store("api_key", "secret_value_123", category="api")
        retrieved = vault.retrieve("api_key")
        assert retrieved == "secret_value_123"

    def test_list_keys(self, tmp_path):
        from core.vault import CredentialVault
        vault = CredentialVault(
            vault_path=str(tmp_path / "test_vault2"),
            master_key="key"
        )
        vault.store("key1", "val1", category="test")
        vault.store("key2", "val2", category="test")
        vault.store("key3", "val3", category="other")

        keys = vault.list_keys(category="test")
        assert len(keys) == 2

    def test_delete(self, tmp_path):
        from core.vault import CredentialVault
        vault = CredentialVault(
            vault_path=str(tmp_path / "test_vault3"),
            master_key="key"
        )
        vault.store("to_delete", "value")
        assert vault.delete("to_delete") is True
        assert vault.retrieve("to_delete") is None

    def test_found_credentials(self, tmp_path):
        from core.vault import CredentialVault
        vault = CredentialVault(
            vault_path=str(tmp_path / "test_vault4"),
            master_key="key"
        )
        vault.store_found_credential(
            target="10.0.0.1", service="ssh",
            username="admin", password="password123",
            source_tool="wordlist_attack"
        )
        creds = vault.get_found_credentials()
        assert len(creds) == 1
        assert creds[0]["password"] == "password123"


# ============================================================
# Test: core/audit.py
# ============================================================
class TestAudit:
    def test_log_execution(self, tmp_path):
        from core.audit import AuditTrail
        audit = AuditTrail.__new__(AuditTrail)
        audit._initialized = False
        audit.__init__(str(tmp_path / "test_audit"))
        entry = audit.log_execution(
            tool_name="port_scanner", target="10.0.0.1",
            args={"ports": "1-1000"}, status="success",
            duration_ms=1234.5, findings_count=3,
            result_data={"open_ports": [22, 80]}
        )
        assert entry["tool"] == "port_scanner"
        assert entry["duration_ms"] == 1234.5

    def test_sensitive_redaction(self, tmp_path):
        from core.audit import AuditTrail
        audit = AuditTrail.__new__(AuditTrail)
        audit._initialized = False
        audit.__init__(str(tmp_path / "test_audit2"))
        entry = audit.log_execution(
            tool_name="test", target="x",
            args={"password": "secret123", "target": "10.0.0.1"},
            status="ok", duration_ms=0
        )
        assert entry["args"]["password"] == "***REDACTED***"
        assert entry["args"]["target"] == "10.0.0.1"

    def test_get_entries(self, tmp_path):
        from core.audit import AuditTrail
        audit = AuditTrail.__new__(AuditTrail)
        audit._initialized = False
        audit.__init__(str(tmp_path / "test_audit3"))
        audit.log_execution("tool1", "t1", {}, "ok", 100)
        audit.log_execution("tool2", "t2", {}, "ok", 200)
        entries = audit.get_entries()
        assert len(entries) == 2


# ============================================================
# Test: core/database.py
# ============================================================
class TestDatabase:
    def test_save_and_get_scan(self, tmp_path):
        from core.database import Database
        db = Database.__new__(Database)
        db._initialized = False
        db.__init__(str(tmp_path / "test.db"))

        from core.models import Finding, Severity
        scan_id = db.save_scan(
            scan_id="test_scan_001",
            tool_name="port_scanner",
            target="10.0.0.1",
            status="success",
            args={"ports": "1-100"},
            data={"open_ports": [22, 80]},
            findings=[
                Finding(title="Port 22 open", severity=Severity.INFO),
            ],
            duration_ms=500.0,
        )
        assert scan_id == "test_scan_001"

        scan = db.get_scan("test_scan_001")
        assert scan is not None
        assert scan["tool_name"] == "port_scanner"

    def test_get_targets(self, tmp_path):
        from core.database import Database
        db = Database.__new__(Database)
        db._initialized = False
        db.__init__(str(tmp_path / "test2.db"))

        db.save_scan("s1", "tool1", "10.0.0.1", "ok", {}, {}, [], 100)
        db.save_scan("s2", "tool2", "10.0.0.2", "ok", {}, {}, [], 100)

        targets = db.get_targets()
        assert len(targets) == 2

    def test_campaign(self, tmp_path):
        from core.database import Database
        db = Database.__new__(Database)
        db._initialized = False
        db.__init__(str(tmp_path / "test3.db"))

        db.create_campaign("campaign_1", "Test Campaign",
                          ["10.0.0.1", "10.0.0.2"], "Test")
        campaign = db.get_campaign("campaign_1")
        assert campaign is not None
        assert campaign["name"] == "Test Campaign"

    def test_dashboard_stats(self, tmp_path):
        from core.database import Database
        db = Database.__new__(Database)
        db._initialized = False
        db.__init__(str(tmp_path / "test4.db"))

        stats = db.get_dashboard_stats()
        assert "total_scans" in stats
        assert "total_findings" in stats
        db.close()


# ============================================================
# Test: core/output.py
# ============================================================
class TestOutput:
    def test_strip_ansi(self):
        from core.output import _strip_ansi
        raw = "\033[91mRed text\033[0m"
        clean = _strip_ansi(raw)
        assert clean == "Red text"

    def test_severity_badge(self):
        from core.output import severity_badge
        badge = severity_badge("high")
        assert "HIGH" in badge

    def test_safe_print(self, capsys):
        from core.output import _safe_print
        _safe_print("Hello World")
        captured = capsys.readouterr()
        assert "Hello World" in captured.out


# ============================================================
# Test: Tool module loading
# ============================================================
class TestToolLoading:
    def test_tool_info_schema(self):
        """Verify all tool modules have valid TOOL_INFO."""
        import importlib
        import pathlib

        modules_dir = pathlib.Path(__file__).parent.parent / "modules"
        errors = []

        for py_file in modules_dir.rglob("*.py"):
            if py_file.name.startswith("_"):
                continue

            rel_path = py_file.relative_to(modules_dir.parent)
            module_path = str(rel_path).replace(os.sep, ".").replace(".py", "")

            try:
                mod = importlib.import_module(module_path)
                info = getattr(mod, "TOOL_INFO", None)
                run_fn = getattr(mod, "run", None)

                if info is None:
                    errors.append(f"{module_path}: Missing TOOL_INFO")
                    continue
                if run_fn is None:
                    errors.append(f"{module_path}: Missing run() function")
                    continue
                if "name" not in info:
                    errors.append(f"{module_path}: TOOL_INFO missing 'name'")
                if "category" not in info:
                    errors.append(f"{module_path}: TOOL_INFO missing 'category'")
            except Exception as e:
                errors.append(f"{module_path}: Import error: {e}")

        assert len(errors) == 0, f"Tool validation errors:\n" + "\n".join(errors)

    def test_all_tools_load(self):
        """Verify the loader can discover and register all tools."""
        from core.loader import load_all
        from core.registry import get_registry
        load_all(quiet=True)
        registry = get_registry()
        tools = registry.search("")
        # Should have at least 30 tools
        assert len(tools) >= 30, f"Only {len(tools)} tools loaded, expected 30+"
