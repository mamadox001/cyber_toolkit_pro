# =============================================================================
# CyberToolkit Pro — Audit Trail
# =============================================================================
# Immutable audit log for all tool executions. Records timestamp, target,
# operator, tool, arguments, result hash, and duration.
# Required for compliance in professional pentesting engagements.
# =============================================================================

import os
import json
import hashlib
import getpass
from datetime import datetime
from typing import Optional, Dict


class AuditTrail:
    """Immutable audit logging for all framework operations."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, audit_dir: str = "logs/audit"):
        if self._initialized:
            return
        self._initialized = True
        self.audit_dir = audit_dir
        os.makedirs(audit_dir, exist_ok=True)
        self._log_file = os.path.join(
            audit_dir,
            f"audit_{datetime.utcnow().strftime('%Y%m%d')}.jsonl"
        )
        self._operator = getpass.getuser()
        self._session_id = datetime.utcnow().strftime("%Y%m%d%H%M%S")

    def log_execution(self, tool_name: str, target: str, args: Dict,
                      status: str, duration_ms: float,
                      findings_count: int = 0,
                      result_data: Optional[Dict] = None) -> Dict:
        """Log a tool execution to the audit trail."""
        # Hash the result for integrity verification
        result_hash = ""
        if result_data:
            raw = json.dumps(result_data, sort_keys=True, default=str)
            result_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

        # Sanitize args — remove sensitive values
        safe_args = {}
        sensitive_keys = {"password", "passwd", "secret", "key", "token", "api_key"}
        for k, v in args.items():
            if k.lower() in sensitive_keys:
                safe_args[k] = "***REDACTED***"
            else:
                safe_args[k] = str(v)[:200]

        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_id": self._session_id,
            "operator": self._operator,
            "tool": tool_name,
            "target": target,
            "args": safe_args,
            "status": status,
            "duration_ms": round(duration_ms, 2),
            "findings_count": findings_count,
            "result_hash": result_hash,
        }

        # Append to JSONL file (one JSON object per line — immutable append)
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except IOError:
            pass

        return entry

    def log_scope_violation(self, tool_name: str, target: str, reason: str) -> Dict:
        """Log a scope violation attempt."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_id": self._session_id,
            "operator": self._operator,
            "event": "SCOPE_VIOLATION",
            "tool": tool_name,
            "target": target,
            "reason": reason,
        }

        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except IOError:
            pass

        return entry

    def log_event(self, event_type: str, details: Dict) -> Dict:
        """Log a generic framework event."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_id": self._session_id,
            "operator": self._operator,
            "event": event_type,
            **details,
        }

        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except IOError:
            pass

        return entry

    def get_entries(self, limit: int = 100, tool: str = "",
                    target: str = "") -> list:
        """Read audit entries with optional filtering."""
        entries = []
        try:
            # Read all audit files
            for fname in sorted(os.listdir(self.audit_dir), reverse=True):
                if not fname.endswith(".jsonl"):
                    continue
                fpath = os.path.join(self.audit_dir, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if tool and entry.get("tool", "") != tool:
                            continue
                        if target and target not in entry.get("target", ""):
                            continue

                        entries.append(entry)
                        if len(entries) >= limit:
                            return entries
        except IOError:
            pass

        return entries

    def get_stats(self) -> Dict:
        """Get summary statistics from the audit trail."""
        entries = self.get_entries(limit=10000)
        tools_used = {}
        targets_hit = set()
        total_findings = 0

        for entry in entries:
            tool = entry.get("tool", "")
            if tool:
                tools_used[tool] = tools_used.get(tool, 0) + 1
            target = entry.get("target", "")
            if target:
                targets_hit.add(target)
            total_findings += entry.get("findings_count", 0)

        return {
            "total_executions": len(entries),
            "unique_tools": len(tools_used),
            "unique_targets": len(targets_hit),
            "total_findings": total_findings,
            "tools_breakdown": tools_used,
            "operator": self._operator,
            "session_id": self._session_id,
        }


# Module-level singleton
_audit = None


def get_audit() -> AuditTrail:
    """Get the global audit trail instance."""
    global _audit
    if _audit is None:
        _audit = AuditTrail()
    return _audit
