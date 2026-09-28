# =============================================================================
# CyberToolkit Pro — Scan Diff / Change Detection Engine
# =============================================================================
# Compares scan results over time to detect changes in attack surface:
# new/removed ports, new findings, severity changes, etc.
# =============================================================================

import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from core.database import get_db
from core import output
from core.logger import get_logger

logger = get_logger("differ")


class ScanDiffer:
    """Compare scan results to detect changes over time."""

    def compare_scans(self, scan_id_old: str, scan_id_new: str) -> Dict:
        """
        Compare two scan results and return a structured diff.

        Returns:
            {
                "old_scan": {...},
                "new_scan": {...},
                "changes": {
                    "new_ports": [...],
                    "removed_ports": [...],
                    "new_findings": [...],
                    "resolved_findings": [...],
                    "severity_changes": [...],
                    "new_data_keys": [...],
                    "removed_data_keys": [...]
                }
            }
        """
        db = get_db()
        old = db.get_scan(scan_id_old)
        new = db.get_scan(scan_id_new)

        if not old:
            return {"error": f"Scan '{scan_id_old}' not found"}
        if not new:
            return {"error": f"Scan '{scan_id_new}' not found"}

        old_data = json.loads(old.get("data", "{}")) if isinstance(old.get("data"), str) else old.get("data", {})
        new_data = json.loads(new.get("data", "{}")) if isinstance(new.get("data"), str) else new.get("data", {})

        old_findings = db.get_findings(scan_id=scan_id_old)
        new_findings = db.get_findings(scan_id=scan_id_new)

        changes = {
            "new_ports": [],
            "removed_ports": [],
            "new_findings": [],
            "resolved_findings": [],
            "severity_changes": [],
            "new_data_keys": [],
            "removed_data_keys": [],
        }

        # --- Port comparison ---
        old_ports = set(self._extract_ports(old_data))
        new_ports = set(self._extract_ports(new_data))
        changes["new_ports"] = sorted(new_ports - old_ports)
        changes["removed_ports"] = sorted(old_ports - new_ports)

        # --- Finding comparison ---
        old_finding_titles = {f.get("title", ""): f for f in old_findings}
        new_finding_titles = {f.get("title", ""): f for f in new_findings}

        for title in new_finding_titles:
            if title not in old_finding_titles:
                changes["new_findings"].append(new_finding_titles[title])

        for title in old_finding_titles:
            if title not in new_finding_titles:
                changes["resolved_findings"].append(old_finding_titles[title])

        # Severity changes for findings that exist in both
        for title in old_finding_titles:
            if title in new_finding_titles:
                old_sev = old_finding_titles[title].get("severity", "info")
                new_sev = new_finding_titles[title].get("severity", "info")
                if old_sev != new_sev:
                    changes["severity_changes"].append({
                        "title": title,
                        "old_severity": old_sev,
                        "new_severity": new_sev,
                    })

        # --- Data key comparison ---
        old_keys = set(old_data.keys())
        new_keys = set(new_data.keys())
        changes["new_data_keys"] = sorted(new_keys - old_keys)
        changes["removed_data_keys"] = sorted(old_keys - new_keys)

        return {
            "old_scan": {"scan_id": scan_id_old, "tool": old.get("tool_name"), "date": old.get("created_at")},
            "new_scan": {"scan_id": scan_id_new, "tool": new.get("tool_name"), "date": new.get("created_at")},
            "changes": changes,
            "has_changes": any(v for v in changes.values() if v),
        }

    def compare_target_over_time(self, target: str, days: int = 30) -> Dict:
        """
        Track how a target's attack surface changed over a time period.
        Compares the oldest and most recent scans within the window.
        """
        db = get_db()
        scans = db.get_scans(target=target, limit=1000)

        if not scans:
            return {"error": f"No scans found for target '{target}'"}

        # Filter to time window
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        filtered = [s for s in scans if s.get("created_at", "") >= cutoff]

        if len(filtered) < 2:
            return {
                "error": f"Need at least 2 scans in the last {days} days (found {len(filtered)})",
                "total_scans": len(filtered),
            }

        oldest = filtered[-1]
        newest = filtered[0]

        diff = self.compare_scans(oldest["scan_id"], newest["scan_id"])
        diff["target"] = target
        diff["time_window_days"] = days
        diff["total_scans_in_window"] = len(filtered)

        return diff

    def print_diff(self, diff: Dict):
        """Pretty-print a scan diff to console."""
        if "error" in diff:
            output.error(diff["error"])
            return

        changes = diff.get("changes", {})
        old_info = diff.get("old_scan", {})
        new_info = diff.get("new_scan", {})

        output.section("Scan Comparison")
        output.info(f"Old: {old_info.get('scan_id', '?')} ({old_info.get('date', '?')})")
        output.info(f"New: {new_info.get('scan_id', '?')} ({new_info.get('date', '?')})")

        if not diff.get("has_changes"):
            output.success("No changes detected")
            return

        # New ports
        if changes.get("new_ports"):
            output.warning(f"+ {len(changes['new_ports'])} NEW port(s) opened:")
            for port in changes["new_ports"]:
                print(f"    {output.Colors.GREEN}+ Port {port}{output.Colors.RESET}")

        # Removed ports
        if changes.get("removed_ports"):
            output.info(f"- {len(changes['removed_ports'])} port(s) closed:")
            for port in changes["removed_ports"]:
                print(f"    {output.Colors.RED}- Port {port}{output.Colors.RESET}")

        # New findings
        if changes.get("new_findings"):
            output.warning(f"! {len(changes['new_findings'])} NEW finding(s):")
            for f in changes["new_findings"]:
                sev = f.get("severity", "info")
                print(f"    {output.severity_badge(sev)} {f.get('title', '?')}")

        # Resolved findings
        if changes.get("resolved_findings"):
            output.success(f"✓ {len(changes['resolved_findings'])} finding(s) RESOLVED:")
            for f in changes["resolved_findings"]:
                print(f"    {output.Colors.GREEN}✓ {f.get('title', '?')}{output.Colors.RESET}")

        # Severity changes
        if changes.get("severity_changes"):
            output.warning(f"~ {len(changes['severity_changes'])} severity change(s):")
            for sc in changes["severity_changes"]:
                print(f"    {sc['title']}: {sc['old_severity']} → {sc['new_severity']}")

    def _extract_ports(self, data: Dict) -> List[int]:
        """Extract port numbers from scan data."""
        ports = []
        for port_info in data.get("open_ports", []):
            if isinstance(port_info, int):
                ports.append(port_info)
            elif isinstance(port_info, dict):
                ports.append(port_info.get("port", 0))
        return ports


# Module-level convenience
_differ = None


def get_differ() -> ScanDiffer:
    """Get the global differ instance."""
    global _differ
    if _differ is None:
        _differ = ScanDiffer()
    return _differ
