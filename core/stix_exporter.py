# =============================================================================
# CyberToolkit Pro — STIX 2.1 Exporter
# =============================================================================
# Export findings and scan results to STIX 2.1 JSON bundles for sharing
# with other security tools and threat intelligence platforms.
# =============================================================================

import json
import uuid
import hashlib
from datetime import datetime
from typing import Dict, List, Optional

from core.database import get_db
from core.logger import get_logger

logger = get_logger("stix")


class STIXExporter:
    """Export framework findings to STIX 2.1 format."""

    SEVERITY_TO_STIX = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "unknown",
    }

    def _stix_id(self, obj_type: str) -> str:
        """Generate a STIX-compliant identifier."""
        return f"{obj_type}--{uuid.uuid4()}"

    def _timestamp(self) -> str:
        """Return current UTC timestamp in STIX format."""
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def export_scan(self, scan_id: str) -> Dict:
        """Export a single scan result as a STIX 2.1 bundle."""
        db = get_db()
        scan = db.get_scan(scan_id)
        if not scan:
            return {"error": f"Scan '{scan_id}' not found"}

        findings = db.get_findings(scan_id=scan_id)
        return self._build_bundle(scan, findings)

    def export_target(self, target: str) -> Dict:
        """Export all findings for a target as a STIX bundle."""
        db = get_db()
        scans = db.get_scans(target=target, limit=1000)
        all_findings = []
        for scan in scans:
            all_findings.extend(db.get_findings(scan_id=scan["scan_id"]))
        return self._build_bundle_multi(target, scans, all_findings)

    def export_campaign(self, campaign_id: str) -> Dict:
        """Export all campaign results as a STIX bundle."""
        db = get_db()
        scans = db.get_scans(campaign_id=campaign_id, limit=1000)
        all_findings = []
        for scan in scans:
            all_findings.extend(db.get_findings(scan_id=scan["scan_id"]))
        return self._build_bundle_multi(
            f"Campaign: {campaign_id}", scans, all_findings
        )

    def _build_bundle(self, scan: Dict, findings: List[Dict]) -> Dict:
        """Build a STIX 2.1 bundle from a scan and its findings."""
        now = self._timestamp()
        objects = []

        # Identity for the tool
        identity_id = self._stix_id("identity")
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "CyberToolkit Pro",
            "identity_class": "tool",
        })

        # Observed data for the scan
        observed_id = self._stix_id("observed-data")
        objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "first_observed": scan.get("created_at", now),
            "last_observed": scan.get("created_at", now),
            "number_observed": 1,
            "object_refs": [],
        })

        # Create indicator for target
        target_val = scan.get("target", "")
        if target_val:
            indicator_id = self._stix_id("indicator")
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "name": f"Target: {target_val}",
                "pattern_type": "stix",
                "pattern": f"[ipv4-addr:value = '{target_val}']",
                "valid_from": now,
            })

        # Create vulnerability objects for findings
        for finding in findings:
            vuln_id = self._stix_id("vulnerability")
            severity = finding.get("severity", "info")
            objects.append({
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vuln_id,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "name": finding.get("title", "Unknown Finding"),
                "description": finding.get("description", ""),
                "x_severity": self.SEVERITY_TO_STIX.get(severity, "unknown"),
                "x_evidence": finding.get("evidence", ""),
                "x_remediation": finding.get("remediation", ""),
                "x_scan_id": finding.get("scan_id", ""),
            })

        return {
            "type": "bundle",
            "id": self._stix_id("bundle"),
            "objects": objects,
        }

    def _build_bundle_multi(self, label: str, scans: List[Dict],
                             findings: List[Dict]) -> Dict:
        """Build a STIX bundle from multiple scans."""
        now = self._timestamp()
        objects = []

        identity_id = self._stix_id("identity")
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "CyberToolkit Pro",
            "identity_class": "tool",
        })

        # Report object
        report_id = self._stix_id("report")
        objects.append({
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": label,
            "published": now,
            "object_refs": [],
            "x_total_scans": len(scans),
            "x_total_findings": len(findings),
        })

        for finding in findings:
            vuln_id = self._stix_id("vulnerability")
            severity = finding.get("severity", "info")
            objects.append({
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vuln_id,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "name": finding.get("title", "Unknown"),
                "description": finding.get("description", ""),
                "x_severity": self.SEVERITY_TO_STIX.get(severity, "unknown"),
            })

        return {
            "type": "bundle",
            "id": self._stix_id("bundle"),
            "objects": objects,
        }

    def to_json(self, bundle: Dict, indent: int = 2) -> str:
        """Serialize STIX bundle to JSON string."""
        return json.dumps(bundle, indent=indent, default=str)

    def save(self, bundle: Dict, filepath: str) -> str:
        """Save STIX bundle to file."""
        import os
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.to_json(bundle))
        return filepath
