# =============================================================================
# CyberToolkit Pro — Multi-Target Campaign Engine
# =============================================================================
# Define and execute campaigns across multiple targets with aggregated
# reporting. Essential for real-world pentests with large scope.
# =============================================================================

import uuid
import time
from datetime import datetime
from typing import List, Dict, Optional

from core.models import ToolResult
from core.database import get_db
from core.async_executor import AsyncExecutor, run_async
from core import output


class Campaign:
    """Represents a multi-target security assessment campaign."""

    def __init__(self, name: str, targets: List[str],
                 pipeline: str = "", description: str = ""):
        self.campaign_id = f"campaign_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        self.name = name
        self.targets = targets
        self.pipeline = pipeline
        self.description = description
        self.results = {}       # {target: [ToolResult, ...]}
        self.status = "pending"
        self.started_at = None
        self.completed_at = None

        # Register in database
        db = get_db()
        db.create_campaign(
            campaign_id=self.campaign_id,
            name=name,
            targets=targets,
            description=description,
            pipeline=pipeline
        )

    def run_tool_across_targets(self, tool_module, extra_args: Dict = None,
                                  max_concurrency: int = 10) -> Dict:
        """Run a single tool against all campaign targets."""
        self.status = "running"
        self.started_at = datetime.utcnow()
        extra_args = extra_args or {}

        executor = AsyncExecutor(max_concurrency=max_concurrency)

        output.section(f"Campaign: {self.name}")
        output.info(f"Running {tool_module.TOOL_INFO.get('name', '?')} across {len(self.targets)} targets")

        async def _run():
            return await executor.run_batch(
                tool_module, self.targets, extra_args, self.campaign_id
            )

        results = run_async(_run())

        # Organize results by target
        for i, target in enumerate(self.targets):
            if i < len(results):
                r = results[i]
                if isinstance(r, Exception):
                    r = ToolResult(
                        tool_name=tool_module.TOOL_INFO.get("name", "?"),
                        target=target, status="error", error=str(r)
                    )
                if target not in self.results:
                    self.results[target] = []
                self.results[target].append(r)

        self.status = "completed"
        self.completed_at = datetime.utcnow()

        # Update database stats
        db = get_db()
        db.update_campaign_stats(self.campaign_id)

        return self.get_summary()

    def run_pipeline_across_targets(self, steps: List[Dict],
                                      max_concurrency: int = 5) -> Dict:
        """Run a full pipeline against all campaign targets."""
        self.status = "running"
        self.started_at = datetime.utcnow()

        output.section(f"Campaign: {self.name}")
        output.info(f"Running {len(steps)}-step pipeline across {len(self.targets)} targets")

        executor = AsyncExecutor(max_concurrency=max_concurrency)

        for target in self.targets:
            output.info(f"Processing target: {target}")

            async def _run_pipeline():
                return await executor.run_pipeline_async(
                    steps, {"target": target}, self.campaign_id
                )

            pipeline_results = run_async(_run_pipeline())

            self.results[target] = []
            for r in pipeline_results:
                if isinstance(r, ToolResult):
                    self.results[target].append(r)

            # Show progress
            findings_count = sum(
                len(r.findings) for r in self.results[target]
                if hasattr(r, "findings")
            )
            output.success(f"  {target}: {len(pipeline_results)} steps, {findings_count} findings")

        self.status = "completed"
        self.completed_at = datetime.utcnow()

        db = get_db()
        db.update_campaign_stats(self.campaign_id)

        return self.get_summary()

    def get_summary(self) -> Dict:
        """Get campaign summary with aggregated statistics."""
        total_findings = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        target_summaries = {}

        for target, results in self.results.items():
            target_findings = 0
            for r in results:
                if hasattr(r, "findings"):
                    for f in r.findings:
                        total_findings += 1
                        target_findings += 1
                        sev = f.severity.value if hasattr(f.severity, "value") else str(f.get("severity", "info"))
                        if sev in severity_counts:
                            severity_counts[sev] += 1

            target_summaries[target] = {
                "scans": len(results),
                "findings": target_findings,
                "statuses": [r.status for r in results if hasattr(r, "status")],
            }

        duration = 0
        if self.started_at and self.completed_at:
            duration = (self.completed_at - self.started_at).total_seconds()

        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "status": self.status,
            "targets": len(self.targets),
            "total_scans": sum(len(r) for r in self.results.values()),
            "total_findings": total_findings,
            "severity_breakdown": severity_counts,
            "target_summaries": target_summaries,
            "duration_seconds": round(duration, 2),
        }


class CampaignManager:
    """Manage multiple campaigns."""

    @staticmethod
    def list_campaigns(limit: int = 50) -> List[Dict]:
        """List all campaigns from the database."""
        return get_db().get_campaigns(limit)

    @staticmethod
    def get_campaign_report(campaign_id: str) -> Dict:
        """Get detailed campaign report."""
        db = get_db()
        campaign = db.get_campaign(campaign_id)
        if not campaign:
            return {}
        scans = db.get_scans(campaign_id=campaign_id, limit=1000)
        findings = []
        for scan in scans:
            findings.extend(db.get_findings(scan_id=scan["scan_id"]))
        campaign["scans"] = scans
        campaign["findings"] = findings
        return campaign
