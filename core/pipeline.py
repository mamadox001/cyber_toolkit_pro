# =============================================================================
# CyberToolkit Pro — Pipeline Engine
# =============================================================================
# Chains tools together in a workflow. Supports YAML profile definitions,
# result passing between stages, conditional execution, and error handling.
#
# Pipeline flow:  Tool A → result → Tool B (gets A's result as context) → ...
# =============================================================================

import os
import yaml
from typing import Any, Dict, List, Optional

from core.registry import get_registry
from core.executor import execute
from core.models import ToolResult
from core import output
from core.logger import get_logger

logger = get_logger("pipeline")


class Pipeline:
    """
    Executes an ordered sequence of tools, passing results forward.

    Can be constructed programmatically or loaded from a YAML profile.
    """

    def __init__(self, name: str, steps: List[str], description: str = ""):
        """
        Parameters:
            name:        pipeline name
            steps:       list of dotted tool paths, e.g. ["reconnaissance.dns_lookup", "scanning.port_scanner"]
            description: human-readable description
        """
        self.name = name
        self.steps = steps
        self.description = description

    @classmethod
    def from_yaml(cls, path: str) -> "Pipeline":
        """Load a pipeline profile from a YAML file."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(
            name=data.get("name", os.path.basename(path)),
            steps=data.get("steps", []),
            description=data.get("description", ""),
        )

    def run(self, args: Dict[str, Any]) -> List[ToolResult]:
        """
        Execute the pipeline sequentially.

        Each tool receives the original args plus a '_pipeline_context' key
        containing all previous results, enabling data chaining.
        """
        registry = get_registry()
        results: List[ToolResult] = []

        output.section(f"Pipeline: {self.name}")
        if self.description:
            output.info(self.description)
        output.info(f"Steps: {' → '.join(self.steps)}\n")

        for i, step in enumerate(self.steps, 1):
            output.info(f"Stage {i}/{len(self.steps)}: {step}")

            tool = registry.get(step)
            if tool is None:
                output.error(f"Tool not found: {step} — skipping")
                results.append(ToolResult(
                    tool_name=step,
                    status="error",
                    error=f"Tool not found in registry",
                ))
                continue

            # Inject pipeline context (previous results) into args
            step_args = args.copy()
            step_args["_pipeline_context"] = [r.to_dict() for r in results]

            # Execute the tool
            result = execute(tool, step_args)
            results.append(result)

            # Log stage result
            if result.status == "success":
                output.success(f"Stage {i} completed ({result.duration_ms:.0f}ms)")
            elif result.status == "error":
                output.error(f"Stage {i} failed: {result.error}")
                logger.error(f"Pipeline '{self.name}' stage {step} failed: {result.error}")
            else:
                output.warning(f"Stage {i}: {result.status}")

        # Summary
        success_count = sum(1 for r in results if r.status == "success")
        output.section("Pipeline Complete")
        output.info(f"{success_count}/{len(self.steps)} stages succeeded")

        total_findings = sum(len(r.findings) for r in results)
        if total_findings:
            output.warning(f"Total findings: {total_findings}")

        return results


# ---------------------------------------------------------------------------
# Profile loader — discovers all YAML profiles in config/profiles/
# ---------------------------------------------------------------------------

def list_profiles(profiles_dir: str = "config/profiles") -> Dict[str, str]:
    """Return a dict of {profile_name: file_path} for all available profiles."""
    profiles = {}
    if not os.path.isdir(profiles_dir):
        return profiles

    for fname in os.listdir(profiles_dir):
        if fname.endswith((".yaml", ".yml")):
            name = fname.rsplit(".", 1)[0]
            profiles[name] = os.path.join(profiles_dir, fname)

    return profiles


def run_profile(profile_name: str, args: Dict[str, Any]) -> List[ToolResult]:
    """Load and execute a named pipeline profile."""
    profiles = list_profiles()

    if profile_name not in profiles:
        output.error(f"Profile '{profile_name}' not found. Available: {', '.join(profiles.keys())}")
        return []

    pipeline = Pipeline.from_yaml(profiles[profile_name])
    return pipeline.run(args)


# Backward-compatible function
def run_pipeline(steps: List[str], args: Dict[str, Any]) -> List[ToolResult]:
    """Run an ad-hoc pipeline from a list of tool steps."""
    pipeline = Pipeline(name="ad-hoc", steps=steps)
    return pipeline.run(args)
