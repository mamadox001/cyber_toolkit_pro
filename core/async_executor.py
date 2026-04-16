# =============================================================================
# CyberToolkit Pro — Async Execution Engine
# =============================================================================
# High-performance async executor for network-heavy tools.
# Uses asyncio for concurrent I/O operations, dramatically improving
# speed for port scanning, HTTP fuzzing, and subdomain discovery.
# =============================================================================

import asyncio
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Callable, Optional

from core.models import ToolResult, Finding, Severity
from core.audit import get_audit
from core.scope import get_scope, ScopeViolation
from core.database import get_db


class AsyncExecutor:
    """Async execution engine for high-performance concurrent operations."""

    def __init__(self, max_concurrency: int = 50, timeout: int = 300):
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self._semaphore = None

    async def run_tool_async(self, tool_module, args: Dict,
                              campaign_id: str = "") -> ToolResult:
        """Run a single tool asynchronously with scope/audit integration."""
        info = tool_module.TOOL_INFO
        tool_name = info.get("name", "unknown")
        target = args.get("target", "")
        scan_id = f"{tool_name}_{uuid.uuid4().hex[:8]}"

        # Scope enforcement
        scope = get_scope()
        try:
            scope.enforce(target)
        except ScopeViolation as e:
            get_audit().log_scope_violation(tool_name, target, str(e))
            return ToolResult(
                tool_name=tool_name, target=target, status="blocked",
                error=f"Scope violation: {e}"
            )

        # Execute in thread pool (since most tools are sync)
        start = time.time()
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, tool_module.run, args),
                timeout=self.timeout
            )
            duration = (time.time() - start) * 1000
        except asyncio.TimeoutError:
            duration = (time.time() - start) * 1000
            result = ToolResult(
                tool_name=tool_name, target=target, status="timeout",
                error=f"Timeout after {self.timeout}s", duration_ms=duration
            )
        except Exception as e:
            duration = (time.time() - start) * 1000
            result = ToolResult(
                tool_name=tool_name, target=target, status="error",
                error=str(e), duration_ms=duration
            )

        if hasattr(result, "duration_ms"):
            result.duration_ms = duration

        # Audit trail
        get_audit().log_execution(
            tool_name=tool_name, target=target, args=args,
            status=result.status if hasattr(result, "status") else "unknown",
            duration_ms=duration,
            findings_count=len(result.findings) if hasattr(result, "findings") else 0,
            result_data=result.data if hasattr(result, "data") else {}
        )

        # Database persistence
        try:
            db = get_db()
            db.save_scan(
                scan_id=scan_id, tool_name=tool_name, target=target,
                status=result.status, args=args,
                data=result.data if hasattr(result, "data") else {},
                findings=result.findings if hasattr(result, "findings") else [],
                duration_ms=duration, campaign_id=campaign_id
            )
        except Exception:
            pass

        return result

    async def run_batch(self, tool_module, targets: List[str],
                         base_args: Dict = None,
                         campaign_id: str = "") -> List[ToolResult]:
        """Run a tool against multiple targets concurrently."""
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        base_args = base_args or {}

        async def _run_one(target):
            async with self._semaphore:
                args = {**base_args, "target": target}
                return await self.run_tool_async(tool_module, args, campaign_id)

        tasks = [_run_one(t) for t in targets]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def run_pipeline_async(self, steps: List[Dict],
                                   initial_args: Dict,
                                   campaign_id: str = "") -> List[ToolResult]:
        """Run a pipeline with data chaining between steps."""
        from core.registry import get_registry
        registry = get_registry()
        results = []
        chain_data = dict(initial_args)

        for step in steps:
            tool_path = step.get("tool", "")
            tool = registry.get(tool_path)
            if tool is None:
                results.append(ToolResult(
                    tool_name=tool_path, target=chain_data.get("target", ""),
                    status="error", error=f"Tool '{tool_path}' not found"
                ))
                continue

            # Merge step-specific args with chain data
            step_args = {**chain_data}
            step_args.update(step.get("args", {}))

            module = tool["module"]
            result = await self.run_tool_async(module, step_args, campaign_id)
            results.append(result)

            # Chain data from this result into next step
            if hasattr(result, "data") and result.data:
                chain_data["_previous_result"] = result.data
                # Auto-extract useful data for chaining
                if "open_ports" in result.data:
                    chain_data["ports"] = result.data["open_ports"]
                if "subdomains" in result.data:
                    chain_data["subdomains"] = result.data["subdomains"]
                if "technologies" in result.data:
                    chain_data["technologies"] = result.data["technologies"]

        return results


def run_async(coro):
    """Run an async coroutine from synchronous code."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# Convenience function
def execute_async(tool_module, args: Dict, campaign_id: str = "") -> ToolResult:
    """Execute a tool asynchronously (sync wrapper)."""
    executor = AsyncExecutor()
    return run_async(executor.run_tool_async(tool_module, args, campaign_id))
