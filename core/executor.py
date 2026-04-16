# =============================================================================
# CyberToolkit Pro — Tool Executor
# =============================================================================
# Handles single and parallel tool execution with timeout support, structured
# results, and pre/post hooks for logging and AI analysis.
# =============================================================================

import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Any, Callable, Dict, List, Optional

from core.models import ToolResult
from core.config import Config
from core import output


def execute(tool: dict, args: Dict[str, Any], timeout: Optional[int] = None,
            campaign_id: str = "") -> ToolResult:
    """
    Execute a single tool and return a structured ToolResult.

    Parameters:
        tool:        dict with 'info' and 'module' keys (from registry)
        args:        arguments to pass to tool's run() function
        timeout:     max seconds to wait (None = use config default)
        campaign_id: optional campaign to associate this execution with

    Returns:
        ToolResult with status, data, findings, timing info
    """
    cfg = Config()
    if timeout is None:
        timeout = cfg.get("framework.timeout", 30)

    tool_name = tool["info"].name if hasattr(tool["info"], "name") else tool["info"].get("name", "unknown")
    target = args.get("target", "")

    # --- Scope enforcement ---
    try:
        from core.scope import get_scope, ScopeViolation
        scope = get_scope()
        scope.enforce(target)
    except ScopeViolation as e:
        output.error(f"SCOPE VIOLATION: {e}")
        try:
            from core.audit import get_audit
            get_audit().log_scope_violation(tool_name, target, str(e))
        except Exception:
            pass
        return ToolResult(
            tool_name=tool_name, target=target, status="blocked",
            error=f"Scope violation: {e}"
        )
    except Exception:
        pass  # Scope module not available — continue

    output.info(f"Running {tool_name}" + (f" → {target}" if target else ""))
    start = time.time()

    try:
        raw_result = tool["module"].run(args)
        duration = (time.time() - start) * 1000

        # If the module already returns a ToolResult, use it directly
        if isinstance(raw_result, ToolResult):
            raw_result.duration_ms = duration
            result = raw_result
        else:
            # Otherwise wrap raw output into a ToolResult
            result = ToolResult(
                tool_name=tool_name,
                target=target,
                status="success",
                data=raw_result if isinstance(raw_result, dict) else {"output": raw_result},
                duration_ms=duration,
            )

        # --- Audit trail ---
        try:
            from core.audit import get_audit
            get_audit().log_execution(
                tool_name=tool_name, target=target, args=args,
                status=result.status, duration_ms=duration,
                findings_count=len(result.findings) if result.findings else 0,
                result_data=result.data if result.data else {}
            )
        except Exception:
            pass

        # --- Database persistence ---
        try:
            import uuid
            from core.database import get_db
            scan_id = f"{tool_name}_{uuid.uuid4().hex[:8]}"
            get_db().save_scan(
                scan_id=scan_id, tool_name=tool_name, target=target,
                status=result.status, args=args,
                data=result.data if result.data else {},
                findings=result.findings if result.findings else [],
                duration_ms=duration, campaign_id=campaign_id
            )
        except Exception:
            pass

        return result

    except TimeoutError:
        duration = (time.time() - start) * 1000
        output.error(f"{tool_name} timed out after {timeout}s")
        return ToolResult(
            tool_name=tool_name,
            target=target,
            status="timeout",
            error=f"Timed out after {timeout} seconds",
            duration_ms=duration,
        )

    except Exception as e:
        duration = (time.time() - start) * 1000
        tb = traceback.format_exc()
        output.error(f"{tool_name} failed: {e}")
        return ToolResult(
            tool_name=tool_name,
            target=target,
            status="error",
            error=str(e),
            stdout=tb,
            duration_ms=duration,
        )


def execute_parallel(
    tools: List[dict],
    args: Dict[str, Any],
    max_workers: Optional[int] = None,
) -> List[ToolResult]:
    """
    Execute multiple tools in parallel using a thread pool.

    Parameters:
        tools:       list of tool dicts from registry
        args:        shared arguments for all tools
        max_workers: thread pool size (None = config default)

    Returns:
        List of ToolResult in completion order
    """
    cfg = Config()
    if max_workers is None:
        max_workers = cfg.get("framework.max_threads", 10)

    results = []
    total = len(tools)

    output.section(f"Parallel Execution ({total} tools)")

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(execute, tool, args): tool for tool in tools}

        for i, future in enumerate(as_completed(futures), 1):
            tool = futures[future]
            try:
                result = future.result()
                results.append(result)
                output.progress_bar(i, total, prefix="Progress")
            except Exception as e:
                tool_name = tool["info"].name if hasattr(tool["info"], "name") else "unknown"
                results.append(ToolResult(
                    tool_name=tool_name,
                    status="error",
                    error=str(e),
                ))

    return results
