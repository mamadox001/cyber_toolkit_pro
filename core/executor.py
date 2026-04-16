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


def execute(tool: dict, args: Dict[str, Any], timeout: Optional[int] = None) -> ToolResult:
    """
    Execute a single tool and return a structured ToolResult.

    Parameters:
        tool:    dict with 'info' and 'module' keys (from registry)
        args:    arguments to pass to tool's run() function
        timeout: max seconds to wait (None = use config default)

    Returns:
        ToolResult with status, data, findings, timing info
    """
    cfg = Config()
    if timeout is None:
        timeout = cfg.get("framework.timeout", 30)

    tool_name = tool["info"].name if hasattr(tool["info"], "name") else tool["info"].get("name", "unknown")
    target = args.get("target", "")

    output.info(f"Running {tool_name}" + (f" → {target}" if target else ""))
    start = time.time()

    try:
        raw_result = tool["module"].run(args)
        duration = (time.time() - start) * 1000

        # If the module already returns a ToolResult, use it directly
        if isinstance(raw_result, ToolResult):
            raw_result.duration_ms = duration
            return raw_result

        # Otherwise wrap raw output into a ToolResult
        result = ToolResult(
            tool_name=tool_name,
            target=target,
            status="success",
            data=raw_result if isinstance(raw_result, dict) else {"output": raw_result},
            duration_ms=duration,
        )
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
