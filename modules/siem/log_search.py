# =============================================================================
# CyberToolkit Pro — Log Search
# =============================================================================
# Full-text search across log files with regex support, time filtering,
# and structured result output.
# =============================================================================

import os
import re
from core.models import ToolResult

TOOL_INFO = {
    "name": "log_search",
    "category": "siem",
    "description": "Search and filter log files with regex and keyword support",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Log file or directory to search"},
        {"name": "query", "required": True, "description": "Search query (supports regex)"},
        {"name": "case_sensitive", "required": False, "default": "false",
         "description": "Case-sensitive search (true/false)"},
        {"name": "max_results", "required": False, "default": "100",
         "description": "Maximum number of results to return"},
    ],
    "tags": ["blue-team", "siem", "search", "query"],
}


def run(args):
    target = args.get("target", "")
    query = args.get("query", "")

    if not target or not query:
        return ToolResult(tool_name="log_search", status="error",
                          error="Both target and query are required")

    if not os.path.exists(target):
        return ToolResult(tool_name="log_search", status="error",
                          error=f"Path not found: {target}")

    case_sensitive = args.get("case_sensitive", "false").lower() == "true"
    max_results = int(args.get("max_results", 100))

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        pattern = re.compile(query, flags)
    except re.error as e:
        return ToolResult(tool_name="log_search", status="error",
                          error=f"Invalid regex: {e}")

    files = []
    if os.path.isdir(target):
        for fname in sorted(os.listdir(target)):
            fpath = os.path.join(target, fname)
            if os.path.isfile(fpath):
                files.append(fpath)
    else:
        files = [target]

    matches = []
    total_searched = 0

    for filepath in files:
        fname = os.path.basename(filepath)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, 1):
                    total_searched += 1
                    if pattern.search(line):
                        matches.append({
                            "file": fname,
                            "line_number": line_no,
                            "content": line.strip()[:300],
                        })
                        if len(matches) >= max_results:
                            break
        except Exception:
            pass

        if len(matches) >= max_results:
            break

    return ToolResult(
        tool_name="log_search",
        target=target,
        status="success",
        data={
            "query": query,
            "total_lines_searched": total_searched,
            "matches_found": len(matches),
            "matches": matches,
            "truncated": len(matches) >= max_results,
        },
    )
