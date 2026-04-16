# =============================================================================
# CyberToolkit Pro — Tool Registry
# =============================================================================
# Central registry for all loaded tools. Provides registration, lookup,
# search, and enumeration of tools by category or dotted path.
#
# Architecture decision: We store tools in a flat dict keyed by
# "category.tool_name" for O(1) lookup, plus a category index for browsing.
# =============================================================================

from typing import Any, Dict, List, Optional
from core.models import ToolInfo


class ToolRegistry:
    """
    Singleton registry holding all discovered tools.

    Tools are indexed two ways:
      1. By dotted path  "scanning.port_scanner"  → for direct lookup
      2. By category     "scanning"                → for browsing
    """

    _instance: Optional["ToolRegistry"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tools: Dict[str, dict] = {}        # dotted_path → {info, module}
            cls._instance._categories: Dict[str, list] = {}   # category → [dotted_paths]
        return cls._instance

    @classmethod
    def reset(cls):
        cls._instance = None

    # ----- Registration -----

    def register(self, tool_info: dict, module: Any) -> str:
        """
        Register a tool module with its metadata.
        Returns the dotted path (e.g. "scanning.port_scanner").
        """
        info = ToolInfo.from_dict(tool_info) if isinstance(tool_info, dict) else tool_info
        dotted = f"{info.category}.{info.name}"

        self._tools[dotted] = {
            "info": info,
            "module": module,
        }

        if info.category not in self._categories:
            self._categories[info.category] = []
        if dotted not in self._categories[info.category]:
            self._categories[info.category].append(dotted)

        return dotted

    # ----- Lookup -----

    def get(self, dotted_path: str) -> Optional[dict]:
        """Get a tool by dotted path (e.g. 'scanning.port_scanner')."""
        return self._tools.get(dotted_path)

    def get_module(self, dotted_path: str):
        """Get just the module for a tool."""
        tool = self._tools.get(dotted_path)
        return tool["module"] if tool else None

    def get_info(self, dotted_path: str) -> Optional[ToolInfo]:
        """Get just the ToolInfo for a tool."""
        tool = self._tools.get(dotted_path)
        return tool["info"] if tool else None

    # ----- Enumeration -----

    def categories(self) -> List[str]:
        """Return sorted list of all categories."""
        return sorted(self._categories.keys())

    def tools_in_category(self, category: str) -> List[dict]:
        """Return all tools in a category."""
        paths = self._categories.get(category, [])
        return [self._tools[p] for p in paths if p in self._tools]

    def all_tools(self) -> Dict[str, dict]:
        """Return all registered tools."""
        return self._tools.copy()

    def tool_count(self) -> int:
        return len(self._tools)

    # ----- Search -----

    def search(self, query: str) -> List[dict]:
        """Search tools by name, description, or tags."""
        query_lower = query.lower()
        results = []
        for path, tool in self._tools.items():
            info = tool["info"]
            searchable = f"{info.name} {info.description} {' '.join(getattr(info, 'tags', []))}".lower()
            if query_lower in searchable or query_lower in path:
                results.append(tool)
        return results

    def __contains__(self, dotted_path: str) -> bool:
        return dotted_path in self._tools

    def __len__(self) -> int:
        return len(self._tools)


# ---------------------------------------------------------------------------
# Module-level convenience functions for backward compatibility
# ---------------------------------------------------------------------------

def register(tool_info: dict, module: Any) -> str:
    """Register a tool. Returns dotted path."""
    return ToolRegistry().register(tool_info, module)


def get_registry() -> ToolRegistry:
    """Get the global ToolRegistry singleton."""
    return ToolRegistry()
