# =============================================================================
# CyberToolkit Pro — Plugin Base Class
# =============================================================================
# Enhanced base class for plugins. Plugins can either be simple modules
# with TOOL_INFO + run(), or classes extending BaseTool for lifecycle hooks.
# =============================================================================

from typing import Any, Dict
from core.models import ToolResult


class BaseTool:
    """
    Base class for object-oriented plugins.

    Subclass this to create tools with setup/teardown lifecycle, built-in
    logging, and structured result output. Simpler tools can remain as
    plain modules with TOOL_INFO dict and run() function.

    Example:
        class MyScanner(BaseTool):
            TOOL_INFO = {
                "name": "my_scanner",
                "category": "scanning",
                "description": "Custom scanner plugin",
                "args": [{"name": "target", "required": True}]
            }

            def execute(self, args):
                # Your logic here
                return {"ports": [80, 443]}
    """

    TOOL_INFO: Dict[str, Any] = {}

    def setup(self, args: Dict[str, Any]) -> None:
        """Called before execute(). Override for initialization."""
        pass

    def execute(self, args: Dict[str, Any]) -> Any:
        """Main tool logic. Override this in subclasses."""
        raise NotImplementedError("Subclasses must implement execute()")

    def teardown(self, args: Dict[str, Any]) -> None:
        """Called after execute(). Override for cleanup."""
        pass

    def run(self, args: Dict[str, Any]) -> ToolResult:
        """
        Full lifecycle wrapper. Calls setup → execute → teardown.
        Returns a structured ToolResult.
        """
        tool_name = self.TOOL_INFO.get("name", self.__class__.__name__)
        target = args.get("target", "")

        try:
            self.setup(args)
            result_data = self.execute(args)

            if isinstance(result_data, ToolResult):
                return result_data

            return ToolResult(
                tool_name=tool_name,
                target=target,
                status="success",
                data=result_data if isinstance(result_data, dict) else {"output": result_data},
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                target=target,
                status="error",
                error=str(e),
            )
        finally:
            try:
                self.teardown(args)
            except Exception:
                pass


# Module-level function so the loader can auto-register class-based tools
def make_module_compatible(tool_class):
    """
    Decorator that creates module-level TOOL_INFO and run() from a BaseTool class.
    This enables class-based plugins to be auto-discovered by the loader.

    Usage:
        @make_module_compatible
        class MyTool(BaseTool):
            ...

    After decoration, the module will have TOOL_INFO and run() at module level.
    """
    import sys
    instance = tool_class()
    module = sys.modules[tool_class.__module__]
    module.TOOL_INFO = tool_class.TOOL_INFO
    module.run = instance.run
    return tool_class
