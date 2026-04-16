# =============================================================================
# CyberToolkit Pro — Module Loader
# =============================================================================
# Auto-discovers and loads tool modules from the modules/ and plugins/
# directories. Validates that each module exposes TOOL_INFO and run().
# =============================================================================

import os
import sys
import importlib
import traceback
from typing import List

from core.registry import register
from core import output


def load_all(base_dirs: List[str] = None, quiet: bool = False) -> int:
    """
    Discover and register all tool modules.

    Scans each base directory recursively for .py files that expose
    both TOOL_INFO (dict) and run (callable). Returns the count of
    successfully loaded tools.
    """
    if base_dirs is None:
        base_dirs = ["modules", "plugins"]

    # Ensure project root is on sys.path
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    loaded = 0
    errors = 0

    for base in base_dirs:
        if not os.path.isdir(base):
            continue

        for root, dirs, files in os.walk(base):
            # Skip __pycache__ and hidden dirs
            dirs[:] = [d for d in dirs if not d.startswith(("__", "."))]

            for filename in sorted(files):
                if not filename.endswith(".py") or filename.startswith("__"):
                    continue

                # Convert file path to module path  (modules/scanning/port_scanner.py → modules.scanning.port_scanner)
                rel_path = os.path.relpath(os.path.join(root, filename), project_root)
                mod_path = rel_path.replace(os.sep, ".").replace("/", ".")[:-3]

                try:
                    module = importlib.import_module(mod_path)
                except Exception as e:
                    if not quiet:
                        output.warning(f"Failed to import {mod_path}: {e}")
                    errors += 1
                    continue

                # Validate required exports
                if not hasattr(module, "TOOL_INFO") or not hasattr(module, "run"):
                    continue

                tool_info = module.TOOL_INFO
                if not isinstance(tool_info, dict):
                    if not quiet:
                        output.warning(f"TOOL_INFO in {mod_path} is not a dict, skipping")
                    continue
                if "name" not in tool_info or "category" not in tool_info:
                    if not quiet:
                        output.warning(f"TOOL_INFO in {mod_path} missing name/category, skipping")
                    continue

                try:
                    dotted = register(tool_info, module)
                    loaded += 1
                except Exception as e:
                    if not quiet:
                        output.warning(f"Failed to register {mod_path}: {e}")
                    errors += 1

    if not quiet:
        output.success(f"Loaded {loaded} tools ({errors} errors)")

    return loaded
