# =============================================================================
# CyberToolkit Pro — Plugin Manager
# =============================================================================
# Install, update, list, and remove third-party plugins from Git repos
# or local directories.
# =============================================================================

import os
import json
import shutil
import subprocess
from typing import Dict, List, Optional

from core import output
from core.logger import get_logger

logger = get_logger("plugin_manager")

PLUGINS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugins")
PLUGINS_REGISTRY = os.path.join(PLUGINS_DIR, ".registry.json")


class PluginManager:
    """Manage third-party plugin installation and updates."""

    def __init__(self, plugins_dir: str = ""):
        self.plugins_dir = plugins_dir or PLUGINS_DIR
        os.makedirs(self.plugins_dir, exist_ok=True)
        self._registry = self._load_registry()

    def _load_registry(self) -> Dict:
        """Load the installed plugin registry."""
        registry_path = os.path.join(self.plugins_dir, ".registry.json")
        if os.path.exists(registry_path):
            try:
                with open(registry_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"plugins": {}}

    def _save_registry(self):
        """Save the plugin registry."""
        registry_path = os.path.join(self.plugins_dir, ".registry.json")
        with open(registry_path, "w", encoding="utf-8") as f:
            json.dump(self._registry, f, indent=2)

    def install(self, source: str) -> bool:
        """
        Install a plugin from a Git URL or local path.

        Supports:
          - Git URLs: https://github.com/user/plugin-name.git
          - Local paths: /path/to/plugin/
        """
        output.section("Plugin Install")

        if source.startswith(("http://", "https://", "git@")):
            return self._install_from_git(source)
        elif os.path.isdir(source):
            return self._install_from_local(source)
        else:
            output.error(f"Invalid plugin source: {source}")
            output.info("Provide a Git URL or local directory path")
            return False

    def _install_from_git(self, git_url: str) -> bool:
        """Clone a plugin from a Git repository."""
        # Extract plugin name from URL
        name = git_url.rstrip("/").split("/")[-1]
        if name.endswith(".git"):
            name = name[:-4]

        dest = os.path.join(self.plugins_dir, name)
        if os.path.exists(dest):
            output.warning(f"Plugin '{name}' already installed. Use 'update' instead.")
            return False

        try:
            output.info(f"Cloning {git_url}...")
            subprocess.run(
                ["git", "clone", "--depth", "1", git_url, dest],
                check=True, capture_output=True, text=True
            )
            self._registry["plugins"][name] = {
                "source": git_url,
                "type": "git",
                "installed_at": __import__("datetime").datetime.utcnow().isoformat(),
                "path": dest,
            }
            self._save_registry()
            output.success(f"Plugin '{name}' installed successfully")

            # Check for requirements
            req_file = os.path.join(dest, "requirements.txt")
            if os.path.exists(req_file):
                output.info(f"Installing plugin dependencies...")
                subprocess.run(
                    ["pip", "install", "-r", req_file],
                    capture_output=True, text=True
                )

            return True
        except subprocess.CalledProcessError as e:
            output.error(f"Git clone failed: {e.stderr}")
            return False
        except FileNotFoundError:
            output.error("Git is not installed. Please install Git first.")
            return False

    def _install_from_local(self, path: str) -> bool:
        """Install a plugin from a local directory."""
        name = os.path.basename(path.rstrip("/\\"))
        dest = os.path.join(self.plugins_dir, name)

        if os.path.exists(dest):
            output.warning(f"Plugin '{name}' already exists")
            return False

        try:
            shutil.copytree(path, dest)
            self._registry["plugins"][name] = {
                "source": path,
                "type": "local",
                "installed_at": __import__("datetime").datetime.utcnow().isoformat(),
                "path": dest,
            }
            self._save_registry()
            output.success(f"Plugin '{name}' installed from local path")
            return True
        except Exception as e:
            output.error(f"Installation failed: {e}")
            return False

    def update(self, name: str = "") -> bool:
        """Update a plugin (or all plugins if name is empty)."""
        output.section("Plugin Update")

        if name:
            plugins = {name: self._registry["plugins"].get(name)}
            if not plugins[name]:
                output.error(f"Plugin '{name}' not found")
                return False
        else:
            plugins = self._registry.get("plugins", {})

        if not plugins:
            output.info("No plugins installed")
            return False

        for pname, info in plugins.items():
            if not info:
                continue
            if info.get("type") == "git":
                path = info.get("path", os.path.join(self.plugins_dir, pname))
                try:
                    output.info(f"Updating '{pname}'...")
                    subprocess.run(
                        ["git", "-C", path, "pull", "--ff-only"],
                        check=True, capture_output=True, text=True
                    )
                    output.success(f"'{pname}' updated")
                except subprocess.CalledProcessError as e:
                    output.error(f"Update failed for '{pname}': {e.stderr}")
            else:
                output.info(f"'{pname}' is a local plugin — manual update required")

        return True

    def remove(self, name: str) -> bool:
        """Remove an installed plugin."""
        output.section("Plugin Remove")

        if name not in self._registry.get("plugins", {}):
            output.error(f"Plugin '{name}' not found")
            return False

        path = self._registry["plugins"][name].get(
            "path", os.path.join(self.plugins_dir, name)
        )

        try:
            if os.path.exists(path):
                shutil.rmtree(path)
            del self._registry["plugins"][name]
            self._save_registry()
            output.success(f"Plugin '{name}' removed")
            return True
        except Exception as e:
            output.error(f"Remove failed: {e}")
            return False

    def list_plugins(self):
        """List all installed plugins."""
        output.section("Installed Plugins")

        plugins = self._registry.get("plugins", {})
        if not plugins:
            output.info("No plugins installed")
            output.info("Install one with: python main.py plugin install <url>")
            return

        rows = []
        for name, info in plugins.items():
            source = info.get("source", "?")[:50]
            ptype = info.get("type", "?")
            installed = info.get("installed_at", "?")[:10]
            rows.append([name, ptype, source, installed])

        output.table(["Name", "Type", "Source", "Installed"], rows)
