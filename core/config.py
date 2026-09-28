# =============================================================================
# CyberToolkit Pro — Configuration System
# =============================================================================
# YAML-based hierarchical config. Loads defaults, then overlays user config.
# Supports environment variable overrides via ${ENV_VAR} syntax in YAML.
# =============================================================================

import os
import re
import yaml
from typing import Any, Dict, Optional


# Default configuration embedded in code — used when no YAML file exists.
DEFAULT_CONFIG: Dict[str, Any] = {
    "framework": {
        "name": "CyberToolkit Pro",
        "version": "2.5.0",
        "log_level": "INFO",
        "log_dir": "logs",
        "report_dir": "reports",
        "max_threads": 10,
        "timeout": 30,
    },
    "scanning": {
        "default_ports": "1-1024",
        "thread_count": 50,
        "timeout": 2,
    },
    "web": {
        "user_agent": "CyberToolkitPro/2.0",
        "timeout": 10,
        "max_redirects": 5,
        "rate_limit_ms": 100,
    },
    "detection": {
        "threshold_requests": 50,
        "threshold_failed_logins": 5,
        "alert_cooldown_seconds": 300,
    },
    "ai": {
        "enabled": True,
        "llm_enabled": False,
        "llm_api_key": "",
        "llm_model": "gpt-4",
        "llm_endpoint": "https://api.openai.com/v1/chat/completions",
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 8443,
    },
}


def _resolve_env_vars(value: Any) -> Any:
    """Replace ${ENV_VAR} placeholders in string values with env var contents."""
    if isinstance(value, str):
        pattern = re.compile(r"\$\{(\w+)\}")
        def replacer(match):
            return os.environ.get(match.group(1), match.group(0))
        return pattern.sub(replacer, value)
    elif isinstance(value, dict):
        return {k: _resolve_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_resolve_env_vars(v) for v in value]
    return value


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class Config:
    """
    Singleton configuration manager.

    Usage:
        cfg = Config()                   # loads defaults
        cfg = Config("config/my.yaml")   # loads defaults + overlay
        cfg.get("scanning.thread_count") # => 50
        cfg.set("scanning.timeout", 5)   # runtime override
    """

    _instance: Optional["Config"] = None
    _data: Dict[str, Any] = {}

    def __new__(cls, config_path: Optional[str] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._data = DEFAULT_CONFIG.copy()
            cls._instance._load(config_path)
        return cls._instance

    @classmethod
    def reset(cls):
        """Reset singleton — used in tests."""
        cls._instance = None

    def _load(self, config_path: Optional[str] = None):
        """Load YAML config file and merge with defaults."""
        # Try default path if none specified
        paths_to_try = []
        if config_path:
            paths_to_try.append(config_path)
        paths_to_try.append("config/default.yaml")

        for path in paths_to_try:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        user_config = yaml.safe_load(f) or {}
                    user_config = _resolve_env_vars(user_config)
                    self._data = _deep_merge(self._data, user_config)
                except Exception as e:
                    print(f"[WARNING] Failed to load config {path}: {e}")

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """
        Get a config value using dotted notation.
        Example: config.get("scanning.thread_count")
        """
        keys = dotted_key.split(".")
        value = self._data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, dotted_key: str, value: Any) -> None:
        """Set a config value at runtime using dotted notation."""
        keys = dotted_key.split(".")
        d = self._data
        for key in keys[:-1]:
            if key not in d or not isinstance(d[key], dict):
                d[key] = {}
            d = d[key]
        d[keys[-1]] = value

    @property
    def data(self) -> dict:
        return self._data
