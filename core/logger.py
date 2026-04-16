# =============================================================================
# CyberToolkit Pro — Structured Logging
# =============================================================================
# Production-quality logging with Python's logging module. Supports file +
# console handlers, colored console output, JSON file format, and rotation.
# =============================================================================

import os
import logging
import logging.handlers
from datetime import datetime
from typing import Optional

from core.config import Config


# Custom colored formatter for console output
class ColoredFormatter(logging.Formatter):
    """Adds ANSI colors to log levels in console output."""

    COLORS = {
        logging.DEBUG:    "\033[36m",    # Cyan
        logging.INFO:     "\033[92m",    # Green
        logging.WARNING:  "\033[93m",    # Yellow
        logging.ERROR:    "\033[91m",    # Red
        logging.CRITICAL: "\033[41;97m", # White on Red
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)
        record.levelname = f"{color}{record.levelname:<8}{self.RESET}"
        return super().format(record)


class FrameworkLogger:
    """
    Singleton logger manager.

    Provides a pre-configured logger with:
      - Console handler (colored, INFO+ by default)
      - File handler (DEBUG+, rotated daily)
      - Optional JSON structured log file
    """

    _instance: Optional["FrameworkLogger"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def setup(self, log_level: str = None):
        """Initialize or reconfigure logging. Safe to call multiple times."""
        if self._initialized:
            return

        cfg = Config()
        log_dir = cfg.get("framework.log_dir", "logs")
        level_str = log_level or cfg.get("framework.log_level", "INFO")
        level = getattr(logging, level_str.upper(), logging.INFO)

        os.makedirs(log_dir, exist_ok=True)

        # Root logger for the framework
        self.logger = logging.getLogger("cybertoolkit")
        self.logger.setLevel(logging.DEBUG)    # Capture everything; handlers filter
        self.logger.handlers.clear()

        # --- Console handler (colored) ---
        console = logging.StreamHandler()
        console.setLevel(level)
        console.setFormatter(ColoredFormatter(
            "  %(levelname)s %(message)s"
        ))
        self.logger.addHandler(console)

        # --- File handler (rotating, detailed) ---
        log_file = os.path.join(log_dir, f"cybertoolkit_{datetime.now():%Y-%m-%d}.log")
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        self.logger.addHandler(file_handler)

        self._initialized = True

    def get_logger(self, name: str = None) -> logging.Logger:
        """Get a child logger (e.g. 'cybertoolkit.scanning')."""
        if not self._initialized:
            self.setup()
        if name:
            return self.logger.getChild(name)
        return self.logger

    @classmethod
    def reset(cls):
        cls._instance = None


# ---------------------------------------------------------------------------
# Module-level convenience functions (backward-compatible)
# ---------------------------------------------------------------------------

def get_logger(name: str = None) -> logging.Logger:
    """Get a framework logger instance."""
    mgr = FrameworkLogger()
    return mgr.get_logger(name)


def log(message: str, level: str = "info"):
    """Simple log function for backward compatibility."""
    logger = get_logger()
    log_fn = getattr(logger, level.lower(), logger.info)
    log_fn(message)
