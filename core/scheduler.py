# =============================================================================
# CyberToolkit Pro — Scan Scheduler
# =============================================================================
# Schedule one-time or recurring scans. Persists schedules to SQLite
# and executes tools on a background thread.
# =============================================================================

import threading
import time
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable

from core.config import Config
from core.database import get_db
from core.logger import get_logger
from core import output

logger = get_logger("scheduler")


class ScheduledTask:
    """Represents a scheduled scan task."""

    def __init__(self, task_id: str, tool_path: str, args: Dict,
                 cron_expr: str = "", run_at: str = "",
                 repeat_interval_minutes: int = 0,
                 description: str = ""):
        self.task_id = task_id
        self.tool_path = tool_path
        self.args = args
        self.cron_expr = cron_expr
        self.run_at = run_at
        self.repeat_interval_minutes = repeat_interval_minutes
        self.description = description
        self.status = "pending"
        self.last_run = None
        self.run_count = 0
        self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict:
        return {
            "task_id": self.task_id,
            "tool_path": self.tool_path,
            "args": self.args,
            "repeat_interval_minutes": self.repeat_interval_minutes,
            "run_at": self.run_at,
            "description": self.description,
            "status": self.status,
            "last_run": self.last_run,
            "run_count": self.run_count,
            "created_at": self.created_at,
        }


class ScanScheduler:
    """Manages scheduled and recurring scan tasks."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._tasks: Dict[str, ScheduledTask] = {}
        self._timers: Dict[str, threading.Timer] = {}
        self._running = True
        self._lock = threading.Lock()

    def schedule_once(self, tool_path: str, args: Dict,
                       run_at: datetime, description: str = "") -> str:
        """Schedule a one-time scan at a specific time."""
        task_id = f"sched_{uuid.uuid4().hex[:8]}"
        task = ScheduledTask(
            task_id=task_id, tool_path=tool_path, args=args,
            run_at=run_at.isoformat(), description=description
        )
        self._tasks[task_id] = task

        delay = (run_at - datetime.utcnow()).total_seconds()
        if delay <= 0:
            delay = 1  # Run immediately if in the past

        timer = threading.Timer(delay, self._execute_task, args=[task_id])
        timer.daemon = True
        timer.start()
        self._timers[task_id] = timer

        logger.info(f"Scheduled one-time task {task_id}: {tool_path} at {run_at}")
        output.success(f"Scheduled task {task_id}: {tool_path} → runs at {run_at.strftime('%Y-%m-%d %H:%M:%S')}")
        return task_id

    def schedule_recurring(self, tool_path: str, args: Dict,
                            interval_minutes: int,
                            description: str = "") -> str:
        """Schedule a recurring scan at fixed intervals."""
        task_id = f"recur_{uuid.uuid4().hex[:8]}"
        task = ScheduledTask(
            task_id=task_id, tool_path=tool_path, args=args,
            repeat_interval_minutes=interval_minutes,
            description=description
        )
        self._tasks[task_id] = task

        self._schedule_next_run(task_id)
        logger.info(f"Scheduled recurring task {task_id}: {tool_path} every {interval_minutes}m")
        output.success(f"Scheduled recurring task {task_id}: {tool_path} every {interval_minutes} minutes")
        return task_id

    def _schedule_next_run(self, task_id: str):
        """Schedule the next execution of a recurring task."""
        task = self._tasks.get(task_id)
        if not task or task.status == "cancelled":
            return

        delay = task.repeat_interval_minutes * 60
        timer = threading.Timer(delay, self._execute_task, args=[task_id])
        timer.daemon = True
        timer.start()
        self._timers[task_id] = timer

    def _execute_task(self, task_id: str):
        """Execute a scheduled task."""
        task = self._tasks.get(task_id)
        if not task or task.status == "cancelled":
            return

        with self._lock:
            task.status = "running"

        logger.info(f"Executing scheduled task {task_id}: {task.tool_path}")

        try:
            from core.registry import get_registry
            from core.executor import execute

            registry = get_registry()
            tool = registry.get(task.tool_path)
            if tool is None:
                logger.error(f"Scheduled task {task_id}: tool '{task.tool_path}' not found")
                task.status = "error"
                return

            result = execute(tool, task.args)
            task.last_run = datetime.utcnow().isoformat()
            task.run_count += 1
            task.status = "completed" if not task.repeat_interval_minutes else "pending"

            # Notify on completion
            try:
                from core.notifier import get_notifier
                get_notifier().notify_scan_complete(
                    task.tool_path, task.args.get("target", ""),
                    result.status,
                    len(result.findings) if result.findings else 0,
                    result.duration_ms
                )
            except Exception:
                pass

            # Schedule next run if recurring
            if task.repeat_interval_minutes:
                self._schedule_next_run(task_id)

        except Exception as e:
            logger.error(f"Scheduled task {task_id} failed: {e}")
            task.status = "error"

    def cancel(self, task_id: str) -> bool:
        """Cancel a scheduled task."""
        task = self._tasks.get(task_id)
        if not task:
            return False

        task.status = "cancelled"
        timer = self._timers.pop(task_id, None)
        if timer:
            timer.cancel()

        output.info(f"Cancelled task {task_id}")
        return True

    def list_tasks(self) -> List[Dict]:
        """List all scheduled tasks."""
        return [t.to_dict() for t in self._tasks.values()]

    def get_task(self, task_id: str) -> Optional[Dict]:
        """Get a specific task."""
        task = self._tasks.get(task_id)
        return task.to_dict() if task else None

    def cancel_all(self):
        """Cancel all scheduled tasks."""
        for task_id in list(self._timers.keys()):
            self.cancel(task_id)


# Module-level singleton
_scheduler = None


def get_scheduler() -> ScanScheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = ScanScheduler()
    return _scheduler
