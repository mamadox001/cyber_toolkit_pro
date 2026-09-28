# =============================================================================
# CyberToolkit Pro — Hacker TUI (Textual User Interface)
# =============================================================================
# An immersive, animated terminal interface combining real-time log
# streaming, tool execution, and dynamic statistics.
# =============================================================================

import sys
import os
import asyncio
from datetime import datetime

# Prevent module errors if textual is not installed
try:
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Tree, Log, Static, Label, Button, Input
    from textual.containers import Container, Horizontal, Vertical
    from textual.reactive import reactive
    from textual import work

    from rich.text import Text
    from rich.panel import Panel
    from rich.align import Align
except ImportError:
    print("[!] Textual or Rich not installed. Run: pip install textual rich")
    sys.exit(1)

from core.registry import get_registry
from core.database import get_db
from core.async_executor import AsyncExecutor

class StatsPanel(Static):
    """Real-time statistics reacting to database changes."""

    scans_run = reactive(0)
    findings = reactive(0)
    crit_count = reactive(0)
    high_count = reactive(0)

    def on_mount(self) -> None:
        self.update_stats()
        self.set_interval(5.0, self.update_stats)

    def update_stats(self) -> None:
        try:
            db = get_db()
            stats = db.get_dashboard_stats()
            self.scans_run = stats.get("total_scans", 0)
            self.findings = stats.get("total_findings", 0)
            sev = stats.get("severity_breakdown", {})
            self.crit_count = sev.get("critical", 0)
            self.high_count = sev.get("high", 0)
        except Exception:
            pass

    def render(self) -> Panel:
        content = (
            f"\n[bold cyan]TARGETS SCANNED:[/bold cyan] {self.scans_run}\n"
            f"[bold red]VULNERABILITIES:[/bold red] {self.findings}\n"
            f"[bold magenta]CRITICAL:[/bold magenta] {self.crit_count}\n"
            f"[bold yellow]HIGH:[/bold yellow] {self.high_count}\n\n"
            "[green]SYSTEM STATUS: ONLINE[/green]\n"
            "[green]ASYNC ENGINE: ACTIVE[/green]\n"
            "[yellow]SCOPE ENFORCEMENT: OK[/yellow]"
        )
        return Panel(content, title="[bold]TELEMETRY[/bold]", border_style="cyan")


class CyberTUI(App):
    """The main TUI Application."""

    CSS = """
    Screen {
        background: $surface-darken-3;
    }

    #main_container {
        height: 100%;
        layout: horizontal;
    }

    #sidebar {
        width: 30%;
        border-right: solid $accent;
        height: 100%;
        padding: 1;
    }

    #console {
        width: 50%;
        height: 100%;
        border: solid $accent;
        background: black;
        padding: 1 2;
    }

    #right_panel {
        width: 20%;
        height: 100%;
        border-left: solid $accent;
        padding: 1;
    }

    #target_input {
        dock: bottom;
        margin: 1 0 0 0;
    }

    Tree {
        background: transparent;
        color: lime;
    }

    Log {
        background: black;
        color: #00FF00;
        border: none;
    }

    Input {
        background: #1a1a2e;
        color: #00FF00;
        border: solid #00FF00;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit Framework"),
        ("r", "run_selected", "Run Selected Tool"),
        ("c", "clear_log", "Clear Terminal"),
    ]

    def __init__(self):
        super().__init__()
        self.registry = get_registry()
        self.executor = AsyncExecutor()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal(id="main_container"):
            # Left Panel: Tool Tree
            with Vertical(id="sidebar"):
                yield Label("[bold cyan]MODULE INFRASTRUCTURE[/bold cyan]")
                tree = Tree("CyberToolkit Pro")
                tree.root.expand()

                # Populate tree
                for cat in sorted(self.registry.categories()):
                    cat_node = tree.root.add(cat.upper(), expand=True)
                    for tool in self.registry.tools_in_category(cat):
                        name = tool["info"].name if hasattr(tool["info"], "name") else tool["info"].get("name")
                        cat_node.add_leaf(name)
                yield tree

                yield Label("\n[bold]TARGET IP/DOMAIN:[/bold]")
                yield Input(
                    placeholder="Enter target IP or domain...",
                    id="target_input",
                    value="127.0.0.1",
                )

            # Center Panel: Console Log
            with Vertical(id="console"):
                yield Label("[bold]EXECUTION TERMINAL[/bold]")
                yield Log(id="terminal_log", highlight=True)

            # Right Panel: Stats
            with Vertical(id="right_panel"):
                yield StatsPanel()

        yield Footer()

    def on_mount(self) -> None:
        self.log_msg("Initializing CyberToolkit Pro v2.5...")
        self.log_msg("[*] Loading modules...")
        self.log_msg(f"[*] {self.registry.tool_count()} modules loaded.")
        self.log_msg("[*] System Ready. Select a tool and press 'r' to execute.")

    def log_msg(self, message: str) -> None:
        log = self.query_one(Log)
        time_str = datetime.now().strftime("%H:%M:%S")
        log.write_line(f"[{time_str}] {message}")

    def log_finding(self, severity: str, title: str) -> None:
        """Log a finding with color-coded severity."""
        sev_colors = {
            "critical": "[bold white on red]",
            "high": "[bold red]",
            "medium": "[bold yellow]",
            "low": "[bold green]",
            "info": "[bold blue]",
        }
        color = sev_colors.get(severity, "[bold white]")
        self.log_msg(f"  {color}[{severity.upper()}][/] {title}")

    def action_clear_log(self) -> None:
        self.query_one(Log).clear()

    def _get_target(self) -> str:
        """Get target from the Input widget."""
        try:
            target_input = self.query_one("#target_input", Input)
            return target_input.value.strip() or "127.0.0.1"
        except Exception:
            return "127.0.0.1"

    @work(exclusive=True, thread=True)
    def run_tool(self, tool_name: str, target: str) -> None:
        """Run tool asynchronously in background thread to prevent UI freeze."""
        tool = None
        for path, t in self.registry._tools.items():
            name = t["info"].name if hasattr(t["info"], "name") else t["info"].get("name")
            if name == tool_name:
                tool = t
                break

        if not tool:
            self.app.call_from_thread(self.log_msg, f"[!] Tool {tool_name} not found")
            return

        self.app.call_from_thread(self.log_msg, f"\n[>>>] LAUNCHING: {tool_name}")
        self.app.call_from_thread(self.log_msg, f"[>>>] TARGET: {target}")

        args = {"target": target}

        import time
        start = time.time()

        try:
            from core.executor import execute
            result = execute(tool, args)

            dur = round(time.time() - start, 2)
            self.app.call_from_thread(self.log_msg, f"[*] Completed in {dur}s")
            self.app.call_from_thread(self.log_msg, f"[*] Status: {result.status.upper()}")

            if result.findings:
                self.app.call_from_thread(
                    self.log_msg,
                    f"[!] WARNING: {len(result.findings)} findings detected!"
                )
                for f in result.findings:
                    sev = f.severity.value if hasattr(f, "severity") and hasattr(f.severity, "value") else "info"
                    title = f.title if hasattr(f, "title") else str(f)
                    self.app.call_from_thread(self.log_finding, sev, title)
            else:
                self.app.call_from_thread(self.log_msg, f"[*] No vulnerabilities found.")

            # Trigger stats update
            stats_panel = self.query_one(StatsPanel)
            self.app.call_from_thread(stats_panel.update_stats)

        except Exception as e:
            self.app.call_from_thread(self.log_msg, f"[!] FATAL ERROR: {str(e)}")

    def action_run_selected(self) -> None:
        tree = self.query_one(Tree)
        if not tree.cursor_node or not tree.cursor_node.is_leaf:
            self.log_msg("[!] Please select a valid module leaf node.")
            return

        tool_name = str(tree.cursor_node.label)
        target = self._get_target()

        # Fire and forget async worker
        self.run_tool(tool_name, target)


def start_tui():
    """Start the Textual TUI."""
    # Pre-load tools so the registry is populated
    from core.loader import load_all
    load_all(quiet=True)

    app = CyberTUI()
    app.run()

if __name__ == "__main__":
    start_tui()
