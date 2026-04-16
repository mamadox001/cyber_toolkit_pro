# =============================================================================
# CyberToolkit Pro — Interactive Shell
# =============================================================================
# Full-featured interactive REPL with command history, help system,
# category browsing, tool argument prompting, and autocomplete support.
# =============================================================================

import sys
import json
from typing import Optional

from core.registry import get_registry
from core.executor import execute
from core.suggester import suggest
from core.pipeline import run_profile, run_pipeline, list_profiles
from core import output
from core.logger import get_logger

logger = get_logger("cli")


# ---------------------------------------------------------------------------
# Readline setup for command history and autocomplete (where available)
# ---------------------------------------------------------------------------
def _setup_readline():
    """Attempt to configure readline for history and tab completion."""
    try:
        import readline
        import rlcompleter

        commands = [
            "run", "list", "search", "pipeline", "profiles",
            "help", "exit", "quit", "clear", "back",
        ]

        def completer(text, state):
            registry = get_registry()
            options = commands + list(registry.all_tools().keys())
            matches = [o for o in options if o.startswith(text)]
            if state < len(matches):
                return matches[state]
            return None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass  # readline not available (some Windows installs)


def _prompt(text: str, default: str = "") -> str:
    """Prompt for input with optional default value."""
    if default:
        prompt_text = f"  {text} [{default}]: "
    else:
        prompt_text = f"  {text}: "
    try:
        value = input(prompt_text).strip()
        return value if value else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def _collect_args(tool_info) -> dict:
    """
    Prompt the user for tool arguments based on the arg schema.
    """
    args = {}
    arg_schemas = []

    if hasattr(tool_info, "args"):
        arg_schemas = tool_info.args
    elif isinstance(tool_info, dict):
        arg_schemas = tool_info.get("args", [])

    if not arg_schemas:
        # Fallback: just ask for target
        target = _prompt("Target (IP/hostname)", "")
        if target:
            args["target"] = target
        return args

    for arg in arg_schemas:
        name = arg.name if hasattr(arg, "name") else arg.get("name", "")
        desc = arg.description if hasattr(arg, "description") else arg.get("description", "")
        required = arg.required if hasattr(arg, "required") else arg.get("required", False)
        default = arg.default if hasattr(arg, "default") else arg.get("default", "")

        label = f"{name}"
        if desc:
            label += f" ({desc})"
        if required:
            label += " *"

        value = _prompt(label, str(default) if default else "")

        if value:
            args[name] = value
        elif required:
            output.warning(f"Required argument '{name}' not provided")

    return args


def interactive_shell():
    """Main interactive shell loop."""
    _setup_readline()

    output.info("Interactive mode — type 'help' for commands, 'exit' to quit\n")

    while True:
        try:
            cmd = input(f"\n  {output.Colors.CYAN}cybertk{output.Colors.RESET} > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n")
            output.info("Goodbye!")
            break

        if not cmd:
            continue

        parts = cmd.split(maxsplit=1)
        command = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if command in ("exit", "quit", "q"):
            output.info("Goodbye!")
            break

        elif command == "help":
            _show_help()

        elif command == "clear":
            import os
            os.system("cls" if os.name == "nt" else "clear")
            output.banner()

        elif command in ("list", "ls"):
            _cmd_list(arg)

        elif command == "search":
            _cmd_search(arg)

        elif command == "run":
            _cmd_run(arg)

        elif command in ("use", "select"):
            _cmd_run(arg)

        elif command == "pipeline":
            _cmd_pipeline(arg)

        elif command == "profiles":
            _cmd_profiles()

        elif command == "categories":
            _cmd_categories()

        elif "." in command:
            # Direct tool invocation  e.g. "scanning.port_scanner"
            _cmd_run(command)

        else:
            output.warning(f"Unknown command: '{command}'. Type 'help' for available commands.")


def _show_help():
    """Display help information."""
    output.section("Commands")
    rows = [
        ["list [category]", "List tools (optionally filter by category)"],
        ["categories", "List all tool categories"],
        ["search <query>", "Search for tools by name/description"],
        ["run <tool.path>", "Run a tool (e.g. run scanning.port_scanner)"],
        ["<tool.path>", "Shorthand: run a tool directly"],
        ["pipeline <name>", "Run a pipeline profile"],
        ["profiles", "List available pipeline profiles"],
        ["clear", "Clear screen"],
        ["help", "Show this help"],
        ["exit", "Exit the shell"],
    ]
    output.table(["Command", "Description"], rows)


def _cmd_categories():
    """List all categories."""
    registry = get_registry()
    output.section("Tool Categories")
    for cat in registry.categories():
        count = len(registry.tools_in_category(cat))
        icon = _category_icon(cat)
        print(f"  {icon} {output.Colors.BOLD}{cat}{output.Colors.RESET}  ({count} tools)")


def _category_icon(cat: str) -> str:
    """Return an icon for a category."""
    icons = {
        "reconnaissance": "🔍",
        "scanning":       "📡",
        "web":            "🌐",
        "exploitation":   "💣",
        "passwords":      "🔑",
        "detection":      "🛡️",
        "log_analysis":   "📋",
        "forensics":      "🔬",
        "siem":           "📊",
        "reporting":      "📝",
    }
    return icons.get(cat, "🔧")


def _cmd_list(category_filter: str = ""):
    """List tools, optionally filtered by category."""
    registry = get_registry()
    categories = registry.categories()

    if category_filter:
        categories = [c for c in categories if c == category_filter]
        if not categories:
            output.warning(f"No category '{category_filter}' found")
            return

    for cat in categories:
        tools = registry.tools_in_category(cat)
        icon = _category_icon(cat)
        output.section(f"{icon}  {cat.upper()}")
        rows = []
        for t in tools:
            info = t["info"]
            name = info.name if hasattr(info, "name") else info.get("name", "")
            desc = info.description if hasattr(info, "description") else info.get("description", "")
            rows.append([f"{cat}.{name}", desc[:55] if desc else "(no description)"])
        output.table(["Tool Path", "Description"], rows)


def _cmd_search(query: str):
    """Search tools."""
    if not query:
        output.warning("Usage: search <query>")
        return

    registry = get_registry()
    results = registry.search(query)

    if not results:
        output.warning(f"No tools found for '{query}'")
        return

    output.section(f"Search: '{query}'")
    rows = []
    for t in results:
        info = t["info"]
        name = info.name if hasattr(info, "name") else info.get("name", "")
        cat = info.category if hasattr(info, "category") else info.get("category", "")
        desc = info.description if hasattr(info, "description") else info.get("description", "")
        rows.append([f"{cat}.{name}", desc[:55]])
    output.table(["Tool", "Description"], rows)


def _cmd_run(tool_path: str):
    """Run a specific tool."""
    if not tool_path:
        output.warning("Usage: run <category.tool_name>")
        return

    registry = get_registry()
    tool = registry.get(tool_path)

    if tool is None:
        # Fuzzy search suggestion
        matches = registry.search(tool_path.split(".")[-1] if "." in tool_path else tool_path)
        output.error(f"Tool '{tool_path}' not found")
        if matches:
            output.info("Did you mean:")
            for m in matches[:5]:
                info = m["info"]
                name = info.name if hasattr(info, "name") else info.get("name", "")
                cat = info.category if hasattr(info, "category") else info.get("category", "")
                print(f"    → {cat}.{name}")
        return

    # Show tool info
    info = tool["info"]
    name = info.name if hasattr(info, "name") else info.get("name", "")
    desc = info.description if hasattr(info, "description") else info.get("description", "")
    cat = info.category if hasattr(info, "category") else info.get("category", "")
    output.section(f"Tool: {name}")
    if desc:
        output.info(desc)
    print()

    # Collect arguments
    args = _collect_args(info)

    # Execute
    result = execute(tool, args)

    # Display results
    if result.data:
        output.section("Results")
        for key, value in result.data.items():
            if isinstance(value, list):
                print(f"  {output.Colors.BOLD}{key}{output.Colors.RESET}:")
                for item in value[:50]:  # Limit display
                    print(f"    • {item}")
                if len(value) > 50:
                    print(f"    ... and {len(value)-50} more")
            elif isinstance(value, dict):
                print(f"  {output.Colors.BOLD}{key}{output.Colors.RESET}:")
                for k, v in value.items():
                    print(f"    {k}: {v}")
            else:
                print(f"  {output.Colors.BOLD}{key}{output.Colors.RESET}: {value}")

    if result.findings:
        output.section("Findings")
        for f in result.findings:
            sev = f.severity.value if hasattr(f, 'severity') and hasattr(f.severity, 'value') else "info"
            title = f.title if hasattr(f, 'title') else str(f)
            print(f"  {output.severity_badge(sev)} {title}")
            if hasattr(f, 'description') and f.description:
                print(f"    {output.Colors.DIM}{f.description}{output.Colors.RESET}")

    if result.error:
        output.error(f"Error: {result.error}")

    # AI suggestions
    suggest(category=cat, result=result)


def _cmd_pipeline(profile_name: str):
    """Run a pipeline profile."""
    if not profile_name:
        output.warning("Usage: pipeline <profile_name>")
        _cmd_profiles()
        return

    target = _prompt("Target", "")
    args = {"target": target}
    run_profile(profile_name, args)


def _cmd_profiles():
    """List available pipeline profiles."""
    profiles = list_profiles()
    if not profiles:
        output.warning("No pipeline profiles found in config/profiles/")
        return

    output.section("Pipeline Profiles")
    rows = [[name, path] for name, path in profiles.items()]
    output.table(["Profile", "Config File"], rows)


# Backward compatibility
def interactive():
    """Legacy entry point — redirects to new shell."""
    interactive_shell()
