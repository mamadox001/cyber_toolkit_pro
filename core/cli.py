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

        elif command == "history":
            _cmd_history(arg)

        elif command == "export":
            _cmd_export(arg)

        elif command == "target":
            _cmd_target(arg)

        elif command == "vault":
            _cmd_vault(arg)

        elif command == "diff":
            _cmd_diff(arg)

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
        ["history [N]", "Show last N scans (default 20)"],
        ["export <scan_id>", "Export scan result to JSON"],
        ["target [list|add|notes]", "Manage targets"],
        ["vault [list|set|get|del]", "Manage credential vault"],
        ["diff <id1> <id2>", "Compare two scan results"],
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
        "osint":          "🕵️",
        "network":        "🔌",
        "wireless":       "📶",
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


# ---------------------------------------------------------------------------
# New CLI commands: history, export, target, vault, diff
# ---------------------------------------------------------------------------

def _cmd_history(arg: str):
    """Show recent scan history from the database."""
    try:
        from core.database import get_db
        limit = int(arg) if arg.strip().isdigit() else 20
        db = get_db()
        scans = db.get_scans(limit=limit)

        if not scans:
            output.info("No scan history found")
            return

        output.section(f"Scan History (last {limit})")
        rows = []
        for s in scans:
            sid = s.get("scan_id", "?")[:20]
            tool = s.get("tool_name", "?")
            target = s.get("target", "?")[:25]
            status = s.get("status", "?")
            date = s.get("created_at", "?")[:19]
            findings = s.get("findings_count", 0)
            rows.append([sid, tool, target, status, str(findings), date])
        output.table(["Scan ID", "Tool", "Target", "Status", "Findings", "Date"], rows)
    except Exception as e:
        output.error(f"Failed to load history: {e}")


def _cmd_export(arg: str):
    """Export a scan result to JSON."""
    if not arg.strip():
        output.warning("Usage: export <scan_id>")
        output.info("Use 'history' to see available scan IDs")
        return

    try:
        from core.database import get_db
        import json
        db = get_db()
        scan_id = arg.strip()
        scan = db.get_scan(scan_id)

        if not scan:
            output.error(f"Scan '{scan_id}' not found")
            return

        findings = db.get_findings(scan_id=scan_id)
        scan["findings_detail"] = findings

        filename = f"reports/{scan_id}.json"
        import os
        os.makedirs("reports", exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(scan, f, indent=2, default=str)
        output.success(f"Exported to {filename}")
    except Exception as e:
        output.error(f"Export failed: {e}")


def _cmd_target(arg: str):
    """Manage targets — list, add, or add notes."""
    try:
        from core.database import get_db
        db = get_db()

        parts = arg.strip().split(maxsplit=1)
        action = parts[0] if parts else "list"

        if action == "list" or not action:
            targets = db.get_targets()
            if not targets:
                output.info("No targets recorded yet")
                return
            output.section("Known Targets")
            rows = []
            for t in targets:
                rows.append([
                    t.get("target", "?"),
                    t.get("target_type", "?"),
                    str(t.get("scan_count", 0)),
                    str(t.get("total_findings", 0)),
                    t.get("last_seen", "?")[:19],
                ])
            output.table(["Target", "Type", "Scans", "Findings", "Last Seen"], rows)

        elif action == "add":
            target_val = parts[1] if len(parts) > 1 else _prompt("Target IP/hostname")
            if target_val:
                # Just querying will auto-create via next scan, show info
                output.success(f"Target '{target_val}' noted. Run a scan to register it.")

        elif action == "notes":
            target_val = parts[1] if len(parts) > 1 else _prompt("Target")
            if target_val:
                history = db.get_target_history(target_val)
                output.section(f"Target: {target_val}")
                output.info(f"Total scans: {len(history.get('scans', []))}")
                output.info(f"Total findings: {len(history.get('findings', []))}")
        else:
            output.warning("Usage: target [list|add|notes] [target]")
    except Exception as e:
        output.error(f"Target command failed: {e}")


def _cmd_vault(arg: str):
    """Manage the credential vault."""
    try:
        from core.vault import get_vault
        vault = get_vault()

        parts = arg.strip().split(maxsplit=2)
        action = parts[0] if parts else "list"

        if action == "list":
            category = parts[1] if len(parts) > 1 else ""
            keys = vault.list_keys(category=category)
            if not keys:
                output.info("Vault is empty")
                return
            output.section("Credential Vault")
            rows = [[k["key"], k.get("category", ""), k.get("stored_at", "")[:19]] for k in keys]
            output.table(["Key", "Category", "Stored At"], rows)

        elif action == "set":
            key = parts[1] if len(parts) > 1 else _prompt("Key name")
            value = _prompt(f"Value for '{key}'")
            category = _prompt("Category", "general")
            if key and value:
                vault.store(key, value, category=category)
                output.success(f"Stored '{key}' in vault")

        elif action == "get":
            key = parts[1] if len(parts) > 1 else _prompt("Key name")
            value = vault.retrieve(key)
            if value:
                output.info(f"{key}: {value}")
            else:
                output.warning(f"Key '{key}' not found")

        elif action in ("del", "delete"):
            key = parts[1] if len(parts) > 1 else _prompt("Key to delete")
            if vault.delete(key):
                output.success(f"Deleted '{key}'")
            else:
                output.warning(f"Key '{key}' not found")

        elif action == "found":
            creds = vault.get_found_credentials()
            if not creds:
                output.info("No found credentials stored")
                return
            output.section("Found Credentials")
            rows = []
            for c in creds:
                rows.append([
                    c.get("target", "?"), c.get("service", "?"),
                    c.get("username", "?"), c.get("source_tool", "?"),
                ])
            output.table(["Target", "Service", "Username", "Source Tool"], rows)

        else:
            output.warning("Usage: vault [list|set|get|del|found] [key] [value]")
    except Exception as e:
        output.error(f"Vault command failed: {e}")


def _cmd_diff(arg: str):
    """Compare two scan results."""
    parts = arg.strip().split()
    if len(parts) < 2:
        output.warning("Usage: diff <scan_id_old> <scan_id_new>")
        output.info("Use 'history' to see available scan IDs")
        return

    try:
        from core.differ import get_differ
        differ = get_differ()
        result = differ.compare_scans(parts[0], parts[1])
        differ.print_diff(result)
    except Exception as e:
        output.error(f"Diff failed: {e}")
