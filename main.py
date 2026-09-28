# =============================================================================
# CyberToolkit Pro — Main Entry Point
# =============================================================================
# Supports two modes:
#   1. Command mode:  python main.py run scanning.port_scanner --target 10.0.0.1
#   2. Interactive:   python main.py --interactive
#
# Subcommands: run, list, search, pipeline, config, dashboard
# =============================================================================

import argparse
import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.loader import load_all
from core.registry import get_registry
from core.executor import execute
from core.pipeline import run_profile, run_pipeline, list_profiles
from core.cli import interactive_shell
from core.config import Config
from core.logger import FrameworkLogger
from core.suggester import suggest
from core import output


def parse_args():
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="cybertoolkit",
        description="CyberToolkit Pro — Professional Cybersecurity Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py list                                  List all tools
  python main.py search "port"                         Search tools
  python main.py run scanning.port_scanner -t 10.0.0.1 Run a specific tool
  python main.py pipeline quick_scan -t example.com    Run a pipeline profile
  python main.py --interactive                         Interactive shell
  python main.py dashboard                             Start web dashboard
        """,
    )

    parser.add_argument(
        "--version", "-V", action="version",
        version="CyberToolkit Pro v2.5.0"
    )

    parser.add_argument(
        "--interactive", "-i", action="store_true",
        help="Launch interactive shell mode"
    )
    parser.add_argument(
        "--config", "-c", default=None,
        help="Path to YAML config file"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress banner and non-essential output"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- run ---
    run_parser = subparsers.add_parser("run", help="Run a specific tool")
    run_parser.add_argument("tool", help="Tool path (e.g. scanning.port_scanner)")
    run_parser.add_argument("--target", "-t", default="", help="Target host/IP")
    run_parser.add_argument("--output-json", "-o", default="", help="Save JSON output to file")
    run_parser.add_argument("--args", "-a", nargs="*", default=[], help="Additional key=value args")

    # --- list ---
    list_parser = subparsers.add_parser("list", help="List all available tools")
    list_parser.add_argument("--category", default="", help="Filter by category")

    # --- search ---
    search_parser = subparsers.add_parser("search", help="Search for tools")
    search_parser.add_argument("query", help="Search query")

    # --- pipeline ---
    pipe_parser = subparsers.add_parser("pipeline", help="Run a pipeline profile")
    pipe_parser.add_argument("profile", help="Profile name (e.g. quick_scan)")
    pipe_parser.add_argument("--target", "-t", default="", help="Target host/IP")
    pipe_parser.add_argument("--args", "-a", nargs="*", default=[], help="Additional key=value args")
    pipe_parser.add_argument("--dry-run", action="store_true", help="Show pipeline steps without executing")

    # --- profiles ---
    subparsers.add_parser("profiles", help="List available pipeline profiles")

    # --- dashboard ---
    dash_parser = subparsers.add_parser("dashboard", help="Start web dashboard")
    dash_parser.add_argument("--host", default="", help="Dashboard host")
    dash_parser.add_argument("--port", "-p", type=int, default=0, help="Dashboard port")

    # --- tui ---
    subparsers.add_parser("tui", help="Launch immersive Hacker TUI (Textual)")

    # --- plugin ---
    plugin_parser = subparsers.add_parser("plugin", help="Manage plugins")
    plugin_sub = plugin_parser.add_subparsers(dest="plugin_action", help="Plugin actions")
    plugin_install = plugin_sub.add_parser("install", help="Install a plugin from URL")
    plugin_install.add_argument("url", help="Plugin Git URL or path")
    plugin_sub.add_parser("list", help="List installed plugins")
    plugin_update = plugin_sub.add_parser("update", help="Update a plugin")
    plugin_update.add_argument("name", nargs="?", default="", help="Plugin name (all if omitted)")
    plugin_remove = plugin_sub.add_parser("remove", help="Remove a plugin")
    plugin_remove.add_argument("name", help="Plugin name to remove")

    # --- cve ---
    cve_parser = subparsers.add_parser("cve", help="Search offline CVE database and calculate CVSS")
    cve_parser.add_argument("query", nargs="?", default="", help="Software name, banner, or CVE ID")
    cve_parser.add_argument("--vector", default="", help="CVSS v3.1 vector string to calculate")

    # --- canary ---
    canary_parser = subparsers.add_parser("canary", help="Active defense honeytokens & tripwires")
    canary_parser.add_argument("--action", choices=["generate", "list"], default="generate", help="Action to perform")
    canary_parser.add_argument("--type", default="http_webhook", choices=["http_webhook", "aws_keys", "git_token", "db_credential"], help="Canary token type")
    canary_parser.add_argument("--memo", default="Deceptive Canary", help="Placement memo")

    # --- mitre ---
    subparsers.add_parser("mitre", help="Display MITRE ATT&CK matrix coverage and posture metrics")

    return parser.parse_args()


def _parse_extra_args(arg_list):
    """Parse key=value pairs from --args flag."""
    result = {}
    for item in arg_list:
        if "=" in item:
            key, val = item.split("=", 1)
            result[key] = val
    return result


def cmd_run(args):
    """Handle the 'run' subcommand."""
    registry = get_registry()
    tool = registry.get(args.tool)

    if tool is None:
        output.error(f"Tool '{args.tool}' not found")
        output.info("Use 'python main.py list' to see available tools")
        return

    tool_args = {"target": args.target}
    tool_args.update(_parse_extra_args(args.args))

    result = execute(tool, tool_args)

    # Show result
    if result.data:
        output.section("Results")
        import json
        print(json.dumps(result.data, indent=2, default=str))

    if result.findings:
        output.section("Findings")
        for f in result.findings:
            sev_badge = output.severity_badge(f.severity.value if hasattr(f.severity, 'value') else f.get("severity", "info"))
            title = f.title if hasattr(f, 'title') else f.get("title", "")
            print(f"  {sev_badge} {title}")

    # AI suggestions
    suggest(result=result)

    # JSON output
    if args.output_json:
        os.makedirs(os.path.dirname(args.output_json) or ".", exist_ok=True)
        with open(args.output_json, "w", encoding="utf-8") as f:
            f.write(result.to_json())
        output.success(f"JSON output saved to {args.output_json}")


def cmd_list(args):
    """Handle the 'list' subcommand."""
    registry = get_registry()
    categories = registry.categories()

    if args.category:
        categories = [c for c in categories if c == args.category]

    for cat in categories:
        output.section(f"Category: {cat}")
        tools = registry.tools_in_category(cat)
        rows = []
        for t in tools:
            info = t["info"]
            name = info.name if hasattr(info, "name") else info.get("name", "")
            desc = info.description if hasattr(info, "description") else info.get("description", "")
            rows.append([f"{cat}.{name}", desc[:60]])
        output.table(["Tool Path", "Description"], rows)


def cmd_search(args):
    """Handle the 'search' subcommand."""
    registry = get_registry()
    results = registry.search(args.query)

    if not results:
        output.warning(f"No tools found matching '{args.query}'")
        return

    output.section(f"Search Results for '{args.query}'")
    rows = []
    for t in results:
        info = t["info"]
        name = info.name if hasattr(info, "name") else info.get("name", "")
        cat = info.category if hasattr(info, "category") else info.get("category", "")
        desc = info.description if hasattr(info, "description") else info.get("description", "")
        rows.append([f"{cat}.{name}", desc[:60]])
    output.table(["Tool Path", "Description"], rows)


def cmd_pipeline(args):
    """Handle the 'pipeline' subcommand."""
    tool_args = {"target": args.target}
    tool_args.update(_parse_extra_args(args.args))
    dry_run = getattr(args, "dry_run", False)
    run_profile(args.profile, tool_args, dry_run=dry_run)


def cmd_profiles(args):
    """Handle the 'profiles' subcommand."""
    profiles = list_profiles()
    if not profiles:
        output.warning("No pipeline profiles found in config/profiles/")
        return

    output.section("Available Pipeline Profiles")
    rows = [[name, path] for name, path in profiles.items()]
    output.table(["Profile", "Config File"], rows)


def cmd_dashboard(args):
    """Handle the 'dashboard' subcommand."""
    try:
        from dashboard.app import start_dashboard
        cfg = Config()
        host = args.host or cfg.get("dashboard.host", "127.0.0.1")
        port = args.port or cfg.get("dashboard.port", 8443)
        start_dashboard(host, port)
    except ImportError:
        output.error("Dashboard dependencies not installed. Run: pip install fastapi uvicorn")
    except Exception as e:
        output.error(f"Failed to start dashboard: {e}")


def cmd_tui(args):
    """Handle the 'tui' subcommand."""
    try:
        from core.tui import start_tui
        start_tui()
    except ImportError as e:
        output.error(f"TUI dependencies not installed: {e}")
        output.info("Run: pip install textual rich")
    except Exception as e:
        output.error(f"Failed to start TUI: {e}")


def cmd_plugin(args):
    """Handle the 'plugin' subcommand."""
    try:
        from core.plugin_manager import PluginManager
        pm = PluginManager()
        action = getattr(args, "plugin_action", None)
        if action == "install":
            pm.install(args.url)
        elif action == "list":
            pm.list_plugins()
        elif action == "update":
            pm.update(getattr(args, "name", ""))
        elif action == "remove":
            pm.remove(args.name)
        else:
            output.info("Usage: python main.py plugin {install|list|update|remove}")
    except ImportError:
        output.error("Plugin manager not available")
    except Exception as e:
        output.error(f"Plugin operation failed: {e}")


def cmd_cve(args):
    """Handle the 'cve' subcommand."""
    from core.cve_lookup import get_cve_engine, calculate_cvss31
    if getattr(args, "vector", None):
        res = calculate_cvss31(args.vector)
        output.info(f"Vector: {res['vector']}")
        output.info(f"Base Score: {res['base_score']} ({res['severity']})")
        output.info(f"Impact: {res['impact']} | Exploitability: {res['exploitability']}")
        return

    engine = get_cve_engine()
    q = getattr(args, "query", "")
    results = engine.search(q) if q else engine.search("")
    output.info(f"Found {len(results)} CVEs matching '{q}':\n")
    for r in results[:8]:
        print(f"  [{r.get('cve')}] {r.get('title')} (CVSS {r.get('base_score')} - {r.get('severity')})")
        print(f"    Product: {r.get('product')} | CWE: {r.get('cwe')}")
        print(f"    Remediation: {r.get('remediation')}\n")


def cmd_canary(args):
    """Handle the 'canary' subcommand."""
    from core.canary import get_canary_manager
    mgr = get_canary_manager()
    action = getattr(args, "action", "generate")
    if action == "list":
        canaries = mgr.list_canaries()
        output.info(f"Active Canary Honeytokens ({len(canaries)} total):")
        for c in canaries:
            print(f"  [{c['token_id']}] Type: {c['token_type']} | Memo: {c['memo']} | Triggers: {c['triggered_count']}")
    else:
        created = mgr.generate_token(token_type=getattr(args, "type", "http_webhook"), memo=getattr(args, "memo", "Deceptive Canary"))
        output.success(f"Generated {created['token_type']} Canary Honeytoken [ID: {created['token_id']}]")
        output.info(f"Payload Data: {created['payload']}")
        output.info("Plant this decoy in sensitive directories/repos. Any access triggers immediate multi-channel alerts.")


def cmd_mitre(args):
    """Handle the 'mitre' subcommand."""
    from core.mitre import get_mitre_engine
    engine = get_mitre_engine()
    view = engine.get_matrix_view()
    output.info(f"MITRE Enterprise ATT&CK Matrix ({view['tactics_count']} Tactics, {view['total_techniques']} Techniques Mapped across {view['total_tools_mapped']} tools):")
    for col in view['columns']:
        print(f"  [{col['tactic_id']}] {col['tactic_name']} ({col['technique_count']} techniques)")
        for t in col['techniques'][:2]:
            print(f"      - {t['id']}: {t['name']} ({len(t['tools'])} tools)")


def main():
    """Main entry point."""
    args = parse_args()

    # Initialize config and logging
    cfg = Config(args.config if hasattr(args, "config") else None)
    FrameworkLogger().setup()

    if not (hasattr(args, "quiet") and args.quiet):
        output.banner()

    # Load all tools
    load_all(quiet=(hasattr(args, "quiet") and args.quiet))

    # Interactive mode
    if hasattr(args, "interactive") and args.interactive:
        interactive_shell()
        return

    # Command dispatch
    commands = {
        "run": cmd_run,
        "list": cmd_list,
        "search": cmd_search,
        "pipeline": cmd_pipeline,
        "profiles": cmd_profiles,
        "dashboard": cmd_dashboard,
        "tui": cmd_tui,
        "plugin": cmd_plugin,
        "cve": cmd_cve,
        "canary": cmd_canary,
        "mitre": cmd_mitre,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        # Default to interactive mode if no command
        interactive_shell()


if __name__ == "__main__":
    main()
