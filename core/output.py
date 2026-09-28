# =============================================================================
# CyberToolkit Pro — Console Output & Formatting
# =============================================================================
# Rich console output with color support, table formatting, status indicators,
# and the framework banner. Falls back gracefully on terminals without color
# or Unicode support.
# =============================================================================

import os
import sys
from typing import List, Optional


# ---------------------------------------------------------------------------
# Force UTF-8 output on Windows to support Unicode box drawing characters
# ---------------------------------------------------------------------------
if os.name == "nt":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# ANSI color codes — disabled when piped to non-TTY or on minimal terminals
# ---------------------------------------------------------------------------
_COLOR_ENABLED = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

if os.name == "nt":
    # Enable ANSI escape sequences on Windows 10+
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        _COLOR_ENABLED = True
    except Exception:
        pass

# Detect if stdout can handle Unicode (fallback to ASCII box drawing)
_UNICODE_OK = True
try:
    "─┌┐│└┘┼█░".encode(sys.stdout.encoding or "ascii")
except (UnicodeEncodeError, LookupError):
    _UNICODE_OK = False


class Colors:
    """ANSI color/style constants."""
    RESET   = "\033[0m"   if _COLOR_ENABLED else ""
    BOLD    = "\033[1m"    if _COLOR_ENABLED else ""
    DIM     = "\033[2m"    if _COLOR_ENABLED else ""
    RED     = "\033[91m"   if _COLOR_ENABLED else ""
    GREEN   = "\033[92m"   if _COLOR_ENABLED else ""
    YELLOW  = "\033[93m"   if _COLOR_ENABLED else ""
    BLUE    = "\033[94m"   if _COLOR_ENABLED else ""
    MAGENTA = "\033[95m"   if _COLOR_ENABLED else ""
    CYAN    = "\033[96m"   if _COLOR_ENABLED else ""
    WHITE   = "\033[97m"   if _COLOR_ENABLED else ""
    BG_RED  = "\033[41m"   if _COLOR_ENABLED else ""
    BG_GREEN = "\033[42m"  if _COLOR_ENABLED else ""
    BG_YELLOW = "\033[43m" if _COLOR_ENABLED else ""


# Box drawing characters with ASCII fallback
class Box:
    H    = "-" if not _UNICODE_OK else "\u2500"   # ─
    V    = "|" if not _UNICODE_OK else "\u2502"   # │
    TL   = "+" if not _UNICODE_OK else "\u250c"   # ┌
    TR   = "+" if not _UNICODE_OK else "\u2510"   # ┐
    BL   = "+" if not _UNICODE_OK else "\u2514"   # └
    BR   = "+" if not _UNICODE_OK else "\u2518"   # ┘
    CROSS = "+" if not _UNICODE_OK else "\u253c"  # ┼
    BLOCK = "#" if not _UNICODE_OK else "\u2588"  # █
    SHADE = "." if not _UNICODE_OK else "\u2591"  # ░


# ---------------------------------------------------------------------------
# Severity → Color mapping
# ---------------------------------------------------------------------------
SEVERITY_COLORS = {
    "info":     Colors.BLUE,
    "low":      Colors.GREEN,
    "medium":   Colors.YELLOW,
    "high":     Colors.RED,
    "critical": Colors.BG_RED + Colors.WHITE,
}


def _safe_print(text: str):
    """Print with encoding error handling for Windows compatibility."""
    try:
        print(text)
    except UnicodeEncodeError:
        # Strip non-ASCII and retry
        safe = text.encode("ascii", errors="replace").decode("ascii")
        print(safe)


def banner():
    """Print the CyberToolkit Pro splash banner."""
    b = f"""{Colors.CYAN}{Colors.BOLD}
   ######  ##    ## ########  ######## ########  ######## ##    ##
  ##    ##  ##  ##  ##     ## ##       ##     ##    ##    ##   ##
  ##         ####   ##     ## ##       ##     ##    ##    ##  ##
  ##          ##    ########  ######   ########     ##    #####
  ##          ##    ##     ## ##       ##   ##      ##    ##  ##
  ##    ##    ##    ##     ## ##       ##    ##     ##    ##   ##
   ######     ##    ########  ######## ##     ##    ##    ##    ##
  {Colors.RESET}{Colors.MAGENTA}+============================================================+
  |{Colors.WHITE}{Colors.BOLD}   CyberToolkit Pro v2.5  --  Offensive & Defensive Sec   {Colors.RESET}{Colors.MAGENTA}|
  |{Colors.DIM}         Professional Cybersecurity Framework              {Colors.RESET}{Colors.MAGENTA}|
  +============================================================+{Colors.RESET}
"""
    _safe_print(b)


def section(title: str):
    """Print a section divider with title."""
    line = Box.H * 60
    _safe_print(f"\n{Colors.CYAN}{Colors.BOLD}{Box.TL}{line}{Box.TR}{Colors.RESET}")
    _safe_print(f"{Colors.CYAN}{Colors.BOLD}{Box.V} {title:<58} {Box.V}{Colors.RESET}")
    _safe_print(f"{Colors.CYAN}{Colors.BOLD}{Box.BL}{line}{Box.BR}{Colors.RESET}")


def info(msg: str):
    _safe_print(f"  {Colors.BLUE}[*]{Colors.RESET} {msg}")


def success(msg: str):
    _safe_print(f"  {Colors.GREEN}[+]{Colors.RESET} {msg}")


def warning(msg: str):
    _safe_print(f"  {Colors.YELLOW}[!]{Colors.RESET} {msg}")


def error(msg: str):
    _safe_print(f"  {Colors.RED}[-]{Colors.RESET} {msg}")


def critical(msg: str):
    _safe_print(f"  {Colors.BG_RED}{Colors.WHITE}[!!!]{Colors.RESET} {Colors.RED}{msg}{Colors.RESET}")


def status(msg: str, state: str = "running"):
    """Print a status line. States: running, done, error."""
    icons = {"running": f"{Colors.YELLOW}>>", "done": f"{Colors.GREEN}OK", "error": f"{Colors.RED}!!"}
    icon = icons.get(state, icons["running"])
    _safe_print(f"  [{icon}{Colors.RESET}] {msg}")


def severity_badge(sev: str) -> str:
    """Return a colored severity badge string."""
    color = SEVERITY_COLORS.get(sev, Colors.RESET)
    return f"{color}[{sev.upper()}]{Colors.RESET}"


def table(headers: List[str], rows: List[List[str]], max_width: Optional[int] = None):
    """
    Print a formatted table with auto-calculated column widths.
    Falls back to simple alignment on very narrow terminals.
    """
    if not rows:
        _safe_print(f"  {Colors.DIM}(no data){Colors.RESET}")
        return

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                # Strip ANSI for width calculation
                clean = _strip_ansi(str(cell))
                col_widths[i] = max(col_widths[i], len(clean))

    # Apply max_width constraint
    if max_width:
        total = sum(col_widths) + 3 * len(col_widths)
        if total > max_width:
            scale = max_width / total
            col_widths = [max(5, int(w * scale)) for w in col_widths]

    sep_char = Box.V
    cross_char = Box.CROSS

    # Header
    header_line = "  " + f" {sep_char} ".join(
        f"{Colors.BOLD}{h:<{col_widths[i]}}{Colors.RESET}" for i, h in enumerate(headers)
    )
    sep = "  " + f"{Box.H}{cross_char}{Box.H}".join(Box.H * w for w in col_widths)

    _safe_print(header_line)
    _safe_print(f"  {Colors.DIM}{sep[2:]}{Colors.RESET}")

    # Rows
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            w = col_widths[i] if i < len(col_widths) else 10
            clean = _strip_ansi(str(cell))
            padding = w - len(clean)
            cells.append(str(cell) + " " * max(0, padding))
        _safe_print("  " + f" {sep_char} ".join(cells))


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences for width calculation."""
    import re
    return re.sub(r"\033\[[0-9;]*m", "", text)


def progress_bar(current: int, total: int, width: int = 40, prefix: str = ""):
    """Print an inline progress bar."""
    if total == 0:
        return
    pct = current / total
    filled = int(width * pct)
    bar = Box.BLOCK * filled + Box.SHADE * (width - filled)
    try:
        print(f"\r  {prefix} [{Colors.CYAN}{bar}{Colors.RESET}] {pct:.0%} ({current}/{total})", end="", flush=True)
    except UnicodeEncodeError:
        bar_ascii = "#" * filled + "." * (width - filled)
        print(f"\r  {prefix} [{bar_ascii}] {pct:.0%} ({current}/{total})", end="", flush=True)
    if current >= total:
        print()
