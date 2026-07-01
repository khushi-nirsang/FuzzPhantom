"""
FuzzPhantom -- Logger
Rich-based colored, leveled logger for consistent CLI output.
"""

from __future__ import annotations

import io
import logging
import sys
from datetime import datetime
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
from rich.text import Text

# -- Force UTF-8 on Windows so Rich box-drawing chars don't crash cp1252 ------
if sys.platform == "win32":
    _safe_out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
else:
    _safe_out = None  # type: ignore[assignment]

# -- Custom theme --------------------------------------------------------------
_THEME = Theme(
    {
        "info": "bold cyan",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "critical": "bold white on red",
        "finding": "bold magenta",
        "subtle": "dim white",
        "banner": "bold bright_cyan",
    }
)

console = Console(theme=_THEME, highlight=False, file=_safe_out)


# ── Rich logging handler ─────────────────────────────────────────────────────
def get_logger(name: str = "fuzzphantom", level: int = logging.INFO) -> logging.Logger:
    """Return a configured Rich logger instance."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                rich_tracebacks=True,
                show_path=False,
                markup=True,
            )
        ],
    )
    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger


# ── Convenience helpers ──────────────────────────────────────────────────────
def print_banner() -> None:
    """Print the FuzzPhantom ASCII banner."""
    banner = r"""
 ███████╗██╗   ██╗███████╗███████╗██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 █████╗  ██║   ██║  ███╔╝   ███╔╝ ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ╚██████╔╝███████╗███████╗██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
"""
    console.print(Text(banner, style="banner"))
    console.print(
        f"  [bold cyan]v1.0.0[/bold cyan]  |  "
        f"[subtle]URL Fuzzing & Recon Toolkit[/subtle]  |  "
        f"[subtle]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/subtle]\n"
    )


def log_finding(category: str, url: str, detail: str, severity: str = "INFO") -> None:
    """Print a colour-coded finding line."""
    sev_color = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold cyan",
        "INFO": "bold white",
    }.get(severity.upper(), "bold white")

    console.print(
        f"  [[{sev_color}]{severity}[/{sev_color}]] "
        f"[finding]{category}[/finding] → [cyan]{url}[/cyan]\n"
        f"    [subtle]{detail}[/subtle]"
    )
