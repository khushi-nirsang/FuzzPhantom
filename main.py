#!/usr/bin/env python3
"""
FuzzPhantom — Main CLI Entry Point
URL Fuzzing & Reconnaissance Toolkit for Bug Bounty Hunters

Usage:
    python main.py -d example.com --subdomains --crawl --fuzz --api
    python main.py -d example.com --wordlist wordlists/subdomains.txt \
                   --payloads payloads/xss.txt payloads/sqli.txt \
                   --output json hackerone --depth 3 --rate 30 --threads 15
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import os
import io
from pathlib import Path

# ── Force UTF-8 output on Windows terminals ──────────────────────────────────
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Ensure project root is on sys.path ──────────────────────────────────────
ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))

from core.context import ScanContext
from core.logger import get_logger, print_banner, console
from rich.table import Table
from rich.panel import Panel
from rich import box


logger = get_logger(__name__)


# ── CLI Argument Parser ───────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzzphantom",
        description="FuzzPhantom — URL Fuzzing & Recon Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan with all modules
  python main.py -d example.com --subdomains --crawl --fuzz --api --smart-wordlist --output json hackerone

  # Quick subdomain scan
  python main.py -d example.com --subdomains --wordlist wordlists/subdomains.txt

  # Fuzz only (provide pre-crawled URLs manually via crawl)
  python main.py -d example.com --crawl --fuzz --payloads payloads/sqli.txt

  # Generate report from crawl + API discovery
  python main.py -d example.com --crawl --api --output bugcrowd intigriti

  # Dry run (no actual requests sent)
  python main.py -d example.com --subdomains --crawl --dry-run
        """,
    )

    # ── Target ───────────────────────────────────────────────────────────────
    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-d", "--domain",
        metavar="DOMAIN",
        help="Primary target domain (e.g. example.com)",
    )
    target_group.add_argument(
        "-D", "--domain-list",
        metavar="FILE",
        help="File containing list of domains (one per line)",
    )
    target_group.add_argument(
        "-U", "--url-list",
        metavar="FILE",
        help="File containing list of URLs to fuzz directly (one per line)",
    )

    # ── Module Selection ─────────────────────────────────────────────────────
    module_group = parser.add_argument_group("Modules")
    module_group.add_argument(
        "--subdomains",
        action="store_true",
        help="Enable subdomain discovery (wordlist + CT logs + zone transfer)",
    )
    module_group.add_argument(
        "--crawl",
        action="store_true",
        help="Enable URL crawler (extracts links, forms, JS routes)",
    )
    module_group.add_argument(
        "--fuzz",
        action="store_true",
        help="Enable parameter fuzzer (injects payloads into URL params)",
    )
    module_group.add_argument(
        "--api",
        action="store_true",
        help="Enable API endpoint discovery and JS analysis",
    )
    module_group.add_argument(
        "--smart-wordlist",
        action="store_true",
        help="Generate domain-specific wordlist from site content (NLP/TF-IDF)",
    )
    module_group.add_argument(
        "--all",
        action="store_true",
        help="Enable ALL modules (shortcut for --subdomains --crawl --fuzz --api --smart-wordlist)",
    )

    # ── Wordlists & Payloads ─────────────────────────────────────────────────
    input_group = parser.add_argument_group("Wordlists & Payloads")
    input_group.add_argument(
        "-w", "--wordlist",
        metavar="FILE",
        help="Subdomain wordlist file (default: wordlists/subdomains.txt)",
    )
    input_group.add_argument(
        "-p", "--payloads",
        nargs="+",
        metavar="FILE",
        help="Payload file(s) for fuzzing (default: all files in payloads/)",
    )

    # ── Output ───────────────────────────────────────────────────────────────
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output",
        nargs="+",
        choices=["json", "hackerone", "bugcrowd", "intigriti"],
        default=["json"],
        metavar="FORMAT",
        help="Output format(s): json, hackerone, bugcrowd, intigriti (default: json)",
    )
    output_group.add_argument(
        "--output-dir",
        metavar="DIR",
        default="reports",
        help="Directory for report output (default: reports/)",
    )

    # ── Performance ──────────────────────────────────────────────────────────
    perf_group = parser.add_argument_group("Performance")
    perf_group.add_argument(
        "--depth",
        type=int,
        default=3,
        metavar="N",
        help="Crawler recursion depth (default: 3)",
    )
    perf_group.add_argument(
        "--rate",
        type=int,
        default=50,
        metavar="N",
        help="Maximum requests per second (default: 50)",
    )
    perf_group.add_argument(
        "--threads",
        type=int,
        default=20,
        metavar="N",
        help="Concurrent workers (default: 20)",
    )
    perf_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="HTTP request timeout in seconds (default: 10)",
    )

    # ── Network ──────────────────────────────────────────────────────────────
    net_group = parser.add_argument_group("Network")
    net_group.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080 for Burp Suite)",
    )
    net_group.add_argument(
        "--user-agent",
        metavar="UA",
        help="Custom User-Agent string",
    )

    # ── Misc ─────────────────────────────────────────────────────────────────
    misc_group = parser.add_argument_group("Misc")
    misc_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate scan without sending real HTTP requests",
    )
    misc_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose debug output",
    )
    misc_group.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress ASCII banner",
    )

    return parser


# ── Context Builder ───────────────────────────────────────────────────────────

def build_context(args: argparse.Namespace) -> ScanContext:
    """Construct a ScanContext from parsed CLI arguments."""
    ctx = ScanContext()

    # Target
    if args.domain:
        ctx.target_domain = args.domain.strip().lower()
        ctx.domains = [ctx.target_domain]

    if args.domain_list:
        domain_file = Path(args.domain_list)
        if not domain_file.exists():
            logger.error(f"Domain list file not found: {args.domain_list}")
            sys.exit(1)
        with open(domain_file, encoding="utf-8") as f:
            extra_domains = [
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
        ctx.domains.extend(extra_domains)
        if not ctx.target_domain and extra_domains:
            ctx.target_domain = extra_domains[0]

    if args.url_list:
        url_file = Path(args.url_list)
        if not url_file.exists():
            logger.error(f"URL list file not found: {args.url_list}")
            sys.exit(1)
        with open(url_file, encoding="utf-8") as f:
            input_urls = [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
        ctx.parameterized_urls.extend(input_urls)
        ctx.crawled_urls.extend(input_urls)
        if not ctx.target_domain and input_urls:
            from urllib.parse import urlparse
            parsed = urlparse(input_urls[0])
            ctx.target_domain = f"{parsed.scheme}://{parsed.netloc}"
            ctx.domains = [ctx.target_domain]

    # Wordlists & payloads
    ctx.wordlist_path = args.wordlist or str(ROOT / "wordlists" / "subdomains.txt")
    ctx.payload_files = args.payloads or []

    # Output
    ctx.output_formats = args.output
    ctx.output_dir = args.output_dir

    # Performance
    ctx.crawl_depth = args.depth
    ctx.rate_limit = args.rate
    ctx.threads = args.threads
    ctx.timeout = args.timeout

    # Network
    ctx.proxy = args.proxy
    if args.user_agent:
        ctx.user_agent = args.user_agent

    # Misc
    ctx.dry_run = args.dry_run
    ctx.verbose = args.verbose
    ctx.smart_wordlist = args.smart_wordlist or args.all

    return ctx


# ── Summary Table ─────────────────────────────────────────────────────────────

def print_summary(ctx: ScanContext) -> None:
    """Print a rich summary table after scan completion."""
    summary = ctx.summary()

    table = Table(
        title="[bold cyan]FuzzPhantom Scan Summary[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Category", style="bold white", width=30)
    table.add_column("Count", style="bold green", justify="right", width=10)

    table.add_row("Subdomains Discovered", str(summary["subdomains"]))
    table.add_row("URLs Crawled", str(summary["crawled_urls"]))
    table.add_row("Parameterized URLs", str(summary["parameterized_urls"]))
    table.add_row("API Endpoints Found", str(summary["api_endpoints"]))
    table.add_row("JavaScript Files", str(summary["js_files"]))
    table.add_row("─" * 25, "─" * 8)

    # Findings by severity
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = sum(1 for f in ctx.findings if f.severity == sev)
        color = {
            "CRITICAL": "bold red on dark_red",
            "HIGH": "bold red",
            "MEDIUM": "bold yellow",
            "LOW": "bold cyan",
            "INFO": "bold white",
        }[sev]
        table.add_row(
            f"Findings — {sev}",
            f"[{color}]{count}[/{color}]",
        )

    console.print()
    console.print(table)
    console.print()


# ── Main Async Runner ─────────────────────────────────────────────────────────

async def run(args: argparse.Namespace) -> None:
    """Main async execution pipeline."""

    if not args.no_banner:
        print_banner()

    # Validate target
    if not args.domain and not args.domain_list and not args.url_list:
        console.print(
            Panel(
                "[bold red]Error:[/bold red] You must specify a target with [bold]-d[/bold], [bold]-D[/bold], or [bold]-U[/bold].\n\n"
                "Run [bold]python main.py --help[/bold] for usage.",
                title="FuzzPhantom",
                border_style="red",
            )
        )
        sys.exit(1)

    # Handle --all flag
    if args.all:
        args.subdomains = True
        args.crawl = True
        args.fuzz = True
        args.api = True
        args.smart_wordlist = True

    if args.url_list and not (args.subdomains or args.crawl or args.fuzz or args.api):
        args.fuzz = True

    ctx = build_context(args)

    import logging
    if args.verbose:
        get_logger().setLevel(logging.DEBUG)

    console.print(
        Panel(
            f"[bold cyan]Target:[/bold cyan] {ctx.target_domain}\n"
            f"[bold cyan]Modules:[/bold cyan] "
            f"{'Subdomains ' if args.subdomains else ''}"
            f"{'Crawl ' if args.crawl else ''}"
            f"{'Fuzz ' if args.fuzz else ''}"
            f"{'API ' if args.api else ''}"
            f"{'SmartWordlist ' if args.smart_wordlist else ''}\n"
            f"[bold cyan]Output:[/bold cyan] {', '.join(ctx.output_formats)} -> {ctx.output_dir}/\n"
            f"[bold cyan]Rate:[/bold cyan] {ctx.rate_limit} req/s  "
            f"[bold cyan]Threads:[/bold cyan] {ctx.threads}  "
            f"[bold cyan]Depth:[/bold cyan] {ctx.crawl_depth}  "
            f"[bold cyan]Proxy:[/bold cyan] {ctx.proxy or 'None'}",
            title="[bold bright_cyan]>> FuzzPhantom Scan Config <<[/bold bright_cyan]",
            border_style="cyan",
        )
    )

    # ── Module Pipeline ────────────────────────────────────────────────────────
    if args.subdomains:
        from modules.subdomain import run_subdomain_discovery
        await run_subdomain_discovery(ctx)

    if args.crawl:
        from modules.crawler import crawl
        await crawl(ctx)

    if args.fuzz:
        from modules.fuzzer import run_fuzzer
        await run_fuzzer(ctx)

    if args.api:
        from modules.api_discovery import run_api_discovery
        await run_api_discovery(ctx)

    if args.smart_wordlist:
        from modules.wordlist_gen import generate_smart_wordlist
        await generate_smart_wordlist(ctx)

    # ── Reporting ─────────────────────────────────────────────────────────────
    from reporting.reporter import generate_reports
    generate_reports(ctx)

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary(ctx)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]>> Scan interrupted by user.[/bold yellow]")
        sys.exit(0)
    except Exception as exc:
        logger.exception(f"Unhandled error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
