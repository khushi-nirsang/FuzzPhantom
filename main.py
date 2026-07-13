#!/usr/bin/env python3
"""
FuzzPhantom — Main CLI Entry Point
URL Fuzzing & Reconnaissance Toolkit for Bug Bounty Hunters

Usage:
    python main.py -d example.com --subdomains --crawl --fuzz --api
    python main.py -d example.com --wordlist wordlists/subdomains.txt \
                   --payloads payloads/xss.txt payloads/sqli.txt \
                   --output json jsonl csv --depth 3 --rate 30 --threads 15
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

  # Directory brute-force with extension fuzzing
  python main.py -d example.com --dir --dir-wordlist wordlists/directories.txt -e php,txt,bak

  # Named placeholders with pitchfork mode
  python main.py --request login.txt -W users.txt:USER -W passwords.txt:PASS --fuzz-mode pitchfork

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
    target_group.add_argument(
        "--request",
        metavar="FILE",
        help="Raw HTTP request file to fuzz (Burp-style, supports FUZZ)",
    )
    target_group.add_argument(
        "--request-scheme",
        choices=["http", "https"],
        default="https",
        help="Scheme for raw requests with relative paths (default: https)",
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
        "--dir",
        "--directories",
        dest="dir_fuzz",
        action="store_true",
        help="Enable directory brute-force fuzzing (ffuf/DirBuster-style)",
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
        help="Enable ALL modules (shortcut for --subdomains --crawl --dir --fuzz --api --smart-wordlist)",
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
    input_group.add_argument(
        "--dir-wordlist",
        metavar="FILE",
        help="Directory brute-force wordlist file (default: wordlists/directories.txt)",
    )
    input_group.add_argument(
        "-e", "--extensions",
        metavar="EXTS",
        help="Directory fuzzing extensions, comma-separated (e.g. php,txt,bak)",
    )
    input_group.add_argument(
        "-W", "--fuzz-wordlist",
        action="append",
        default=[],
        metavar="FILE:KEY",
        help="Named request fuzzing wordlist; repeatable (e.g. users.txt:USER)",
    )
    input_group.add_argument(
        "--fuzz-mode",
        choices=["sniper", "pitchfork", "clusterbomb"],
        default="sniper",
        help="Multi-wordlist mode for named placeholders (default: sniper)",
    )
    input_group.add_argument(
        "--mutate-wordlist",
        action="store_true",
        help="Generate case, backup, numeric, slash, and tech variants for directory words",
    )
    input_group.add_argument(
        "--mutate-depth",
        type=int,
        default=1,
        metavar="N",
        help="Word mutation intensity: 1 or 2 (default: 1)",
    )

    # ── Output ───────────────────────────────────────────────────────────────
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output",
        nargs="+",
        choices=["json", "jsonl", "csv", "pdf", "hackerone", "bugcrowd", "intigriti"],
        default=["json"],
        metavar="FORMAT",
        help="Output format(s): json, jsonl, csv, pdf, hackerone, bugcrowd, intigriti (default: json)",
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
        "--dir-depth",
        type=int,
        default=3,
        metavar="N",
        help="Directory fuzzing recursion depth (default: 3)",
    )
    perf_group.add_argument(
        "--rate",
        type=int,
        default=200,
        metavar="N",
        help="Maximum requests per second (default: 200)",
    )
    perf_group.add_argument(
        "--threads",
        type=int,
        default=80,
        metavar="N",
        help="Concurrent workers (default: 80)",
    )
    perf_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="HTTP request timeout in seconds (default: 10)",
    )
    perf_group.add_argument(
        "--no-calibration",
        action="store_true",
        help="Disable auto-calibration false-positive filtering",
    )
    perf_group.add_argument(
        "--calibration-samples",
        type=int,
        default=6,
        metavar="N",
        help="Random baseline probes per base URL (default: 6)",
    )
    perf_group.add_argument(
        "--calibration-size-tolerance",
        type=int,
        default=200,
        metavar="BYTES",
        help="Minimum soft-404 size tolerance in bytes (default: 200)",
    )
    perf_group.add_argument(
        "--calibration-profile",
        choices=["strict", "balanced", "relaxed"],
        default="balanced",
        help="Auto-calibration sensitivity profile (default: balanced)",
    )
    perf_group.add_argument(
        "--delay",
        type=int,
        default=0,
        metavar="MS",
        help="Fixed delay between requests in milliseconds",
    )
    perf_group.add_argument(
        "--jitter",
        type=int,
        default=0,
        metavar="MS",
        help="Random extra delay between requests in milliseconds",
    )
    perf_group.add_argument(
        "--max-errors",
        type=int,
        default=0,
        metavar="N",
        help="Stop directory fuzzing after N request errors (0 = disabled)",
    )
    perf_group.add_argument(
        "--max-hits",
        type=int,
        default=0,
        metavar="N",
        help="Stop directory fuzzing after N confirmed hits (0 = disabled)",
    )

    # ── Network ──────────────────────────────────────────────────────────────
    net_group = parser.add_argument_group("Network")
    net_group.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080 for Burp Suite)",
    )
    net_group.add_argument(
        "--proxy-max-failures",
        type=int,
        default=3,
        metavar="N",
        help="Quarantine rotating HTTP proxies after N failures (default: 3)",
    )
    net_group.add_argument(
        "--replay-proxy",
        metavar="URL",
        help="Replay matched directory/request fuzzing hits through this HTTP/SOCKS proxy",
    )
    net_group.add_argument(
        "--user-agent",
        metavar="UA",
        help="Custom User-Agent string",
    )
    net_group.add_argument(
        "-X", "--method",
        metavar="METHOD",
        help="HTTP method for directory/request fuzzing (default: GET)",
    )
    net_group.add_argument(
        "-H", "--header",
        action="append",
        default=[],
        metavar="HEADER",
        help="Custom request header; repeatable, supports FUZZ (e.g. 'X-Test: FUZZ')",
    )
    net_group.add_argument(
        "--data",
        metavar="BODY",
        help="Request body for fuzzing; supports FUZZ and implies POST unless -X is set",
    )
    net_group.add_argument(
        "-r",
        "--follow-redirects",
        action="store_true",
        help="Follow redirects during directory/request fuzzing",
    )
    net_group.add_argument(
        "--recursion-status",
        metavar="CODES",
        help="Only recurse into hits with these status codes/ranges",
    )
    net_group.add_argument(
        "--recursion-match",
        metavar="REGEX",
        help="Only recurse into URLs matching this regex",
    )
    net_group.add_argument(
        "--recursion-filter",
        metavar="REGEX",
        help="Do not recurse into URLs matching this regex",
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
        "-q", "--quiet",
        action="store_true",
        help="Suppress live result/progress output",
    )
    misc_group.add_argument(
        "--silent",
        action="store_true",
        help="Alias for --quiet",
    )
    misc_group.add_argument(
        "--only-urls",
        action="store_true",
        help="Print only matched URLs in live output",
    )
    misc_group.add_argument(
        "--resume",
        action="store_true",
        help="Resume directory fuzzing from the previous resume state",
    )
    misc_group.add_argument(
        "--resume-file",
        metavar="FILE",
        help="Custom resume-state file path",
    )
    misc_group.add_argument(
        "--version",
        action="version",
        version="FuzzPhantom 1.0.0",
    )
    misc_group.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress ASCII banner",
    )

    # ── Matchers & Filters (ffuf-style) ──────────────────────────────────────
    filter_group = parser.add_argument_group("Matchers & Filters")
    filter_group.add_argument(
        "-mc", "--match-status",
        metavar="CODES",
        help="Match HTTP status codes (comma-separated, e.g. 200,302)",
    )
    filter_group.add_argument(
        "-fc", "--filter-status",
        metavar="CODES",
        help="Filter HTTP status codes (comma-separated, e.g. 404,500)",
    )
    filter_group.add_argument(
        "-ms", "--match-size",
        metavar="SIZES",
        help="Match response size in bytes (comma-separated)",
    )
    filter_group.add_argument(
        "-fs", "--filter-size",
        metavar="SIZES",
        help="Filter response size in bytes (comma-separated)",
    )
    filter_group.add_argument(
        "-mw", "--match-words",
        metavar="WORDS",
        help="Match response word count (comma-separated)",
    )
    filter_group.add_argument(
        "-fw", "--filter-words",
        metavar="WORDS",
        help="Filter response word count (comma-separated)",
    )
    filter_group.add_argument(
        "-ml", "--match-lines",
        metavar="LINES",
        help="Match response line count (comma-separated/ranges)",
    )
    filter_group.add_argument(
        "-fl", "--filter-lines",
        metavar="LINES",
        help="Filter response line count (comma-separated/ranges)",
    )
    filter_group.add_argument(
        "-mt", "--match-time",
        metavar="MS",
        help="Match response time in milliseconds (comma-separated/ranges)",
    )
    filter_group.add_argument(
        "-ft", "--filter-time",
        metavar="MS",
        help="Filter response time in milliseconds (comma-separated/ranges)",
    )
    filter_group.add_argument(
        "-mr", "--match-regex",
        metavar="REGEX",
        help="Match response body regex",
    )
    filter_group.add_argument(
        "-fr", "--filter-regex",
        metavar="REGEX",
        help="Filter response body regex",
    )
    filter_group.add_argument(
        "-mh", "--match-header",
        metavar="REGEX",
        help="Match response header regex",
    )
    filter_group.add_argument(
        "-fh", "--filter-header",
        metavar="REGEX",
        help="Filter response header regex",
    )
    filter_group.add_argument(
        "-mct", "--match-content-type",
        metavar="REGEX",
        help="Match Content-Type regex",
    )
    filter_group.add_argument(
        "-fct", "--filter-content-type",
        metavar="REGEX",
        help="Filter Content-Type regex",
    )

    return parser


# ── Context Builder ───────────────────────────────────────────────────────────

def build_context(args: argparse.Namespace) -> ScanContext:
    """Construct a ScanContext from parsed CLI arguments."""
    ctx = ScanContext()

    # Target
    if args.domain:
        ctx.target_domain = args.domain.strip()
        ctx.domains = [ctx.target_domain]

    if args.request:
        request_file = Path(args.request)
        if not request_file.exists():
            logger.error(f"Raw request file not found: {args.request}")
            sys.exit(1)
        from core.raw_request import parse_raw_request
        try:
            template = parse_raw_request(
                request_file.read_text(encoding="utf-8", errors="replace"),
                default_scheme=args.request_scheme,
            )
        except ValueError as exc:
            logger.error(f"Invalid raw request file: {exc}")
            sys.exit(1)

        ctx.target_domain = template.target_url
        ctx.domains = [template.target_url]
        ctx.request_method = template.method
        ctx.request_headers = template.headers
        ctx.request_body = template.body

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
    ctx.dir_wordlist_path = args.dir_wordlist or str(ROOT / "wordlists" / "directories.txt")
    ctx.payload_files = args.payloads or []
    ctx.fuzz_mode = args.fuzz_mode
    ctx.mutate_wordlist = args.mutate_wordlist
    ctx.mutate_depth = max(1, min(2, args.mutate_depth))

    for item in args.fuzz_wordlist or []:
        if ":" not in item:
            logger.error(f"Invalid fuzz wordlist '{item}'. Use FILE:KEY, e.g. users.txt:USER")
            sys.exit(1)
        path_text, key = item.rsplit(":", 1)
        key = key.strip()
        if not key:
            logger.error(f"Invalid fuzz wordlist '{item}'. Placeholder key is empty.")
            sys.exit(1)
        wordlist_file = Path(path_text)
        if not wordlist_file.exists():
            logger.error(f"Fuzz wordlist file not found: {path_text}")
            sys.exit(1)
        with open(wordlist_file, encoding="utf-8", errors="ignore") as f:
            words = [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
        if not words:
            logger.warning(f"Fuzz wordlist is empty: {path_text}")
        ctx.fuzz_wordlists[key] = words

    # Output
    ctx.output_formats = args.output
    ctx.output_dir = args.output_dir

    # Performance
    ctx.crawl_depth = args.depth
    ctx.dir_depth = max(1, args.dir_depth)
    ctx.rate_limit = args.rate
    ctx.threads = args.threads
    ctx.timeout = args.timeout
    ctx.auto_calibration = not args.no_calibration
    ctx.calibration_samples = max(1, args.calibration_samples)
    ctx.calibration_size_tolerance = max(0, args.calibration_size_tolerance)
    ctx.calibration_profile = args.calibration_profile
    ctx.delay_ms = max(0, args.delay)
    ctx.jitter_ms = max(0, args.jitter)
    ctx.max_errors = max(0, args.max_errors)
    ctx.max_hits = max(0, args.max_hits)

    # Network
    ctx.proxy = args.proxy
    ctx.proxy_max_failures = max(1, args.proxy_max_failures)
    ctx.replay_proxy = args.replay_proxy
    if args.user_agent:
        ctx.user_agent = args.user_agent
    if args.method:
        ctx.request_method = args.method.upper()
    elif not ctx.request_method:
        ctx.request_method = "GET"
    if args.data and not args.method and not args.request:
        ctx.request_method = "POST"
    if args.data is not None:
        ctx.request_body = args.data
    ctx.follow_redirects = args.follow_redirects
    if not ctx.request_headers:
        ctx.request_headers = {}
    for header in args.header or []:
        if ":" not in header:
            logger.warning(f"Invalid header ignored: {header}")
            continue
        name, value = header.split(":", 1)
        name = name.strip()
        if not name:
            logger.warning(f"Invalid header ignored: {header}")
            continue
        ctx.request_headers[name] = value.strip()

    # Misc
    ctx.dry_run = args.dry_run
    ctx.verbose = args.verbose
    ctx.quiet = args.quiet or args.silent
    ctx.output_only_urls = args.only_urls
    ctx.resume = args.resume
    ctx.resume_file = args.resume_file or ""
    ctx.smart_wordlist = args.smart_wordlist or args.all
    ctx.dir_extensions = [
        ext.strip().lstrip(".")
        for ext in (args.extensions or "").split(",")
        if ext.strip()
    ]

    # Matchers & Filters parsing
    from core.matchers import parse_number_spec, validate_regex

    def numeric_spec(val: str | None) -> str | None:
        if not val:
            return None
        try:
            parse_number_spec(val)
            return val
        except ValueError:
            logger.warning(f"Invalid numeric matcher/filter spec: {val}")
            return None

    def regex_spec(val: str | None) -> str | None:
        if not val:
            return None
        if not validate_regex(val):
            logger.warning(f"Invalid regex matcher/filter ignored: {val}")
            return None
        return val

    ctx.match_status = numeric_spec(args.match_status)
    ctx.filter_status = numeric_spec(args.filter_status)
    ctx.match_size = numeric_spec(args.match_size)
    ctx.filter_size = numeric_spec(args.filter_size)
    ctx.match_words = numeric_spec(args.match_words)
    ctx.filter_words = numeric_spec(args.filter_words)
    ctx.match_lines = numeric_spec(args.match_lines)
    ctx.filter_lines = numeric_spec(args.filter_lines)
    ctx.match_time = numeric_spec(args.match_time)
    ctx.filter_time = numeric_spec(args.filter_time)
    ctx.match_regex = regex_spec(args.match_regex)
    ctx.filter_regex = regex_spec(args.filter_regex)
    ctx.match_header = regex_spec(args.match_header)
    ctx.filter_header = regex_spec(args.filter_header)
    ctx.match_content_type = regex_spec(args.match_content_type)
    ctx.filter_content_type = regex_spec(args.filter_content_type)
    ctx.recursion_status = numeric_spec(args.recursion_status)
    ctx.recursion_match = regex_spec(args.recursion_match)
    ctx.recursion_filter = regex_spec(args.recursion_filter)

    ctx.configure_storage()
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
    table.add_row("Directories Found", str(summary["directories"]))
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
    if not args.domain and not args.domain_list and not args.url_list and not args.request:
        console.print(
            Panel(
                "[bold red]Error:[/bold red] You must specify a target with [bold]-d[/bold], [bold]-D[/bold], [bold]-U[/bold], or [bold]--request[/bold].\n\n"
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
        args.dir_fuzz = True
        args.fuzz = True
        args.api = True
        args.smart_wordlist = True

    if args.request and not (args.subdomains or args.crawl or args.dir_fuzz or args.fuzz or args.api):
        args.dir_fuzz = True

    if args.url_list and not (args.subdomains or args.crawl or args.dir_fuzz or args.fuzz or args.api):
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
            f"{'DirFuzz ' if args.dir_fuzz else ''}"
            f"{'Fuzz ' if args.fuzz else ''}"
            f"{'API ' if args.api else ''}"
            f"{'SmartWordlist ' if args.smart_wordlist else ''}\n"
            f"[bold cyan]Output:[/bold cyan] {', '.join(ctx.output_formats)} -> {ctx.output_dir}/\n"
            f"[bold cyan]Rate:[/bold cyan] {ctx.rate_limit} req/s  "
            f"[bold cyan]Threads:[/bold cyan] {ctx.threads}  "
            f"[bold cyan]Delay:[/bold cyan] {ctx.delay_ms}+{ctx.jitter_ms}ms  "
            f"[bold cyan]Depth:[/bold cyan] {ctx.crawl_depth}  "
            f"[bold cyan]DirDepth:[/bold cyan] {ctx.dir_depth}  "
            f"[bold cyan]Method:[/bold cyan] {ctx.request_method}  "
            f"[bold cyan]Redirects:[/bold cyan] {'follow' if ctx.follow_redirects else 'capture'}  "
            f"[bold cyan]Proxy:[/bold cyan] {ctx.proxy or 'None'}"
            f"{f'  [bold cyan]Replay:[/bold cyan] {ctx.replay_proxy}' if ctx.replay_proxy else ''}",
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

    if args.dir_fuzz:
        from modules.dir_fuzzer import run_dir_fuzzer
        await run_dir_fuzzer(ctx)

        if args.crawl:
            discovered_dirs = [
                f.url for f in ctx.findings
                if f.category == "Directory Found"
            ]
            if discovered_dirs:
                from modules.crawler import crawl
                await crawl(ctx, start_urls=discovered_dirs)

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
