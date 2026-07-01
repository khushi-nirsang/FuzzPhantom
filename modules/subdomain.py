"""
FuzzPhantom — Subdomain Discovery Module
Three discovery strategies:
  1. Wordlist brute-force with async DNS resolution
  2. Certificate Transparency logs (crt.sh)
  3. DNS zone-transfer attempt
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Generator

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import requests
import tldextract

from core.context import ScanContext
from core.logger import get_logger, log_finding, console

logger = get_logger(__name__)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _load_wordlist(path: str) -> list[str]:
    """Load subdomain wordlist, stripping comments and blank lines."""
    p = Path(path)
    if not p.exists():
        logger.warning(f"Wordlist not found: {path}")
        return []
    with open(p, encoding="utf-8", errors="ignore") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


def _wordlist_chunks(words: list[str], size: int) -> Generator[list[str], None, None]:
    """Yield successive n-sized chunks from the wordlist."""
    for i in range(0, len(words), size):
        yield words[i : i + size]


def _extract_root(domain: str) -> str:
    """Extract registered root domain (e.g. 'example.com' from 'sub.example.com')."""
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"


# ── Strategy 1: DNS Brute-Force ──────────────────────────────────────────────

async def _resolve_subdomain(
    subdomain: str,
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    ctx: ScanContext,
    semaphore: asyncio.Semaphore,
) -> None:
    """Attempt to resolve a single subdomain candidate."""
    fqdn = f"{subdomain}.{domain}"
    async with semaphore:
        try:
            await resolver.resolve(fqdn, "A")
            ctx.add_subdomain(fqdn)
            log_finding("Subdomain [Brute-force]", fqdn, "Resolved via DNS A record", "INFO")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug(f"DNS error for {fqdn}: {exc}")


async def bruteforce_subdomains(domain: str, wordlist: str, ctx: ScanContext) -> None:
    """Async DNS brute-force using the provided wordlist."""
    console.rule(f"[bold cyan]Subdomain Brute-Force → {domain}[/bold cyan]")
    words = _load_wordlist(wordlist)
    if not words:
        logger.warning("Empty wordlist, skipping brute-force.")
        return

    import dns.asyncresolver
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = ctx.timeout
    resolver.lifetime = ctx.timeout

    semaphore = asyncio.Semaphore(ctx.threads)
    tasks = [
        _resolve_subdomain(w, domain, resolver, ctx, semaphore)
        for w in words
    ]
    logger.info(f"Testing {len(tasks)} candidates against {domain}…")
    await asyncio.gather(*tasks)
    logger.info(f"Brute-force complete. Found {len(ctx.subdomains)} subdomains so far.")


# ── Strategy 2: Certificate Transparency (crt.sh) ───────────────────────────

def fetch_ct_subdomains(domain: str, ctx: ScanContext) -> None:
    """
    Query crt.sh certificate transparency API for subdomains.
    Uses synchronous requests (crt.sh is an external API).
    """
    console.rule(f"[bold cyan]Certificate Transparency → {domain}[/bold cyan]")
    root = _extract_root(domain)
    url = f"https://crt.sh/?q=%.{root}&output=json"

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        entries = resp.json()
    except requests.RequestException as exc:
        logger.error(f"crt.sh request failed: {exc}")
        return
    except ValueError:
        logger.error("crt.sh returned non-JSON response.")
        return

    found: set[str] = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for line in name_value.splitlines():
            candidate = line.strip().lstrip("*.")
            if candidate.endswith(root) and candidate not in found:
                found.add(candidate)
                ctx.add_subdomain(candidate)
                log_finding(
                    "Subdomain [CT Log]",
                    candidate,
                    f"Issuer: {entry.get('issuer_name', 'N/A')}",
                    "INFO",
                )

    logger.info(f"CT logs returned {len(found)} unique subdomain(s).")


# ── Strategy 3: DNS Zone Transfer ────────────────────────────────────────────

def attempt_zone_transfer(domain: str, ctx: ScanContext) -> None:
    """
    Attempt a DNS AXFR zone transfer. Misconfigured servers may expose
    all DNS records. Findings are HIGH severity.
    """
    console.rule(f"[bold cyan]Zone Transfer Attempt → {domain}[/bold cyan]")
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
    except Exception as exc:
        logger.debug(f"NS lookup failed for {domain}: {exc}")
        return

    for ns in ns_records:
        ns_host = str(ns.target).rstrip(".")
        logger.info(f"Trying zone transfer from NS: {ns_host}")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=10))
            for name, _node in zone.nodes.items():
                fqdn = f"{name}.{domain}"
                ctx.add_subdomain(fqdn)
            log_finding(
                "Zone Transfer",
                domain,
                f"AXFR succeeded on {ns_host} — {len(zone.nodes)} records exposed",
                "HIGH",
            )
            from core.context import Finding
            ctx.add_finding(
                Finding(
                    category="Zone Transfer",
                    url=f"dns://{domain}",
                    severity="HIGH",
                    detail=f"AXFR succeeded on nameserver {ns_host}. "
                           f"{len(zone.nodes)} DNS records exposed.",
                )
            )
        except Exception:
            logger.debug(f"Zone transfer failed for {ns_host} (expected).")


# ── Public entry point ────────────────────────────────────────────────────────

async def run_subdomain_discovery(ctx: ScanContext) -> None:
    """
    Run all three subdomain discovery strategies for each domain in ctx.
    Populates ctx.subdomains.
    """
    domains = ctx.domains if ctx.domains else [ctx.target_domain]
    wordlist = ctx.wordlist_path or str(
        Path(__file__).parent.parent / "wordlists" / "subdomains.txt"
    )

    for domain in domains:
        # CT logs (sync, fast)
        fetch_ct_subdomains(domain, ctx)
        # Zone transfer attempt
        attempt_zone_transfer(domain, ctx)
        # DNS brute-force (async)
        await bruteforce_subdomains(domain, wordlist, ctx)

    logger.info(
        f"[bold green]Subdomain discovery complete.[/bold green] "
        f"Total unique subdomains: [bold]{len(ctx.subdomains)}[/bold]"
    )
