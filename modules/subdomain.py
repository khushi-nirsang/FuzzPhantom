"""
FuzzPhantom — Subdomain Discovery Module
Three discovery strategies:
  1. Wordlist brute-force with async DNS resolution
  2. Certificate Transparency logs (crt.sh)
  3. DNS zone-transfer attempt
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Generator
from urllib.parse import quote, urlparse

import dns.resolver
import dns.zone
import dns.query
import dns.exception
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
    parsed = urlparse(domain if "://" in domain else f"//{domain}")
    host = parsed.netloc or parsed.path
    host = host.strip().strip("/").split("/")[0].split(":")[0].lower()
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"


def _valid_subdomain(candidate: str, root: str) -> str | None:
    host = candidate.strip().lower().lstrip("*.").rstrip(".")
    if not host or host == root or not host.endswith(f".{root}"):
        return None
    if "/" in host or " " in host or "*" in host:
        return None
    if not re.fullmatch(r"[a-z0-9_.-]+", host):
        return None
    return host


# ── Strategy 1: DNS Brute-Force ──────────────────────────────────────────────

async def _resolve_subdomain(
    subdomain: str,
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    ctx: ScanContext,
) -> None:
    """Attempt to resolve a single subdomain candidate."""
    fqdn = f"{subdomain}.{domain}"
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
    domain = _extract_root(domain)
    console.rule(f"[bold cyan]Subdomain Brute-Force → {domain}[/bold cyan]")
    words = _load_wordlist(wordlist)
    if not words:
        logger.warning("Empty wordlist, skipping brute-force.")
        return

    import dns.asyncresolver
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.timeout = min(2.0, float(ctx.timeout))
    resolver.lifetime = min(4.0, float(ctx.timeout))

    queue = asyncio.Queue()
    for w in words:
        queue.put_nowait(w)

    async def worker() -> None:
        while not queue.empty():
            try:
                w = queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            await _resolve_subdomain(w, domain, resolver, ctx)
            queue.task_done()

    num_workers = min(max(ctx.threads * 5, ctx.threads), len(words), 500)
    logger.info(f"Testing {len(words)} candidates against {domain} using {num_workers} workers…")
    workers = [asyncio.create_task(worker()) for _ in range(num_workers)]
    await asyncio.gather(*workers)
    logger.info(f"Brute-force complete. Found {len(ctx.subdomains)} subdomains so far.")


# ── Strategy 2: Certificate Transparency (crt.sh) ───────────────────────────

async def fetch_ct_subdomains(domain: str, ctx: ScanContext, session: FuzzSession) -> None:
    """
    Query crt.sh certificate transparency API for subdomains.
    Uses async session requests.
    """
    console.rule(f"[bold cyan]Certificate Transparency → {domain}[/bold cyan]")
    root = _extract_root(domain)
    url = f"https://crt.sh/?q=%.{root}&output=json"

    try:
        resp = await session.get(url)
        if resp is None:
            return
        async with resp:
            if resp.status != 200:
                logger.error(f"crt.sh request failed with status {resp.status}")
                return
            try:
                entries = await resp.json()
            except Exception:
                logger.error("crt.sh returned non-JSON response.")
                return
    except Exception as exc:
        logger.error(f"crt.sh request failed: {exc}")
        return

    found: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value", "")
        for line in name_value.splitlines():
            candidate = _valid_subdomain(line, root)
            if candidate and candidate not in found:
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

async def fetch_hackertarget_subdomains(domain: str, ctx: ScanContext, session: FuzzSession) -> None:
    """No-key passive source similar to assetfinder-style aggregation."""
    root = _extract_root(domain)
    url = f"https://api.hackertarget.com/hostsearch/?q={quote(root)}"
    try:
        resp = await session.get(url)
        if resp is None:
            return
        async with resp:
            if resp.status != 200:
                return
            text = await resp.text(errors="replace")
    except Exception as exc:
        logger.debug(f"HackerTarget lookup failed for {root}: {exc}")
        return

    found = 0
    for line in text.splitlines():
        host = line.split(",", 1)[0]
        candidate = _valid_subdomain(host, root)
        if candidate:
            ctx.add_subdomain(candidate)
            found += 1
    logger.info(f"HackerTarget returned {found} subdomain candidate(s).")


async def fetch_otx_subdomains(domain: str, ctx: ScanContext, session: FuzzSession) -> None:
    """AlienVault OTX passive DNS, no API key required for this endpoint."""
    root = _extract_root(domain)
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(root)}/passive_dns"
    try:
        resp = await session.get(url)
        if resp is None:
            return
        async with resp:
            if resp.status != 200:
                return
            data = json.loads(await resp.text(errors="replace"))
    except Exception as exc:
        logger.debug(f"OTX lookup failed for {root}: {exc}")
        return

    found = 0
    for item in data.get("passive_dns", []):
        candidate = _valid_subdomain(str(item.get("hostname", "")), root)
        if candidate:
            ctx.add_subdomain(candidate)
            found += 1
    logger.info(f"AlienVault OTX returned {found} subdomain candidate(s).")


async def fetch_rapiddns_subdomains(domain: str, ctx: ScanContext, session: FuzzSession) -> None:
    """RapidDNS HTML scrape fallback for additional passive coverage."""
    root = _extract_root(domain)
    url = f"https://rapiddns.io/subdomain/{quote(root)}?full=1"
    try:
        resp = await session.get(url)
        if resp is None:
            return
        async with resp:
            if resp.status != 200:
                return
            text = await resp.text(errors="replace")
    except Exception as exc:
        logger.debug(f"RapidDNS lookup failed for {root}: {exc}")
        return

    found_hosts = {
        candidate
        for match in re.findall(rf"([a-zA-Z0-9_.-]+\.{re.escape(root)})", text)
        if (candidate := _valid_subdomain(match, root))
    }
    for host in found_hosts:
        ctx.add_subdomain(host)
    logger.info(f"RapidDNS returned {len(found_hosts)} subdomain candidate(s).")


def attempt_zone_transfer(domain: str, ctx: ScanContext) -> None:
    """
    Attempt a DNS AXFR zone transfer. Misconfigured servers may expose
    all DNS records. Findings are HIGH severity.
    """
    domain = _extract_root(domain)
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
    from core.session import FuzzSession
    domains = sorted({
        root
        for domain in (ctx.domains if ctx.domains else [ctx.target_domain])
        if (root := _extract_root(domain))
    })
    wordlist = ctx.wordlist_path or str(
        Path(__file__).parent.parent / "wordlists" / "subdomains.txt"
    )

    async with FuzzSession(ctx) as session:
        for domain in domains:
            await asyncio.gather(
                fetch_ct_subdomains(domain, ctx, session),
                fetch_hackertarget_subdomains(domain, ctx, session),
                fetch_otx_subdomains(domain, ctx, session),
                fetch_rapiddns_subdomains(domain, ctx, session),
                asyncio.to_thread(attempt_zone_transfer, domain, ctx),
                bruteforce_subdomains(domain, wordlist, ctx)
            )

    logger.info(
        f"[bold green]Subdomain discovery complete.[/bold green] "
        f"Total unique subdomains: [bold]{len(ctx.subdomains)}[/bold]"
    )
