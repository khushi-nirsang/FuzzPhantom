"""
FuzzPhantom — Directory Brute-Force Fuzzer
ffuf / dirbuster-style async directory discovery with:
  - Auto-calibration  (ffuf -ac equivalent) — detects site's "not found" baseline
    BEFORE fuzzing and silently discards false-positive matches
  - Recursive depth   (ffuf -recursion)      — re-fuzzes discovered sub-directories
  - Severity tagging  by HTTP status code
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import random
import re
import string
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.context import ScanContext, Finding
from core.matchers import number_matches, regex_matches
from core.session import FuzzSession
from core.logger import get_logger, console

logger = get_logger(__name__)


def log_finding(*_args: object, **_kwargs: object) -> None:
    """Legacy no-op; directory hits are printed as compact ffuf-style rows."""
    return None

_INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503}

_SEVERITY_MAP: dict[int, tuple[str, str]] = {
    200: ("HIGH",   "Accessible — content returned"),
    201: ("HIGH",   "Created — possible upload endpoint"),
    204: ("MEDIUM", "No Content — endpoint exists"),
    301: ("INFO",   "Permanent redirect"),
    302: ("INFO",   "Temporary redirect"),
    307: ("INFO",   "Temporary redirect"),
    308: ("INFO",   "Permanent redirect"),
    401: ("HIGH",   "Unauthorized — authentication required"),
    403: ("MEDIUM", "Forbidden — resource blocked but exists"),
    405: ("MEDIUM", "Method Not Allowed — endpoint exists"),
    500: ("MEDIUM", "Internal Server Error — possible vulnerability"),
    502: ("INFO",   "Bad Gateway"),
    503: ("INFO",   "Service Unavailable"),
}

_STATIC_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
    ".pdf", ".css", ".js", ".xml", ".html", ".htm", ".json",
}

_BUILTIN_WORDS = [
    "admin", "administrator", "login", "dashboard", "panel",
    "api", "api/v1", "api/v2", "v1", "v2", "graphql", "rest",
    "static", "assets", "uploads", "files", "media", "images",
    "config", "configuration", "settings", "env", "debug",
    "backup", "temp", "test", "dev", "internal", "private",
    "user", "users", "account", "auth", "oauth", "token",
    "health", "status", "ping", "metrics", "actuator",
    "robots.txt", "sitemap.xml", ".env", ".git",
    "wp-admin", "wp-login.php", "wp-json", "xmlrpc.php",
    "search", "find", "query", "export", "import", "upload",
    "secret", "secrets", "credentials", "keys", "password",
    "swagger", "swagger-ui", "openapi.json", "api-docs",
]


# ── Wordlist ──────────────────────────────────────────────────────────────────

def _format_eta(seconds: float) -> str:
    if seconds < 0 or seconds == float("inf"):
        return "--:--"
    seconds = int(seconds)
    mins, secs = divmod(seconds, 60)
    hours, mins = divmod(mins, 60)
    if hours:
        return f"{hours:02d}:{mins:02d}:{secs:02d}"
    return f"{mins:02d}:{secs:02d}"


def _payload_label(payloads: dict[str, str]) -> str:
    if not payloads:
        return ""
    if set(payloads) == {"FUZZ"}:
        return payloads["FUZZ"]
    return " ".join(f"{key}={value}" for key, value in payloads.items())


def _extract_title(body_text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160]


def _body_signature(body_text: str) -> str:
    text = re.sub(r"\s+", " ", body_text).strip().lower()
    return text[:240]


def _print_hit_row(
    url: str,
    status: int,
    size: int,
    words: int,
    lines: int,
    elapsed_ms: int,
    payloads: dict[str, str],
    ctx: ScanContext,
) -> None:
    if ctx.quiet:
        return
    if ctx.output_only_urls:
        console.print(url)
        return
    label = _payload_label(payloads)
    prefix = f"{label:<24} " if label else ""
    console.print(
        f"{prefix}[cyan]{url}[/cyan] "
        f"[Status: {status}, Size: {size}, Words: {words}, Lines: {lines}, Duration: {elapsed_ms}ms]"
    )


async def _mark_progress(
    progress: dict[str, object],
    ctx: ScanContext,
    force: bool = False,
) -> None:
    lock = progress["lock"]
    assert isinstance(lock, asyncio.Lock)
    async with lock:
        progress["tested"] = int(progress["tested"]) + 1
        tested = int(progress["tested"])
        total = int(progress["total"])
        now = time.monotonic()
        last_print = float(progress["last_print"])

        if ctx.quiet:
            return
        if not force and tested < total and now - last_print < 1.0:
            return

        progress["last_print"] = now
        elapsed = max(0.001, now - float(progress["start"]))
        rps = tested / elapsed
        remaining = max(0, total - tested)
        eta = _format_eta(remaining / rps if rps > 0 else float("inf"))
        console.print(
            f"[subtle]Progress {tested}/{total} | {rps:.1f} req/s | ETA {eta}[/subtle]"
        )


def _load_wordlist(ctx: ScanContext) -> list[str]:
    candidates = []
    if ctx.dir_wordlist_path:
        candidates.append(Path(ctx.dir_wordlist_path))
    candidates.extend([
        Path(__file__).parent.parent / "wordlists" / "directories.txt",
        Path(__file__).parent.parent / "wordlists" / "common.txt",
    ])

    for candidate in candidates:
        if candidate.exists():
            words = [
                ln.strip()
                for ln in candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
                if ln.strip() and not ln.startswith("#")
            ]
            if words:
                logger.info(f"Wordlist: {len(words)} entries ({candidate.name})")
                return words
    logger.warning("No wordlist file found — using built-in list")
    return _BUILTIN_WORDS


def _mutate_words(words: list[str], ctx: ScanContext) -> list[str]:
    if not ctx.mutate_wordlist:
        return words

    tech_words = {
        "admin": ["administrator", "admin-panel", "cpanel"],
        "api": ["api/v1", "api/v2", "graphql", "swagger", "openapi.json"],
        "login": ["signin", "auth", "oauth", "sso"],
        "upload": ["uploads", "files", "media"],
        "config": ["configuration", ".env", "settings"],
        "backup": ["bak", "backup.zip", "backup.tar.gz", "old"],
    }
    backup_suffixes = ["~", ".bak", ".old", ".orig", ".save", ".tmp", ".backup"]
    numeric_suffixes = ["1", "2", "01", "2024", "2025", "2026"]

    seen: set[str] = set()
    mutated: list[str] = []

    def add(value: str) -> None:
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            mutated.append(value)

    for word in words:
        add(word)
        base = word.rstrip("/")
        if not base:
            continue
        add(base.lower())
        add(base.upper())
        add(base.capitalize())
        if not word.endswith("/") and "." not in Path(urlparse(word).path).name:
            add(f"{base}/")
        for variant in tech_words.get(base.lower(), []):
            add(variant)
        for suffix in backup_suffixes:
            add(f"{base}{suffix}")
        if ctx.mutate_depth >= 2:
            for num in numeric_suffixes:
                add(f"{base}{num}")
                add(f"{base}-{num}")
                add(f"{base}_{num}")

    logger.info(f"Word mutations: {len(words)} base words -> {len(mutated)} candidates")
    return mutated


def _augment_words_from_context(words: list[str], ctx: ScanContext) -> list[str]:
    learned: set[str] = set()
    source_urls = list(ctx.crawled_urls) + list(ctx.api_endpoints) + list(ctx.parameterized_urls)
    for url in source_urls:
        parsed = urlparse(url)
        parts = [part for part in parsed.path.split("/") if part]
        for part in parts:
            clean = part.strip()
            if not clean:
                continue
            learned.add(clean)
            stem = Path(clean).stem
            if stem and stem != clean:
                learned.add(stem)
        for i in range(1, len(parts)):
            learned.add("/".join(parts[:i]))
    for term in ctx.smart_wordlist_terms[:500]:
        term = term.strip().strip("/")
        if term and re.fullmatch(r"[A-Za-z0-9_.-]{2,80}", term):
            learned.add(term)

    if not learned:
        return words

    seen: set[str] = set()
    merged: list[str] = []
    for word in list(words) + sorted(learned):
        if word and word not in seen:
            seen.add(word)
            merged.append(word)
    logger.info(f"Context word learning: +{len(learned)} candidates from crawl/API data")
    return merged


def _expand_extensions(words: list[str], extensions: list[str]) -> list[str]:
    """Return original words plus extension variants such as admin.php."""
    if not extensions:
        return words

    expanded: list[str] = []
    seen: set[str] = set()
    normalized_exts = [
        ext.strip().lstrip(".")
        for ext in extensions
        if ext.strip()
    ]

    for word in words:
        variants = [word]
        parsed_path = urlparse(word).path
        suffix = Path(parsed_path).suffix
        if not word.endswith("/") and not suffix:
            variants.extend(f"{word}.{ext}" for ext in normalized_exts)

        for variant in variants:
            if variant not in seen:
                seen.add(variant)
                expanded.append(variant)

    logger.info(
        f"Extension expansion: {len(words)} base words -> {len(expanded)} candidates"
    )
    return expanded


def _load_fuzz_wordlists(ctx: ScanContext) -> dict[str, list[str]]:
    if ctx.fuzz_wordlists:
        wordlists = {key: words[:] for key, words in ctx.fuzz_wordlists.items()}
    else:
        wordlists = {"FUZZ": _load_wordlist(ctx)}

    if "FUZZ" in wordlists:
        wordlists["FUZZ"] = _augment_words_from_context(wordlists["FUZZ"], ctx)
        wordlists["FUZZ"] = _mutate_words(wordlists["FUZZ"], ctx)
        wordlists["FUZZ"] = _expand_extensions(wordlists["FUZZ"], ctx.dir_extensions)

    for key, words in wordlists.items():
        logger.info(f"Fuzz wordlist {key}: {len(words)} entries")
    return wordlists


def _iter_payload_sets(
    wordlists: dict[str, list[str]],
    mode: str,
) -> tuple[int, object]:
    keys = list(wordlists)
    if not keys:
        return 0, iter(())

    if mode == "pitchfork":
        total = min((len(wordlists[key]) for key in keys), default=0)
        iterator = (
            dict(zip(keys, values))
            for values in zip(*(wordlists[key] for key in keys))
        )
        return total, iterator

    if mode == "clusterbomb":
        total = 1
        for key in keys:
            total *= len(wordlists[key])
        iterator = (
            dict(zip(keys, values))
            for values in itertools.product(*(wordlists[key] for key in keys))
        )
        return total, iterator

    # Sniper: fuzz one placeholder at a time while other placeholders use
    # their first word as a stable baseline value.
    defaults = {
        key: words[0]
        for key, words in wordlists.items()
        if words
    }
    total = sum(len(words) for words in wordlists.values())

    def sniper_iter():
        for key in keys:
            for word in wordlists[key]:
                payloads = defaults.copy()
                payloads[key] = word
                yield payloads

    return total, sniper_iter()


# ── Auto-Calibration (ffuf -ac) ───────────────────────────────────────────────

class Baseline:
    """
    Represents the "not found" signature for a given base URL.
    If a probe response matches this baseline, it is a false positive.
    """
    def __init__(self) -> None:
        self.status_codes: set[int] = set()
        self.body_hashes:  set[str] = set()
        self.body_snippets: set[str] = set()
        self.titles: set[str] = set()
        self.redirect_locations: set[str] = set()
        self.size_avg:     float    = 0.0
        self.size_std:     float    = 200.0  # tolerance in bytes
        self.words_avg:    float    = 0.0
        self.words_std:    float    = 20.0
        self.lines_avg:    float    = 0.0
        self.lines_std:    float    = 10.0
        self._has_3xx_baseline: bool = False  # True if site uses catch-all redirects
        self.disabled: bool = False

    def _class(self, status: int) -> int:
        return status // 100  # 200->2, 301->3, 404->4, etc.

    def is_false_positive(
        self,
        status: int,
        body_hash: str,
        size: int,
        words: int = 0,
        lines: int = 0,
        body_text: str = "",
        title: str = "",
        redirect_location: str = "",
    ) -> bool:
        if self.disabled:
            return False

        if redirect_location and redirect_location in self.redirect_locations:
            return True

        if title and title in self.titles and status in self.status_codes:
            return True

        snippet = _body_signature(body_text)
        if snippet and snippet in self.body_snippets and status in self.status_codes:
            return True

        # ── Key rule: catch-all redirect detection ───────────────────────────
        # If calibration shows ANY 3xx (302, 301, 307...) AND the probe also
        # returns ANY 3xx, it's a false positive — the server uses catch-all
        # redirects. We don't care which exact 3xx code it is.
        if self._has_3xx_baseline and 300 <= status < 400:
            return True

        # Standard status mismatch: clearly a real/different response
        if status not in self.status_codes:
            return False

        # Same status + identical body hash = definite false positive
        if body_hash and body_hash in self.body_hashes:
            return True

        # Same status + similar size = likely false positive
        if abs(size - self.size_avg) < self.size_std:
            return True

        if words and abs(words - self.words_avg) < self.words_std:
            return True

        if lines and abs(lines - self.lines_avg) < self.lines_std:
            return True

        return False


async def _calibrate(base_url: str, session: FuzzSession, ctx: ScanContext) -> Baseline:
    """
    Probe 4 random non-existent paths to learn the site's "not found" pattern.
    This mirrors ffuf's auto-calibration (-ac flag).
    """
    bl = Baseline()
    bl.size_std = float(ctx.calibration_size_tolerance)
    profile_multiplier = {"strict": 1.0, "balanced": 2.0, "relaxed": 3.0}[ctx.calibration_profile]
    if ctx.calibration_profile == "strict":
        bl.words_std = 5.0
        bl.lines_std = 3.0
    elif ctx.calibration_profile == "relaxed":
        bl.size_std = max(bl.size_std, 500.0)
        bl.words_std = 40.0
        bl.lines_std = 20.0
    if not ctx.auto_calibration:
        bl.disabled = True
        logger.info(f"Auto-calibration disabled for {base_url}")
        return bl

    sizes: list[int] = []
    word_counts: list[int] = []
    line_counts: list[int] = []

    logger.info(f"Auto-calibrating baseline for {base_url} …")

    for _ in range(ctx.calibration_samples):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        payloads = {key: rand for key in _placeholder_keys(ctx)}
        url, headers, body = _render_request(base_url, payloads, ctx)
        try:
            resp = await session.request(
                ctx.request_method,
                url,
                data=body,
                headers=headers or None,
                allow_redirects=ctx.follow_redirects,
            )
            if resp is None:
                continue
            async with resp:
                bl.status_codes.add(resp.status)
                location = resp.headers.get("Location", "")
                if location:
                    bl.redirect_locations.add(location)
                body = await resp.content.read(8192)
                body_text = body.decode(errors="replace")
                bl.body_hashes.add(hashlib.md5(body).hexdigest())
                snippet = _body_signature(body_text)
                if snippet:
                    bl.body_snippets.add(snippet)
                title = _extract_title(body_text)
                if title:
                    bl.titles.add(title)
                sizes.append(len(body))
                word_counts.append(len(body.split()))
                line_counts.append(len(body.split(b"\n")))
        except Exception:
            pass
        await asyncio.sleep(0.05)

    if sizes:
        bl.size_avg = sum(sizes) / len(sizes)
        if len(sizes) > 1:
            import statistics
            bl.size_std = max(float(ctx.calibration_size_tolerance), statistics.stdev(sizes) * profile_multiplier)
    if word_counts:
        bl.words_avg = sum(word_counts) / len(word_counts)
        if len(word_counts) > 1:
            import statistics
            bl.words_std = max(5.0, statistics.stdev(word_counts) * profile_multiplier)
    if line_counts:
        bl.lines_avg = sum(line_counts) / len(line_counts)
        if len(line_counts) > 1:
            import statistics
            bl.lines_std = max(3.0, statistics.stdev(line_counts) * profile_multiplier)

    # Mark if site uses catch-all 3xx redirects (the most common false-positive pattern)
    bl._has_3xx_baseline = any(300 <= s < 400 for s in bl.status_codes)

    logger.info(
        f"Baseline: status={bl.status_codes}  "
        f"avg_size={bl.size_avg:.0f}B  tolerance=±{bl.size_std:.0f}B  "
        f"catch-all-redirect={'YES — all 3xx will be filtered' if bl._has_3xx_baseline else 'no'}"
    )
    return bl


# ── Single Path Probe ─────────────────────────────────────────────────────────

def _should_recurse(url: str, status: int, ctx: ScanContext) -> bool:
    path = urlparse(url).path.lower()
    if any(path.endswith(ext) for ext in _STATIC_EXTS):
        return False
    if ctx.recursion_status and not number_matches(ctx.recursion_status, status):
        return False
    if ctx.recursion_match and not regex_matches(ctx.recursion_match, url):
        return False
    if ctx.recursion_filter and regex_matches(ctx.recursion_filter, url):
        return False
    return True


def _resume_path(ctx: ScanContext) -> Path:
    if ctx.resume_file:
        return Path(ctx.resume_file)
    target = ctx.target_domain or "unknown"
    digest = hashlib.sha1(f"{target}|{ctx.request_method}|{ctx.dir_wordlist_path}".encode()).hexdigest()[:12]
    return Path(ctx.output_dir) / f"fuzzphantom_resume_{digest}.json"


def _load_resume_state(ctx: ScanContext) -> set[str]:
    if not ctx.resume:
        return set()
    path = _resume_path(ctx)
    if not path.exists():
        logger.info(f"Resume requested, but no resume file exists yet: {path}")
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        visited = {str(item) for item in data.get("visited", [])}
        logger.info(f"Resume loaded: {len(visited)} tested requests from {path}")
        return visited
    except Exception as exc:
        logger.warning(f"Could not read resume file {path}: {exc}")
        return set()


def _save_resume_state(ctx: ScanContext, visited: set[str]) -> None:
    if not ctx.resume:
        return
    path = _resume_path(ctx)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "target": ctx.target_domain,
        "method": ctx.request_method,
        "visited": sorted(visited),
        "updated_at": int(time.time()),
    }
    try:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.debug(f"Could not write resume file {path}: {exc}")


async def _stop_requested(progress: dict[str, object]) -> bool:
    lock = progress["lock"]
    assert isinstance(lock, asyncio.Lock)
    async with lock:
        return bool(progress.get("stop"))


async def _record_error(progress: dict[str, object], ctx: ScanContext) -> None:
    lock = progress["lock"]
    assert isinstance(lock, asyncio.Lock)
    async with lock:
        progress["errors"] = int(progress.get("errors", 0)) + 1
        if ctx.max_errors and int(progress["errors"]) >= ctx.max_errors:
            progress["stop"] = True


async def _record_hit(progress: dict[str, object], ctx: ScanContext) -> None:
    lock = progress["lock"]
    assert isinstance(lock, asyncio.Lock)
    async with lock:
        progress["hits"] = int(progress.get("hits", 0)) + 1
        if ctx.max_hits and int(progress["hits"]) >= ctx.max_hits:
            progress["stop"] = True


def _placeholder_keys(ctx: ScanContext) -> list[str]:
    keys = list(ctx.fuzz_wordlists) if ctx.fuzz_wordlists else ["FUZZ"]
    if "FUZZ" not in keys:
        keys.append("FUZZ")
    return keys


def _replace_placeholders(value: str, payloads: dict[str, str]) -> str:
    rendered = value
    for key, replacement in payloads.items():
        rendered = rendered.replace(key, replacement)
    return rendered


def _has_request_template(ctx: ScanContext) -> bool:
    keys = _placeholder_keys(ctx)
    if any(key in ctx.request_body for key in keys):
        return True
    return any(
        key in name or key in value
        for name, value in ctx.request_headers.items()
        for key in keys
    )


def _render_request(
    base_url: str,
    payloads: dict[str, str],
    ctx: ScanContext,
) -> tuple[str, dict[str, str], str | None]:
    path_word = payloads.get("FUZZ") or next(iter(payloads.values()), "")
    if any(key in base_url for key in payloads):
        url = _replace_placeholders(base_url, payloads)
    elif _has_request_template(ctx):
        url = base_url
    else:
        url = urljoin(base_url.rstrip("/") + "/", path_word.lstrip("/"))

    headers = {
        _replace_placeholders(name, payloads): _replace_placeholders(value, payloads)
        for name, value in ctx.request_headers.items()
    }
    body = _replace_placeholders(ctx.request_body, payloads) if ctx.request_body else None
    return url, headers, body


async def _probe(
    base_url: str,
    payloads: dict[str, str],
    session: FuzzSession,
    ctx: ScanContext,
    sem: asyncio.Semaphore,
    next_queue: set[str],
    visited: set[str],
    baseline: Baseline,
    progress: dict[str, object],
) -> None:
    if await _stop_requested(progress):
        return

    url, headers, body = _render_request(base_url, payloads, ctx)

    visit_key = f"{ctx.request_method} {url} {body or ''} {headers}"
    if visit_key in visited:
        await _mark_progress(progress, ctx)
        return
    visited.add(visit_key)

    async with sem:
        try:
            t0 = time.monotonic()
            resp = await session.request(
                ctx.request_method,
                url,
                data=body,
                headers=headers or None,
                allow_redirects=ctx.follow_redirects,
            )
            await _mark_progress(progress, ctx)
            if resp is None:
                return

            async with resp:
                status = resp.status
                elapsed_ms = int((time.monotonic() - t0) * 1000)

                try:
                    body_bytes = await resp.content.read(8192)
                    cl_hdr = resp.headers.get("Content-Length")
                    size = int(cl_hdr) if cl_hdr else len(body_bytes)
                    body_hash = hashlib.md5(body_bytes).hexdigest()
                    body_text = body_bytes.decode(errors="replace")
                except Exception:
                    body_bytes = b""
                    body_hash = ""
                    body_text = ""
                    size = 0

                words = len(body_bytes.split())
                lines = len(body_bytes.split(b"\n"))
                headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                content_type = resp.headers.get("Content-Type", "")
                title = _extract_title(body_text)
                redirect_location = resp.headers.get("Location", "")
                final_url = str(resp.url)

                # ── Match/Filter Logic (ffuf-style) ───────────────────────────
                if ctx.filter_status and number_matches(ctx.filter_status, status):
                    return
                if ctx.filter_size and number_matches(ctx.filter_size, size):
                    return
                if ctx.filter_words and number_matches(ctx.filter_words, words):
                    return
                if ctx.filter_lines and number_matches(ctx.filter_lines, lines):
                    return
                if ctx.filter_time and number_matches(ctx.filter_time, elapsed_ms):
                    return
                if ctx.filter_regex and regex_matches(ctx.filter_regex, body_text):
                    return
                if ctx.filter_header and regex_matches(ctx.filter_header, headers_text):
                    return
                if ctx.filter_content_type and regex_matches(ctx.filter_content_type, content_type):
                    return

                matched = True
                if ctx.match_status:
                    if not number_matches(ctx.match_status, status):
                        matched = False
                elif status not in _INTERESTING:
                    matched = False
                if ctx.match_size and not number_matches(ctx.match_size, size):
                    matched = False
                if ctx.match_words and not number_matches(ctx.match_words, words):
                    matched = False
                if ctx.match_lines and not number_matches(ctx.match_lines, lines):
                    matched = False
                if ctx.match_time and not number_matches(ctx.match_time, elapsed_ms):
                    matched = False
                if ctx.match_regex and not regex_matches(ctx.match_regex, body_text):
                    matched = False
                if ctx.match_header and not regex_matches(ctx.match_header, headers_text):
                    matched = False
                if ctx.match_content_type and not regex_matches(ctx.match_content_type, content_type):
                    matched = False

                if not matched:
                    return

                # ── Auto-calibration false-positive filter ────────────────────
                if baseline.is_false_positive(
                    status,
                    body_hash,
                    size,
                    words=words,
                    lines=lines,
                    body_text=body_text,
                    title=title,
                    redirect_location=redirect_location,
                ):
                    return  # Matches "not found" baseline — discard

                severity, detail = _SEVERITY_MAP.get(status, ("INFO", f"HTTP {status}"))
                _print_hit_row(
                    final_url, status, size, words, lines, elapsed_ms, payloads, ctx
                )
                await session.replay_request(
                    ctx.request_method,
                    final_url,
                    data=body,
                    headers=headers or None,
                )

                log_finding(
                    f"Dir [{status}]", url,
                    f"{detail} — {size}B {elapsed_ms}ms", severity,
                )

                ctx.add_finding(Finding(
                    category="Directory Found",
                    url=final_url,
                    status_code=status,
                    response_length=size,
                    severity=severity,
                    detail=f"[{status}] {detail} ({size}B, {elapsed_ms}ms)",
                    extra={
                        "word": payloads.get("FUZZ", ""),
                        "payloads": payloads,
                        "elapsed_ms": elapsed_ms,
                        "status": status,
                        "words": words,
                        "lines": lines,
                        "method": ctx.request_method,
                        "content_type": content_type,
                        "requested_url": url,
                        "redirect_location": redirect_location,
                        "follow_redirects": ctx.follow_redirects,
                    },
                ))
                await _record_hit(progress, ctx)

                if (
                    ctx.request_method == "GET"
                    and not _has_request_template(ctx)
                    and _should_recurse(final_url, status, ctx)
                ):
                    next_queue.add(final_url)

        except Exception as exc:
            await _record_error(progress, ctx)
            logger.debug(f"Dir probe error {url}: {exc}")


# ── Main Entry Point ──────────────────────────────────────────────────────────

async def _run_depth_probes(
    base_urls: set[str],
    wordlists: dict[str, list[str]],
    session: FuzzSession,
    ctx: ScanContext,
    sem: asyncio.Semaphore,
    next_queue: set[str],
    visited: set[str],
    baselines: dict[str, Baseline],
    progress: dict[str, object],
) -> None:
    """
    Probe one recursion layer with a bounded queue.
    This keeps memory stable for large ffuf-style wordlists.
    """
    worker_count = max(1, ctx.threads)
    queue: asyncio.Queue[tuple[str, dict[str, str], Baseline] | None] = asyncio.Queue(
        maxsize=worker_count * 4
    )

    async def worker() -> None:
        while True:
            item = await queue.get()
            try:
                if item is None:
                    return

                base_url, payloads, baseline = item
                await _probe(
                    base_url, payloads, session, ctx, sem,
                    next_queue, visited, baseline, progress,
                )
            finally:
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

    for base_url in base_urls:
        baseline = baselines.get(base_url, Baseline())
        _, payload_sets = _iter_payload_sets(wordlists, ctx.fuzz_mode)
        for payloads in payload_sets:
            if await _stop_requested(progress):
                break
            await queue.put((base_url, payloads, baseline))
        if await _stop_requested(progress):
            break

    for _ in workers:
        await queue.put(None)

    await queue.join()
    await asyncio.gather(*workers)


async def run_dir_fuzzer(ctx: ScanContext, max_depth: int | None = None) -> None:
    """
    ffuf/dirbuster-style directory brute-forcer with:
      - Auto-calibration (ffuf -ac): filters out site-wide false positives
      - Recursive depth  (ffuf -recursion): re-fuzzes every discovered directory
    """
    console.rule("[bold cyan]Directory Brute-Force Fuzzer[/bold cyan]")

    max_depth = max_depth or ctx.dir_depth
    wordlists = _load_fuzz_wordlists(ctx)
    candidate_count, _ = _iter_payload_sets(wordlists, ctx.fuzz_mode)
    wordlist = range(candidate_count)

    target = ctx.target_domain
    if not target.startswith("http"):
        target = f"https://{target}"

    current_queue: set[str] = {target}
    for sd in ctx.subdomains[:10]:
        current_queue.add(f"https://{sd}" if not sd.startswith("http") else sd)

    visited: set[str] = _load_resume_state(ctx)
    sem = asyncio.Semaphore(ctx.threads)

    async with FuzzSession(ctx) as session:
        # Per-host baseline calibration in parallel
        base_urls = list(current_queue)
        calibration_results = await asyncio.gather(
            *[_calibrate(base_url, session, ctx) for base_url in base_urls]
        )
        baselines = dict(zip(base_urls, calibration_results))

        for depth in range(1, max_depth + 1):
            if not current_queue:
                break

            logger.info(
                f"Dir fuzzing depth {depth}/{max_depth} — "
                f"{len(current_queue)} base URL(s) × {len(wordlist)} words…"
            )
            next_queue: set[str] = set()
            progress: dict[str, object] = {
                "tested": 0,
                "total": len(current_queue) * candidate_count,
                "hits": 0,
                "errors": 0,
                "stop": False,
                "start": time.monotonic(),
                "last_print": 0.0,
                "lock": asyncio.Lock(),
            }

            await _run_depth_probes(
                current_queue, wordlists, session, ctx, sem,
                next_queue, visited, baselines, progress,
            )
            _save_resume_state(ctx, visited)

            if progress.get("stop"):
                logger.warning(
                    "Directory fuzzing stopped early "
                    f"(hits={progress.get('hits', 0)}, errors={progress.get('errors', 0)})"
                )
                break

            # Calibrate newly found bases only when another recursion layer will run.
            new_bases = [nb for nb in next_queue if nb not in baselines]
            if depth < max_depth and new_bases:
                new_results = await asyncio.gather(
                    *[_calibrate(nb, session, ctx) for nb in new_bases]
                )
                for nb, bl in zip(new_bases, new_results):
                    baselines[nb] = bl

            current_queue = next_queue

    dir_count = sum(1 for f in ctx.findings if f.category == "Directory Found")
    logger.info(
        f"[bold green]Directory fuzzing complete.[/bold green] "
        f"[bold]{dir_count}[/bold] real paths discovered "
        f"(false positives filtered by auto-calibration)"
    )
