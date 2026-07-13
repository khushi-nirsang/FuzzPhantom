"""
FuzzPhantom — Session Manager
Async HTTP session with rate limiting, retry logic, proxy support,
and configurable headers. All modules import `get_session()`.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
try:
    from aiohttp_socks import ProxyConnector
except ImportError:  # pragma: no cover - optional dependency guard
    ProxyConnector = None  # type: ignore[assignment]

from core.context import ScanContext
from core.logger import get_logger

logger = get_logger(__name__)


class RateLimiter:
    """
    Token-bucket rate limiter.
    Limits outgoing requests to `rate` per second across all coroutines.
    """

    def __init__(self, rate: int) -> None:
        self.rate = max(1, rate)
        self._tokens = float(self.rate)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        sleep_for = 0.0
        async with self._lock:
            now = time.monotonic()
            elapsed = max(0.0, now - self._last_refill)
            self._tokens = min(float(self.rate), self._tokens + elapsed * self.rate)
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
            else:
                needed = 1.0 - self._tokens
                sleep_for = needed / self.rate
                self._tokens = 0.0
                self._last_refill = now + sleep_for

        if sleep_for > 0.0:
            await asyncio.sleep(sleep_for)


class FuzzSession:
    """
    Async HTTP session wrapper with rate limiting, retries, and proxy support.
    Use as an async context manager:

        async with FuzzSession(ctx) as session:
            resp = await session.get("https://example.com")
    """

    MAX_RETRIES = 3
    RETRY_BACKOFF = 0.5  # seconds

    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self._rate_limiter = RateLimiter(ctx.rate_limit)
        self._session: ClientSession | None = None
        self._proxies: list[str] = []
        self._http_proxies: list[str] = []
        self._socks_proxies: list[str] = []
        self._dead_proxies: set[str] = set()
        self._proxy_failures: dict[str, int] = {}
        self._proxy_index = 0
        self._session_proxy: str | None = None

        # Load rotating proxies
        if ctx.proxy:
            import os
            if os.path.isfile(ctx.proxy):
                try:
                    with open(ctx.proxy, "r", encoding="utf-8", errors="ignore") as f:
                        self._proxies = [line.strip() for line in f if line.strip()]
                except Exception as exc:
                    logger.error(f"Failed to read proxy file: {exc}")
            else:
                self._proxies = [p.strip() for p in ctx.proxy.split(",") if p.strip()]
        for proxy in self._proxies:
            if proxy.lower().startswith(("socks4://", "socks5://", "socks5h://")):
                self._socks_proxies.append(proxy)
            else:
                self._http_proxies.append(proxy)

    def _get_next_proxy(self) -> str | None:
        if not self._http_proxies:
            return None
        for _ in range(len(self._http_proxies)):
            proxy = self._http_proxies[self._proxy_index % len(self._http_proxies)]
            self._proxy_index += 1
            if proxy not in self._dead_proxies:
                return proxy
        return None

    def _mark_proxy_success(self, proxy: str | None) -> None:
        if not proxy:
            return
        self._proxy_failures[proxy] = 0

    def _mark_proxy_failure(self, proxy: str | None, exc: BaseException) -> None:
        if not proxy:
            return
        failures = self._proxy_failures.get(proxy, 0) + 1
        self._proxy_failures[proxy] = failures
        if failures >= self.ctx.proxy_max_failures:
            self._dead_proxies.add(proxy)
            logger.warning(f"Proxy quarantined after {failures} failures: {proxy} ({exc})")

    def _default_headers(self) -> dict[str, str]:
        # Realistic Chrome-like headers to avoid basic WAF/bot detection
        ua = self.ctx.user_agent
        if "FuzzPhantom" in ua or "compatible" in ua:
            ua = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            )
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive",
        }

    async def __aenter__(self) -> "FuzzSession":
        connector: TCPConnector
        if self._socks_proxies:
            if ProxyConnector is None:
                logger.warning("aiohttp-socks is not installed; SOCKS proxy support disabled.")
                connector = TCPConnector(
                    limit=self.ctx.threads,
                    limit_per_host=0,
                    ssl=False,
                    ttl_dns_cache=300,
                    keepalive_timeout=30,
                )
            else:
                self._session_proxy = self._socks_proxies[0]
                if len(self._socks_proxies) > 1:
                    logger.warning("Multiple SOCKS proxies provided; using the first one for this session.")
                connector = ProxyConnector.from_url(  # type: ignore[union-attr]
                    self._session_proxy,
                    limit=self.ctx.threads,
                    ssl=False,
                )
                if self._http_proxies:
                    logger.warning("Mixed HTTP and SOCKS proxies provided; SOCKS session proxy takes precedence.")
        else:
            connector = TCPConnector(
                limit=self.ctx.threads,
                limit_per_host=0,
                ssl=False,
                ttl_dns_cache=300,
                keepalive_timeout=30,
            )
        timeout = ClientTimeout(total=self.ctx.timeout)
        headers = self._default_headers()

        self._session = ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            trust_env=True,
        )
        return self

    async def replay_request(
        self,
        method: str,
        url: str,
        data: str | bytes | dict | None = None,
        headers: dict | None = None,
    ) -> None:
        """Replay a confirmed hit through a separate proxy for Burp/ZAP review."""
        proxy = self.ctx.replay_proxy
        if not proxy or self.ctx.dry_run:
            return

        method = method.upper()
        timeout = ClientTimeout(total=self.ctx.timeout)
        merged_headers = self._default_headers()
        if headers:
            merged_headers.update(headers)

        try:
            if proxy.lower().startswith(("socks4://", "socks5://", "socks5h://")):
                if ProxyConnector is None:
                    logger.warning("aiohttp-socks is not installed; replay SOCKS proxy skipped.")
                    return
                connector = ProxyConnector.from_url(proxy, ssl=False)  # type: ignore[union-attr]
                async with ClientSession(connector=connector, timeout=timeout, headers=merged_headers) as replay:
                    async with replay.request(method, url, data=data, allow_redirects=False) as resp:
                        await resp.read()
            else:
                connector = TCPConnector(ssl=False)
                async with ClientSession(connector=connector, timeout=timeout, headers=merged_headers) as replay:
                    async with replay.request(
                        method,
                        url,
                        data=data,
                        allow_redirects=False,
                        proxy=proxy,
                    ) as resp:
                        await resp.read()
            logger.debug(f"Replayed hit through proxy {proxy}: {method} {url}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.debug(f"Replay proxy failed for {method} {url}: {exc}")

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()

    async def _pace(self) -> None:
        await self._rate_limiter.acquire()
        delay = max(0, self.ctx.delay_ms) / 1000
        jitter = max(0, self.ctx.jitter_ms) / 1000
        if jitter:
            delay += random.uniform(0, jitter)
        if delay:
            await asyncio.sleep(delay)

    async def get(
        self,
        url: str,
        params: dict | None = None,
        headers: dict | None = None,
        allow_redirects: bool = True,
    ) -> aiohttp.ClientResponse | None:
        """Rate-limited GET with automatic retries."""
        if self.ctx.dry_run:
            logger.debug(f"[DRY RUN] GET {url}")
            return None

        await self._pace()

        for attempt in range(self.MAX_RETRIES):
            proxy = self._get_next_proxy()
            try:
                assert self._session is not None
                resp = await self._session.get(
                    url,
                    params=params,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    proxy=proxy,
                )
                self._mark_proxy_success(proxy)
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                self._mark_proxy_failure(proxy, exc)
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep(self.RETRY_BACKOFF * (attempt + 1))
                else:
                    logger.debug(f"Failed GET {url}: {exc}")
                    return None
        return None

    async def request(
        self,
        method: str,
        url: str,
        data: str | bytes | dict | None = None,
        json: dict | None = None,
        headers: dict | None = None,
        allow_redirects: bool = True,
    ) -> aiohttp.ClientResponse | None:
        """Rate-limited HTTP request with automatic retries."""
        method = method.upper()
        if self.ctx.dry_run:
            logger.debug(f"[DRY RUN] {method} {url}")
            return None

        await self._pace()

        for attempt in range(self.MAX_RETRIES):
            proxy = self._get_next_proxy()
            try:
                assert self._session is not None
                resp = await self._session.request(
                    method,
                    url,
                    data=data,
                    json=json,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    proxy=proxy,
                )
                self._mark_proxy_success(proxy)
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                self._mark_proxy_failure(proxy, exc)
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep(self.RETRY_BACKOFF * (attempt + 1))
                else:
                    logger.debug(f"Failed {method} {url}: {exc}")
                    return None
        return None

    async def post(
        self,
        url: str,
        data: dict | None = None,
        json: dict | None = None,
        headers: dict | None = None,
    ) -> aiohttp.ClientResponse | None:
        """Rate-limited POST with automatic retries."""
        if self.ctx.dry_run:
            logger.debug(f"[DRY RUN] POST {url}")
            return None

        await self._pace()

        for attempt in range(self.MAX_RETRIES):
            proxy = self._get_next_proxy()
            try:
                assert self._session is not None
                resp = await self._session.post(
                    url,
                    data=data,
                    json=json,
                    headers=headers,
                    proxy=proxy,
                )
                self._mark_proxy_success(proxy)
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                self._mark_proxy_failure(proxy, exc)
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep(self.RETRY_BACKOFF * (attempt + 1))
                else:
                    logger.debug(f"Failed POST {url}: {exc}")
                    return None
        return None
