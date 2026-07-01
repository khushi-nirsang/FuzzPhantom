"""
FuzzPhantom — Session Manager
Async HTTP session with rate limiting, retry logic, proxy support,
and configurable headers. All modules import `get_session()`.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from core.context import ScanContext
from core.logger import get_logger

logger = get_logger(__name__)


class RateLimiter:
    """
    Token-bucket rate limiter.
    Limits outgoing requests to `rate` per second across all coroutines.
    """

    def __init__(self, rate: int) -> None:
        self.rate = rate
        self._tokens = rate
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            refill = elapsed * self.rate
            self._tokens = min(self.rate, self._tokens + refill)
            self._last_refill = now

            if self._tokens < 1:
                sleep_for = (1 - self._tokens) / self.rate
                await asyncio.sleep(sleep_for)
                self._tokens = 0
            else:
                self._tokens -= 1


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
        self._proxy_index = 0

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

    def _get_next_proxy(self) -> str | None:
        if not self._proxies:
            return None
        proxy = self._proxies[self._proxy_index % len(self._proxies)]
        self._proxy_index += 1
        return proxy

    async def __aenter__(self) -> "FuzzSession":
        connector = TCPConnector(
            limit=self.ctx.threads,
            limit_per_host=0,  # Enable high parallel connections per host
            ssl=False,  # Disable SSL verification for bug bounty targets
            ttl_dns_cache=300,
        )
        timeout = ClientTimeout(total=self.ctx.timeout)
        headers = {
            "User-Agent": self.ctx.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

        self._session = ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            trust_env=True,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()

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

        await self._rate_limiter.acquire()

        for attempt in range(self.MAX_RETRIES):
            try:
                assert self._session is not None
                resp = await self._session.get(
                    url,
                    params=params,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    proxy=self._get_next_proxy(),
                )
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep(self.RETRY_BACKOFF * (attempt + 1))
                else:
                    logger.debug(f"Failed GET {url}: {exc}")
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

        await self._rate_limiter.acquire()

        for attempt in range(self.MAX_RETRIES):
            try:
                assert self._session is not None
                resp = await self._session.post(
                    url,
                    data=data,
                    json=json,
                    headers=headers,
                    proxy=self._get_next_proxy(),
                )
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep(self.RETRY_BACKOFF * (attempt + 1))
                else:
                    logger.debug(f"Failed POST {url}: {exc}")
                    return None
        return None
