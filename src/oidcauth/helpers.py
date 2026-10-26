"""Open-redirect guard and the login ticket stores."""

from __future__ import annotations

import asyncio
import time
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Callable, Protocol
from urllib.parse import urlsplit

from .errors import TicketNotFoundError
from .flow import random_token

if TYPE_CHECKING:  # pragma: no cover
    pass


def safe_return_to(raw: str | None, fallback: str = "/") -> str:
    """Accepts only same-origin relative paths ("/jobs?x=1") and returns
    fallback for anything else (absolute URLs, scheme-relative "//host",
    backslash tricks, control characters), preventing open redirects."""
    if not raw or not raw.startswith("/") or raw.startswith("//") or "\\" in raw:
        return fallback
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        return fallback
    try:
        u = urlsplit(raw)
    except ValueError:
        return fallback
    if u.scheme or u.netloc or "@" in u.netloc:
        return fallback
    return raw


def _seconds(ttl: timedelta | float) -> float:
    return ttl.total_seconds() if isinstance(ttl, timedelta) else float(ttl)


class TicketStore(Protocol):
    """Hands a value (typically the session token the app issued after a
    successful login) from the callback redirect to the SPA without putting the
    token itself in a URL. A ticket is random, short-lived and single-use.

    Implementations must make take atomic (get + delete). Use MemoryTicketStore
    for a single instance; RedisTicketStore (GETDEL) when running replicas.
    """

    async def put(self, value: str, ttl: timedelta | float) -> str: ...

    async def take(self, ticket: str) -> str:
        """Returns the value; raises TicketNotFoundError when the ticket is
        unknown, expired or already taken."""
        ...


class MemoryTicketStore:
    """An in-process TicketStore."""

    def __init__(self, now: Callable[[], float] = time.time) -> None:
        self._items: dict[str, tuple[str, float]] = {}
        self._lock = asyncio.Lock()
        self.now = now

    async def put(self, value: str, ttl: timedelta | float) -> str:
        ticket = random_token()
        async with self._lock:
            now = self.now()
            for k in [k for k, (_, exp) in self._items.items() if now > exp]:
                del self._items[k]
            self._items[ticket] = (value, now + _seconds(ttl))
        return ticket

    async def take(self, ticket: str) -> str:
        async with self._lock:
            item = self._items.pop(ticket, None)
        if item is None or self.now() > item[1]:
            raise TicketNotFoundError()
        return item[0]


class RedisTicketStore:
    """A TicketStore in Redis (redis.asyncio.Redis or a compatible client):
    SET with expiry, then GETDEL, so a ticket is taken once across replicas."""

    def __init__(self, redis: Any, prefix: str = "oidc:ticket:") -> None:
        self._redis = redis
        self._prefix = prefix

    async def put(self, value: str, ttl: timedelta | float) -> str:
        ticket = random_token()
        ms = max(1, int(_seconds(ttl) * 1000))
        await self._redis.set(self._prefix + ticket, value, px=ms)
        return ticket

    async def take(self, ticket: str) -> str:
        if not ticket:
            raise TicketNotFoundError()
        value = await self._redis.getdel(self._prefix + ticket)
        if value is None:
            raise TicketNotFoundError()
        return value.decode() if isinstance(value, bytes) else str(value)
