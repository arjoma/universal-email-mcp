"""Small in-memory sliding-window rate limiter.

State is per process: with several instances each one counts on its own (a limit of N
becomes at most N times the instance count). The only shared limit is the send limit,
which is counted in the store. See ``docs/operator-env.md`` ("Rate limits").

Memory is bounded twice: a key keeps at most ``limit`` timestamps, and at most ``max_keys``
keys are tracked - when the table is full, expired keys go first, then the oldest ones.
(A flood of distinct keys can push out the counters of real ones early; the cost is a
forgotten window, never a wrongly refused user.)
Keys live only in process memory and are never logged.
"""

from __future__ import annotations

import ipaddress
import time
from collections import deque
from collections.abc import Callable

DEFAULT_MAX_KEYS = 20_000
"""Distinct keys one limiter tracks."""


def ip_group(address: str) -> str:
    """The key an address is limited under: IPv4 as is, IPv6 grouped per /64 (one subscriber
    holds a whole /64, so single addresses would be free to rotate), IPv4-mapped IPv6 as its
    IPv4 address. Anything that is not an address - a forged header, an empty peer - shares
    one bucket (``"-"``), so garbage cannot be varied to dodge a limit or fill the table."""
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return "-"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


class RateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = DEFAULT_MAX_KEYS,
    ) -> None:
        self.limit = max(1, limit)
        self.window = window_seconds
        self._clock = clock
        self._max_keys = max(1, max_keys)
        self._events: dict[str, deque[float]] = {}

    def __len__(self) -> int:
        return len(self._events)

    def _live(self, key: str) -> deque[float] | None:
        q = self._events.get(key)
        if q is None:
            return None
        cutoff = self._clock() - self.window
        while q and q[0] <= cutoff:
            q.popleft()
        if not q:
            del self._events[key]
            return None
        return q

    def blocked(self, key: str) -> bool:
        """Has ``key`` used up its allowance (without counting a new event)?"""
        q = self._live(key)
        return q is not None and len(q) >= self.limit

    def retry_after(self, key: str) -> int:
        """Whole seconds until ``key`` may act again (0 = now)."""
        q = self._live(key)
        if q is None or len(q) < self.limit:
            return 0
        return max(1, int(q[0] + self.window - self._clock()) + 1)

    def _make_room(self) -> None:
        cutoff = self._clock() - self.window
        for key in [k for k, q in self._events.items() if not q or q[-1] <= cutoff]:
            del self._events[key]
        keep = self._max_keys - max(1, self._max_keys // 10)
        # insertion order: oldest first, but keys that are blocked right now go last
        for key in [k for k, q in self._events.items() if len(q) < self.limit]:
            if len(self._events) <= keep:
                return
            del self._events[key]
        while len(self._events) > keep:
            del self._events[next(iter(self._events))]

    def add(self, key: str) -> None:
        """Record one event for ``key``."""
        q = self._live(key)
        if q is None:
            if len(self._events) >= self._max_keys:
                self._make_room()
            q = self._events[key] = deque(maxlen=self.limit)
        q.append(self._clock())

    def allow(self, key: str) -> bool:
        """Count an event unless the allowance is used up; False = refuse."""
        if self.blocked(key):
            return False
        self.add(key)
        return True

    def reset(self, key: str) -> None:
        self._events.pop(key, None)


class LimiterSet:
    """Several limiters over the same kind of action, e.g. a burst and a sustained window.
    An event counts in all of them or - when one refuses - in none."""

    def __init__(self, *limiters: RateLimiter) -> None:
        self.limiters = limiters

    def retry_after(self, key: str) -> int:
        return max((lim.retry_after(key) for lim in self.limiters), default=0)

    def add(self, key: str) -> None:
        for lim in self.limiters:
            lim.add(key)

    def hit(self, key: str) -> int:
        """Count an event; returns 0 when allowed, else the seconds to wait (nothing counted)."""
        wait = self.retry_after(key)
        if not wait:
            self.add(key)
        return wait
