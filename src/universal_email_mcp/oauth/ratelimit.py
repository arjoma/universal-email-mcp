"""Small in-memory sliding-window rate limiter.

State is per process: with several instances each one counts on its own (a limit of N
becomes at most N times the instance count). A shared counter in the store is a TODO.
Memory is bounded: when ``max_keys`` is reached the oldest keys are dropped.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 20_000,
    ) -> None:
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._events: dict[str, deque[float]] = {}

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
        q = self._live(key)
        if q is None or len(q) < self.limit:
            return 0
        return max(1, int(q[0] + self.window - self._clock()) + 1)

    def add(self, key: str) -> None:
        """Record one event for ``key``."""
        q = self._live(key)
        if q is None:
            if len(self._events) >= self._max_keys:
                for old in list(self._events)[: self._max_keys // 10 or 1]:
                    del self._events[old]
            q = self._events[key] = deque()
        q.append(self._clock())

    def allow(self, key: str) -> bool:
        """Count an event unless the allowance is used up; False = refuse."""
        if self.blocked(key):
            return False
        self.add(key)
        return True

    def reset(self, key: str) -> None:
        self._events.pop(key, None)
