"""Rate limit of tool calls in remote mode (per instance, in memory).

Every call counts against the user (all grants together) and against its grant, each with a
burst window and a sustained window; tools that change something (``audit.WRITE_TOOLS``)
also count against a tighter limit of their own. A refused call counts nowhere, so a client
that waits as told gets through again. The check runs before the call takes a pool slot and
before anything touches a mail server.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from universal_email_mcp import audit
from universal_email_mcp.errors import RateLimited
from universal_email_mcp.oauth.config import Rate, RateLimits
from universal_email_mcp.oauth.ratelimit import LimiterSet, RateLimiter


def _set(*rates: Rate, clock: Callable[[], float]) -> LimiterSet:
    return LimiterSet(*(RateLimiter(r.count, r.seconds, clock=clock) for r in rates))


@dataclass(frozen=True, slots=True)
class Refusal:
    scope: str
    """``tool_user``, ``tool_grant`` or ``tool_write`` (the ``ratelimit.hit`` scope)."""
    retry_after: int


class ToolRateLimiter:
    def __init__(self, rates: RateLimits, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._user = _set(rates.tool_user_burst, rates.tool_user, clock=clock)
        self._grant = _set(rates.tool_grant_burst, rates.tool_grant, clock=clock)
        self._write = _set(rates.tool_write_burst, rates.tool_write, clock=clock)

    def check(self, user_id: str, grant_id: str, tool: str) -> Refusal | None:
        """Count the call, or say why it is refused."""
        checks = [("tool_user", self._user, user_id), ("tool_grant", self._grant, grant_id)]
        if tool in audit.WRITE_TOOLS:
            checks.append(("tool_write", self._write, user_id))
        worst: Refusal | None = None
        for scope, limiters, key in checks:
            wait = limiters.retry_after(key)
            if wait and (worst is None or wait > worst.retry_after):
                worst = Refusal(scope, wait)
        if worst is not None:
            return worst
        for _, limiters, key in checks:
            limiters.add(key)
        return None

    @staticmethod
    def error(refusal: Refusal) -> RateLimited:
        """The structured error the AI client receives (English, no internals)."""
        wait = refusal.retry_after
        return RateLimited(
            "Too many tool calls in a short time; this call was not run.",
            hint=(
                f"Wait {wait} seconds, then try again. Make fewer, larger requests "
                "(for example several messages per call) instead of many small ones."
            ),
            retry_after=wait,
        )
