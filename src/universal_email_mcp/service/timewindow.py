"""Natural time windows (``today``, ``this_week`` …) → day ranges in a time zone.

A window is a range of *days in the user's time zone* (``tz``: the zone of ``now``,
the server's local zone by default); ``before`` is exclusive. IMAP ``SINCE``/``BEFORE``
compare the server's idea of the arrival day, so the search layer widens the range and
filters exactly on the arrival instant (``SearchCriteria.tz``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, tzinfo
from typing import Literal, get_args

from universal_email_mcp.errors import InvalidArgument

Preset = Literal[
    "today",
    "yesterday",
    "this_week",
    "last_week",
    "last_7_days",
    "last_30_days",
    "this_month",
    "last_month",
    "last_90_days",
    "this_year",
]
PRESETS: tuple[Preset, ...] = get_args(Preset)


@dataclass(frozen=True, slots=True)
class Window:
    since: date | None
    before: date | None
    """Exclusive."""
    tz: tzinfo | None = None
    """The zone the days are in (``None``: unknown, server-day semantics)."""

    def describe(self) -> str:
        if self.since and self.before:
            last = self.before - timedelta(days=1)
            return str(self.since) if last == self.since else f"{self.since} – {last}"
        if self.since:
            return f"since {self.since}"
        if self.before:
            return f"before {self.before}"
        return "all time"


def _parse_day(value: str, what: str) -> date:
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError as e:
        raise InvalidArgument(
            f"{what} = {value!r} is not a date", hint="Use YYYY-MM-DD, e.g. 2026-09-28."
        ) from e


def resolve_window(
    window: str | None = None,
    since: str | None = None,
    before: str | None = None,
    *,
    now: datetime | None = None,
) -> Window:
    """Combine a preset with explicit ``since``/``before`` (explicit values win)."""
    now = now or datetime.now().astimezone()
    tz = now.tzinfo
    today = now.date()
    w_since: date | None = None
    w_before: date | None = None
    if window:
        key = window.strip().lower().replace(" ", "_").replace("-", "_")
        if key not in PRESETS:
            raise InvalidArgument(
                f"unknown time window {window!r}", hint=f"Use one of: {', '.join(PRESETS)}."
            )
        monday = today - timedelta(days=today.weekday())
        first = today.replace(day=1)
        match key:
            case "today":
                w_since = today
            case "yesterday":
                w_since, w_before = today - timedelta(days=1), today
            case "this_week":
                w_since = monday
            case "last_week":
                w_since, w_before = monday - timedelta(days=7), monday
            case "last_7_days":
                w_since = today - timedelta(days=6)
            case "last_30_days":
                w_since = today - timedelta(days=29)
            case "last_90_days":
                w_since = today - timedelta(days=89)
            case "this_month":
                w_since = first
            case "last_month":
                w_since, w_before = (first - timedelta(days=1)).replace(day=1), first
            case _:  # this_year
                w_since = today.replace(month=1, day=1)
    if since:
        w_since = _parse_day(since, "since")
    if before:
        w_before = _parse_day(before, "before")
    if w_since and w_before and w_before <= w_since:
        raise InvalidArgument("'before' must be later than 'since'")
    return Window(w_since, w_before, tz)
