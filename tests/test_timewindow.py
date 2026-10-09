"""Time windows are days in the user's zone and exact on the arrival instant.

Nothing here reads the wall clock: ``now`` and the zone are injected. The IMAP side is
covered against Dovecot in ``tests/integration/test_imap_dovecot.py``.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from universal_email_mcp.mail.imap import SearchCriteria
from universal_email_mcp.mail.pop3 import matches
from universal_email_mcp.service.timewindow import resolve_window

from .fakes import summary

AHEAD = ZoneInfo("Pacific/Auckland")  # UTC+13 in October
BEHIND = ZoneInfo("America/Los_Angeles")  # UTC-7 in October


@pytest.mark.parametrize("zone", [AHEAD, BEHIND], ids=["ahead-of-utc", "behind-utc"])
def test_today_just_after_local_midnight_is_the_local_day(zone: ZoneInfo):
    now = datetime(2026, 10, 10, 0, 30, tzinfo=zone)
    w = resolve_window("today", now=now)
    assert w.since == date(2026, 10, 10) and w.before is None
    assert w.tz is now.tzinfo
    crit = SearchCriteria(since=w.since, before=w.before, tz=w.tz)
    lo, hi = crit.day_bounds()
    assert lo == datetime(2026, 10, 10, tzinfo=zone) and hi is None
    # the server search starts a day earlier: it counts days in its own zone
    assert crit.server_days() == (date(2026, 10, 9), None)


def test_without_a_zone_nothing_is_widened():
    crit = SearchCriteria(since=date(2026, 10, 10), before=date(2026, 10, 12))
    assert crit.server_days() == (date(2026, 10, 10), date(2026, 10, 12))
    assert crit.day_bounds() == (None, None)


def test_before_is_widened_the_other_way():
    crit = SearchCriteria(since=date(2026, 10, 10), before=date(2026, 10, 11), tz=AHEAD)
    assert crit.server_days() == (date(2026, 10, 9), date(2026, 10, 12))
    lo, hi = crit.day_bounds()
    assert hi == datetime(2026, 10, 11, tzinfo=AHEAD) and lo is not None


@pytest.mark.parametrize(
    ("zone", "first_inside"),
    [
        (AHEAD, datetime(2026, 10, 9, 11, 0, tzinfo=UTC)),  # 00:00 on Oct 10 in Auckland
        (BEHIND, datetime(2026, 10, 10, 7, 0, tzinfo=UTC)),  # 00:00 on Oct 10 in Los Angeles
    ],
    ids=["ahead-of-utc", "behind-utc"],
)
def test_pop3_filters_on_the_arrival_instant_in_the_zone(zone: ZoneInfo, first_inside: datetime):
    crit = SearchCriteria(since=date(2026, 10, 10), before=date(2026, 10, 11), tz=zone)

    def hit(at: datetime) -> bool:
        return matches(replace(summary("P", "INBOX", 1), received=at, date=at), crit)

    one = timedelta(minutes=1)
    assert hit(first_inside)
    assert not hit(first_inside - one)
    assert hit(first_inside + timedelta(days=1) - one)
    assert not hit(first_inside + timedelta(days=1))


def test_shown_flags_must_agree_with_the_unread_and_flagged_filter():
    """The search ran before the flags were read again; a hit the message no longer
    satisfies (read meanwhile) is dropped instead of listed under ``unread``."""
    from universal_email_mcp.service.mail import flags_agree

    base = summary("A", "INBOX", 1)
    unread, read = base, replace(base, flags=("\\Seen",))
    flagged = replace(base, flags=("\\Flagged",))
    assert flags_agree(unread, SearchCriteria(unseen=True))
    assert not flags_agree(read, SearchCriteria(unseen=True))
    assert flags_agree(read, SearchCriteria(unseen=False))
    assert not flags_agree(unread, SearchCriteria(unseen=False))
    assert flags_agree(flagged, SearchCriteria(flagged=True))
    assert not flags_agree(unread, SearchCriteria(flagged=True))
    assert flags_agree(unread, SearchCriteria())
    pop = replace(base, ref=replace(base.ref, account="P", folder="INBOX"))
    assert flags_agree(pop, SearchCriteria(unseen=True))
