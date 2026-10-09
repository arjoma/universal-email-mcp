"""Archive scheme: where ``move_messages(to="archive")`` files a message.

Webmailers and clients split their archive folder by year (``Archive/2025``) or by
month (``Archive/2025/10`` or ``Archive/2025-10``). The scheme is detected from the
children of the archive folder (or fixed per account with ``archive_scheme``) and
each message goes to the folder of **its** date.

Detection looks at folder *names* only, and only ASCII digits are recognised: the
year and month folder names the server side creates are built from integers,
never from text of a mail. An empty archive (or one without date folders) is
``flat``: the safe default creates nothing; ``yearly`` / ``monthly`` must be asked
for with ``archive_scheme``.

The date is the message's ``Date`` header (what Thunderbird and webmail archive
plugins file by), because INTERNALDATE is the *import* date of every mail of a
migrated mailbox. The header is trusted only if it is parseable, not before 1990
and not later than INTERNALDATE + 1 day; a forged header can then only choose an
older year folder (names are built from integers, so that is harmless). Otherwise
INTERNALDATE (not before 1990, clamped to now), otherwise now.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from universal_email_mcp.models import ArchiveScheme, MessageSummary

MIN_YEAR = 1990
_YEAR = re.compile(r"(?:19|20)[0-9]{2}")
_MONTH = re.compile(r"0?[1-9]|1[0-2]")
_YEAR_MONTH = re.compile(r"((?:19|20)[0-9]{2})[-._ ](0?[1-9]|1[0-2])")

MonthForm = Literal["nested", "dashed"]


@dataclass(frozen=True, slots=True)
class ArchiveLayout:
    scheme: Literal["flat", "yearly", "monthly"]
    month_form: MonthForm = "nested"
    """Monthly only: ``2025/10`` (nested) or ``2025-10`` (dashed)."""
    detected: bool = True
    """``False`` when the account configuration fixed the scheme."""

    def describe(self) -> str:
        if self.scheme == "monthly":
            form = "YYYY/MM" if self.month_form == "nested" else "YYYY-MM"
            return f"monthly ({form})"
        return self.scheme


def detect(children: Iterable[Sequence[str]]) -> ArchiveLayout:
    """The scheme of an archive from the paths (levels) of the folders below it."""
    years = nested = dashed = 0
    for rel in children:
        names = [unicodedata.normalize("NFC", p).strip() for p in rel]
        if len(names) == 1:
            if _YEAR.fullmatch(names[0]):
                years += 1
            elif _YEAR_MONTH.fullmatch(names[0]):
                dashed += 1
        elif len(names) == 2 and _YEAR.fullmatch(names[0]) and _MONTH.fullmatch(names[1]):
            nested += 1
    if nested or dashed:
        return ArchiveLayout("monthly", "nested" if nested >= dashed else "dashed")
    if years:
        return ArchiveLayout("yearly")
    return ArchiveLayout("flat")


def layout_for(configured: ArchiveScheme, children: Iterable[Sequence[str]]) -> ArchiveLayout:
    """The configured scheme, else the detected one. A configured monthly scheme
    still follows the month form the archive already uses (default nested)."""
    found = detect(children)
    if configured == "auto":
        return found
    if configured == "monthly":
        form = found.month_form if found.scheme == "monthly" else "nested"
        return ArchiveLayout("monthly", form, detected=False)
    return ArchiveLayout(configured, detected=False)


def _naive(d: datetime) -> datetime:
    return d.astimezone().replace(tzinfo=None) if d.tzinfo else d


def archive_moment(s: MessageSummary, now: datetime) -> datetime:
    """The moment that decides a message's archive folder (see module doc)."""
    received = _naive(s.received) if s.received is not None else None
    if received is not None and received.year < MIN_YEAR:
        received = None
    limit = (received or now) + timedelta(days=1)
    if s.date is not None:
        when = _naive(s.date)
        if when.year >= MIN_YEAR and when <= min(limit, now + timedelta(days=1)):
            return min(when, now)
    return min(received, now) if received is not None else now


def relative_path(layout: ArchiveLayout, when: datetime) -> tuple[str, ...]:
    """Folder levels below the archive folder for ``when`` (built from integers)."""
    year, month = int(when.year), int(when.month)
    if layout.scheme == "flat":
        return ()
    if layout.scheme == "yearly":
        return (f"{year:04d}",)
    if layout.month_form == "dashed":
        return (f"{year:04d}-{month:02d}",)
    return (f"{year:04d}", f"{month:02d}")


def canon_level(level: str) -> str:
    """Comparison form of one folder level: digits without leading zeros
    (``09`` = ``9``), other names case-folded and NFC-normalised."""
    s = unicodedata.normalize("NFC", level).strip()
    if s.isascii() and s.isdigit():
        return str(int(s))
    m = _YEAR_MONTH.fullmatch(s)
    if m:
        return f"{int(m.group(1))}-{int(m.group(2))}"
    return s.casefold()
