"""Who the user has written to: the per-account "sent-to" address set.

An address counts as one the user has *written to* when it appears in To/Cc
of a message in the account's Sent folder within the last ``SENT_TO_DAYS`` days
(at most ``SENT_TO_HEADERS`` messages, newest first). Merely *receiving* mail
from someone never counts — otherwise the author of an injected mail would be
"known".

``find_contacts`` uses the set for its ``sent_to`` column (overview and search
alike). It is meant to be the basis of the send-time recipient trust check
(roadmap WP 2d, design §7.1): reuse :meth:`SentToIndex.get` there instead of
scanning Sent again.

The set is built from the header index (:class:`.index.HeaderIndex`) and kept per
(account, Sent folder, UIDVALIDITY); later calls only read the headers of new
UIDs. Addresses of messages deleted from Sent stay in the set until it is
rebuilt (TTL or UIDVALIDITY change). When the Sent folder is missing or the
header bound was hit, the set is *incomplete*: an address not in it is then
"unknown", never "not written to".
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from universal_email_mcp.mail.imap import ImapSession, SearchCriteria
from universal_email_mcp.service.index import HeaderIndex

SENT_TO_DAYS = 730
SENT_TO_HEADERS = 5_000
DEFAULT_TTL = 1800.0


@dataclass(frozen=True, slots=True)
class SentTo:
    addresses: frozenset[str]
    """Lower-cased addresses the user has written to."""
    complete: bool
    """False: Sent missing or the bound was hit — absence means "unknown"."""
    note: str | None = None

    def has(self, email: str) -> bool | None:
        """``True`` (written to), ``False`` (not, within the window) or ``None``
        (unknown: the set is incomplete)."""
        if email.strip().lower() in self.addresses:
            return True
        return False if self.complete else None


@dataclass(slots=True)
class _Entry:
    uidvalidity: int
    created: float
    uids: set[int] = field(default_factory=set[int])
    addresses: set[str] = field(default_factory=set[str])


class SentToIndex:
    def __init__(
        self,
        index: HeaderIndex,
        *,
        days: int = SENT_TO_DAYS,
        max_headers: int = SENT_TO_HEADERS,
        ttl: float = DEFAULT_TTL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._index = index
        self.days = days
        self.max_headers = max_headers
        self.ttl = ttl
        self._clock = clock
        self._entries: dict[tuple[str, str], _Entry] = {}
        self._lock = threading.Lock()

    def get(self, session: ImapSession, *, now: datetime | None = None) -> SentTo:
        """The account's sent-to set (runs in the account's worker thread)."""
        account = session.account_name
        sent = session.folder_for_role("sent")
        if sent is None:
            return SentTo(frozenset(), False, f"{account}: no Sent folder found")
        now = now or datetime.now(UTC)
        res = session.search(sent.name, SearchCriteria(since=(now - timedelta(self.days)).date()))
        key = (account, res.folder)
        with self._lock:
            entry = self._entries.get(key)
            if (
                entry is None
                or entry.uidvalidity != res.uidvalidity
                or self._clock() - entry.created > self.ttl
            ):
                entry = self._entries[key] = _Entry(res.uidvalidity, self._clock())
        uids = list(res.uids[: self.max_headers])
        new = [u for u in uids if u not in entry.uids]
        if new:
            for s in self._index.summaries(session, res.folder, res.uidvalidity, new):
                for a in (*s.to, *s.cc):
                    email = a.email.strip().lower()
                    if "@" in email:
                        entry.addresses.add(email)
            entry.uids.update(new)
        note = None
        complete = len(res.uids) <= self.max_headers
        if not complete:
            note = (
                f"{account}: 'sent to' covers the newest {self.max_headers} of "
                f"{len(res.uids)} sent messages"
            )
        return SentTo(frozenset(entry.addresses), complete, note)
