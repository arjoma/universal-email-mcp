"""Who the user has written to: per-account "sent-to" knowledge.

An address counts as one the user has *written to* when it appears in To or Cc
of a message in the account's Sent folder within the last ``SENT_TO_DAYS`` days.
Merely *receiving* mail from someone never counts — otherwise the author of an
injected mail would be "known".

Two sources, both per (account, Sent folder, UIDVALIDITY) and kept across calls:

- an **address set** built incrementally by UID from the To/Cc header fields only
  (no envelope, no BODYSTRUCTURE; batched FETCH) — :meth:`SentToIndex.update`;
- an **exact per-recipient check** for addresses the set cannot decide yet: one
  ``UID SEARCH SINCE … OR TO x CC x …`` in Sent for all of them, with the hits'
  To/Cc compared exactly (the server matches substrings) —
  :meth:`SentToIndex.check`.

``find_contacts`` uses the set where it is complete and the check for the
contacts it shows. :meth:`SentToIndex.check` is the API the send-time recipient
trust check (roadmap WP 2d, design §7.1) is meant to use.

Addresses of messages deleted from Sent stay in the set until UIDVALIDITY
changes. When the Sent folder is missing or a bound was hit, the answer is
``None`` ("unknown"), never "not written to".
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from universal_email_mcp.mail.imap import ImapSession, SearchCriteria

SENT_TO_DAYS = 730
UPDATE_HEADERS = 5_000
"""Most new Sent messages one :meth:`SentToIndex.update` reads (later calls go on)."""
MAX_CHECKS = 20
"""Most open addresses one :meth:`SentToIndex.check` searches for (one SEARCH)."""
MAX_VERIFY = 500
"""Most search hits whose To/Cc are fetched (header fields only) to compare."""
NEGATIVE_TTL = 600.0
"""Seconds a definite "not written to" from a check is reused."""


@dataclass(frozen=True, slots=True)
class SentTo:
    addresses: frozenset[str]
    """Lower-cased addresses the user has written to (as far as read)."""
    complete: bool
    """True: every Sent message of the window was read — absence means "no"."""
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
    seen: set[int] = field(default_factory=set[int])
    addresses: set[str] = field(default_factory=set[str])
    complete: bool = False
    negatives: dict[str, float] = field(default_factory=dict[str, float])


class SentToIndex:
    def __init__(
        self,
        *,
        days: int = SENT_TO_DAYS,
        update_headers: int = UPDATE_HEADERS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.days = days
        self.update_headers = update_headers
        self._clock = clock
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    def _since(self, now: datetime | None) -> date:
        return ((now or datetime.now(UTC)) - timedelta(days=self.days)).date()

    def snapshot(self, account: str) -> SentTo:
        """What is known without any I/O."""
        with self._lock:
            e = self._entries.get(account)
            if e is None:
                return SentTo(frozenset(), False)
            return SentTo(frozenset(e.addresses), e.complete)

    def has_index(self, account: str) -> bool:
        with self._lock:
            return account in self._entries

    def _entry(self, account: str, uidvalidity: int) -> _Entry:
        with self._lock:
            e = self._entries.get(account)
            if e is None or e.uidvalidity != uidvalidity:
                e = self._entries[account] = _Entry(uidvalidity)
            return e

    def update(
        self, session: ImapSession, *, now: datetime | None = None, max_new: int | None = None
    ) -> SentTo:
        """Read the To/Cc of Sent messages not seen yet (newest first, at most
        ``max_new``) into the account's set. Runs in the account's worker thread."""
        account = session.account_name
        sent = session.folder_for_role("sent")
        if sent is None:
            return SentTo(frozenset(), False, f"{account}: no Sent folder found")
        res = session.search(sent.name, SearchCriteria(since=self._since(now)))
        e = self._entry(account, res.uidvalidity)
        limit = self.update_headers if max_new is None else max_new
        missing = [u for u in res.uids if u not in e.seen]
        take = missing[:limit]
        if take:
            recipients = session.fetch_recipients(res.folder, take, uidvalidity=res.uidvalidity)
            with self._lock:
                for addrs in recipients.values():
                    e.addresses.update(addrs)
                e.seen.update(take)
        e.complete = len(missing) <= len(take)
        note = None
        if not e.complete:
            note = (
                f"{account}: 'sent to' has read {len(e.seen)} of {len(res.uids)} sent "
                "messages so far; the rest is checked per address"
            )
        return SentTo(frozenset(e.addresses), e.complete, note)

    def check(
        self, session: ImapSession, addresses: Iterable[str], *, now: datetime | None = None
    ) -> dict[str, bool | None]:
        """Has the user written to each address (Sent, To/Cc, last ``days`` days)?

        ``True``/``False`` are definite; ``None`` means unknown (no Sent folder,
        more than ``MAX_CHECKS`` open addresses, or too many substring hits to
        verify). Uses the address set first; the open addresses go into one exact
        server search (``OR TO x CC x …``) whose hits' To/Cc are fetched and
        compared exactly. Runs in the account's worker thread. This is the
        per-recipient API for the send-time trust check (WP 2d).
        """
        wanted = list(dict.fromkeys(a.strip().lower() for a in addresses if "@" in a))
        sent = session.folder_for_role("sent")
        if sent is None:
            return dict.fromkeys(wanted)
        account = session.account_name
        out: dict[str, bool | None] = {}
        pending: list[str] = []
        snap = self.snapshot(account)
        for addr in wanted:
            known = snap.has(addr)
            if known is None:
                with self._lock:
                    e = self._entries.get(account)
                    checked = e.negatives.get(addr) if e else None
                if checked is not None and self._clock() - checked < NEGATIVE_TTL:
                    known = False
            if known is not None:
                out[addr] = known
            elif len(pending) < MAX_CHECKS:
                pending.append(addr)
            else:
                out[addr] = None
        if not pending:
            return out
        res = session.search_recipients(sent.name, pending, since=self._since(now))
        hits = list(res.uids[:MAX_VERIFY])
        recipients = (
            session.fetch_recipients(res.folder, hits, uidvalidity=res.uidvalidity) if hits else {}
        )
        seen = {a for r in recipients.values() for a in r}
        all_verified = len(res.uids) <= len(hits)
        e = self._entry(account, res.uidvalidity)
        stamp = self._clock()
        with self._lock:
            for addr in pending:
                if addr in seen:
                    e.addresses.add(addr)
                    out[addr] = True
                elif all_verified:
                    e.negatives[addr] = stamp
                    out[addr] = False
                else:
                    out[addr] = None  # too many substring hits to tell
        return out
