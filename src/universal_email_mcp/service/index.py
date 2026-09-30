"""In-process header index: cached message summaries per (account, folder).

A pure speed-up — correctness never depends on it. Entries are keyed by
``(account, folder)`` and tagged with the folder's UIDVALIDITY; a different
UIDVALIDITY drops the entry. New mail is added incrementally with
:meth:`ImapSession.fetch_summaries_since_uid`; UIDs older than the cached range
are fetched on demand. Bounded: max summaries per folder (lowest UIDs evicted
first), LRU over folders, and a TTL after which an entry is rebuilt. Callers that
show results pass ``refresh_flags=True`` so cached entries get current flags.

Which UIDs exist is always decided by a fresh server SEARCH in the caller; the
index only supplies their headers. Thread-safe (worker threads of different
accounts share one index); callers hold the account's session lock.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace

from universal_email_mcp.errors import UidValidityChanged
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.models import MessageSummary

DEFAULT_MAX_PER_FOLDER = 5_000
DEFAULT_MAX_FOLDERS = 64
DEFAULT_TTL = 300.0
INCREMENTAL_WINDOW = 500
"""Incremental sync only when the new UIDs lie within this distance of the cached
high-water mark; otherwise just the requested UIDs are fetched."""


@dataclass(slots=True)
class _Entry:
    uidvalidity: int
    created: float
    last_uid: int = 0
    """High-water mark: UIDs above it are new mail, fetched incrementally."""
    items: dict[int, MessageSummary] = field(default_factory=dict[int, MessageSummary])


@dataclass(slots=True)
class IndexStats:
    hits: int = 0
    misses: int = 0
    incremental: int = 0
    invalidations: int = 0


class HeaderIndex:
    def __init__(
        self,
        *,
        max_per_folder: int = DEFAULT_MAX_PER_FOLDER,
        max_folders: int = DEFAULT_MAX_FOLDERS,
        ttl: float = DEFAULT_TTL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_per_folder = max_per_folder
        self.max_folders = max_folders
        self.ttl = ttl
        self._clock = clock
        self._entries: OrderedDict[tuple[str, str], _Entry] = OrderedDict()
        self._lock = threading.Lock()
        self.stats = IndexStats()

    def __len__(self) -> int:
        return len(self._entries)

    def invalidate(self, account: str, folder: str | None = None) -> None:
        with self._lock:
            for key in [k for k in self._entries if k[0] == account and folder in (None, k[1])]:
                del self._entries[key]

    def _entry(self, key: tuple[str, str], uidvalidity: int) -> _Entry:
        now = self._clock()
        with self._lock:
            e = self._entries.get(key)
            if e is not None and (e.uidvalidity != uidvalidity or now - e.created > self.ttl):
                if e.uidvalidity != uidvalidity:
                    self.stats.invalidations += 1
                e = None
            if e is None:
                e = _Entry(uidvalidity=uidvalidity, created=now)
                self._entries[key] = e
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_folders:
                self._entries.popitem(last=False)
            return e

    def summaries(
        self,
        session: ImapSession,
        folder: str,
        uidvalidity: int,
        uids: Sequence[int],
        *,
        refresh_flags: bool = False,
    ) -> list[MessageSummary]:
        """Summaries for ``uids`` (same order; vanished UIDs are skipped).

        ``folder`` is the wire name and ``uidvalidity`` comes from the caller's
        SEARCH; raises :class:`UidValidityChanged` if the folder changed since.
        ``refresh_flags``: re-read the flags of entries served from the cache (one
        cheap FETCH FLAGS) — for results shown to the user (unread, flagged).
        """
        key = (session.account_name, folder)
        entry = self._entry(key, uidvalidity)
        cached = [u for u in uids if u in entry.items]
        if refresh_flags and cached:
            flags = session.fetch_flags(folder, cached, uidvalidity=uidvalidity)
            with self._lock:
                for u in cached:
                    s = entry.items.get(u)
                    if s is None:
                        continue
                    if u not in flags:  # expunged meanwhile
                        del entry.items[u]
                    elif flags[u] != s.flags:
                        entry.items[u] = replace(s, flags=flags[u])
        missing = [u for u in uids if u not in entry.items]
        if missing and 0 < entry.last_uid < max(missing) <= entry.last_uid + INCREMENTAL_WINDOW:
            try:
                batch = session.fetch_summaries_since_uid(
                    folder, uidvalidity, entry.last_uid, limit=INCREMENTAL_WINDOW
                )
            except UidValidityChanged:
                self.invalidate(session.account_name, folder)
                raise
            self.stats.incremental += 1
            self._store(entry, batch.summaries)
            entry.last_uid = max(entry.last_uid, batch.last_uid)
            missing = [u for u in uids if u not in entry.items]
        self.stats.hits += len(uids) - len(missing)
        self.stats.misses += len(missing)
        if missing:
            fetched = session.fetch_summaries(folder, missing, uidvalidity=uidvalidity)
            self._store(entry, fetched)
            entry.last_uid = max(entry.last_uid, *missing)
        found = {u: entry.items[u] for u in uids if u in entry.items}
        return [found[u] for u in uids if u in found]

    def _store(self, entry: _Entry, summaries: Sequence[MessageSummary]) -> None:
        with self._lock:
            for s in summaries:
                entry.items[s.ref.uid] = s
            overflow = len(entry.items) - self.max_per_folder
            if overflow > 0:
                for uid in sorted(entry.items)[:overflow]:
                    del entry.items[uid]
