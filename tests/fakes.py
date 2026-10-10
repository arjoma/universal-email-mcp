"""In-memory stand-ins for :class:`ImapSession` (unit tests of the service layer).

Protocol behaviour is tested against Dovecot (tests/integration); these fakes only
exercise routing, paging, caching and fan-out logic.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from universal_email_mcp.config import Config, parse_config
from universal_email_mcp.errors import FolderNotFound, ServerUnreachable, UidValidityChanged
from universal_email_mcp.mail.imap import (
    MAX_RELATED_IDS,
    FolderStatus,
    IncrementalBatch,
    SearchCriteria,
    SearchResult,
)
from universal_email_mcp.models import Account, Address, FolderInfo, MessageRef, MessageSummary

BASE = datetime(2026, 9, 1, tzinfo=UTC)


def summary(
    account: str,
    folder: str,
    uid: int,
    *,
    uidvalidity: int = 1,
    subject: str = "",
    sender: str = "",
) -> MessageSummary:
    when = BASE + timedelta(hours=uid)
    return MessageSummary(
        ref=MessageRef(
            account,
            folder,
            uidvalidity,
            uid,
            key=ref_key("imap.example.org", f"{account.lower()}@example.org"),
        ),
        date=when,
        received=when,
        from_=(Address(sender, f"{sender.lower() or 'x'}@example.org"),),
        to=(),
        cc=(),
        reply_to=(),
        subject=subject or f"{account} {folder} #{uid}",
        flags=(),
        size=100,
        has_attachments=False,
        message_id=f"<{account}-{uid}@example.org>",
        in_reply_to=None,
        references=(),
    )


class FakeSession:
    """Folders with messages; ``hang`` makes every call block, ``fail_next`` makes
    the next call raise :class:`ServerUnreachable` (a dropped connection).

    ``close``/``abort`` of a real session do network I/O and may block, so calling
    them on the event loop thread is a bug: such calls are recorded in
    ``called_on_loop`` (tests assert it stays empty) and made slow by ``close_delay``.
    """

    def __init__(self, account: str, folders: dict[str, list[int]], uidvalidity: int = 1) -> None:
        self.account_name = account
        self.writes_started = 0
        self.uidvalidity = uidvalidity
        self.folders = {
            name: {
                u: summary(account, name, u, uidvalidity=uidvalidity, sender=account) for u in uids
            }
            for name, uids in folders.items()
        }
        self.calls: list[str] = []
        self.hang = 0.0
        self.fail_next = False
        self.closed = False
        self.aborted = threading.Event()
        self.role_warnings: list[str] = []
        self.capabilities: tuple[str, ...] = ("IMAP4REV1",)
        self.features: Any = None
        self.called_on_loop: list[str] = []
        self.related_queries: list[list[str]] = []
        self.close_delay = 0.0
        self.refreshes: list[bool] = []

    def _tick(self, what: str) -> None:
        self.calls.append(what)
        if self.hang:
            deadline = time.monotonic() + self.hang
            while time.monotonic() < deadline and self.hang:
                if self.aborted.is_set():
                    raise ServerUnreachable("aborted")
                time.sleep(0.01)
        if self.fail_next:
            self.fail_next = False
            raise ServerUnreachable("connection reset")

    def _blocking(self, what: str) -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            self.called_on_loop.append(what)
        if self.close_delay:
            time.sleep(self.close_delay)

    def close(self) -> None:
        self._blocking("close")
        self.closed = True

    def abort(self) -> None:
        self._blocking("abort")
        self.aborted.set()
        self.closed = True

    def namespace(self) -> None:
        return None

    def quota(self) -> None:
        return None

    def list_folders(self, *, with_counts: bool = False, refresh: bool = False) -> list[FolderInfo]:
        self._tick("LIST")
        self.refreshes.append(refresh)
        roles = {"INBOX": "inbox", "Sent": "sent", "Archive": "archive"}
        return [
            FolderInfo(name=n, display_name=n, delimiter="/", flags=(), role=roles.get(n))  # pyright: ignore[reportArgumentType]
            for n in self.folders
        ]

    def folder_status(self, folder: str) -> FolderStatus:
        self._tick(f"STATUS {folder}")
        if folder not in self.folders:
            raise FolderNotFound(f"no folder named {folder!r}")
        box = self.folders[folder]
        unseen = sum(1 for m in box.values() if "\\Seen" not in m.flags)
        return FolderStatus(folder, len(box), unseen, None, self.uidvalidity)

    def resolve_folder(self, name: str) -> FolderInfo:
        for f in self.list_folders():
            if name in (f.name, f.role) or f.name.casefold() == name.casefold():
                return f
        raise FolderNotFound(f"no folder named {name!r}")

    def folder_for_role(self, role: str) -> FolderInfo | None:
        return next((f for f in self.list_folders() if f.role == role), None)

    def search(self, folder: str, criteria: SearchCriteria | None = None) -> SearchResult:
        self._tick(f"SEARCH {folder}")
        uids = sorted(self.folders[folder], reverse=True)
        return SearchResult(self.account_name, folder, self.uidvalidity, tuple(uids), "uid")

    def search_related(self, folder: str, message_ids: Sequence[str]) -> SearchResult:
        self._tick(f"RELATED {folder}")
        ids = set(list(message_ids)[:MAX_RELATED_IDS])
        self.related_queries.append(list(message_ids))
        uids = sorted(
            (
                u
                for u, m in self.folders[folder].items()
                if ids & {m.message_id, m.in_reply_to, *m.references}
            ),
            reverse=True,
        )
        return SearchResult(self.account_name, folder, self.uidvalidity, tuple(uids), "uid")

    def search_recipients(
        self, folder: str, addresses: Sequence[str], *, since: Any = None
    ) -> SearchResult:
        """Substring match like a real server (``hanna@`` contains ``anna@``)."""
        self._tick(f"RSEARCH {folder} {len(addresses)}")
        wanted = [a.lower() for a in addresses]
        uids = sorted(
            (
                u
                for u, m in self.folders[folder].items()
                if any(w in x.email.lower() for x in (*m.to, *m.cc) for w in wanted)
            ),
            reverse=True,
        )
        return SearchResult(self.account_name, folder, self.uidvalidity, tuple(uids), "uid")

    def fetch_recipients(
        self, folder: str, uids: Sequence[int], *, uidvalidity: int | None = None
    ) -> dict[int, tuple[str, ...]]:
        self._tick(f"RFETCH {folder} {len(uids)}")
        if uidvalidity is not None and uidvalidity != self.uidvalidity:
            raise UidValidityChanged("changed")
        box = self.folders[folder]
        return {
            u: tuple(x.email.lower() for x in (*box[u].to, *box[u].cc)) for u in uids if u in box
        }

    def fetch_flags(
        self, folder: str, uids: Sequence[int], *, uidvalidity: int | None = None
    ) -> dict[int, tuple[str, ...]]:
        self._tick(f"FLAGS {folder} {len(uids)}")
        if uidvalidity is not None and uidvalidity != self.uidvalidity:
            raise UidValidityChanged("changed")
        box = self.folders[folder]
        return {u: box[u].flags for u in uids if u in box}

    def fetch_summaries(
        self, folder: str, uids: Sequence[int], *, uidvalidity: int | None = None
    ) -> list[MessageSummary]:
        self._tick(f"FETCH {folder} {len(uids)}")
        if uidvalidity is not None and uidvalidity != self.uidvalidity:
            raise UidValidityChanged("changed")
        box = self.folders[folder]
        return [box[u] for u in uids if u in box]

    def fetch_summaries_since_uid(
        self, folder: str, uidvalidity: int | None, last_uid: int, limit: int = 500
    ) -> IncrementalBatch:
        self._tick(f"SINCE {folder} {last_uid}")
        if uidvalidity is not None and uidvalidity != self.uidvalidity:
            raise UidValidityChanged("changed")
        new = sorted(u for u in self.folders[folder] if u > last_uid)
        take = new[:limit]
        sums = tuple(self.folders[folder][u] for u in take)
        return IncrementalBatch(
            folder, self.uidvalidity, sums, take[-1] if take else last_uid, len(new) > limit
        )


def config(*names: str, timeout: float = 2.0, **limits: Any) -> Config:
    return parse_config(
        {
            "accounts": [
                {"name": n, "username": f"{n.lower()}@example.org", "server": "imap.example.org"}
                for n in names
            ],
            "limits": {"account_timeout": timeout, **limits},
        }
    )


class Connector:
    """Connector for :class:`AccountRouter` handing out prepared fake sessions."""

    def __init__(self, sessions: dict[str, FakeSession]) -> None:
        self.sessions = sessions
        self.connects: list[str] = []
        self.fail: dict[str, Exception] = {}
        self.delay = 0.0
        """Seconds each connect takes (a tarpitting server)."""
        self.active = 0
        self.peak = 0
        self._lock = threading.Lock()

    def __call__(self, account: Account, _config: Config) -> FakeSession:
        self.connects.append(account.name)
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            if self.delay:
                time.sleep(self.delay)
        finally:
            with self._lock:
                self.active -= 1
        if account.name in self.fail:
            raise self.fail[account.name]
        s = self.sessions[account.name]
        s.closed = False
        s.aborted.clear()
        return s


def ref_key(host: str, username: str, kind: str = "imap") -> str:
    """The account key a config-loaded account gets (``config.parse_config``): what a message id
    for that mailbox has to carry."""
    from universal_email_mcp.models import account_key

    return account_key(f"{kind}\0{host.lower()}\0{username}")
