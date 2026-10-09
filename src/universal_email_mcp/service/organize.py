"""Organize operations: mark, move, delete (to Trash) and create folders.

The write side of the service layer. Every decision comes from the caller (the
user through the client, bounded by permissions and policy); nothing here reads
instructions out of mail. Results are reported **per message**: a batch is never
silently all-or-nothing, and one stale or missing message does not hide the
others' outcome.

Flow of a batch: ids are decoded and de-duplicated, the account's permission is
checked for each one, the messages are grouped per account and folder (one
session, one SELECT per group), and the group is changed with UID-scoped
commands after the UIDVALIDITY in the id was checked against the folder. Moved
messages get new ids (from ``COPYUID``) that are returned so the client can keep
working with them. The header index is invalidated for every touched folder.

Delete means *move to the account's Trash folder*; mail that already is in Trash
is left alone and permanent deletion does not exist.
"""

from __future__ import annotations

import unicodedata
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from imapclient.imap_utf7 import encode as utf7_encode

from universal_email_mcp.config import Config
from universal_email_mcp.errors import (
    InvalidArgument,
    InvalidRef,
    MailError,
    MessageNotFound,
    NotPermitted,
    NoTrashFolder,
    ProtocolError,
    ServerUnreachable,
)
from universal_email_mcp.mail.foldername import split_new_path
from universal_email_mcp.mail.folders import decode_folder_name
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.models import Account, FolderInfo, MessageRef, MessageSummary
from universal_email_mcp.service import folder_list, fuzzy
from universal_email_mcp.service.index import HeaderIndex
from universal_email_mcp.service.router import AccountProblem, AccountRouter

Status = Literal["ok", "unchanged", "failed"]
Permission = Literal["organize", "delete"]


@dataclass(slots=True)
class Outcome:
    """What happened to one message of a batch (``id`` is the id as given)."""

    id: str
    status: Status = "failed"
    account: str = ""
    folder: str = ""
    """Source folder (decoded display name)."""
    subject: str = ""
    sender: str = ""
    flags: tuple[str, ...] | None = None
    """Mark: the message's flags afterwards."""
    destination: str = ""
    """Move/delete: the folder it went to (decoded display name)."""
    new_id: str | None = None
    """Move/delete: the message's new id (``None`` = unknown or not moved)."""
    code: str = ""
    message: str = ""
    hint: str = ""

    def fail(self, err: MailError | AccountProblem) -> Outcome:
        self.status = "failed"
        self.code = err.code
        self.message = err.message
        self.hint = err.hint
        return self


@dataclass(slots=True)
class BatchResult:
    outcomes: list[Outcome]
    notes: list[str] = field(default_factory=list[str])

    def count(self, status: Status) -> int:
        return sum(1 for o in self.outcomes if o.status == status)


@dataclass(frozen=True, slots=True)
class CreateResult:
    account: str
    path: str
    """The folder as the user knows it (display path, ``/``-separated)."""
    created: tuple[str, ...]
    existing: tuple[str, ...]
    subscribed: bool
    notes: tuple[str, ...] = ()


@dataclass(slots=True)
class _Group:
    """Messages of one account that share a source folder and UIDVALIDITY."""

    folder: str
    uidvalidity: int
    items: list[tuple[Outcome, MessageRef]] = field(
        default_factory=list[tuple[Outcome, MessageRef]]
    )


Op = Callable[[ImapSession, "_Ctx", _Group, list[tuple[Outcome, MessageRef]]], None]


@dataclass(slots=True)
class _Ctx:
    """Per-account state shared by the groups of one batch."""

    session: ImapSession
    prefix: str
    dest: FolderInfo | None = None
    notes: list[str] = field(default_factory=list[str])
    failure: MailError | None = None
    """Set when the destination could not be determined: every group fails with it."""


class Organizer:
    def __init__(
        self,
        config: Config,
        router: AccountRouter,
        index: HeaderIndex,
        prefix: Callable[[ImapSession], str],
    ) -> None:
        self.config = config
        self.router = router
        self.index = index
        self._prefix = prefix

    # ------------------------------------------------------------ batches

    def _decode(
        self, ids: Sequence[str], permission: Permission
    ) -> tuple[list[Outcome], dict[str, list[tuple[Outcome, MessageRef]]]]:
        """Outcomes in input order (duplicates dropped) and the refs per account."""
        cap = self.config.limits.max_batch_messages
        unique = list(dict.fromkeys(ids))
        if not unique:
            raise InvalidArgument("no message ids given", hint="Pass ids from find_messages.")
        if len(unique) > cap:
            raise InvalidArgument(
                f"{len(unique)} messages in one call; the limit is {cap}",
                hint=f"Split the request into batches of at most {cap} messages. Nothing was changed.",
            )
        outcomes: list[Outcome] = []
        by_account: dict[str, list[tuple[Outcome, MessageRef]]] = defaultdict(list)
        accounts: dict[str, Account | MailError] = {}
        for mid in unique:
            out = Outcome(mid)
            outcomes.append(out)
            try:
                ref = MessageRef.decode(mid)
            except InvalidRef as e:
                out.fail(e)
                continue
            if ref.account not in accounts:
                accounts[ref.account] = self._account(ref.account, permission)
            acc = accounts[ref.account]
            out.account = ref.account
            if isinstance(acc, MailError):
                out.fail(acc)
                continue
            out.folder = decode_folder_name(ref.folder)
            by_account[acc.name].append((out, ref))
        return outcomes, by_account

    def _account(self, name: str, permission: Permission) -> Account | MailError:
        try:
            acc = self.router.account(name, permission)
        except MailError as e:
            if e.code == "CONFIG_INVALID":
                return InvalidRef("message id refers to an unknown account")
            return e
        if acc.name != name:  # ids carry the exact configured name
            return InvalidRef("message id refers to an unknown account")
        return acc

    async def _run(
        self,
        ids: Sequence[str],
        permission: Permission,
        op: Op,
        *,
        dest_for: Callable[[ImapSession, _Ctx], None] | None = None,
    ) -> BatchResult:
        outcomes, by_account = self._decode(ids, permission)
        result = BatchResult(outcomes)
        if not by_account:
            return result
        accounts = [self.config.account(n) for n in by_account]

        def make(acc: Account) -> Callable[[ImapSession], list[str]]:
            def fn(session: ImapSession) -> list[str]:
                return self._account_work(session, by_account[acc.name], op, dest_for)

            return fn

        async def work(acc: Account) -> list[str]:
            return await self.router.call(acc, make(acc))

        fan = await self.router.fanout(accounts, work)
        for acc_name, notes in fan.results.items():
            result.notes += [f"{acc_name}: {n}" for n in notes]
        for p in fan.problems:
            for out, _ref in by_account[p.account]:
                if out.status == "failed" and not out.code:
                    out.fail(self._maybe_applied(p))
        return result

    @staticmethod
    def _maybe_applied(p: AccountProblem) -> AccountProblem:
        if p.code in ("TIMEOUT", "SERVER_UNREACHABLE"):
            return AccountProblem(
                p.account,
                p.code,
                p.message,
                "The change may or may not have been applied: search again before retrying.",
            )
        return p

    def _account_work(
        self,
        session: ImapSession,
        items: list[tuple[Outcome, MessageRef]],
        op: Op,
        dest_for: Callable[[ImapSession, _Ctx], None] | None,
    ) -> list[str]:
        ctx = _Ctx(session, self._prefix(session))
        if dest_for is not None:
            try:
                dest_for(session, ctx)
            except MailError as e:
                ctx.failure = e
        groups: dict[tuple[str, int], _Group] = {}
        for out, ref in items:
            g = groups.setdefault(
                (ref.folder, ref.uidvalidity), _Group(ref.folder, ref.uidvalidity)
            )
            g.items.append((out, ref))
        for g in groups.values():
            if ctx.failure is not None:
                for out, _ in g.items:
                    out.fail(ctx.failure)
                continue
            try:
                self._group(session, ctx, g, op)
            except ServerUnreachable:
                raise
            except MailError as e:
                for out, _ in g.items:
                    if not out.code and out.status != "ok":
                        out.fail(e)
        return ctx.notes

    def _group(self, session: ImapSession, ctx: _Ctx, g: _Group, op: Op) -> None:
        """Describe the group's messages, drop the ones that are gone, run ``op``."""
        # A retry after a lost connection re-runs the batch: finished ones stay.
        g.items = [(o, r) for o, r in g.items if o.status == "failed" and not o.code]
        if not g.items:
            return
        uids = list(dict.fromkeys(ref.uid for _o, ref in g.items))
        summaries = {
            s.ref.uid: s
            for s in self.index.summaries(session, g.folder, g.uidvalidity, uids)  # EXAMINE
        }
        live: list[tuple[Outcome, MessageRef]] = []
        for out, ref in g.items:
            s = summaries.get(ref.uid)
            if s is None:
                out.fail(MessageNotFound(f"message {ref.uid} is not in {out.folder!r} any more"))
                continue
            _describe(out, s)
            live.append((out, ref))
        try:
            if live:
                op(session, ctx, g, live)
        finally:
            self.index.invalidate(session.account_name, g.folder)

    # ------------------------------------------------------------ mark

    async def mark(
        self, ids: Sequence[str], *, seen: bool | None, flagged: bool | None
    ) -> BatchResult:
        add: list[str] = []
        remove: list[str] = []
        for flag, wanted in (("\\Seen", seen), ("\\Flagged", flagged)):
            if wanted is True:
                add.append(flag)
            elif wanted is False:
                remove.append(flag)
        if not (add or remove):
            raise InvalidArgument(
                "nothing to change", hint="Set seen and/or flagged to true or false."
            )

        def op(
            session: ImapSession, _ctx: _Ctx, g: _Group, live: list[tuple[Outcome, MessageRef]]
        ) -> None:
            change = session.set_flags(
                g.folder,
                [r.uid for _o, r in live],
                uidvalidity=g.uidvalidity,
                add=add,
                remove=remove,
            )
            for out, ref in live:
                flags = change.flags.get(ref.uid)
                if flags is None:
                    out.fail(MessageNotFound(f"message {ref.uid} vanished from {out.folder!r}"))
                else:
                    out.status, out.flags = "ok", flags

        return await self._run(ids, "organize", op)

    # ------------------------------------------------------------ move / delete

    async def move(self, ids: Sequence[str], *, to: str) -> BatchResult:
        if not to or not to.strip():
            raise InvalidArgument("no destination folder given", hint="Pass 'to'.")

        def dest_for(session: ImapSession, ctx: _Ctx) -> None:
            info, note = folder_list.resolve_folder(session, to, ctx.prefix, refresh=True)
            if info.role == "trash":
                raise InvalidArgument(
                    "the destination is the Trash folder",
                    hint="Use delete_messages to move mail to Trash.",
                )
            ctx.dest = info
            if note:
                ctx.notes.append(note)

        return await self._run(ids, "organize", self._move_op, dest_for=dest_for)

    async def delete(self, ids: Sequence[str]) -> BatchResult:
        def dest_for(session: ImapSession, ctx: _Ctx) -> None:
            session.list_folders(refresh=True)
            trash = session.folder_for_role("trash")
            if trash is None:
                raise NoTrashFolder("this account has no Trash folder")
            ctx.dest = trash

        return await self._run(ids, "delete", self._move_op, dest_for=dest_for)

    def _move_op(
        self,
        session: ImapSession,
        ctx: _Ctx,
        g: _Group,
        live: list[tuple[Outcome, MessageRef]],
    ) -> None:
        dest = ctx.dest
        assert dest is not None
        shown = dest.display_name
        if g.folder == dest.name or g.folder.upper() == dest.name.upper() == "INBOX":
            for out, _ref in live:
                out.status, out.destination = "unchanged", shown
                out.message = (
                    "already in Trash; permanent deletion is not offered"
                    if dest.role == "trash"
                    else "already in that folder"
                )
            return
        try:
            res = session.move_messages(
                g.folder, [r.uid for _o, r in live], dest.name, uidvalidity=g.uidvalidity
            )
        finally:
            self.index.invalidate(session.account_name, dest.name)
        for out, ref in live:
            out.destination = shown
            if ref.uid in res.copied_only:
                out.fail(
                    ProtocolError(
                        f"copied to {shown!r}, but the original could not be removed: "
                        "the message is now in both folders"
                    )
                )
            elif ref.uid in res.moved:
                out.status = "ok"
                new_uid = res.moved[ref.uid]
                if new_uid is not None and res.dest_uidvalidity is not None:
                    try:
                        out.new_id = MessageRef(
                            ref.account, res.dest, res.dest_uidvalidity, new_uid
                        ).encode()
                    except InvalidRef:
                        pass
                if out.new_id is None:
                    out.message = "moved; the server did not report its new id (search the folder)"
            else:
                out.fail(MessageNotFound(f"message {ref.uid} vanished from {out.folder!r}"))

    # ------------------------------------------------------------ create_folder

    def _target_account(self, account: str | None) -> Account:
        if account:
            return self.router.account(account, "organize")
        accounts, _problems = self.router.select(None, "organize")
        if not accounts:
            raise NotPermitted("no account allows creating folders")
        if len(accounts) > 1:
            raise InvalidArgument(
                "several accounts allow creating folders",
                hint="Pass account= with one of: " + ", ".join(a.name for a in accounts) + ".",
            )
        return accounts[0]

    async def create_folder(
        self, name: str, *, parent: str | None, account: str | None
    ) -> CreateResult:
        split_new_path(name, None)  # fail early, before connecting
        acc = self._target_account(account)

        def fn(session: ImapSession) -> CreateResult:
            return self._create(session, acc, name, parent)

        async def work(a: Account) -> CreateResult:
            return await self.router.call(a, fn)

        return await self.router.run_one(acc, work)

    def _create(
        self, session: ImapSession, acc: Account, name: str, parent: str | None
    ) -> CreateResult:
        prefix = self._prefix(session)
        folders = session.list_folders(refresh=True)
        delimiter = _delimiter(session, folders)
        levels = split_new_path(name, delimiter)
        notes: list[str] = []
        base: tuple[str, ...] = ()
        if parent:
            roots = folder_list.build(folders, prefix)
            node, note = folder_list.resolve(roots, parent, where=f" in account {acc.name!r}")
            if note:
                notes.append(note)
            base = node.path
            if node.info is not None and session.is_foreign(node.info.name):
                raise NotPermitted(
                    "folders cannot be created in another user's or a shared namespace"
                )
        full = (*base, *levels)
        if len(full) > 8:
            raise InvalidArgument("the folder would be nested more than 8 levels deep")
        known = {tuple(_fold(p) for p in fuzzy.folder_path(f, prefix)): f for f in folders}
        created: list[str] = []
        existing: list[str] = []
        subscribed = True
        parent_wire: str | None = None  # the server's own spelling of the levels so far
        for i in range(1, len(full) + 1):
            path = full[:i]
            hit = known.get(tuple(_fold(p) for p in path))
            if hit is not None:
                existing.append(hit.display_name)
                parent_wire = hit.name
                continue
            level = utf7_encode(full[i - 1]).decode("ascii")
            wire = prefix + level if parent_wire is None else f"{parent_wire}{delimiter}{level}"
            parent_wire = wire
            if session.create_folder(wire):
                created.append("/".join(path))
                if wire in session.subscribe_failed:
                    subscribed = False
            else:
                existing.append("/".join(path))
        if not created:
            notes.append("the folder already exists; nothing was changed")
        if not subscribed:
            notes.append(
                "created, but subscribing failed: the folder may be hidden in mail clients"
            )
        session.list_folders(refresh=True)
        return CreateResult(
            acc.name, "/".join(full), tuple(created), tuple(existing), subscribed, tuple(notes)
        )


# ----------------------------------------------------------------- helpers


def _fold(s: str) -> str:
    return unicodedata.normalize("NFC", s).casefold()


def _delimiter(session: ImapSession, folders: Sequence[FolderInfo]) -> str:
    """The server's hierarchy delimiter: personal namespace, else the most common
    one in the folder list, else ``/``."""
    ns = session.namespace()
    if ns and ns.personal and ns.personal[0][1]:
        return ns.personal[0][1]
    counts: dict[str, int] = defaultdict(int)
    for f in folders:
        if f.delimiter:
            counts[f.delimiter] += 1
    return max(counts, key=lambda d: counts[d]) if counts else "/"


def _describe(out: Outcome, s: MessageSummary) -> None:
    out.subject = s.subject
    out.sender = ", ".join(a.name or a.email for a in s.from_[:2])
