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

``move(to="archive")`` files each message into the folder of its date below the
account's archive folder (:mod:`archive`); ``with_conversation`` first collects
the conversation of every given message (read-only, a bounded search in the
same account, see ``MailService._conversation_members``), checks the batch cap
against the whole set, and ``dry_run`` stops after reporting what would happen.
The decision where mail goes comes from the caller and the account's folders,
never from header or body text.
"""

from __future__ import annotations

import time
import unicodedata
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from imapclient.imap_utf7 import encode as utf7_encode

from universal_email_mcp.config import Config
from universal_email_mcp.errors import (
    InvalidArgument,
    InvalidRef,
    MailError,
    MessageNotFound,
    NoArchiveFolder,
    NotPermitted,
    NoTrashFolder,
    ProtocolError,
    ServerUnreachable,
)
from universal_email_mcp.mail.foldername import split_new_path
from universal_email_mcp.mail.folders import decode_folder_name
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.models import Account, FolderInfo, MessageRef, MessageSummary
from universal_email_mcp.service import archive, folder_list, fuzzy
from universal_email_mcp.service.index import HeaderIndex
from universal_email_mcp.service.router import AccountProblem, AccountRouter

Status = Literal["ok", "unchanged", "failed", "planned"]
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
    member: bool = False
    """Conversation move: found as a member of the conversation, not named by the caller."""
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
    dry_run: bool = False

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


@dataclass(frozen=True, slots=True)
class Conversation:
    """The conversation of one message as ``move_messages`` takes it along."""

    members: list[MessageSummary]
    """The message itself and its conversation (same account), unordered."""
    notes: list[str] = field(default_factory=list[str])


ConversationOf = Callable[[ImapSession, MessageRef, float], Conversation]
"""(session, message, monotonic deadline shared by all searches of the batch)"""

MOVE_ROLES_BY_DEFAULT = ("inbox", "sent", "archive")
"""Roles of the folders whose conversation members move along (plus the folders
of the given messages themselves and the archive's subfolders). Trash, Junk and
Drafts never take part."""
_NEVER_ROLES = ("trash", "junk", "drafts")


@dataclass(slots=True)
class _ArchivePlan:
    """Where ``to="archive"`` files mail in one account."""

    folder: FolderInfo
    path: tuple[str, ...]
    layout: archive.ArchiveLayout
    known: dict[tuple[str, ...], FolderInfo]
    """Folders below the archive by canonical relative path (see ``archive.canon_level``)."""
    delimiter: str
    now: datetime

    def target(self, when: datetime) -> tuple[str, ...]:
        return archive.relative_path(self.layout, when)

    def contains(self, path: tuple[str, ...]) -> bool:
        return _fold_path(path[: len(self.path)]) == _fold_path(self.path)


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
    archive: _ArchivePlan | None = None
    dry_run: bool = False
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
        conversation_of: ConversationOf | None = None,
    ) -> None:
        self.config = config
        self.router = router
        self.index = index
        self._prefix = prefix
        self._conversation_of = conversation_of

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
        return await self._execute(BatchResult(outcomes), by_account, op, dest_for=dest_for)

    async def _execute(
        self,
        result: BatchResult,
        by_account: dict[str, list[tuple[Outcome, MessageRef]]],
        op: Op,
        *,
        dest_for: Callable[[ImapSession, _Ctx], None] | None = None,
    ) -> BatchResult:
        if not by_account:
            return result
        accounts = [self.config.account(n) for n in by_account]

        def make(acc: Account) -> Callable[[ImapSession], list[str]]:
            def fn(session: ImapSession) -> list[str]:
                return self._account_work(
                    session, by_account[acc.name], op, dest_for, result.dry_run
                )

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
        dry_run: bool = False,
    ) -> list[str]:
        ctx = _Ctx(session, self._prefix(session), dry_run=dry_run)
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

    async def move(
        self,
        ids: Sequence[str],
        *,
        to: str,
        with_conversation: bool = False,
        dry_run: bool = False,
    ) -> BatchResult:
        if not to or not to.strip():
            raise InvalidArgument("no destination folder given", hint="Pass 'to'.")
        to_archive = to.strip().casefold() == "archive"

        def dest_for(session: ImapSession, ctx: _Ctx) -> None:
            if to_archive:
                ctx.archive = self._archive_plan(session, ctx)
                return
            info, note = folder_list.resolve_folder(
                session, to, ctx.prefix, refresh=True, exact=True
            )
            if info.role == "trash":
                raise InvalidArgument(
                    "the destination is the Trash folder",
                    hint="Use delete_messages to move mail to Trash.",
                )
            ctx.dest = info
            if note:
                ctx.notes.append(note)

        outcomes, by_account = self._decode(ids, "organize")
        result = BatchResult(outcomes, dry_run=dry_run)
        if with_conversation:
            await self._add_conversations(result, by_account)
        op = self._archive_op if to_archive else self._move_op
        return await self._execute(result, by_account, op, dest_for=dest_for)

    # ------------------------------------------------------------ conversations

    async def _add_conversations(
        self, result: BatchResult, by_account: dict[str, list[tuple[Outcome, MessageRef]]]
    ) -> None:
        """Add the conversation members of every given message (read-only), after
        checking that given messages and members together fit the batch cap."""
        if self._conversation_of is None:  # pragma: no cover - wired by MailService
            raise InvalidArgument("conversations are not available")
        cap = self.config.limits.max_batch_messages
        accounts = [self.config.account(n) for n in by_account]

        def make(acc: Account) -> Callable[[ImapSession], _Found]:
            def fn(session: ImapSession) -> _Found:
                return self._collect(session, by_account[acc.name])

            return fn

        async def work(acc: Account) -> _Found:
            return await self.router.call(acc, make(acc))

        fan = await self.router.fanout(accounts, work)
        for p in fan.problems:  # read-only so far: nothing was changed
            for out, _ref in by_account[p.account]:
                if not out.code:
                    out.fail(p)
        total = len(result.outcomes)
        for found in fan.results.values():
            total += len(found.members)
        if total > cap:
            raise InvalidArgument(
                f"the messages and their conversations come to {total} messages; "
                f"the limit is {cap}",
                hint=f"Nothing was changed. Move fewer messages at once (at most {cap} "
                "including the conversation members), or move without with_conversation.",
            )
        for acc_name, found in fan.results.items():
            result.notes += [f"{acc_name}: {n}" for n in found.notes]
            for out, ref in found.members:
                by_account[acc_name].append((out, ref))
                result.outcomes.append(out)
            result.outcomes += found.left
        for p in fan.problems:
            by_account.pop(p.account, None)

    def _collect(self, session: ImapSession, items: list[tuple[Outcome, MessageRef]]) -> _Found:
        """Conversation members of the given messages, split into the ones that move
        along and the ones that stay where the user filed them."""
        assert self._conversation_of is not None
        prefix = self._prefix(session)
        folders = {f.name: f for f in session.list_folders(refresh=True)}
        arch = session.folder_for_role("archive")
        arch_path = fuzzy.folder_path(arch, prefix) if arch else None
        anchors = {ref.folder for _o, ref in items}
        taken = {ref for _o, ref in items}
        found = _Found()
        deadline = time.monotonic() + self.config.limits.account_timeout * 0.5
        covered: set[MessageRef] = set()
        for out, ref in items:
            if ref in covered:  # already a member of an earlier conversation
                continue
            try:
                conv = self._conversation_of(session, ref, deadline)
            except ServerUnreachable:
                raise
            except MailError as e:
                out.fail(e)
                continue
            found.notes += [n for n in conv.notes if n not in found.notes]
            for m in conv.members:
                if m.ref in taken:
                    continue
                taken.add(m.ref)
                covered.add(m.ref)
                try:
                    mid = m.ref.encode()
                except InvalidRef:
                    continue
                member = Outcome(
                    mid,
                    account=m.ref.account,
                    folder=decode_folder_name(m.ref.folder),
                    member=True,
                )
                _describe(member, m)
                f = folders.get(m.ref.folder)
                if f is not None and self._moves_along(f, anchors, arch_path, prefix):
                    found.members.append((member, m.ref))
                else:
                    member.status = "unchanged"
                    member.message = f"left in {member.folder!r}: filed in another folder"
                    found.left.append(member)
        return found

    @staticmethod
    def _moves_along(
        f: FolderInfo, anchors: set[str], arch_path: tuple[str, ...] | None, prefix: str
    ) -> bool:
        if f.role in _NEVER_ROLES or not f.selectable:
            return False
        if f.role in MOVE_ROLES_BY_DEFAULT or f.name in anchors:
            return True
        if arch_path is not None:
            path = fuzzy.folder_path(f, prefix)
            return _fold_path(path[: len(arch_path)]) == _fold_path(arch_path)
        return False

    # ------------------------------------------------------------ archive

    def _archive_plan(self, session: ImapSession, ctx: _Ctx) -> _ArchivePlan:
        folders = session.list_folders(refresh=True)
        arch = session.folder_for_role("archive")
        if arch is None:
            raise NoArchiveFolder("this account has no Archive folder")
        configured = self.config.account(session.account_name).archive_scheme
        path = fuzzy.folder_path(arch, ctx.prefix)
        below: list[tuple[str, ...]] = []
        known: dict[tuple[str, ...], FolderInfo] = {}
        for f in folders:
            p = fuzzy.folder_path(f, ctx.prefix)
            if len(p) > len(path) and _fold_path(p[: len(path)]) == _fold_path(path):
                rel = p[len(path) :]
                below.append(rel)
                if f.selectable:
                    known.setdefault(tuple(archive.canon_level(x) for x in rel), f)
        layout = archive.layout_for(configured, below)
        ctx.notes.append(
            f"archive: {arch.display_name!r}, scheme {layout.describe()}"
            + (" (detected)" if layout.detected else " (configured)")
        )
        return _ArchivePlan(arch, path, layout, known, _delimiter(session, folders), datetime.now())

    def _archive_op(
        self,
        session: ImapSession,
        ctx: _Ctx,
        g: _Group,
        live: list[tuple[Outcome, MessageRef]],
    ) -> None:
        plan = ctx.archive
        assert plan is not None
        source = next((f for f in session.list_folders() if f.name == g.folder), None)
        if source is not None and plan.contains(fuzzy.folder_path(source, ctx.prefix)):
            for out, _ref in live:
                out.status, out.destination = "unchanged", plan.folder.display_name
                out.message = "already in the archive"
            return
        by_uid = {
            s.ref.uid: s
            for s in self.index.summaries(
                session, g.folder, g.uidvalidity, [r.uid for _o, r in live]
            )
        }
        targets: dict[tuple[str, ...], list[tuple[Outcome, MessageRef]]] = defaultdict(list)
        for out, ref in live:
            s = by_uid.get(ref.uid)
            when = archive.archive_moment(s, plan.now) if s is not None else plan.now
            targets[plan.target(when)].append((out, ref))
        for rel, members in targets.items():
            try:
                dest, created = self._archive_folder(session, ctx, plan, rel)
            except ServerUnreachable:
                raise
            except MailError as e:
                for out, _ref in members:
                    out.fail(e)
                continue
            if dest is None:  # dry run, folder missing
                shown = "/".join((plan.folder.display_name, *rel))
                for out, _ref in members:
                    out.status, out.destination = "planned", shown
                    out.message = "the folder would be created"
                continue
            if created:
                ctx.notes.append(f"created folder {dest.display_name!r}")
            self._move_to(session, ctx, g, members, dest)

    def _archive_folder(
        self, session: ImapSession, ctx: _Ctx, plan: _ArchivePlan, rel: tuple[str, ...]
    ) -> tuple[FolderInfo | None, bool]:
        """The folder for ``rel`` below the archive (created when missing, except in
        a dry run, which returns ``None``) and whether it was created."""
        if not rel:
            return plan.folder, False
        key = tuple(archive.canon_level(x) for x in rel)
        hit = plan.known.get(key)
        if hit is not None:
            return hit, False
        if ctx.dry_run:
            return None, False
        folders = session.list_folders(refresh=True)
        full = (*plan.path, *rel)
        self._ensure_levels(session, ctx.prefix, folders, plan.delimiter, full)
        want = tuple(archive.canon_level(x) for x in full)
        for f in session.list_folders(refresh=True):
            p = fuzzy.folder_path(f, ctx.prefix)
            if tuple(archive.canon_level(x) for x in p) == want:
                plan.known[key] = f
                return f, True
        raise ProtocolError(f"the folder {'/'.join(rel)!r} was created but cannot be found")

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
        assert ctx.dest is not None
        self._move_to(session, ctx, g, live, ctx.dest)

    def _move_to(
        self,
        session: ImapSession,
        ctx: _Ctx,
        g: _Group,
        live: list[tuple[Outcome, MessageRef]],
        dest: FolderInfo,
    ) -> None:
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
        if ctx.dry_run:
            for out, _ref in live:
                out.status, out.destination = "planned", shown
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

    @staticmethod
    def _ensure_levels(
        session: ImapSession,
        prefix: str,
        folders: Sequence[FolderInfo],
        delimiter: str,
        full: tuple[str, ...],
    ) -> tuple[list[str], list[str], bool]:
        """CREATE (and SUBSCRIBE) the levels of ``full`` that do not exist; returns
        the created and the existing levels and whether subscribing worked."""
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
        return created, existing, subscribed

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
            node, note = folder_list.resolve(
                roots, parent, exact=True, where=f" in account {acc.name!r}"
            )
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
        created, existing, subscribed = self._ensure_levels(
            session, prefix, folders, delimiter, full
        )
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


def _fold_path(path: Sequence[str]) -> tuple[str, ...]:
    return tuple(_fold(p) for p in path)


@dataclass(slots=True)
class _Found:
    """Conversation members found in one account."""

    members: list[tuple[Outcome, MessageRef]] = field(
        default_factory=list[tuple[Outcome, MessageRef]]
    )
    left: list[Outcome] = field(default_factory=list[Outcome])
    notes: list[str] = field(default_factory=list[str])


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
