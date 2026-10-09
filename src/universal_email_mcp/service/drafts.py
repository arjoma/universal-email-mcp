"""Drafts: compose a message and save it in the account's Drafts folder.

``save_draft`` creates a draft (new, reply, reply-all, forward) or **updates** one.
It never sends anything. What decides recipients, sender and attachments is the
caller (user through the client, bounded by permissions and policy) - never text
inside a mail: replies derive their recipients from the original's headers like a
mail client does and show them (with warnings) in the result; forwards attach only
parts that exist in the original message, fetched through the server-verified part
lookup, never files from disk or URLs.

Sender selection (design plan section 5): an explicit ``from`` names one of the
configured identities (address or identity name, never free text); for a reply the
identity whose address the original was sent to; then an identity that stores into
the original's account; then the default identity.

Update semantics: the new version is APPENDed first; only then the old version is
removed, and only if it really is a ``\\Draft`` in this account's Drafts folder
(``\\Deleted`` + ``UID EXPUNGE`` of that one UID; without UIDPLUS the old version is
left in place and the result says so). A failed removal never loses the new draft.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from universal_email_mcp.config import Config
from universal_email_mcp.errors import (
    InvalidArgument,
    InvalidRef,
    MailError,
    NoDraftsFolder,
    NotPermitted,
)
from universal_email_mcp.mail import compose
from universal_email_mcp.mail.compose import Draft, FileAttachment, Original
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.models import Account, Address, Identity, Message, MessageRef
from universal_email_mcp.service.index import HeaderIndex
from universal_email_mcp.service.router import AccountRouter, ensure_ref_matches
from universal_email_mcp.service.trust import SentToIndex

QUOTE_FETCH_CHARS = compose.MAX_QUOTE_CHARS + 1_000
MAX_FORWARD_BYTES = 10 * 1024 * 1024
"""Total size of the files a forward carries (decoded)."""
DRAFT_FLAGS = ("\\Draft", "\\Seen")
Replaced = Literal["none", "removed", "kept"]


@dataclass(slots=True)
class DraftResult:
    id: str | None
    """The saved draft's id (``None`` if the server did not report it and it could
    not be found; the draft is saved all the same)."""
    account: str
    folder: str
    """Display name of the Drafts folder."""
    draft: Draft
    sender_reason: str
    replaced: Replaced
    replaced_note: str = ""
    warnings: list[str] = field(default_factory=list[str])


@dataclass(slots=True)
class Built:
    """A composed draft that has not been stored yet."""

    draft: Draft
    ident: Identity
    reason: str
    """Why this sender was chosen."""
    store: Account
    """The account whose Drafts folder receives it."""
    old: _OldDraft | None
    own: set[str]


@dataclass(slots=True)
class _Loaded:
    original: Original
    attachments: list[FileAttachment]
    warnings: list[str]


@dataclass(slots=True)
class _OldDraft:
    ref: MessageRef
    to: tuple[Address, ...]
    cc: tuple[Address, ...]
    from_: tuple[Address, ...]
    subject: str
    in_reply_to: str | None
    references: tuple[str, ...]


class Drafter:
    def __init__(
        self,
        config: Config,
        router: AccountRouter,
        index: HeaderIndex,
        sent_to: SentToIndex,
        own_addresses: Callable[[], set[str]],
    ) -> None:
        self.config = config
        self.router = router
        self.index = index
        self.sent_to = sent_to
        self._own = own_addresses

    # ------------------------------------------------------------ accounts

    def _account(self, name: str, permission: str) -> Account:
        try:
            acc = self.router.account(name, permission)
        except MailError as e:
            if e.code == "CONFIG_INVALID":
                raise InvalidRef("message id refers to an unknown account") from e
            raise
        if acc.name != name:  # ids carry the exact configured name
            raise InvalidRef("message id refers to an unknown account")
        return acc

    def account_for(self, name: str, permission: str) -> Account:
        """The account a message id names, checked for ``permission``."""
        return self._account(name, permission)

    # ------------------------------------------------------------ identities

    def _identity(
        self, explicit: str | None, original: Original | None, original_account: str | None
    ) -> tuple[Identity, str, str]:
        """``(identity, address, reason)``."""
        idents = self.config.identities
        if not idents:
            raise InvalidArgument(
                "no identities are configured",
                hint="Local mode: add an [[identities]] table to the configuration (address, "
                "name, account). Remote mode: the user adds a sender identity linked to the "
                "mailbox in the portal and allows this client to draft. Drafts are written as "
                "one of the configured identities.",
            )
        if explicit and explicit.strip():
            wanted = compose.header_text(explicit, "from", max_chars=200)
            parsed = compose.parse_recipients([wanted], "from") if "@" in wanted else []
            key = (parsed[0].email if len(parsed) == 1 else wanted).casefold()
            for ident in idents:
                for addr in ident.addresses:
                    if addr.casefold() == key:
                        return ident, addr, "chosen by the caller"
            for ident in idents:
                if ident.name.casefold() == key:
                    return ident, ident.addresses[0], "chosen by the caller"
            names = ", ".join(a for i in idents for a in i.addresses)
            raise InvalidArgument(
                "'from' is not one of the configured identities",
                hint=f"Use one of: {names}. A sender address cannot be made up.",
            )
        if original is not None:
            for a in (*original.to, *original.cc):
                key = a.email.casefold()
                for ident in idents:
                    for addr in ident.addresses:
                        if addr.casefold() == key:
                            return ident, addr, "the address the original was sent to"
        if original_account is not None:
            for ident in sorted(idents, key=lambda i: not i.default):
                if (
                    ident.store_account
                    and ident.store_account.casefold() == original_account.casefold()
                ):
                    return ident, ident.addresses[0], "an identity of the original's account"
        default = self.config.default_identity or idents[0]
        return default, default.addresses[0], "the default identity"

    # ------------------------------------------------------------ loading the original

    async def _load_original(self, ref: MessageRef, acc: Account, *, attachments: bool) -> _Loaded:
        limits = self.config.limits
        att_cap = limits.max_attachment_bytes

        def fn(session: ImapSession) -> _Loaded:
            msg = session.fetch_message(
                ref,
                max_bytes=limits.max_message_bytes,
                max_body_chars=QUOTE_FETCH_CHARS,
                body_offset=0,
            )
            return _loaded(session, ref, msg, attachments=attachments, att_cap=att_cap)

        async def work(a: Account) -> _Loaded:
            return await self.router.call(a, fn)

        return await self.router.run_one(acc, work)

    # ------------------------------------------------------------ save

    async def build(
        self,
        *,
        to: Sequence[str] | None,
        cc: Sequence[str] | None,
        bcc: Sequence[str] | None,
        subject: str | None,
        body: str,
        sender: str | None,
        reply_to_id: str | None,
        reply_all: bool,
        forward_id: str | None,
        draft_id: str | None,
        account: str | None,
        include_attachments: bool = True,
    ) -> Built:
        """Validate and compose everything for a draft without touching the Drafts
        folder (``save`` stores the result; ``send_message`` shows it first)."""
        if reply_to_id and forward_id:
            raise InvalidArgument("reply_to_id and forward_id cannot be combined")
        if reply_all and not reply_to_id:
            raise InvalidArgument("reply_all needs reply_to_id")
        if not isinstance(body, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise InvalidArgument("body must be text")
        # Everything the caller passed is validated before any connection is made.
        to_list = None if to is None else compose.parse_recipients(to, "to")
        cc_list = None if cc is None else compose.parse_recipients(cc, "cc")
        bcc_list = None if bcc is None else compose.parse_recipients(bcc, "bcc")
        subject_text = None if subject is None else compose.header_text(subject, "subject")
        if len(body) > compose.MAX_BODY_CHARS:
            raise InvalidArgument(f"the body is longer than {compose.MAX_BODY_CHARS} characters")
        if sender is not None and not sender.strip():
            sender = None
        if sender:
            compose.header_text(sender, "from", max_chars=200)

        old_ref = MessageRef.decode(draft_id) if draft_id else None
        if old_ref is not None and old_ref.is_pop3:
            raise NotPermitted("POP3 accounts are read-only: that is not a draft id")
        if old_ref is not None:
            store = self._account(old_ref.account, "drafts")
            if account and account.casefold() != store.name.casefold():
                raise InvalidArgument("the draft belongs to another account than 'account'")
        orig_ref_id = reply_to_id or forward_id
        orig_ref = MessageRef.decode(orig_ref_id) if orig_ref_id else None
        orig_acc = self._account(orig_ref.account, "read") if orig_ref else None
        if orig_ref is not None and orig_acc is not None:
            ensure_ref_matches(orig_ref, orig_acc)

        loaded: _Loaded | None = None
        if orig_ref is not None and orig_acc is not None:
            loaded = await self._load_original(
                orig_ref, orig_acc, attachments=bool(forward_id) and include_attachments
            )

        old: _OldDraft | None = None
        if old_ref is not None:
            old = await self._load_old(old_ref, self._account(old_ref.account, "drafts"))

        warnings: list[str] = list(loaded.warnings) if loaded else []
        original = loaded.original if loaded else None
        kind: compose.Kind = "reply" if reply_to_id else "forward" if forward_id else "new"

        ident, address, reason = self._identity(
            sender if sender else None, original, orig_ref.account if orig_ref else None
        )
        if not sender and old is not None:  # keep the sender of the draft being updated
            for a in old.from_:
                hit = self._match_identity(a.email)
                if hit is not None:
                    ident, address, reason = hit[0], hit[1], "the sender of the draft being updated"
                    break

        # recipients and subject
        own = {a.casefold() for i in self.config.identities for a in i.addresses} | self._own()
        derived_to: list[Address] = []
        derived_cc: list[Address] = []
        if kind == "reply" and original is not None:
            derived_to, derived_cc, w = compose.reply_recipients(original, own, reply_all=reply_all)
            warnings += w
        elif old is not None and kind == "new":
            derived_to, derived_cc = list(old.to), list(old.cc)
        to_final = compose.dedupe(derived_to if to_list is None else to_list)
        cc_final = compose.dedupe(derived_cc if cc_list is None else cc_list)
        bcc_final = compose.dedupe(bcc_list or [])
        taken: set[str] = set()
        for group in (to_final, cc_final, bcc_final):  # one entry per address overall
            group[:] = [
                a for a in group if not (a.email.lower() in taken or taken.add(a.email.lower()))
            ]
        total = len(to_final) + len(cc_final) + len(bcc_final)
        cap = self.config.policy.max_recipients
        if total > cap:
            raise InvalidArgument(
                f"{total} recipients; the policy allows at most {cap}",
                hint="Name fewer recipients (to/cc/bcc). Nothing was saved.",
            )

        if subject_text is not None:
            subject_final = subject_text
        elif kind == "reply" and original is not None:
            subject_final = compose.reply_subject(original.subject)
        elif kind == "forward" and original is not None:
            subject_final = compose.forward_subject(original.subject)
        elif old is not None:
            subject_final = old.subject
        else:
            subject_final = ""
        if not subject_final:
            warnings.append("the draft has no subject")
        if not (to_final or cc_final or bcc_final):
            warnings.append("the draft has no recipient yet")
        if any(a.email.lower() in own for a in (*to_final, *cc_final, *bcc_final)):
            warnings.append("a recipient is one of your own addresses")

        req = compose.Request(
            sender=ident,
            address=address,
            kind=kind,
            to=to_final,
            cc=cc_final,
            bcc=bcc_final,
            subject=subject_final,
            body=body,
            original=original,
            attachments=loaded.attachments if loaded and kind == "forward" else (),
            in_reply_to=old.in_reply_to if old and original is None else None,
            references=old.references if old and original is None else (),
            warnings=warnings,
        )
        draft = compose.compose(req)

        store_name = self._store_account(old_ref, account, ident)
        store = self._account(store_name, "drafts")
        return Built(draft, ident, reason, store, old, own)

    async def save(
        self,
        *,
        to: Sequence[str] | None,
        cc: Sequence[str] | None,
        bcc: Sequence[str] | None,
        subject: str | None,
        body: str,
        sender: str | None,
        reply_to_id: str | None,
        reply_all: bool,
        forward_id: str | None,
        draft_id: str | None,
        account: str | None,
        include_attachments: bool = True,
    ) -> DraftResult:
        built = await self.build(
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=body,
            sender=sender,
            reply_to_id=reply_to_id,
            reply_all=reply_all,
            forward_id=forward_id,
            draft_id=draft_id,
            account=account,
            include_attachments=include_attachments,
        )
        result = await self._append(built.store, built.draft, built.old, built.reason)
        await self._recipient_note(built.store, built.draft, built.own, result)
        return result

    async def store(self, built: Built) -> DraftResult:
        """Append a built draft to its Drafts folder (a new draft, nothing replaced)."""
        return await self._append(built.store, built.draft, None, built.reason)

    def _match_identity(self, email_addr: str) -> tuple[Identity, str] | None:
        key = email_addr.casefold()
        for ident in self.config.identities:
            for addr in ident.addresses:
                if addr.casefold() == key:
                    return ident, addr
        return None

    def _store_account(
        self, old_ref: MessageRef | None, account: str | None, ident: Identity
    ) -> str:
        if old_ref is not None:
            return old_ref.account
        if account:
            return self.config.account(account).name
        if ident.store_account:
            return ident.store_account
        raise InvalidArgument(
            f"identity {ident.name!r} has no account for its drafts",
            hint="Pass account= (an IMAP account that allows drafts) or set store_account "
            "(or account) on the identity.",
        )

    # ------------------------------------------------------------ the old version

    async def _load_old(self, ref: MessageRef, acc: Account) -> _OldDraft:
        def fn(session: ImapSession) -> _OldDraft:
            drafts = drafts_folder(session)
            if ref.folder != drafts.name:
                raise InvalidArgument(
                    "that message is not in the Drafts folder, so it is not a draft",
                    hint="Only drafts created by save_draft (or found in Drafts) can be updated.",
                )
            found = self.index.summaries(
                session, ref.folder, ref.uidvalidity, [ref.uid], refresh_flags=True
            )
            if not found:
                raise InvalidArgument(
                    "that draft does not exist any more (sent or deleted?)",
                    hint="Create a new draft with save_draft.",
                )
            s = found[0]
            if "\\Draft" not in s.flags:
                raise InvalidArgument(
                    "that message is in Drafts but is not marked as a draft",
                    hint="Only messages carrying the \\Draft flag can be updated.",
                )
            return _OldDraft(ref, s.to, s.cc, s.from_, s.subject, s.in_reply_to, s.references)

        async def work(a: Account) -> _OldDraft:
            return await self.router.call(a, fn)

        return await self.router.run_one(acc, work)

    # ------------------------------------------------------------ writing

    async def _append(
        self, acc: Account, draft: Draft, old: _OldDraft | None, reason: str
    ) -> DraftResult:
        def fn(session: ImapSession) -> DraftResult:
            drafts = drafts_folder(session)
            res = session.append_message(drafts.name, draft.raw, flags=DRAFT_FLAGS)
            self.index.invalidate(session.account_name, drafts.name)
            new_id: str | None = None
            if res.uid is not None and res.uidvalidity is not None:
                new_id = MessageRef(acc.name, res.folder, res.uidvalidity, res.uid).encode()
            replaced: Replaced = "none"
            note = ""
            if old is not None:
                replaced, note = self._remove_old(session, drafts.name, old, new_id)
            return DraftResult(
                id=new_id,
                account=acc.name,
                folder=drafts.display_name,
                draft=draft,
                sender_reason=reason,
                replaced=replaced,
                replaced_note=note,
                warnings=list(draft.warnings),
            )

        async def work(a: Account) -> DraftResult:
            return await self.router.call(a, fn)

        out = await self.router.run_one(acc, work)
        if out.id is None:
            out.warnings.append(
                "the server did not report the new draft's id; find it in the Drafts folder"
            )
        return out

    def _remove_old(
        self, session: ImapSession, drafts_wire: str, old: _OldDraft, new_id: str | None
    ) -> tuple[Replaced, str]:
        if old.ref.folder != drafts_wire or (new_id is not None and old.ref.encode() == new_id):
            return "kept", "the previous version was left untouched (not in the Drafts folder)"
        try:
            outcome = session.remove_draft(
                old.ref.folder, old.ref.uid, uidvalidity=old.ref.uidvalidity
            )
        except MailError as e:
            return (
                "kept",
                f"the previous version could not be removed ({e.message}); delete it by hand",
            )
        finally:
            self.index.invalidate(session.account_name, drafts_wire)
        if outcome == "removed":
            return "removed", "the previous version was removed (its id is void)"
        why = {
            "missing": "it was already gone",
            "not_a_draft": "it no longer carries the \\Draft flag, so it was not touched",
            "no_uidplus": "the server lacks UIDPLUS, so nothing can be removed safely",
        }[outcome]
        return "kept", f"the previous version was left in place: {why}"

    async def _recipient_note(
        self, acc: Account, draft: Draft, own: set[str], result: DraftResult
    ) -> None:
        """Informational only: recipients the user never wrote to (the send-time
        check is part of the send work, WP 2d). Failures are ignored."""
        emails = [a.email for a in draft.recipients if a.email.lower() not in own]
        if not emails:
            return

        def fn(session: ImapSession) -> dict[str, bool | None]:
            return self.sent_to.check(session, emails)

        async def work(a: Account) -> dict[str, bool | None]:
            return await self.router.call(a, fn)

        try:
            known = await self.router.run_one(acc, work)
        except MailError:
            result.warnings.append(
                "could not check whether you have written to the recipients before"
            )
            return
        new = [e for e in emails if known.get(e.lower()) is False]
        unknown = [e for e in emails if known.get(e.lower()) is None]
        if new:
            result.warnings.append(
                "you have not written to these recipients before: " + ", ".join(new[:5])
            )
        if unknown:
            result.warnings.append(
                "could not tell whether you have written to: " + ", ".join(unknown[:5])
            )


# ----------------------------------------------------------------- helpers


def drafts_folder(session: ImapSession):  # noqa: ANN202
    session.list_folders()
    folder = session.folder_for_role("drafts")
    if folder is None:
        raise NoDraftsFolder("this account has no Drafts folder")
    if session.is_foreign(folder.name):
        raise NotPermitted("the Drafts folder is in another user's or a shared namespace")
    return folder


def _loaded(
    session: ImapSession, ref: MessageRef, msg: Message, *, attachments: bool, att_cap: int
) -> _Loaded:
    s = msg.summary
    original = Original(
        message_id=s.message_id,
        in_reply_to=s.in_reply_to,
        references=s.references,
        subject=s.subject,
        from_=s.from_,
        reply_to=s.reply_to,
        to=s.to,
        cc=s.cc,
        date=s.date,
        body=msg.body.text,
        body_truncated=msg.body.truncated or msg.source_truncated,
    )
    warnings: list[str] = []
    files: list[FileAttachment] = []
    if msg.source_truncated:
        warnings.append("the original is very large; only its beginning is quoted")
    if attachments:
        total = 0
        listed = [a for a in msg.attachments if not a.inline]
        skipped_inline = len(msg.attachments) - len(listed)
        if skipped_inline:
            warnings.append(
                f"{skipped_inline} inline part(s) (images in the text) are not included "
                "in the plain-text draft"
            )
        for att in listed:
            name = compose.safe_filename(att.filename)
            if len(files) >= compose.MAX_ATTACHMENTS:
                warnings.append(f"not attached (more than {compose.MAX_ATTACHMENTS} files): {name}")
                continue
            if total + att.size > MAX_FORWARD_BYTES:
                warnings.append(
                    f"not attached (total size limit {MAX_FORWARD_BYTES} bytes): {name}"
                )
                continue
            try:
                got = session.fetch_attachment(ref, att.part_id, max_bytes=att_cap)
            except MailError as e:
                warnings.append(f"not attached ({e.message}): {name}")
                continue
            if got.data is None:
                warnings.append(f"not attached (larger than the {att_cap} byte limit): {name}")
                continue
            if total + len(got.data) > MAX_FORWARD_BYTES:
                warnings.append(
                    f"not attached (total size limit {MAX_FORWARD_BYTES} bytes): {name}"
                )
                continue
            total += len(got.data)
            files.append(FileAttachment(name, got.leaf.content_type, got.data))
    return _Loaded(original, files, warnings)
