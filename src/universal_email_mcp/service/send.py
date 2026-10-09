"""Sending mail: policy, recipient check, confirmation, SMTP, bookkeeping.

``send_message`` always goes through a **draft**: a new message is composed and
saved in Drafts first (:class:`~universal_email_mcp.service.drafts.Drafter`), an
existing draft is re-read from the server. Only then is anything decided, so every
refusal, declined confirmation and failed send leaves the draft behind and the user
loses nothing.

The order of a send:

1. the draft is parsed as it would be transmitted (:func:`parse_outgoing`): exactly
   one sender, which must be a configured identity allowed to send; every
   To/Cc/Bcc address of every header instance;
2. hard limits of the policy (recipient count, allowed domains, size, send rate);
3. each recipient is classified (:mod:`.recipients`);
4. the policy decides whether the user must confirm: ``draft`` never sends,
   ``confirm`` always asks, ``confirm-external`` asks unless every recipient is
   internal, ``on`` asks only when a recipient is a look-alike. A look-alike is never
   sent without the user's confirmation, in any mode;
5. the confirmation is an MCP elicitation showing sender, recipients with their class
   and warnings, subject, attachments and the start of the text. Declined, cancelled
   or - when the client cannot elicit - impossible: the draft stays;
6. the bytes that were shown are the bytes that are sent (the draft is not re-read);
7. afterwards, best effort and never turning a delivered mail into an error: copy into
   Sent (and the thread folder, ``file_replies``), remove the draft (UID-scoped),
   ``\\Answered`` on the original of a reply.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from universal_email_mcp import audit
from universal_email_mcp.config import Config, SendPolicy, resolve_password
from universal_email_mcp.errors import (
    AlreadySent,
    InvalidArgument,
    InvalidRef,
    MailError,
    MessageNotFound,
    NotPermitted,
    RateLimited,
    TooLarge,
)
from universal_email_mcp.mail import smtp
from universal_email_mcp.mail.imap import ANSWERED_FLAGS, ImapSession
from universal_email_mcp.mail.mime import sanitize_line, sanitize_text
from universal_email_mcp.mail.outgoing import Outgoing, parse_outgoing, strip_headers
from universal_email_mcp.models import Account, Address, Identity, MessageRef
from universal_email_mcp.server import render
from universal_email_mcp.service.drafts import Built, Drafter, drafts_folder
from universal_email_mcp.service.index import HeaderIndex
from universal_email_mcp.service.recipients import (
    Classified,
    Field,
    RecipientChecker,
    count_by_class,
)
from universal_email_mcp.service.router import AccountRouter
from universal_email_mcp.service.trust import SentToIndex

log = logging.getLogger(__name__)

SendStatus = Literal["sent", "draft_kept", "declined"]

MAX_CONFIRM_CHARS = 4_000
FIND_ORIGINAL_FOLDERS = 25
FIND_ORIGINAL_SECONDS = 10.0
Submit = Callable[..., smtp.SmtpReceipt]


# ----------------------------------------------------------------- policy


def send_offered(config: Config) -> bool:
    """Is ``send_message`` registered? The policy must allow sending, and an identity
    must be allowed to send (``send = true``) with an SMTP account and a store account
    that grants the ``drafts`` permission (the draft is the safety net)."""
    p = config.policy
    if p.read_only or p.send == "off":
        return False
    for i in config.identities:
        if not (i.send and i.smtp_account and i.store_account):
            continue
        store = config.account(i.store_account)
        if store.kind == "imap" and store.permissions.drafts:
            return True
    return False


def domain_allowed(domain: str, allowed: Sequence[str]) -> bool:
    d = domain.lower()
    return not allowed or any(d == a or d.endswith("." + a) for a in allowed)


def confirmation_reasons(mode: SendPolicy, classified: Sequence[Classified]) -> list[str]:
    """Why the user has to confirm (empty: the policy lets the mail go without)."""
    reasons: list[str] = []
    looks = [c for c in classified if c.klass == "lookalike"]
    if looks:
        reasons.append(f"{len(looks)} recipient(s) look like other addresses")
    if mode == "confirm":
        reasons.append("the policy asks for confirmation of every message")
    elif mode == "confirm-external" and any(c.klass != "internal" for c in classified):
        reasons.append("the message goes to recipients outside your organisation")
    return reasons


class SendLimiter:
    """Sends per SMTP account per hour and per day, counted in memory."""

    def __init__(self, per_hour: int, per_day: int, clock: Callable[[], float] = time.time) -> None:
        self.per_hour, self.per_day, self._clock = per_hour, per_day, clock
        self._sent: dict[str, deque[float]] = {}

    def _recent(self, key: str) -> deque[float]:
        q = self._sent.setdefault(key, deque())
        cutoff = self._clock() - 86_400
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def check(self, key: str) -> None:
        q = self._recent(key)
        now = self._clock()
        hour = [t for t in q if t > now - 3_600]
        if len(hour) >= self.per_hour:
            wait = int((hour[0] + 3_600 - now) / 60) + 1
            raise RateLimited(
                f"{len(hour)} messages were sent in the last hour; the policy allows "
                f"{self.per_hour}",
                hint=f"Try again in about {wait} minute(s), or the user raises "
                "policy.max_sends_per_hour.",
            )
        if len(q) >= self.per_day:
            raise RateLimited(
                f"{len(q)} messages were sent in the last 24 hours; the policy allows "
                f"{self.per_day}",
                hint="Try again later, or the user raises policy.max_sends_per_day.",
            )

    def record(self, key: str) -> None:
        self._recent(key).append(self._clock())


# ----------------------------------------------------------------- confirmation text


def _name(a: Address) -> str:
    # An "@" in a display name could pose as another address next to the real one.
    return sanitize_line(a.name).replace("@", "(at)")[:60]


def _addr(a: Address) -> str:
    n = _name(a)
    return f"{n} <{a.email}>" if n else a.email


def _tag(c: Classified) -> str:
    return {
        "internal": "internal",
        "known": "written to before",
        "new": "NEW - never written to" if not c.history_unknown else "NEW - history unknown",
        "lookalike": "LOOK-ALIKE",
    }[c.klass]


def confirmation_text(
    ident: Identity,
    out: Outgoing,
    classified: Sequence[Classified],
    reasons: Sequence[str],
    *,
    note: str = "",
) -> str:
    """The text the user sees before a message leaves. Everything that comes from
    the message is sanitised (no control or bidi characters, links defanged)."""
    lines = ["Send this e-mail? It cannot be taken back.", ""]
    lines.append(f"From: {_addr(out.sender)}  (identity {sanitize_line(ident.name)[:40]})")
    by_field: dict[str, list[Classified]] = {"to": [], "cc": [], "bcc": []}
    for c in classified:
        by_field[c.field].append(c)
    for fld, label in (("to", "To"), ("cc", "Cc"), ("bcc", "Bcc")):
        for c in by_field[fld]:
            lines.append(f"{label}: {_addr(c.address)}  [{_tag(c)}]")
    if by_field["bcc"]:
        lines.append("(Bcc recipients are hidden from the others.)")
    lines.append(f"Subject: {sanitize_line(out.subject)[:200] or '(none)'}")
    if out.attachments:
        shown = ", ".join(
            f"{sanitize_line(n)[:60]} ({render.fmt_size(z)})" for n, z in out.attachments[:10]
        )
        extra = f" and {len(out.attachments) - 10} more" if len(out.attachments) > 10 else ""
        lines.append(f"Attachments: {shown}{extra}")
    warnings = [
        f"! {c.email}: {sanitize_line(n)[:200]}"
        for c in classified
        for n in c.notes
        if c.klass in ("lookalike", "new")
    ]
    if warnings:
        lines += ["", "Check this:", *warnings[:10]]
    if reasons:
        lines += ["", "Confirmation needed because " + "; ".join(reasons) + "."]
    if note:
        lines.append(sanitize_line(note)[:200])
    lines += ["", "Text:"]
    if out.preview:
        body = render.defang_body(out.preview)
        lines += ["> " + ln for ln in sanitize_text(body).split("\n")[:15]]
    else:
        lines.append("> (no plain text)" if not out.has_text_body else "> (empty)")
    return "\n".join(lines)[:MAX_CONFIRM_CHARS]


# ----------------------------------------------------------------- results


@dataclass(slots=True)
class SendResult:
    status: SendStatus
    account: str
    """The SMTP account (or the store account if nothing was sent)."""
    identity: str
    sender: Address
    recipients: list[Classified]
    subject: str
    message_id: str | None
    attachments: tuple[tuple[str, int], ...]
    size: int
    draft_id: str | None
    """The draft that is still there (not sent); ``None`` after a send."""
    reasons: list[str] = field(default_factory=list[str])
    """Why the mail was not sent / why the user had to confirm."""
    receipt: str | None = None
    sent_copy: str = ""
    steps: list[str] = field(default_factory=list[str])
    warnings: list[str] = field(default_factory=list[str])
    confirmation: Literal["asked", "not_needed", "unavailable"] = "not_needed"


@dataclass(slots=True)
class Prepared:
    """A send that is fully worked out but has not touched anything yet.

    Built (read-only) before the user is asked, and rebuilt from the same arguments
    when the protocol resumes after the question (2026-07-28 multi-round trips): the
    question carries a fingerprint of the content, so an answer only counts for the
    text it was given for."""

    out: Outgoing
    ident: Identity
    smtp_account: Account
    store: Account
    """The account whose Drafts / Sent folders are used."""
    ref: MessageRef | None
    """An existing draft (send by id); ``None`` for a new message."""
    built: Built | None
    """A composed new message that is stored as a draft when executed."""
    original: MessageRef | None
    classified: list[Classified]
    warnings: list[str]
    reasons: list[str]
    """Why the user must confirm (empty: the policy lets it go)."""
    keep_reason: str | None
    """Set when the policy forbids sending: the mail only stays a draft."""
    prompt: str
    sender_reason: str = ""

    @property
    def needs_confirmation(self) -> bool:
        return self.keep_reason is None and bool(self.reasons)


Decision = Literal["accepted", "declined", "cancelled", "unavailable", "not_needed"]
"""What the user (or the client's lack of a way to ask) decided."""


def fingerprint(raw: bytes) -> str:
    """Short digest of the message content (not of Message-ID and Date, which a
    recomposition changes), shown in the confirmation so that the question - and
    with it the user's answer - is bound to exactly this message."""
    body = strip_headers(raw, frozenset({"message-id", "date"}))
    return hashlib.sha256(body).hexdigest()[:10]


class Sender:
    def __init__(
        self,
        config: Config,
        router: AccountRouter,
        index: HeaderIndex,
        sent_to: SentToIndex,
        drafter: Drafter,
        own_addresses: Callable[[], set[str]],
        *,
        submit: Submit = smtp.submit,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.router = router
        self.index = index
        self.drafter = drafter
        self._submit = submit
        pol = config.policy
        self.checker = RecipientChecker(router, sent_to, own_addresses, pol.internal_domains)
        self.limiter = SendLimiter(pol.max_sends_per_hour, pol.max_sends_per_day, clock)
        self._sent: set[str] = set()
        self._in_flight: set[str] = set()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------ preparing (read only)

    async def prepare_new(self, *, reply_to_id: str | None = None, **compose: Any) -> Prepared:
        """Compose a new message (nothing is stored) and work out the send."""
        self._allowed()
        built = await self.drafter.build(reply_to_id=reply_to_id, draft_id=None, **compose)
        return await self._prepare(
            parse_outgoing(built.draft.raw),
            built.store,
            built=built,
            ref=None,
            original=MessageRef.decode(reply_to_id) if reply_to_id else None,
            warnings=list(built.draft.warnings),
            sender_reason=built.reason,
        )

    async def prepare_draft(self, draft_id: str) -> Prepared:
        """Re-read an existing draft from the server and work out the send."""
        self._allowed()
        ref = MessageRef.decode(draft_id)
        acc = self.drafter.account_for(ref.account, "drafts")
        max_bytes = self.config.limits.max_send_bytes

        def fn(session: ImapSession) -> bytes:
            folder = drafts_folder(session)
            if ref.folder != folder.name:
                raise InvalidArgument(
                    "that message is not in the Drafts folder, so it is not a draft",
                    hint="Only drafts (save_draft, or written in the mail client) can be sent.",
                )
            flags, raw = session.fetch_raw_message(ref, max_bytes=max_bytes)
            if "\\Draft" not in flags:
                raise InvalidArgument(
                    "that message is in Drafts but is not marked as a draft",
                    hint="Only messages carrying the \\Draft flag can be sent.",
                )
            return raw

        async def work(a: Account) -> bytes:
            return await self.router.call(a, fn)

        try:
            raw = await self.router.run_one(acc, work)
        except MessageNotFound as e:
            raise InvalidArgument(
                "that draft does not exist any more (sent or deleted?)",
                hint="Create a new one with save_draft or send_message.",
            ) from e
        return await self._prepare(
            parse_outgoing(raw),
            acc,
            built=None,
            ref=ref,
            original=None,
            warnings=[],
            sender_reason="the draft's From address",
        )

    def _allowed(self) -> None:
        pol = self.config.policy
        if pol.read_only or pol.send == "off":
            raise NotPermitted("the policy does not allow sending mail")

    def _identity(self, address: str) -> Identity:
        key = address.casefold()
        for ident in self.config.identities:
            if any(a.casefold() == key for a in ident.addresses):
                if not (ident.send and ident.smtp_account):
                    raise NotPermitted(
                        f"identity {ident.name!r} is not allowed to send",
                        hint="The message was not sent. Choose another sender with from= (see "
                        "account_info), or the user sets send = true on the identity.",
                    )
                return ident
        raise NotPermitted(
            "the draft's From address is not one of the configured identities",
            hint="Only mail from a configured identity is sent. Create the draft again "
            "with save_draft.",
        )

    def _hard_checks(self, out: Outgoing, smtp_account: str) -> None:
        pol = self.config.policy
        recipients = out.recipients
        if not recipients:
            raise InvalidArgument("the draft has no recipient", hint="Add to/cc/bcc.")
        if len(recipients) > pol.max_recipients:
            raise InvalidArgument(
                f"{len(recipients)} recipients; the policy allows at most {pol.max_recipients}"
            )
        bad = [
            a.email
            for a in recipients
            if not domain_allowed(a.email.rpartition("@")[2], pol.allowed_recipient_domains)
        ]
        if bad:
            raise NotPermitted(
                f"{len(bad)} recipient(s) are outside the allowed domains: " + ", ".join(bad[:5]),
                hint="Allowed: " + ", ".join(pol.allowed_recipient_domains) + ".",
            )
        if len(out.raw) > self.config.limits.max_send_bytes:
            raise TooLarge(
                f"the message is {len(out.raw)} bytes; the limit is "
                f"{self.config.limits.max_send_bytes}",
                hint="Remove attachments.",
            )
        if out.message_id and out.message_id in self._sent:
            raise AlreadySent("this message was already sent in this session")
        self.limiter.check(smtp_account)

    async def _prepare(
        self,
        out: Outgoing,
        store: Account,
        *,
        built: Built | None,
        ref: MessageRef | None,
        original: MessageRef | None,
        warnings: list[str],
        sender_reason: str,
    ) -> Prepared:
        ident = self._identity(out.sender.email)
        smtp_acc = self.config.account(ident.smtp_account or "")
        self._hard_checks(out, smtp_acc.name)
        pairs: list[tuple[Field, Address]] = [
            *(("to", a) for a in out.to),
            *(("cc", a) for a in out.cc),
            *(("bcc", a) for a in out.bcc),
        ]
        classified, notes = await self.checker.check(store, pairs)
        mode = self.config.policy.send
        keep = (
            "the policy is 'draft': this server never sends, it only keeps drafts"
            if mode == "draft"
            else None
        )
        reasons = confirmation_reasons(mode, classified)
        prompt = ""
        if reasons and keep is None:
            prompt = confirmation_text(
                ident, out, classified, reasons, note=f"Content fingerprint {fingerprint(out.raw)}"
            )
        return Prepared(
            out=out,
            ident=ident,
            smtp_account=smtp_acc,
            store=store,
            ref=ref,
            built=built,
            original=original,
            classified=classified,
            warnings=[*warnings, *notes],
            reasons=reasons,
            keep_reason=keep,
            prompt=prompt,
            sender_reason=sender_reason,
        )

    # ------------------------------------------------------------ executing

    async def execute(self, p: Prepared, decision: Decision) -> SendResult:
        """Do what was decided. A new message is stored as a draft first, so every
        outcome but a clean send leaves it behind."""
        out = p.out
        base = dict(
            account=p.smtp_account.name,
            recipients=count_by_class(p.classified),
            attachments=len(out.attachments),
            size=audit.size_bucket(len(out.raw)),
            mode=self.config.policy.send,
        )
        audit.event("send.requested", **base)
        result = SendResult(
            status="draft_kept",
            account=p.smtp_account.name,
            identity=p.ident.name,
            sender=out.sender,
            recipients=p.classified,
            subject=out.subject,
            message_id=out.message_id,
            attachments=out.attachments,
            size=len(out.raw),
            draft_id=None,
            warnings=list(p.warnings),
        )
        if p.built is not None:
            stored = await self.drafter.store(p.built)
            p.ref = MessageRef.decode(stored.id) if stored.id else None
            if p.ref is None:
                result.warnings.append(
                    "the server did not report the new draft's id, so it cannot be removed "
                    "after sending"
                )
        result.draft_id = p.ref.encode() if p.ref else None
        if p.keep_reason is not None:
            result.reasons = [p.keep_reason]
            audit.event("send.draft_kept", **base, reason="policy")
            return result
        if p.needs_confirmation:
            if decision == "accepted":
                result.confirmation = "asked"
                audit.event("send.confirmed", **base)
            elif decision in ("declined", "cancelled"):
                result.confirmation = "asked"
                result.status = "declined"
                result.reasons = [*p.reasons, f"the user {decision} the confirmation"]
                audit.event("send.declined", **base, outcome=decision)
                return result
            else:
                result.confirmation = "unavailable"
                result.reasons = [
                    *p.reasons,
                    "the client cannot ask the user for confirmation, so the mail stays a draft",
                ]
                audit.event("send.draft_kept", **base, reason="no_confirmation")
                return result
        return await self._deliver(p, result, base)

    async def _deliver(
        self, p: Prepared, result: SendResult, base: Mapping[str, Any]
    ) -> SendResult:
        out, smtp_acc = p.out, p.smtp_account
        mid = out.message_id or ""
        envelope = [a.email for a in out.recipients]
        async with self._lock:
            self.limiter.check(smtp_acc.name)
            if mid and (mid in self._sent or mid in self._in_flight):
                raise AlreadySent("this message was already sent (or is being sent) just now")
            if mid:
                self._in_flight.add(mid)
            try:

                def run() -> smtp.SmtpReceipt:
                    cfg = self.config
                    endpoint = smtp_acc.server.smtp
                    if endpoint is None:  # pragma: no cover - guarded by config validation
                        raise NotPermitted("the account has no SMTP server")
                    return self._submit(
                        endpoint,
                        smtp_acc.username,
                        resolve_password(smtp_acc),
                        sender=out.sender.email,
                        recipients=envelope,
                        raw=out.raw,
                        max_bytes=cfg.limits.max_send_bytes,
                        tls=smtp_acc.tls,
                        net=cfg.net_policy(),
                    )

                try:
                    receipt = await asyncio.to_thread(run)
                except MailError as e:
                    audit.event("send.failed", **base, code=e.code)
                    if p.ref is not None:
                        e.hint = (e.hint + " " if e.hint else "") + (
                            f"The message is kept as a draft (id {p.ref.encode()})."
                        )
                    raise
                except Exception:
                    audit.event("send.failed", **base, code="UNEXPECTED")
                    raise
                if mid:
                    self._sent.add(mid)
                self.limiter.record(smtp_acc.name)
            finally:
                self._in_flight.discard(mid)
        audit.event("send.sent", **base)
        result.status = "sent"
        result.receipt = receipt.reply
        result.draft_id = None
        await self._afterwards(p, result)
        return result

    # ------------------------------------------------------------ after the send

    async def _afterwards(self, p: Prepared, result: SendResult) -> None:
        """Copies, draft removal, ``\\Answered``: never raises, reports in ``result``."""
        out = p.out
        steps = result.steps
        found: list[MessageRef] = []
        try:

            async def work(a: Account) -> tuple[str, list[str], MessageRef | None]:
                return await self.router.call(a, lambda s: self._store_steps(s, p))

            copy, notes, orig = await self.router.run_one(p.store, work)
            result.sent_copy = copy
            steps += notes
            if orig is not None:
                found.append(orig)
        except MailError as e:
            result.sent_copy = f"not saved ({e.code})"
            steps.append(
                f"the message was sent, but saving the copy / removing the draft failed: "
                f"{sanitize_line(e.message)[:150]}"
            )
            result.draft_id = p.ref.encode() if p.ref else None
        original = p.original or (found[0] if found else None)
        if original is not None and out.in_reply_to:
            steps.append(await self._mark_answered(original))

    def _store_steps(
        self, session: ImapSession, draft: Prepared
    ) -> tuple[str, list[str], MessageRef | None]:
        out, ident, smtp_acc = draft.out, draft.ident, draft.smtp_account
        notes: list[str] = []
        folders = session.list_folders()
        orig = (
            draft.original
            if draft.original and draft.original.account == session.account_name
            else None
        )
        if orig is None and out.in_reply_to:
            orig = self._find_original(session, out.in_reply_to)
        thread_folder = None
        if orig is not None:
            info = next((f for f in folders if f.name == orig.folder), None)
            if info is not None and info.role is None and info.name.upper() != "INBOX":
                thread_folder = info
        sent = session.folder_for_role("sent")
        server_saves = bool(smtp_acc.server.smtp_saves_sent)
        targets: list[tuple[str, str]] = []
        copy_text = "no copy saved"
        if ident.save_sent == "never":
            copy_text = "no copy saved (save_sent = never)"
        else:
            want_thread = (
                ident.file_replies in ("thread_folder", "both") and thread_folder is not None
            )
            want_sent = ident.file_replies in ("sent", "both") or thread_folder is None
            if want_sent:
                if ident.save_sent == "auto" and server_saves:
                    notes.append("no copy in Sent: the SMTP server files its own")
                elif sent is None:
                    notes.append("no copy in Sent: the account has no Sent folder")
                else:
                    targets.append((sent.name, sent.display_name))
            if want_thread and thread_folder is not None:
                targets.append((thread_folder.name, thread_folder.display_name))
        saved: list[str] = []
        for wire, display in targets:
            try:
                session.append_message(wire, out.raw, flags=("\\Seen",))
                saved.append(display)
            except MailError as e:
                notes.append(f"copy into {display!r} failed: {sanitize_line(e.message)[:100]}")
            finally:
                self.index.invalidate(session.account_name, wire)
        if saved:
            copy_text = "saved in " + ", ".join(repr(s) for s in saved)
        if draft.ref is not None:
            try:
                outcome = session.remove_draft(
                    draft.ref.folder, draft.ref.uid, uidvalidity=draft.ref.uidvalidity
                )
            except MailError as e:
                outcome = "failed"
                notes.append(f"the draft could not be removed ({sanitize_line(e.message)[:100]})")
            finally:
                self.index.invalidate(session.account_name, draft.ref.folder)
            if outcome == "removed":
                notes.append("the draft was removed")
            elif outcome != "failed":
                notes.append(f"the draft stays in Drafts ({outcome}); delete it by hand")
        return copy_text, notes, orig

    def _find_original(self, session: ImapSession, message_id: str) -> MessageRef | None:
        """The message a draft replies to, searched in this account's folders (INBOX
        first, bounded in folders and time). ``None`` if not found."""
        skip = {"drafts", "trash", "junk", "sent"}
        folders = [f for f in session.list_folders() if f.selectable and f.role not in skip]
        folders.sort(key=lambda f: (f.name.upper() != "INBOX", f.display_name.casefold()))
        deadline = time.monotonic() + FIND_ORIGINAL_SECONDS
        for f in folders[:FIND_ORIGINAL_FOLDERS]:
            if time.monotonic() > deadline:
                break
            try:
                res = session.search_related(f.name, [message_id])
                if not res.uids:
                    continue
                for s in self.index.summaries(
                    session, res.folder, res.uidvalidity, list(res.uids[:20])
                ):
                    if s.message_id == message_id:
                        return s.ref
            except MailError:
                continue
        return None

    async def _mark_answered(self, ref: MessageRef) -> str:
        try:
            acc = self.config.account(ref.account)
        except MailError:
            return "the original was not marked as answered (unknown account)"
        if not acc.permissions.organize:
            return "the original was not marked as answered (no 'organize' permission)"

        def fn(session: ImapSession) -> str:
            res = session.set_flags(
                ref.folder,
                [ref.uid],
                uidvalidity=ref.uidvalidity,
                add=["\\Answered"],
                allowed=ANSWERED_FLAGS,
            )
            self.index.invalidate(session.account_name, ref.folder)
            return (
                "the original is marked as answered"
                if ref.uid in res.flags
                else "the original was not marked as answered (it is gone)"
            )

        async def work(a: Account) -> str:
            return await self.router.call(a, fn)

        try:
            return await self.router.run_one(acc, work)
        except InvalidRef:
            return "the original was not marked as answered (invalid reference)"
        except MailError as e:
            return f"the original was not marked as answered ({e.code})"
