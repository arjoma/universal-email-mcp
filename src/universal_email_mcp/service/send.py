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
   and warnings, subject, attachments and the start of the text. Declined or cancelled:
   the draft stays. When the client cannot elicit, the policy's ``send_fallback`` decides:
   ``draft`` (the draft stays), and in remote mode ``portal`` (a pending approval in the
   portal; nothing goes out until the user approves there) or ``send-unless-flagged``
   (sends directly unless a recipient is new or a look-alike - then it waits in the portal;
   a look-alike is never sent without a human);
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
from typing import Any, Literal, Protocol

from universal_email_mcp import audit
from universal_email_mcp.bounded import run_deadline
from universal_email_mcp.config import Config, SendPolicy, resolve_password
from universal_email_mcp.errors import (
    AlreadySent,
    InvalidArgument,
    InvalidRef,
    MailError,
    MessageNotFound,
    NotPermitted,
    RateLimited,
    SendOutcomeUnknown,
    TooLarge,
)
from universal_email_mcp.mail import smtp
from universal_email_mcp.mail.imap import ANSWERED_FLAGS, ImapSession
from universal_email_mcp.mail.mime import sanitize_line, sanitize_text
from universal_email_mcp.mail.outgoing import (
    MAX_TEXT_CHARS,
    Outgoing,
    parse_outgoing,
    strip_headers,
)
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

SendStatus = Literal["sent", "draft_kept", "declined", "pending_approval"]

MAX_CONFIRM_CHARS = 6_000
MAX_HEAD_CHARS = 4_000
SHOW_TEXT_CHARS = 3_000
SHOW_TEXT_LINES = 80
SHOW_ATTACHMENTS = 20
FIND_ORIGINAL_FOLDERS = 25
FIND_ORIGINAL_SECONDS = 10.0
Submit = Callable[..., smtp.SmtpReceipt]
FINGERPRINT_CHARS = 16


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

    def reserve(self, key: str) -> float:
        """Count a send that is about to start (so concurrent sends see it); the returned
        token goes to :meth:`release` if the send certainly did not happen."""
        now = self._clock()
        self._recent(key).append(now)
        return now

    def release(self, key: str, token: float) -> None:
        try:
            self._recent(key).remove(token)
        except ValueError:
            pass


@dataclass(frozen=True, slots=True)
class ApprovalTicket:
    """A send that waits for the user in the portal."""

    id: str
    url: str
    expires_in_minutes: int


class RemoteSend(Protocol):
    """What remote mode adds to a send (the portal and the store; WP 3f). Local mode has
    none of it: confirmation is the client's elicitation or the draft stays."""

    async def check_rate(self) -> None:
        """Raise :class:`RateLimited` when this user sent too much (shared by instances)."""
        ...

    async def record_send(self) -> None: ...

    async def claim(self, content_hash: str) -> bool:
        """Reserve "this exact message goes out now"; ``False`` for a replay."""
        ...

    async def release(self, content_hash: str) -> None: ...

    async def request_approval(
        self, *, identity: Identity, content_hash: str, draft: MessageRef
    ) -> ApprovalTicket: ...

    def audit_fields(self) -> Mapping[str, Any]:
        """Pseudonymous ids added to every audit event of the user's sends."""
        ...


def is_flagged(classified: Sequence[Classified]) -> bool:
    """Does the recipient check flag something (a new address or a look-alike)?"""
    return any(c.klass in ("new", "lookalike") for c in classified)


# ----------------------------------------------------------------- confirmation text


def _name(a: Address) -> str:
    # An "@" in a display name could pose as another address next to the real one.
    return sanitize_line(a.name).replace("@", "(at)")[:60]


def address_text(a: Address) -> str:
    n = _name(a)
    return f"{n} <{a.email}>" if n else a.email


def class_tag(c: Classified) -> str:
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
    text: str | None = None,
    quoted: str = "",
) -> str:
    """The text the user sees before a message leaves. Everything that comes from
    the message is sanitised (no control or bidi characters, links defanged).

    ``text`` is the new text the message adds (for a composed message: before the
    quoted original, which is only summarised); without it the whole body is shown.
    What is cut is announced with numbers, never silently."""
    lines = ["Send this e-mail? It cannot be taken back.", ""]
    lines.append(f"From: {address_text(out.sender)}  (identity {sanitize_line(ident.name)[:40]})")
    by_field: dict[str, list[Classified]] = {"to": [], "cc": [], "bcc": []}
    for c in classified:
        by_field[c.field].append(c)
    for fld, label in (("to", "To"), ("cc", "Cc"), ("bcc", "Bcc")):
        for c in by_field[fld]:
            lines.append(f"{label}: {address_text(c.address)}  [{class_tag(c)}]")
    if by_field["bcc"]:
        lines.append("(Bcc recipients are hidden from the others.)")
    lines.append(f"Subject: {sanitize_line(out.subject)[:200] or '(none)'}")
    if out.attachments:
        n_att = len(out.attachments)
        lines.append(f"Attachments ({n_att}):")
        lines += [
            f"  {sanitize_line(n)[:80]} ({render.fmt_size(z)})"
            for n, z in out.attachments[:SHOW_ATTACHMENTS]
        ]
        if n_att > SHOW_ATTACHMENTS:
            lines.append(f"  ... and {n_att - SHOW_ATTACHMENTS} more attachment(s) NOT listed")
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
    head = "\n".join(lines)
    if len(head) > MAX_HEAD_CHARS:
        head = (
            head[:MAX_HEAD_CHARS] + f"\n... {len(head) - MAX_HEAD_CHARS} more characters NOT shown"
        )
    shown_lines, cut_note = text_excerpt(text if text is not None else out.preview)
    out_lines = ["", "Text:"]
    if shown_lines:
        out_lines += ["> " + ln for ln in shown_lines]
        if cut_note:
            out_lines.append(cut_note)
    else:
        out_lines.append("> (no plain text)" if not out.has_text_body else "> (empty)")
    if out.preview_cut:
        out_lines.append(preview_cut_note(out))
    if quoted.strip():
        q_lines = len(quoted.strip().split("\n"))
        out_lines.append(f"[quoted original: {q_lines} lines, not shown]")
    if out.html_shown:
        html_lines, html_note = html_excerpt(out)
        out_lines += ["", html_heading(out)]
        out_lines += ["> " + ln for ln in html_lines]
        if html_note:
            out_lines.append(html_note)
    for heading, lines_, note in extra_sections(out):
        out_lines += ["", heading, *["> " + ln for ln in lines_]]
        if note:
            out_lines.append(note)
    if out.remote_images:
        out_lines += ["", remote_images_warning(out)]
    return (head + "\n".join(out_lines))[: MAX_HEAD_CHARS + 200 + 2 * MAX_CONFIRM_CHARS]


def preview_cut_note(out: Outgoing) -> str:
    return f"... {out.preview_cut} more characters beyond the first {MAX_TEXT_CHARS} NOT shown"


def html_heading(out: Outgoing) -> str:
    return (
        "HTML version (differs from the text above - recipients with an HTML mail client "
        "read this):"
        if out.has_text_body
        else "HTML version (the message has no plain text part - recipients read this):"
    )


def html_excerpt(out: Outgoing) -> tuple[list[str], str]:
    """Lines of the HTML version's text and the notice for what is cut (same rules as the
    plain text; the 300000-character cut of the extraction is announced too)."""
    lines, note = text_excerpt(out.html_text)
    if out.html_cut:
        extra = f"... {out.html_cut} more characters of the HTML version NOT shown"
        note = f"{note}\n{extra}" if note else extra
    return lines, note


def extra_sections(out: Outgoing) -> list[tuple[str, list[str], str]]:
    """(heading, lines, cut notice) for every further inline text part: mail clients show
    them as well, so the user must see them (the number listed is capped, the rest
    announced)."""
    sections: list[tuple[str, list[str], str]] = []
    for n, part in enumerate(out.extra_parts, start=1):
        lines, note = text_excerpt(part.text)
        if part.cut:
            extra = f"... {part.cut} more characters of this part NOT shown"
            note = f"{note}\n{extra}" if note else extra
        sections.append((f"Additional text part {n} ({part.kind}):", lines, note))
    if out.extra_more:
        sections.append(
            (
                f"... {out.extra_more} more text part(s) NOT shown",
                [],
                "",
            )
        )
    return sections


def remote_images_warning(out: Outgoing) -> str:
    return (
        f"! The HTML version loads {out.remote_images} remote image(s): they can tell the "
        "sender when and where the mail is read (tracking)."
    )


def text_excerpt(text: str) -> tuple[list[str], str]:
    """The part of a message text a confirmation shows, sanitised and defanged: its lines
    and - when something was cut - the notice saying how much (never silent). The rules
    are shared by the elicitation prompt and the portal's approval page."""
    plain = sanitize_text(text).strip()
    if not plain:
        return [], ""
    # Defanging is slow on very long unbroken runs: only the part that can be shown goes
    # through it (twice the limit leaves room for the longer defanged form).
    body = render.defang_body(plain[: 2 * SHOW_TEXT_CHARS]).strip()
    shown = "\n".join(body[:SHOW_TEXT_CHARS].split("\n")[:SHOW_TEXT_LINES])
    cut = len(plain) - len(shown) if len(plain) > 2 * SHOW_TEXT_CHARS else len(body) - len(shown)
    note = ""
    if cut > 0:
        n_lines = plain.count("\n") - shown.count("\n")
        note = f"... {cut} more characters ({n_lines} lines) of the text NOT shown"
    return shown.split("\n"), note


def split_quoted(text: str) -> tuple[str, str]:
    """Split a stored reply draft into the new text and the quoted original behind it
    (trailing ``>`` lines and their "... wrote:" line). Conservative: anything that is not
    clearly a quote at the end stays in the new text, so nothing is hidden by a split."""
    lines = text.split("\n")
    last_plain = max(
        (i for i, ln in enumerate(lines) if ln.strip() and not _quoted(ln)), default=-1
    )
    start = next((i for i in range(last_plain + 1, len(lines)) if _quoted(lines[i])), None)
    if start is None:
        return text, ""
    j = start - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    if j >= 0 and lines[j].rstrip().endswith(":") and start - j <= 2:
        start = j
    return "\n".join(lines[:start]).rstrip(), "\n".join(lines[start:])


def _quoted(line: str) -> bool:
    return line.lstrip().startswith(">")


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
    confirmation: Literal["asked", "not_needed", "unavailable", "fallback"] = "not_needed"
    approval: ApprovalTicket | None = None
    """Set with ``pending_approval``: where the user approves."""


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


def content_hash(raw: bytes) -> str:
    """Digest of the message content (not of Message-ID and Date, which a recomposition
    changes): what a confirmation, an approval and the replay guard are bound to."""
    return hashlib.sha256(strip_headers(raw, frozenset({"message-id", "date"}))).hexdigest()


def fingerprint(raw: bytes) -> str:
    """Short form of :func:`content_hash`, shown in the confirmation so that the question -
    and with it the user's answer - is bound to exactly this message."""
    return content_hash(raw)[:FINGERPRINT_CHARS]


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
        remote: RemoteSend | None = None,
    ) -> None:
        self.config = config
        self.remote = remote
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
        if ref.is_pop3:
            raise NotPermitted("POP3 accounts are read-only: that is not a draft id")
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
        smtp_acc = self.config.smtp_account(ident.smtp_account or "")
        self._hard_checks(out, smtp_acc.name)
        if self.remote is not None:
            await self.remote.check_rate()
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
                ident,
                out,
                classified,
                reasons,
                note=f"Content fingerprint {fingerprint(out.raw)}",
                text=built.draft.body if built is not None else None,
                quoted=built.draft.quoted if built is not None else "",
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
        base: dict[str, Any] = dict(
            account=p.smtp_account.name,
            recipients=count_by_class(p.classified),
            attachments=len(out.attachments),
            size=audit.size_bucket(len(out.raw)),
            mode=self.config.policy.send,
            **(self.remote.audit_fields() if self.remote else {}),
        )
        await audit.record("send.requested", **base)
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
            await audit.record("send.draft_kept", **base, reason="policy")
            return result
        if p.needs_confirmation:
            if decision == "accepted":
                result.confirmation = "asked"
                await audit.record("send.confirmed", **base)
            elif decision in ("declined", "cancelled"):
                result.confirmation = "asked"
                result.status = "declined"
                result.reasons = [*p.reasons, f"the user {decision} the confirmation"]
                await audit.record("send.declined", **base, outcome=decision)
                return result
            else:
                return await self._fallback(p, result, base)
        return await self._deliver(p, result, base)

    async def _fallback(
        self, p: Prepared, result: SendResult, base: Mapping[str, Any]
    ) -> SendResult:
        """The client cannot ask the user: what ``send_fallback`` says. Nothing here sends
        without a human, except ``send-unless-flagged`` for recipients the check does not
        flag (never a new address, never a look-alike)."""
        mode = self.config.policy.send_fallback if self.remote is not None else "draft"
        if mode == "send-unless-flagged" and not is_flagged(p.classified):
            result.confirmation = "fallback"
            await audit.record("send.fallback_send", **base)
            return await self._deliver(p, result, base)
        result.confirmation = "unavailable"
        if mode != "draft" and self.remote is not None and p.ref is not None:
            ticket = await self.remote.request_approval(
                identity=p.ident, content_hash=content_hash(p.out.raw), draft=p.ref
            )
            result.status = "pending_approval"
            result.approval = ticket
            result.reasons = [
                *p.reasons,
                "the client cannot ask the user for confirmation here, so the user has to "
                "approve this message in the portal first",
            ]
            await audit.record("send.approval_requested", **base, approval=ticket.id)
            return result
        result.reasons = [
            *p.reasons,
            "the client cannot ask the user for confirmation, so the mail stays a draft",
        ]
        await audit.record("send.draft_kept", **base, reason="no_confirmation")
        return result

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
            claimed = ""
            if self.remote is not None:
                await self.remote.check_rate()
                claimed = content_hash(out.raw)
                if not await self.remote.claim(claimed):
                    await audit.record("send.replay_refused", **base)
                    raise AlreadySent(
                        "this exact message was sent a moment ago (or is being sent)",
                        hint="Nothing was sent again. Change the message if a second copy "
                        "is really wanted, after a few minutes.",
                    )
            if mid:
                self._in_flight.add(mid)
            reserved = self.limiter.reserve(smtp_acc.name)
        cfg = self.config
        try:

            def run() -> smtp.SmtpReceipt:
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
                    net=cfg.net_policy(smtp_acc),
                )

            try:
                try:
                    receipt = await run_deadline(
                        run, seconds=cfg.net_policy(smtp_acc).total_timeout
                    )
                except TimeoutError:  # the thread did not even end after the watchdog
                    raise SendOutcomeUnknown("the SMTP server did not finish in time") from None
            except MailError as e:
                await audit.record("send.failed", **base, code=e.code)
                if not isinstance(e, SendOutcomeUnknown):
                    # unknown outcome: the mail may be out, so the claim stays (no resend)
                    await self._unclaim(claimed)
                    self.limiter.release(smtp_acc.name, reserved)
                if p.ref is not None:
                    e.hint = (e.hint + " " if e.hint else "") + (
                        f"The message is kept as a draft (id {p.ref.encode()})."
                    )
                raise
            except Exception:
                await audit.record("send.failed", **base, code="UNEXPECTED")
                await self._unclaim(claimed)
                self.limiter.release(smtp_acc.name, reserved)
                raise
            if mid:
                self._sent.add(mid)
            if self.remote is not None:
                await self._record_remote()
        except asyncio.CancelledError:
            if mid:  # the SMTP thread may still deliver: never allow a second copy
                self._sent.add(mid)
            raise
        finally:
            self._in_flight.discard(mid)
        await audit.record("send.sent", **base)
        result.status = "sent"
        result.receipt = receipt.reply
        result.draft_id = None
        await self._afterwards(p, result)
        return result

    async def _unclaim(self, claimed: str) -> None:
        """The send failed before the server took the message: a retry is fine."""
        if self.remote is not None and claimed:
            try:
                await self.remote.release(claimed)
            except Exception:  # noqa: BLE001 - the marker expires on its own
                log.warning("could not release the send marker", exc_info=True)

    async def _record_remote(self) -> None:
        """Count the send for the shared rate limit; a failure never undoes a delivery."""
        assert self.remote is not None
        try:
            await self.remote.record_send()
        except Exception:  # noqa: BLE001
            log.warning("could not record the send for the rate limit", exc_info=True)

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
        if not (acc.permissions.organize or acc.permissions.drafts):
            return "the original was not marked as answered (no 'organize' or 'drafts' permission)"

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
