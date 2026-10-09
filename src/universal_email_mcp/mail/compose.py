"""Composing draft messages: new, reply, reply-all and forward.

Pure functions over data: no I/O, no configuration lookups. The caller decides the
sender (one of the configured identities) and passes everything else in.

Two kinds of input, handled differently:

- **Caller input** (recipients, subject, body, sender name from the model/user) is
  validated strictly and refused with :class:`InvalidArgument` when it is not clean:
  control characters (CR, LF, NUL, ...) in any header value, malformed addresses,
  too many or too long values. There is no sanitising that could hide an injection.
- **Original mail** (the message being replied to or forwarded) is attacker
  controlled. Its addresses, names, Message-ID and References are only used after
  strict syntax checks; whatever fails them is dropped (and reported as a warning)
  instead of copied. The original's text is quoted as inert plain text.

Output is plain text only (UTF-8, ``format=flowed`` is not used), built with the
standard library ``email`` package under the SMTP policy, so every header goes
through the library's own encoder (RFC 2047 encoded words, folding) and a header
value with a line break cannot be produced.
"""

from __future__ import annotations

import email.policy
import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email import message_from_bytes
from email.headerregistry import Address as HeaderAddress
from email.message import EmailMessage
from email.utils import format_datetime, getaddresses, make_msgid
from typing import Literal

from universal_email_mcp.errors import InvalidArgument
from universal_email_mcp.mail.mime import sanitize_line, sanitize_text
from universal_email_mcp.models import Address, Identity

MAX_SUBJECT_CHARS = 500
MAX_NAME_CHARS = 100
MAX_BODY_CHARS = 200_000
MAX_ADDRESS_CHARS = 254
MAX_REFERENCES = 10
"""References kept in a reply: the first message of the conversation and the latest
ones (RFC 5322 3.6.4 advises against unbounded growth)."""
MAX_MSGID_CHARS = 255
MAX_QUOTE_CHARS = 6_000
MAX_ATTACHMENTS = 20
MAX_FILENAME_CHARS = 120

Kind = Literal["new", "reply", "forward"]

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_ATOM = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
_LOCAL_RE = re.compile(rf"\A{_ATOM}(?:\.{_ATOM})*\Z")
_DOMAIN_LABEL = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_MSGID_RE = re.compile(
    rf"\A<({_ATOM}(?:\.{_ATOM})*)@((?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?)"
    rf"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?)*)>\Z"
)
_MIME_TYPE_RE = re.compile(r"\A[a-z0-9][a-z0-9!#$&^_.+-]{0,40}/[a-z0-9][a-z0-9!#$&^_.+-]{0,60}\Z")
_REPLY_PREFIX = re.compile(r"\A\s*(?:(?:re|aw|antw|sv|vs)(?:\[\d{1,3}\])?\s*:\s*)+", re.I)
_FORWARD_PREFIX = re.compile(r"\A\s*(?:(?:fwd?|wg|tr)(?:\[\d{1,3}\])?\s*:\s*)+", re.I)


# ----------------------------------------------------------------- data


@dataclass(frozen=True, slots=True)
class Original:
    """The message being replied to or forwarded, as read from the mailbox.

    Everything in it is untrusted; :func:`compose` filters it."""

    message_id: str | None
    in_reply_to: str | None
    references: tuple[str, ...]
    subject: str
    from_: tuple[Address, ...]
    reply_to: tuple[Address, ...]
    to: tuple[Address, ...]
    cc: tuple[Address, ...]
    date: datetime | None
    body: str
    body_truncated: bool = False


FORWARD_MARKER = "---------- Forwarded message ----------"
"""First line of the block :func:`forward_block` adds."""


@dataclass(frozen=True, slots=True)
class OriginInfo:
    """What the server knows about the original behind a reply or forward: the facts
    shown to the user before the message leaves (everything still untrusted text)."""

    kind: Literal["reply", "forward"]
    sender: str
    date: str
    subject: str
    """The original's subject."""
    subject_ok: bool
    """Does the draft's subject read ``Re:`` / ``Fwd:`` + the original's subject?"""


@dataclass(frozen=True, slots=True)
class FileAttachment:
    """A file taken from an existing message (never from the local disk)."""

    filename: str
    content_type: str
    data: bytes


@dataclass(frozen=True, slots=True)
class Draft:
    """A composed message and what to show about it."""

    raw: bytes
    message_id: str
    sender: Address
    to: tuple[Address, ...]
    cc: tuple[Address, ...]
    bcc: tuple[Address, ...]
    subject: str
    in_reply_to: str | None
    references: tuple[str, ...]
    body: str
    """What the author wrote plus the signature (without the quoted original)."""
    quoted: str
    """The quoted/forwarded original (``""`` for a new message)."""
    attachments: tuple[tuple[str, str, int], ...]
    """(file name, content type, size) of the attached files."""
    warnings: tuple[str, ...]
    origin: OriginInfo | None = None
    """The original of a reply or forward (``None`` for a new message)."""

    @property
    def recipients(self) -> tuple[Address, ...]:
        return (*self.to, *self.cc, *self.bcc)


# ----------------------------------------------------------------- validation of caller input


def header_text(value: str, what: str, *, max_chars: int = MAX_SUBJECT_CHARS) -> str:
    """A header value from the caller: refused (not cleaned) if it holds a line
    break, NUL or any other control character, or is too long."""
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise InvalidArgument(f"{what} must be text")
    if _CTRL.search(value):
        raise InvalidArgument(
            f"{what} contains a line break or control character",
            hint="Use plain single-line text. Nothing was saved.",
        )
    value = value.strip()
    if len(value) > max_chars:
        raise InvalidArgument(f"{what} is longer than {max_chars} characters")
    return value


def _ascii_domain(domain: str) -> str | None:
    domain = domain.strip().rstrip(".")
    if not domain or len(domain) > 253:
        return None
    try:
        ascii_domain = domain.encode("idna").decode("ascii") if not domain.isascii() else domain
    except UnicodeError:
        return None
    labels = ascii_domain.split(".")
    if len(labels) < 2 or not all(_DOMAIN_LABEL.match(x) for x in labels):
        return None
    return ascii_domain.lower()


def clean_email(addr: str) -> str | None:
    """A conservative ``local@domain`` (ASCII local part, IDNA domain), else ``None``."""
    addr = addr.strip()
    if not addr or len(addr) > MAX_ADDRESS_CHARS or _CTRL.search(addr):
        return None
    local, sep, domain = addr.rpartition("@")
    if not sep or len(local) > 64 or not _LOCAL_RE.match(local):
        return None
    ascii_domain = _ascii_domain(domain)
    return f"{local}@{ascii_domain}" if ascii_domain else None


def _safe_name(name: str) -> str | None:
    """A display name that is safe to write into a header, else ``None``."""
    name = sanitize_line(name)
    if not name or len(name) > MAX_NAME_CHARS or "=?" in name or _CTRL.search(name):
        return None
    return name


def parse_recipients(values: Sequence[str] | None, what: str) -> list[Address]:
    """Addresses from the caller (``a@b``, ``Name <a@b>``, several per string).
    Anything that is not a clean address is refused."""
    out: list[Address] = []
    for value in values or ():
        value = header_text(value, what, max_chars=2 * MAX_ADDRESS_CHARS)
        if not value:
            continue
        if value.count("<") != value.count(">"):
            raise InvalidArgument(f"{what}: {value[:80]!r} is not a valid e-mail address")
        parsed = getaddresses([value], strict=True)
        if not parsed or any(not addr for _n, addr in parsed):
            raise InvalidArgument(f"{what}: {value[:80]!r} is not a valid e-mail address")
        for name, addr in parsed:
            clean = clean_email(addr)
            if clean is None:
                raise InvalidArgument(f"{what}: {addr[:80]!r} is not a valid e-mail address")
            shown = _safe_name(name)
            if name.strip() and shown is None:
                raise InvalidArgument(f"{what}: the name for {clean} is not acceptable")
            out.append(Address(shown or "", clean))
    return out


def dedupe(addresses: Iterable[Address]) -> list[Address]:
    seen: set[str] = set()
    out: list[Address] = []
    for a in addresses:
        key = a.email.lower()
        if key not in seen:
            seen.add(key)
            out.append(a)
    return out


# ----------------------------------------------------------------- filtering of the original


def valid_msgid(value: str | None) -> str | None:
    if value and len(value) <= MAX_MSGID_CHARS and _MSGID_RE.match(value):
        return value
    return None


def thread_headers(original: Original) -> tuple[str | None, tuple[str, ...]]:
    """``(In-Reply-To, References)`` of a reply to ``original``: only well-formed
    ids, de-duplicated, the first one and the latest ones kept."""
    parent = valid_msgid(original.message_id)
    refs = [m for m in dict.fromkeys(valid_msgid(r) for r in original.references) if m]
    if parent:
        refs = [r for r in refs if r != parent]
        refs.append(parent)
    if len(refs) > MAX_REFERENCES:
        refs = [refs[0], *refs[-(MAX_REFERENCES - 1) :]]
    return parent, tuple(refs)


def _trusted_addresses(addresses: Iterable[Address], warnings: list[str]) -> list[Address]:
    """Addresses of the original that pass the strict syntax check; names that look
    like encoded words or are odd are dropped (the address is kept)."""
    out: list[Address] = []
    dropped = 0
    for a in addresses:
        clean = clean_email(a.email)
        if clean is None:
            dropped += 1
            continue
        out.append(Address(_safe_name(a.name) or "", clean))
    if dropped:
        warnings.append(f"{dropped} malformed address(es) in the original were ignored")
    return out


def reply_subject(subject: str) -> str:
    base = _REPLY_PREFIX.sub("", sanitize_line(subject)).strip()
    return f"Re: {base}"[:MAX_SUBJECT_CHARS]


def forward_subject(subject: str) -> str:
    base = _FORWARD_PREFIX.sub("", sanitize_line(subject)).strip()
    return f"Fwd: {base}"[:MAX_SUBJECT_CHARS]


def _subject_core(subject: str) -> str:
    """The subject without any reply/forward prefixes, case and spacing normalised."""
    text = sanitize_line(subject)
    previous = None
    while previous != text:
        previous = text
        text = _FORWARD_PREFIX.sub("", _REPLY_PREFIX.sub("", text)).strip()
    return " ".join(text.casefold().split())[: MAX_SUBJECT_CHARS - 10]


def subject_matches_original(subject: str, original_subject: str, kind: str) -> bool:
    """``Re:`` (reply) or ``Fwd:`` (forward) followed by the original's subject. A
    different subject on a reply or forward is how a message gets sent under a
    harmless-looking title."""
    prefix = _REPLY_PREFIX if kind == "reply" else _FORWARD_PREFIX
    return bool(prefix.match(sanitize_line(subject))) and _subject_core(subject) == _subject_core(
        original_subject
    )


def origin_info(original: Original, kind: Literal["reply", "forward"], subject: str) -> OriginInfo:
    return OriginInfo(
        kind=kind,
        sender=_addr_line(original.from_, 1) or "(unknown sender)",
        date=_when(original.date),
        subject=_line(original.subject) or "(no subject)",
        subject_ok=subject_matches_original(subject, original.subject, kind),
    )


def reply_recipients(
    original: Original, own: set[str], *, reply_all: bool
) -> tuple[list[Address], list[Address], list[str]]:
    """``(to, cc, warnings)`` of a reply, derived from the original's headers like a
    mail client does: Reply-To (else From) gets the answer; reply-all adds the
    other To/Cc recipients. The user's own addresses never appear."""
    warnings: list[str] = []
    senders = _trusted_addresses(original.from_, warnings)
    reply_to = _trusted_addresses(original.reply_to, warnings)
    target = reply_to or senders
    if reply_to and senders:
        sender_domains = {a.email.rpartition("@")[2].lower() for a in senders}
        foreign = sorted(
            {a.email for a in reply_to if a.email.rpartition("@")[2].lower() not in sender_domains}
        )
        if foreign:
            warnings.append(
                "the original has a Reply-To that points to a different domain "
                f"({', '.join(foreign[:3])}) than its sender "
                f"({', '.join(a.email for a in senders[:2])}); the reply goes to the Reply-To "
                "address — check that this is intended"
            )
    if target and all(a.email.lower() in own for a in target):
        # Replying to one's own mail: the answer goes to whom it was written to.
        target = _trusted_addresses(original.to, warnings)
    to = [a for a in dedupe(target) if a.email.lower() not in own]
    cc: list[Address] = []
    if reply_all:
        others = _trusted_addresses([*original.to, *original.cc], warnings)
        taken = {a.email.lower() for a in to}
        cc = [
            a for a in dedupe(others) if a.email.lower() not in own and a.email.lower() not in taken
        ]
    return to, cc, warnings


# ----------------------------------------------------------------- text blocks


def _line(text: str, limit: int = 200) -> str:
    text = sanitize_line(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _addr_line(addresses: Iterable[Address], limit: int = 6) -> str:
    items = [f"{a.name} <{a.email}>" if a.name else a.email for a in addresses]
    more = f" (+{len(items) - limit} more)" if len(items) > limit else ""
    return _line(", ".join(items[:limit]) + more, 400)


def _when(dt: datetime | None) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if dt else "an unknown date"


def _clip(text: str) -> tuple[str, bool]:
    text = sanitize_text(text).strip("\n")
    if len(text) <= MAX_QUOTE_CHARS:
        return text, False
    return text[:MAX_QUOTE_CHARS].rstrip() + "\n[…]", True


def quote_block(original: Original) -> str:
    """The original as quoted text (``> `` prefix, attribution line). Inert text."""
    who = _addr_line(original.from_, 1) or "the sender"
    text, _clipped = _clip(original.body)
    lines = [f"On {_when(original.date)}, {who} wrote:"]
    lines += [f"> {ln}" if ln.strip() else ">" for ln in text.split("\n")]
    if original.body_truncated:
        lines.append("> […]")
    return "\n".join(lines)


def forward_block(original: Original) -> str:
    text, _clipped = _clip(original.body)
    lines = [
        FORWARD_MARKER,
        f"From: {_addr_line(original.from_)}",
        f"Date: {_when(original.date)}",
        f"Subject: {_line(original.subject)}",
        f"To: {_addr_line(original.to)}",
    ]
    if original.cc:
        lines.append(f"Cc: {_addr_line(original.cc)}")
    lines += ["", text]
    if original.body_truncated:
        lines.append("[…]")
    return "\n".join(lines)


def assemble_text(body: str, signature: str, quoted: str) -> str:
    """The author's text, the identity's signature (``-- `` separator) and the
    quoted original, separated by blank lines."""
    parts = [sanitize_text(body).strip("\n")]
    sig = sanitize_text(signature).strip("\n")
    if sig:
        parts.append("-- \n" + sig)
    if quoted:
        parts.append(quoted)
    return "\n\n".join(p for p in parts if p) + "\n"


# ----------------------------------------------------------------- attachments


def safe_filename(name: str | None) -> str:
    name = sanitize_line(name or "").replace("/", "_").replace("\\", "_")
    name = unicodedata.normalize("NFC", name).strip(" .")
    if "=?" in name:
        name = name.replace("=?", "_?")
    if len(name) > MAX_FILENAME_CHARS:
        stem, dot, ext = name.rpartition(".")
        if dot and len(ext) < 12:
            name = stem[: MAX_FILENAME_CHARS - len(ext) - 1] + dot + ext
        else:
            name = name[:MAX_FILENAME_CHARS]
    return name or "attachment"


def _attach(msg: EmailMessage, att: FileAttachment) -> tuple[str, str]:
    ctype = att.content_type.strip().lower()
    if not _MIME_TYPE_RE.match(ctype):
        ctype = "application/octet-stream"
    filename = safe_filename(att.filename)
    maintype, _, subtype = ctype.partition("/")
    if ctype == "message/rfc822":
        try:
            inner = message_from_bytes(att.data)
            msg.add_attachment(inner, filename=filename)
            return filename, ctype
        except Exception:  # noqa: BLE001 - fall back to an opaque file
            ctype, maintype, subtype = "application/octet-stream", "application", "octet-stream"
    if maintype in ("message", "multipart"):
        ctype, maintype, subtype = "application/octet-stream", "application", "octet-stream"
    if maintype == "text":
        # Keep the declared type but ship the bytes as an opaque base64 body: the
        # charset is not known here and must not be guessed.
        msg.add_attachment(
            att.data, maintype="application", subtype="octet-stream", filename=filename
        )
        list(msg.iter_attachments())[-1].set_type(ctype)
        return filename, ctype
    msg.add_attachment(att.data, maintype=maintype, subtype=subtype, filename=filename)
    return filename, ctype


# ----------------------------------------------------------------- composing


@dataclass(slots=True)
class Request:
    sender: Identity
    address: str
    """The identity address used in ``From`` (one of ``sender.addresses``)."""
    kind: Kind = "new"
    to: Sequence[Address] = ()
    cc: Sequence[Address] = ()
    bcc: Sequence[Address] = ()
    subject: str = ""
    body: str = ""
    original: Original | None = None
    attachments: Sequence[FileAttachment] = ()
    in_reply_to: str | None = None
    references: Sequence[str] = ()
    """Explicit threading (an updated reply draft keeps its threading); ignored
    when ``original`` is set."""
    now: datetime | None = None
    warnings: list[str] = field(default_factory=list[str])


def compose(req: Request) -> Draft:
    """Build the message. Recipients, subject and body in ``req`` are final (the
    caller already derived reply recipients and subject prefixes)."""
    body = req.body
    if len(body) > MAX_BODY_CHARS:
        raise InvalidArgument(f"the body is longer than {MAX_BODY_CHARS} characters")
    subject = header_text(req.subject, "subject")
    addr = clean_email(req.address)
    if addr is None:
        raise InvalidArgument("the sender address is not valid")
    sender = Address(_safe_name(req.sender.display_name) or "", addr)

    in_reply_to: str | None = None
    references: tuple[str, ...] = ()
    quoted = ""
    origin: OriginInfo | None = None
    if req.original is not None:
        if req.kind == "reply":
            in_reply_to, references = thread_headers(req.original)
            quoted = quote_block(req.original)
            origin = origin_info(req.original, "reply", subject)
        elif req.kind == "forward":
            quoted = forward_block(req.original)
            origin = origin_info(req.original, "forward", subject)
    else:
        in_reply_to = valid_msgid(req.in_reply_to)
        references = tuple(m for m in map(valid_msgid, req.references) if m)[:MAX_REFERENCES]

    text = assemble_text(body, req.sender.signature, quoted)
    own_text = assemble_text(body, req.sender.signature, "")
    warnings = list(req.warnings)

    msg = EmailMessage(policy=email.policy.SMTP)
    msg["From"] = _header_address(sender)
    for header, group in (("To", req.to), ("Cc", req.cc), ("Bcc", req.bcc)):
        if group:
            msg[header] = [_header_address(a) for a in group]
    if subject:
        msg["Subject"] = subject
    now = req.now or datetime.now(UTC)
    msg["Date"] = format_datetime(now)
    domain = addr.rpartition("@")[2]
    message_id = make_msgid(idstring=None, domain=domain)
    msg["Message-ID"] = message_id
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = " ".join(references)
    msg.set_content(text, charset="utf-8")
    attached: list[tuple[str, str, int]] = []
    for att in list(req.attachments)[:MAX_ATTACHMENTS]:
        name, ctype = _attach(msg, att)
        attached.append((name, ctype, len(att.data)))
    return Draft(
        raw=msg.as_bytes(),
        message_id=message_id,
        sender=sender,
        to=tuple(req.to),
        cc=tuple(req.cc),
        bcc=tuple(req.bcc),
        subject=subject,
        in_reply_to=in_reply_to,
        references=references,
        body=own_text.rstrip("\n"),
        quoted=quoted,
        attachments=tuple(attached),
        warnings=tuple(warnings),
        origin=origin,
    )


def _header_address(a: Address) -> HeaderAddress:
    local, _, domain = a.email.rpartition("@")
    return HeaderAddress(display_name=a.name, username=local, domain=domain)
