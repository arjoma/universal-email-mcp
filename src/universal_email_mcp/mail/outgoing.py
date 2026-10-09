"""Reading a message that is about to be sent.

A draft that ``send_message`` is asked to send may have been written by this server
(``save_draft``), by the user's mail client, or edited by anybody with access to the
mailbox. Before anything leaves, :func:`parse_outgoing` re-reads the bytes exactly as
they would be transmitted and extracts what the confirmation must show and what the
envelope is made of: **one** sender, every To/Cc/Bcc address (all header instances),
the attachments and a body preview. Anything that does not parse cleanly is refused
rather than guessed.

:func:`strip_headers` removes headers from the raw bytes without re-serialising the
message (so signatures and encodings stay intact); the SMTP layer uses it to make sure
no ``Bcc`` header is ever transmitted.
"""

from __future__ import annotations

import email.policy
import re
from dataclasses import dataclass
from email import message_from_bytes
from email.errors import MissingHeaderBodySeparatorDefect
from email.message import EmailMessage
from email.utils import getaddresses

from universal_email_mcp.errors import InvalidArgument
from universal_email_mcp.mail.compose import clean_email, valid_msgid
from universal_email_mcp.mail.mime import sanitize_text
from universal_email_mcp.models import Address

MAX_RECIPIENT_HEADERS = 50
MAX_TEXT_CHARS = 300_000
_EOL = re.compile(rb"\r\n|\r|\n")
_HEADER_END = re.compile(rb"\r\n\r\n")


@dataclass(frozen=True, slots=True)
class Outgoing:
    raw: bytes
    """The message as it is transmitted (CRLF line ends; still with its Bcc header)."""
    sender: Address
    to: tuple[Address, ...]
    cc: tuple[Address, ...]
    bcc: tuple[Address, ...]
    subject: str
    message_id: str | None
    in_reply_to: str | None
    attachments: tuple[tuple[str, int], ...]
    """(file name, decoded size)."""
    preview: str
    """The plain-text body (sanitised, unescaped, capped; escape it for display)."""
    has_text_body: bool

    @property
    def recipients(self) -> tuple[Address, ...]:
        """To, Cc and Bcc without duplicates (first occurrence wins)."""
        seen: set[str] = set()
        out: list[Address] = []
        for a in (*self.to, *self.cc, *self.bcc):
            if a.email.lower() not in seen:
                seen.add(a.email.lower())
                out.append(a)
        return tuple(out)


def normalize_eol(raw: bytes) -> bytes:
    """Every line break becomes CRLF (SMTP requires it; bare LF/CR would be a
    smuggling vector for servers that treat them as line ends)."""
    return _EOL.sub(b"\r\n", raw)


def strip_headers(raw: bytes, names: frozenset[str]) -> bytes:
    """Remove the headers called ``names`` (lower case) from the header block of
    ``raw`` (folded continuation lines go with them). The body is untouched."""
    raw = normalize_eol(raw)
    m = _HEADER_END.search(raw)
    if m is None:
        head, body = raw, b""
        sep = b""
    else:
        head, body, sep = raw[: m.start()], raw[m.end() :], b"\r\n\r\n"
    kept: list[bytes] = []
    dropping = False
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t"):
            if not dropping:
                kept.append(line)
            continue
        name = line.split(b":", 1)[0].strip().decode("ascii", "replace").lower()
        dropping = ":" in line.decode("latin-1") and name in names
        if not dropping:
            kept.append(line)
    return b"\r\n".join(kept) + sep + body


def has_header(raw: bytes, name: str) -> bool:
    """Does the header block contain a header called ``name``?"""
    return strip_headers(raw, frozenset({name.lower()})) != normalize_eol(raw)


def _addresses(msg: EmailMessage, header: str) -> tuple[Address, ...]:
    values = [str(v) for v in msg.get_all(header, [])]
    if len(values) > MAX_RECIPIENT_HEADERS:
        raise InvalidArgument(f"the message has more than {MAX_RECIPIENT_HEADERS} {header} headers")
    out: list[Address] = []
    pairs: list[tuple[str, str]] = []
    for value in values:
        got = getaddresses([value], strict=True)
        if ("", "") in got and not value.strip().lower().startswith("undisclosed-recipients"):
            raise InvalidArgument(
                f"a {header} header cannot be parsed as addresses",
                hint="Edit the draft (save_draft) so that every recipient is a plain address.",
            )
        pairs += got
    for name, addr in pairs:
        if not addr and not name:
            continue
        clean = clean_email(addr)
        if clean is None:
            raise InvalidArgument(
                f"a {header} address is not valid and cannot be sent to",
                hint="Edit the draft (save_draft) so that every recipient is a plain address.",
            )
        out.append(Address(sanitize_text(name).replace("\n", " ").strip()[:100], clean))
    return tuple(out)


def parse_outgoing(raw: bytes) -> Outgoing:
    """Parse ``raw`` for sending; :class:`InvalidArgument` if it is not sendable."""
    raw = normalize_eol(raw)
    msg = message_from_bytes(raw, policy=email.policy.default)
    if not isinstance(msg, EmailMessage):  # pragma: no cover - policy.default yields these
        raise InvalidArgument("the message cannot be read")
    if any(isinstance(d, MissingHeaderBodySeparatorDefect) for d in msg.defects):
        raise InvalidArgument(
            "the message's header block is malformed (a line is not a header)",
            hint="Create the draft again with save_draft.",
        )
    froms = msg.get_all("From", [])
    if len(froms) != 1:
        raise InvalidArgument(
            "the message must have exactly one From header",
            hint="Create the draft again with save_draft.",
        )
    senders = _addresses(msg, "From")
    if len(senders) != 1:
        raise InvalidArgument(
            "the From header must name exactly one address",
            hint="Create the draft again with save_draft.",
        )
    to, cc, bcc = (_addresses(msg, h) for h in ("To", "Cc", "Bcc"))
    atts: list[tuple[str, int]] = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True)
        size = len(payload) if isinstance(payload, bytes) else 0
        atts.append((sanitize_text(part.get_filename() or "attachment")[:120], size))
    body = msg.get_body(preferencelist=("plain",))
    text = ""
    if body is not None:
        try:
            text = str(body.get_content())
        except (LookupError, ValueError, UnicodeError):
            text = ""
    preview = sanitize_text(text).strip()[:MAX_TEXT_CHARS]
    return Outgoing(
        raw=raw,
        sender=senders[0],
        to=to,
        cc=cc,
        bcc=bcc,
        subject=sanitize_text(str(msg.get("Subject", ""))).replace("\n", " ").strip()[:500],
        message_id=valid_msgid(str(msg.get("Message-ID", "")).strip()),
        in_reply_to=valid_msgid(str(msg.get("In-Reply-To", "")).strip()),
        attachments=tuple(atts),
        preview=preview,
        has_text_body=body is not None,
    )
