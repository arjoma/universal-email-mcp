"""The server's view of a message structure: IMAP ``BODYSTRUCTURE`` as a flat list of leaves.

Python's MIME parser and the IMAP server disagree on malformed structures
(multipart without boundary, a child reusing its parent's boundary, …). The server
decides what ``BODY[n]`` returns, so **attachment section numbers come from the
server's BODYSTRUCTURE**, never from the Python parse: :func:`leaves` numbers the
parts exactly like RFC 3501 does, and everything that fetches a part looks it up
here first (type, encoding, size, file name come from the same server answer that
numbers the part).

``message/rfc822`` parts are leaves (their inner structure is not walked): the
section addresses the whole forwarded message.

Everything in a BODYSTRUCTURE is attacker-controlled text (file names, types).
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any, cast

from universal_email_mcp.mail.mime import (
    MAX_LISTED_PARTS,
    REPORT_TYPES,
    ParsedMessage,
    decode_header,
    display_filename,
)
from universal_email_mcp.models import Attachment

MAX_DEPTH = 40
MAX_LEAVES = 2_000
"""Parts looked at per message (the server's structure can be arbitrarily wide)."""

SECTION_RE = re.compile(r"\A[1-9][0-9]{0,3}(\.[1-9][0-9]{0,3}){0,19}\Z")
"""A part section number as this module produces them; anything else (``1.MIME``,
``TEXT``, ``HEADER`` …) is not an attachment id."""


@dataclass(frozen=True, slots=True)
class BodyLeaf:
    """One non-multipart part as the server sees it."""

    section: str
    content_type: str
    """Lower-case ``type/subtype`` as declared (untrusted)."""
    charset: str | None
    filename: str | None
    """Display-safe (see :func:`mime.display_filename`)."""
    disposition: str | None
    content_id: str | None
    encoding: str
    """Lower-case Content-Transfer-Encoding (``7bit`` when absent)."""
    size: int
    """Octets of the *encoded* part."""
    in_alternative: bool = False
    """Inside a ``multipart/alternative`` (text versions of one body)."""

    @property
    def is_body_text(self) -> bool:
        """Reads as message text rather than as a file: unnamed inline
        ``text/plain`` / ``text/html`` and machine-readable report parts."""
        if self.disposition == "attachment":
            return False
        if self.content_type in REPORT_TYPES:
            return True
        return self.content_type in ("text/plain", "text/html") and not self.filename


def decoded_size(encoding: str, size: int) -> int:
    """Estimated decoded size of a part of ``size`` encoded octets.

    Base64 is assumed to be wrapped at 76 characters (CRLF every 78 octets): exact
    for mail clients' output, about 3 % low for an unwrapped single line.
    Quoted-printable is an upper bound."""
    if encoding == "base64":
        lines = -(-size // 78)
        return max(0, (size - 2 * lines) * 3 // 4)
    return size


def _s(v: object) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return "" if v is None else str(v)


def _pairs(params: object) -> dict[str, str]:
    """``(name, value, name, value …)`` → dict with lower-case names."""
    if not isinstance(params, (tuple, list)):
        return {}
    items = cast(Sequence[object], params)
    out: dict[str, str] = {}
    for k, v in zip(items[0::2], items[1::2], strict=False):
        out.setdefault(_s(k).lower(), _s(v))
    return out


def _rfc2231(params: dict[str, str], name: str) -> str | None:
    """Value of parameter ``name`` incl. RFC 2231 forms (``name*``, ``name*0*``)."""
    if name in params:
        return decode_header(params[name])
    if f"{name}*" in params:
        return _percent(params[f"{name}*"], extended=True)
    chunks: list[tuple[int, str, bool]] = []
    for k, v in params.items():
        m = re.fullmatch(re.escape(name) + r"\*(\d{1,3})(\*?)", k)
        if m:
            chunks.append((int(m[1]), v, bool(m[2])))
    if not chunks:
        return None
    chunks.sort()
    charset_prefix = ""
    parts: list[str] = []
    for n, (_i, v, encoded) in enumerate(chunks):
        if n == 0 and encoded:
            m = re.match(r"([^']*)'[^']*'(.*)", v, re.S)
            if m:
                charset_prefix, v = m[1], m[2]
        parts.append(
            urllib.parse.unquote(v, charset_prefix or "utf-8", "replace") if encoded else v
        )
    return "".join(parts)


def _percent(value: str, *, extended: bool) -> str:
    m = re.match(r"([^']*)'[^']*'(.*)", value, re.S) if extended else None
    charset, rest = (m[1], m[2]) if m else ("", value)
    try:
        return urllib.parse.unquote(rest, charset or "utf-8", "replace")
    except LookupError:
        return urllib.parse.unquote(rest, "utf-8", "replace")


def _leaf(section: str, part: Sequence[Any], in_alternative: bool) -> BodyLeaf:
    ctype = _s(part[0]).lower()
    subtype = _s(part[1]).lower() if len(part) > 1 else ""
    full = f"{ctype}/{subtype}"
    params = _pairs(part[2] if len(part) > 2 else None)
    content_id = _s(part[3]).strip() if len(part) > 3 and part[3] else None
    encoding = _s(part[5]).lower().strip() if len(part) > 5 and part[5] else "7bit"
    try:
        size = int(part[6]) if len(part) > 6 else 0
    except (TypeError, ValueError):
        size = 0
    disp_index = 9 if ctype == "text" else 11 if full == "message/rfc822" else 8
    disposition: str | None = None
    disp_params: dict[str, str] = {}
    raw_disp = part[disp_index] if len(part) > disp_index else None
    if isinstance(raw_disp, (tuple, list)) and raw_disp:
        d = cast(Sequence[object], raw_disp)
        disposition = _s(d[0]).lower() or None
        disp_params = _pairs(d[1] if len(d) > 1 else None)
    name = _rfc2231(disp_params, "filename") or _rfc2231(params, "name")
    return BodyLeaf(
        section=section,
        content_type=full,
        charset=params.get("charset") or None,
        filename=display_filename(name) if name else None,
        disposition=disposition,
        content_id=content_id,
        encoding=encoding,
        size=max(0, size),
        in_alternative=in_alternative,
    )


def leaves(bs: Any) -> list[BodyLeaf] | None:
    """All leaf parts of a parsed BODYSTRUCTURE in server order, numbered like
    ``BODY[section]``. ``None`` when the structure is unusable (not a structure,
    nested deeper than :data:`MAX_DEPTH`, or more than :data:`MAX_LEAVES` parts) —
    callers then refuse instead of guessing."""
    out: list[BodyLeaf] = []

    def walk(part: Any, section: str, depth: int, alt: bool) -> bool:
        if depth > MAX_DEPTH or not isinstance(part, (tuple, list)) or not part:
            return False
        items = cast(Sequence[Any], part)
        if isinstance(items[0], list):  # multipart: ([children], subtype, …)
            subtype = _s(items[1]).lower() if len(items) > 1 else ""
            for i, child in enumerate(cast(list[Any], items[0]), 1):
                if not walk(
                    child,
                    f"{section}.{i}" if section else str(i),
                    depth + 1,
                    alt or subtype == "alternative",
                ):
                    return False
            return True
        if len(out) >= MAX_LEAVES:
            return False
        out.append(_leaf(section or "1", items, alt))
        return True

    try:
        return out if walk(bs, "", 0, False) else None
    except (TypeError, ValueError, IndexError, RecursionError):
        return None


def find(parts: Sequence[BodyLeaf], section: str) -> BodyLeaf | None:
    return next((p for p in parts if p.section == section), None)


def attachments_for(
    parsed: ParsedMessage, server: Sequence[BodyLeaf] | None, *, truncated: bool
) -> tuple[tuple[Attachment, ...], tuple[str, ...]]:
    """The attachment list to show, with section numbers from the server.

    When the parser's part list matches the server's (same sections and types, the
    message was read completely) the parser's richer list is used. Otherwise —
    malformed MIME, a partial fetch, a structure too deep to parse — the list is
    derived from BODYSTRUCTURE alone, sizes are then estimates. Returns
    ``(attachments, notes)``."""
    if server is None:
        return (
            parsed.attachments,
            ("the server's message structure was unusable: attachments cannot be downloaded",),
        )
    aligned = tuple((p.section, p.content_type) for p in server) == parsed.leaves
    if aligned and not truncated:
        fixed = tuple(
            replace(a, size=leaf.size)
            if a.content_type.startswith("message/") and (leaf := find(server, a.part_id))
            else a
            for a in parsed.attachments
        )
        return fixed, ()
    out: list[Attachment] = []
    skipped = 0
    for leaf in server:
        if leaf.is_body_text:
            continue
        if len(out) >= MAX_LISTED_PARTS:
            skipped += 1
            continue
        out.append(
            Attachment(
                part_id=leaf.section,
                filename=leaf.filename,
                content_type=leaf.content_type,
                size=decoded_size(leaf.encoding, leaf.size),
                inline=leaf.disposition == "inline"
                or (leaf.disposition is None and leaf.content_id is not None),
                content_id=leaf.content_id,
                size_estimated=True,
            )
        )
    notes = [
        "message larger than the size limit: attachments are listed from the server's "
        "structure, sizes are estimates"
        if truncated
        else "the server and the parser read this message's MIME structure differently "
        "(malformed message?): attachments are listed from the server's view, sizes are estimates"
    ]
    if skipped:
        notes.append(f"{skipped} more parts not listed (at most {MAX_LISTED_PARTS})")
    return tuple(out), tuple(notes)


_TEXT_TYPES = frozenset(
    {
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-yaml",
        "application/yaml",
        "application/toml",
        "application/x-sh",
        "application/sql",
        "application/ics",
        "image/svg+xml",
    }
)


def is_text_like(leaf: BodyLeaf, data: bytes) -> bool:
    """Show as (fenced) text instead of handing out bytes: a text type by what the
    sender declared **and** content that looks like text (no NUL bytes unless the
    declared charset is UTF-16/32). SVG and HTML count as text so they are never
    returned as something a client might render."""
    ctype = leaf.content_type
    declared = (
        ctype.startswith("text/") or ctype in _TEXT_TYPES or ctype.endswith(("+json", "+xml"))
    )
    if not declared:
        return False
    if (leaf.charset or "").lower().replace("-", "").startswith(("utf16", "utf32", "ucs")):
        return True
    return b"\x00" not in data[:8192]
