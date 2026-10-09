"""MIME parsing: robust header decoding, body text selection, attachment listing,
text windows, and fencing of untrusted content.

Everything here treats mail as hostile input: bad charsets fall back instead of
raising, invisible/bidi control characters are removed, HTML is reduced to visible
text (hidden elements, scripts, styles, images and tracking pixels are dropped),
and :func:`fence_untrusted` marks content so a model can tell data from instructions.
"""

from __future__ import annotations

import binascii
import codecs
import email.errors
import email.header
import email.utils
import html as html_mod
import quopri
import re
import secrets
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.message import Message
from email.parser import BytesHeaderParser, BytesParser
from typing import Literal

from universal_email_mcp.models import Address, Attachment, TextSlice

# --------------------------------------------------------------------------- text hygiene

# Zero-width, bidi overrides/isolates, invisible separators and fillers (Hangul),
# variation selectors (incl. the supplement U+E0100–E01EF, which can smuggle one
# byte per character), tag characters, BOM, interlinear annotations, shorthand and
# musical format controls. U+2028/2029 are handled as line breaks.
# Raw strings: the regex engine reads the escapes, the source holds no literal
# control or astral characters.
_INVISIBLE = re.compile(
    r"[\xad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f"
    r"\u202a-\u202e\u2060-\u2064\u2066-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0"
    r"\ufff9-\ufffb\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    r"\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)
_LINE_SEP = re.compile(r"[\u2028\u2029\x85]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_CONTROL_ALL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_text(text: str) -> str:
    """Normalise newlines and drop invisible/bidi/control characters (keeps \\t, \\n)."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _LINE_SEP.sub("\n", text)
    text = _INVISIBLE.sub("", text)
    return _CONTROL.sub("", text)


def sanitize_line(text: str) -> str:
    """Like :func:`sanitize_text` for single-line values (headers): no line breaks."""
    text = _LINE_SEP.sub(" ", text)
    text = _INVISIBLE.sub("", text)
    text = _CONTROL_ALL.sub(" ", text)
    return re.sub(r" {2,}", " ", text).strip()


_FENCE_TAG = re.compile(r"<(\s*/?\s*untrusted[\s_-]*content)", re.IGNORECASE)


def fence_untrusted(text: str, *, source: str = "email", nonce: str | None = None) -> str:
    """Wrap untrusted mail content in explicit markers.

    The markers carry a random nonce, so content cannot close the fence even if it
    imitates the tag; imitations are defused anyway (``<`` → ``‹``). Invisible and
    bidi control characters are removed.
    """
    nonce = nonce or secrets.token_hex(6)
    src = re.sub(r"[^A-Za-z0-9 ._:-]", "", source)[:64] or "email"
    clean = _FENCE_TAG.sub(r"‹\1", sanitize_text(text))
    return (
        f'<untrusted-content source="{src}" nonce="{nonce}">\n'
        f"{clean}\n"
        f'</untrusted-content nonce="{nonce}">'
    )


def slice_text(text: str, max_chars: int, offset: int = 0) -> TextSlice:
    """Return a window of ``text`` starting at ``offset`` with at most ``max_chars``."""
    if max_chars < 1:
        raise ValueError("max_chars must be positive")
    total = len(text)
    offset = max(0, min(offset, total))
    end = min(total, offset + max_chars)
    return TextSlice(
        text=text[offset:end],
        offset=offset,
        total_chars=total,
        next_offset=end if end < total else None,
    )


# --------------------------------------------------------------------------- headers


def _decode_bytes(data: bytes, charset: str | None) -> str:
    """Decode with the declared charset, falling back to UTF-8, then Windows-1252."""
    candidates: list[str] = []
    if charset:
        cs = charset.strip().strip('"').lower()
        if cs in ("unknown-8bit", "x-unknown", "us-ascii", "ascii"):
            cs = ""
        if cs:
            try:
                codecs.lookup(cs)
                candidates.append(cs)
            except LookupError:
                pass
    candidates += ["utf-8", "cp1252"]
    for cs in candidates:
        try:
            return data.decode(cs)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="replace")  # pragma: no cover - latin-1 never fails


def decode_text(data: bytes, charset: str | None = None) -> str:
    """Decode bytes as text: declared charset, else UTF-8, else Windows-1252."""
    return _decode_bytes(data, charset)


def decode_transfer(data: bytes, encoding: str) -> bytes:
    """Undo a Content-Transfer-Encoding. Tolerant: garbage inside base64 is skipped,
    a dangling character is dropped, unknown encodings are returned as they are.
    The output is never larger than the input."""
    enc = encoding.strip().lower()
    if enc == "base64":
        chars = re.sub(rb"[^A-Za-z0-9+/]", b"", data)
        if len(chars) % 4 == 1:
            chars = chars[:-1]
        return binascii.a2b_base64(chars + b"=" * (-len(chars) % 4))
    if enc == "quoted-printable":
        return quopri.decodestring(data)
    return data


def _fix_surrogates(s: str) -> str:
    """Raw 8-bit header bytes arrive as surrogate escapes; decode them properly."""
    if not any("\udc80" <= c <= "\udcff" for c in s):
        return s
    return _decode_bytes(s.encode("ascii", "surrogateescape"), None)


def _unfold(value: str) -> str:
    return re.sub(r"\r?\n(?=[ \t])", "", value)


def decode_header(value: str | bytes | None) -> str:
    """Decode an RFC 2047 header value robustly; always returns a clean single line."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = _decode_bytes(value, None)
    value = _unfold(_fix_surrogates(str(value)))
    try:
        chunks = email.header.decode_header(value)
    except (email.errors.HeaderParseError, ValueError, LookupError):
        return sanitize_line(value)
    out: list[str] = []
    for chunk, charset in chunks:
        if isinstance(chunk, bytes):
            out.append(_decode_bytes(chunk, charset))
        else:
            out.append(_fix_surrogates(chunk))
    return sanitize_line("".join(out))


_EMAIL_RE = re.compile(r"[^\s<>\"',;:()\[\]]+@[^\s<>\"',;:()\[\]]+")


def parse_addresses(*values: str | None) -> tuple[Address, ...]:
    """Parse one or more address-list header values into :class:`Address` items."""
    raw = [_unfold(_fix_surrogates(v)) for v in values if v]
    if not raw:
        return ()
    result: list[Address] = []
    pairs = email.utils.getaddresses(raw)
    for name, addr in pairs:
        addr = sanitize_line(addr)
        if not addr:
            continue
        result.append(Address(name=decode_header(name), email=addr))
    if not result:  # strict parser gave up: salvage bare addresses
        for v in raw:
            for m in _EMAIL_RE.findall(v):
                result.append(Address(name="", email=sanitize_line(m)))
    return tuple(result)


_MSGID_RE = re.compile(r"<[^<>\s]+>")


def parse_msgid_list(value: str | None) -> tuple[str, ...]:
    """Message-IDs (with angle brackets) in order of appearance, deduplicated."""
    if not value:
        return ()
    ids: list[str] = []
    for m in _MSGID_RE.findall(_unfold(_fix_surrogates(value))):
        m = sanitize_line(m)
        if m not in ids:
            ids.append(m)
    return tuple(ids)


def parse_msgid(value: str | None) -> str | None:
    ids = parse_msgid_list(value)
    if ids:
        return ids[0]
    cleaned = sanitize_line(_unfold(value or ""))
    return cleaned or None


def parse_date(value: str | None) -> datetime | None:
    """RFC 5322 date → aware datetime (naive/-0000 dates are taken as UTC)."""
    if not value:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(sanitize_line(_unfold(value)))
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


@dataclass(frozen=True, slots=True)
class HeaderFields:
    """Decoded header fields used for summaries, threading and search."""

    from_: tuple[Address, ...] = ()
    to: tuple[Address, ...] = ()
    cc: tuple[Address, ...] = ()
    reply_to: tuple[Address, ...] = ()
    subject: str = ""
    date: datetime | None = None
    message_id: str | None = None
    in_reply_to: str | None = None
    references: tuple[str, ...] = ()


SUMMARY_HEADERS = (
    "From",
    "To",
    "Cc",
    "Reply-To",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
)


def _all(msg: Message, name: str) -> list[str]:
    # raw_items() keeps raw 8-bit bytes as surrogate escapes (get_all() would turn
    # them into replacement characters); _fix_surrogates() decodes them later.
    wanted = name.lower()
    return [str(v) for k, v in msg.raw_items() if k.lower() == wanted]


def _first(msg: Message, name: str) -> str | None:
    values = _all(msg, name)
    return values[0] if values else None


def header_fields_from_message(msg: Message) -> HeaderFields:
    """Extract :class:`HeaderFields` from a message parsed with ``policy.compat32``."""
    return HeaderFields(
        from_=parse_addresses(*_all(msg, "From")),
        to=parse_addresses(*_all(msg, "To")),
        cc=parse_addresses(*_all(msg, "Cc")),
        reply_to=parse_addresses(*_all(msg, "Reply-To")),
        subject=decode_header(_first(msg, "Subject")),
        date=parse_date(_first(msg, "Date")),
        message_id=parse_msgid(_first(msg, "Message-ID")),
        in_reply_to=parse_msgid(_first(msg, "In-Reply-To")),
        references=parse_msgid_list(" ".join(_all(msg, "References"))),
    )


def parse_header_block(raw: bytes) -> HeaderFields:
    """Parse a raw header block (e.g. ``BODY[HEADER.FIELDS (...)]``)."""
    msg = BytesHeaderParser(policy=policy.compat32).parsebytes(raw)
    return header_fields_from_message(msg)


# --------------------------------------------------------------------------- HTML

_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none"
    r"|visibility\s*:\s*(hidden|collapse)"
    r"|opacity\s*:\s*0*(\.0+)?\s*(;|!|$)"
    r"|font-size\s*:\s*0+(\.0+)?\s*(px|pt|em|rem|%)?\s*(;|!|$)"
    r"|max-(height|width)\s*:\s*0+\s*(px)?\s*(;|!|$)"
    r"|mso-hide\s*:\s*all"
    r"|text-indent\s*:\s*-\d{3,}",
    re.IGNORECASE,
)
_ZERO_BOX = re.compile(r"(^|;)\s*(height|width)\s*:\s*0+\s*(px)?\s*(;|!|$)", re.IGNORECASE)
_OVERFLOW_HIDDEN = re.compile(r"overflow\s*:\s*hidden", re.IGNORECASE)

_DROP_TAGS = frozenset(
    {
        "script",
        "style",
        "head",
        "title",
        "meta",
        "link",
        "template",
        "noscript",
        "object",
        "embed",
        "iframe",
        "frame",
        "svg",
        "math",
        "img",
        "picture",
        "video",
        "audio",
        "canvas",
        "map",
        "input",
        "select",
        "textarea",
        "button",
    }
)


def _is_hidden(el: object) -> bool:
    attrib = getattr(el, "attrib", {})
    if "hidden" in attrib:
        return True
    if str(attrib.get("aria-hidden", "")).lower() == "true":
        return True
    style = str(attrib.get("style", ""))
    if style and (
        _HIDDEN_STYLE.search(style) or (_ZERO_BOX.search(style) and _OVERFLOW_HIDDEN.search(style))
    ):
        return True
    return False


def html_to_text(html: str, *, max_input_chars: int = 2_000_000) -> str:
    """Convert HTML mail to readable text: visible content only, links as
    ``text (url)`` (plain text, not Markdown links)."""
    from inscriptis import Inscriptis
    from inscriptis.model.config import ParserConfig
    from lxml import html as lxml_html
    from lxml.etree import ParserError, SubElement

    html = html[:max_input_chars]
    html = re.sub(r"^\s*<\?xml[^>]*\?>", "", html)
    if not html.strip():
        return ""
    try:
        tree = lxml_html.fromstring(html)
    except (ParserError, ValueError):
        try:
            tree = lxml_html.fromstring(html.encode("utf-8", "replace"))
        except (ParserError, ValueError):
            return _strip_tags(html)

    doomed: list[lxml_html.HtmlElement] = []
    for el in tree.iter():
        tag = el.tag
        if not isinstance(tag, str):  # comments, processing instructions
            doomed.append(el)
            continue
        local = tag.rsplit("}", 1)[-1].lower()
        if local in _DROP_TAGS or _is_hidden(el):
            doomed.append(el)
    for el in doomed:
        if el is tree:
            return ""
        parent = el.getparent()
        if parent is None:
            continue
        if isinstance(el, lxml_html.HtmlElement):
            el.drop_tree()  # keeps the tail text
        else:
            tail = el.tail
            prev = el.getprevious()
            parent.remove(el)
            if tail:
                if prev is not None:
                    prev.tail = (prev.tail or "") + tail
                else:
                    parent.text = (parent.text or "") + tail

    # Link targets are kept as plain text after the link text ("text (url)") —
    # never as Markdown link syntax with attacker-chosen link text; callers defang
    # the URLs before showing them.
    for a in tree.iter("a"):
        href = " ".join(str(a.get("href") or "").split())[:2000]
        if not href or href.startswith("#"):
            continue
        label = " ".join(a.text_content().split())
        if label == href or label.rstrip("/") == href.rstrip("/"):
            continue
        SubElement(a, "span").text = f" ({href})"
    text = Inscriptis(tree, ParserConfig(display_links=False)).get_text()
    return _tidy(text)


def _strip_tags(html: str) -> str:
    text = re.sub(r"(?is)<(script|style|head)\b.*?</\1\s*>", " ", html)
    text = re.sub(r"(?s)<[^>]*>", " ", text)
    return _tidy(html_mod.unescape(text))


def _tidy(text: str) -> str:
    lines = [line.rstrip() for line in sanitize_text(text).split("\n")]
    text = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


# --------------------------------------------------------------------------- bodies

MAX_TEXT_PARTS = 100
"""Inline text parts shown in the body; further ones are listed as attachments."""
MAX_LISTED_PARTS = 100
"""Attachments and other parts listed per message."""
REPORT_TYPES = frozenset(
    {
        "message/delivery-status",
        "message/global-delivery-status",
        "message/disposition-notification",
        "message/global-disposition-notification",
        "message/feedback-report",
    }
)
"""Machine-readable report parts (bounces, read receipts, abuse reports): plain
header-style text, shown in the body."""

TextSource = Literal["plain", "html", "mixed", "none", "unparseable"]


@dataclass(frozen=True, slots=True)
class ParsedMessage:
    headers: HeaderFields
    text: str
    text_source: TextSource
    attachments: tuple[Attachment, ...]
    notes: tuple[str, ...] = ()
    """What the body leaves out or shortens (limits); safe, server-generated text."""
    leaves: tuple[tuple[str, str], ...] = ()
    """``(section, content type)`` of every leaf part as Python numbered them, to
    compare with the server's BODYSTRUCTURE (see :mod:`mail.bodystructure`)."""


def _part_bytes(part: Message) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001 - broken transfer encodings must not abort parsing
        payload = None
    if isinstance(payload, bytes):
        return payload
    raw = part.get_payload()
    return raw.encode("utf-8", "surrogateescape") if isinstance(raw, str) else b""


def part_text(part: Message) -> str:
    """Decoded text of a leaf part with charset fallback."""
    try:
        charset = part.get_content_charset()
    except Exception:  # noqa: BLE001 - malformed parameters
        charset = None
    return _decode_bytes(_part_bytes(part), charset)


def _is_container(part: Message) -> bool:
    """A multipart whose children are IMAP body parts. ``message/*`` parts are
    leaves for IMAP (Python parses some of them into sub-messages)."""
    return part.is_multipart() and part.get_content_maintype() != "message"


def iter_parts(msg: Message, prefix: str = "") -> Iterator[tuple[str, Message]]:
    """Yield ``(imap_section, leaf_part)``; ``message/*`` parts are leaves."""
    if not _is_container(msg):
        yield (prefix or "1"), msg
        return
    for section, sub in _children(msg, prefix):
        if _is_container(sub):
            yield from iter_parts(sub, section)
        else:
            yield section, sub


def _children(part: Message, prefix: str) -> list[tuple[str, Message]]:
    payload = part.get_payload()
    if not isinstance(payload, list):  # pragma: no cover - defensive
        return []
    return [
        (f"{prefix}.{i}" if prefix else str(i), sub)
        for i, sub in enumerate(payload, 1)
        if isinstance(sub, Message)
    ]


MAX_FILENAME_CHARS = 120


def display_filename(name: str) -> str | None:
    """A file name safe to show (still untrusted text: escape it in Markdown).

    Replaces path separators with ``_`` (``../x`` → ``.._x``; the name is display-only),
    removes control, invisible and bidi characters, and shortens very long names in
    the middle so the extension stays visible. Double extensions are shown as they
    are. Nothing here is ever used as a path."""
    name = sanitize_line(name)
    name = re.sub(r"[\\/]+", "_", name).strip()
    if len(name) > MAX_FILENAME_CHARS:
        stem, dot, ext = name.rpartition(".")
        ext = ext[:16] if dot else ""
        keep = MAX_FILENAME_CHARS - len(ext) - 2
        base = stem if dot else name
        name = base[:keep] + "…" + (f".{ext}" if dot else "")
    return name or None


def _filename(part: Message) -> str | None:
    name: str | None
    try:
        name = part.get_filename() or part.get_param("name")  # pyright: ignore[reportAssignmentType]
    except Exception:  # noqa: BLE001
        name = None
    if isinstance(name, tuple):  # RFC 2231 triple from get_param
        name = email.utils.collapse_rfc2231_value(name)
    if not name:
        return None
    return display_filename(decode_header(str(name)))


def _disposition(part: Message) -> str | None:
    try:
        value = part.get_content_disposition()
    except Exception:  # noqa: BLE001
        return None
    return value.lower() if value else None


def _part_size(part: Message) -> int:
    if part.get_content_maintype() == "message":
        inner = part.get_payload()
        if isinstance(inner, list):
            try:
                return sum(len(m.as_bytes()) for m in inner if isinstance(m, Message))
            except Exception:  # noqa: BLE001
                return 0
    return len(_part_bytes(part))


_Kind = Literal["plain", "html", "report"]


def _text_kind(part: Message) -> _Kind | None:
    """How a leaf part reads as body text, or ``None`` for an attachment: inline
    ``text/plain`` / ``text/html`` without a file name, and report parts."""
    if _disposition(part) == "attachment":
        return None
    ctype = part.get_content_type()
    if ctype in REPORT_TYPES:
        return "report"
    if _filename(part):
        return None
    if ctype == "text/plain":
        return "plain"
    if ctype == "text/html":
        return "html"
    return None


def _cached_text(part: Message, cache: dict[int, str]) -> str:
    key = id(part)
    if key not in cache:
        cache[key] = part_text(part)
    return cache[key]


def _body_parts(
    part: Message, section: str, out: list[tuple[str, Message, _Kind]], cache: dict[int, str]
) -> None:
    """Collect the parts that make up the body, in order: every inline text part of
    a ``multipart/mixed`` (or any other multipart), one version of each
    ``multipart/alternative`` — the plain one if it has text, else the first with
    any text part (HTML). Decoded plain texts are kept in ``cache``."""
    if not _is_container(part):
        kind = _text_kind(part)
        if kind is not None:
            out.append((section, part, kind))
        return
    children = _children(part, section)
    if part.get_content_type() != "multipart/alternative":
        for sec, sub in children:
            _body_parts(sub, sec, out, cache)
        return
    versions: list[list[tuple[str, Message, _Kind]]] = []
    for sec, sub in children:
        version: list[tuple[str, Message, _Kind]] = []
        _body_parts(sub, sec, version, cache)
        if version:
            versions.append(version)
    for version in versions:
        if all(k != "html" for _s, _p, k in version) and any(
            k == "plain" and _cached_text(p, cache).strip() for _s, p, k in version
        ):
            out.extend(version)
            return
    if versions:
        out.extend(next((v for v in versions if any(k == "html" for *_x, k in v)), versions[0]))


def _after_headers(data: bytes) -> bytes:
    if data.startswith((b"\r\n", b"\n")):
        return data[data.index(b"\n") + 1 :]
    m = re.search(rb"\r?\n\r?\n", data)
    return data[m.end() :] if m else b""


def _split_multipart(body: bytes, boundary: bytes) -> list[bytes]:
    """The body parts of a multipart body (without the line break that belongs to
    the next delimiter); stops at the close delimiter."""
    delims = list(re.finditer(rb"^--" + re.escape(boundary) + rb"(--)?[ \t]*\r?$", body, re.M))
    chunks: list[bytes] = []
    for k, m in enumerate(delims):
        if m.group(1):
            break
        start = m.end() + (1 if body[m.end() : m.end() + 1] == b"\n" else 0)
        end = delims[k + 1].start() if k + 1 < len(delims) else len(body)
        chunk = body[start:end]
        chunks.append(chunk[:-2] if chunk.endswith(b"\r\n") else chunk.removesuffix(b"\n"))
    return chunks


def _raw_part_body(raw: bytes, msg: Message, section: str) -> bytes | None:
    """The undecoded body bytes of the leaf at IMAP ``section``, cut from the
    original message (Python re-parses some ``message/*`` bodies before their
    transfer encoding is undone). ``None`` when the part cannot be located with
    certainty (malformed MIME): the caller falls back to the parsed part."""
    data, node = raw, msg
    if _is_container(msg):
        for index in section.split("."):
            boundary = node.get_boundary()
            children = node.get_payload()
            if not boundary or not isinstance(children, list) or not index.isdigit():
                return None
            chunks = _split_multipart(
                _after_headers(data), boundary.encode("utf-8", "surrogateescape")
            )
            n = int(index)
            if not 1 <= n <= min(len(chunks), len(children)):
                return None
            data, node = chunks[n - 1], children[n - 1]
            if not isinstance(node, Message):
                return None
    head = BytesHeaderParser(policy=policy.compat32).parsebytes(data)
    if head.get_content_type() != node.get_content_type():
        return None
    return _after_headers(data)


def _report_text(part: Message, raw_body: bytes | None) -> str:
    """A report part (header-style blocks) as text: transfer encoding undone,
    charset decoded (UTF-8 for the ``global`` types), RFC 2047 words decoded,
    every name and value sanitised. Uses the original body bytes when known."""
    body = raw_body if raw_body is not None else _serialized_body(part)
    cte = str(part.get("Content-Transfer-Encoding", "")).strip().lower()
    if cte == "base64":
        chars = re.sub(rb"[^A-Za-z0-9+/]", b"", body)
        if len(chars) % 4 == 1:
            chars = chars[:-1]  # a dangling character cannot be decoded
        body = binascii.a2b_base64(chars + b"=" * (-len(chars) % 4))
    elif cte == "quoted-printable":
        body = quopri.decodestring(body)
    try:
        charset = part.get_content_charset()
    except Exception:  # noqa: BLE001 - malformed parameters
        charset = None
    # Line by line: one stray 8-bit byte must not turn the rest into mojibake.
    lines_raw = body.replace(b"\r\n", b"\n").split(b"\n")
    text = _unfold("\n".join(_decode_bytes(ln, charset or "utf-8") for ln in lines_raw))
    blocks: list[str] = []
    for chunk in re.split(r"\n[ \t]*\n", text.strip()):
        lines: list[str] = []
        for line in chunk.split("\n"):
            m = _REPORT_FIELD.match(line)
            if m:
                lines.append(f"{sanitize_line(m[1])}: {decode_header(m[2])}")
            elif line.strip():
                lines.append(sanitize_line(line))
        if lines:
            blocks.append("\n".join(lines))
    return _tidy("\n\n".join(blocks))


_REPORT_FIELD = re.compile(r"([^:\s]{1,100}):[ \t]*(.*)")


def _serialized_body(part: Message) -> bytes:
    try:
        data = part.as_bytes(policy=policy.compat32)
    except Exception:  # noqa: BLE001 - unserialisable structure: show nothing
        return b""
    return _after_headers(data)


# Box drawing (U+2500–U+257F), dashes, bars and lines, then "part" — any
# horizontal whitespace (also NBSP) before, between and after.
_FAKE_SEPARATOR = re.compile(
    r"^([^\S\n]*)(?=[\u2500-\u257f\u2010-\u2015\u2212\u23af\u2e3a\u2e3b\ufe58\ufe63"
    r"\uff0d\u2014\u30fc=_~*#+-]{3,}[^\S\n]*part\b)",
    re.IGNORECASE | re.MULTILINE,
)


def _defuse_separators(text: str) -> str:
    """Mail text cannot fake the server's ``──── part N`` lines (``› `` prefix)."""
    return _FAKE_SEPARATOR.sub(r"\1› ", text)


_LABELS: dict[_Kind, str] = {
    "plain": "text",
    "html": "HTML converted to text",
    "report": "delivery report",
}


def parse_message(raw: bytes, *, max_html_chars: int = 2_000_000) -> ParsedMessage:
    """Parse a full RFC 5322 message: headers, body text, attachments.

    The body is every inline text part in order (one version of each
    ``multipart/alternative``, plain text preferred, HTML converted to visible
    text), separated by a marker line when there are several. Limits
    (``MAX_TEXT_PARTS``, ``max_html_chars`` in total, ``MAX_LISTED_PARTS``) never
    drop anything silently: text parts left out are listed as attachments and
    ``notes`` says what was left out or shortened.

    A structure too deeply nested for the parser (``RecursionError``, e.g. thousands
    of nested multiparts) degrades to headers only with ``text_source="unparseable"``
    instead of failing the call or the session.
    """
    headers = header_fields_from_message(BytesHeaderParser(policy=policy.compat32).parsebytes(raw))
    try:
        return _parse_body(raw, headers, max_html_chars)
    except RecursionError:
        return ParsedMessage(headers=headers, text="", text_source="unparseable", attachments=())


def _parse_body(raw: bytes, headers: HeaderFields, max_html_chars: int) -> ParsedMessage:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    notes: list[str] = []

    candidates: list[tuple[str, Message, _Kind]] = []
    cache: dict[int, str] = {}
    _body_parts(msg, "" if _is_container(msg) else "1", candidates, cache)
    body_parts = {id(p) for _s, p, _k in candidates}
    if len(candidates) > MAX_TEXT_PARTS:
        extra = len(candidates) - MAX_TEXT_PARTS
        notes.append(
            f"{len(candidates)} text parts: the body shows the first {MAX_TEXT_PARTS}, "
            f"the other {extra} are listed as attachments"
        )
        candidates = candidates[:MAX_TEXT_PARTS]

    segments: list[tuple[str, _Kind, str]] = []
    shown: set[int] = set()
    html_budget = max_html_chars
    unconverted: list[str] = []
    for section, part, kind in candidates:
        if kind == "html":
            html = part_text(part)
            if html_budget <= 0:
                unconverted.append(section)
                continue
            if len(html) > html_budget:
                notes.append(f"HTML part {section} is too long; only its beginning is shown")
            text = html_to_text(html, max_input_chars=html_budget)
            html_budget -= len(html)
        elif kind == "report":
            text = _report_text(part, _raw_part_body(raw, msg, section))
        else:
            text = _tidy(_cached_text(part, cache))
        shown.add(id(part))
        if text:
            segments.append((section, kind, _defuse_separators(text)))

    if unconverted:
        notes.append(
            f"{len(unconverted)} HTML part{'s' if len(unconverted) != 1 else ''} not "
            "converted (size limit), listed as attachments: "
            + ", ".join(unconverted[:5])
            + (" …" if len(unconverted) > 5 else "")
        )

    if len(segments) > 1:
        text = "\n\n".join(
            (f"──── part {sec} ({_LABELS[kind]}) ────\n\n" if n else "") + body
            for n, (sec, kind, body) in enumerate(segments)
        )
    else:
        text = segments[0][2] if segments else ""
    source: TextSource = "none"
    if segments:
        has_html = any(k == "html" for _s, k, _t in segments)
        has_plain = any(k != "html" for _s, k, _t in segments)
        source = "mixed" if has_html and has_plain else "html" if has_html else "plain"

    attachments: list[Attachment] = []
    unlisted = 0
    for section, part in iter_parts(msg):
        if id(part) in shown:
            continue
        kind = _text_kind(part)
        if kind is not None and id(part) not in body_parts:
            continue  # a version of an alternative that was not chosen: same content
        if len(attachments) >= MAX_LISTED_PARTS:
            unlisted += 1
            continue
        cid = part.get("Content-ID")
        disp = _disposition(part)
        attachments.append(
            Attachment(
                part_id=section,
                filename=_filename(part),
                content_type=part.get_content_type(),
                size=_part_size(part),
                inline=kind is not None or disp == "inline" or (disp is None and cid is not None),
                content_id=parse_msgid(str(cid)) if cid else None,
            )
        )
    if unlisted:
        notes.append(f"{unlisted} more parts not listed (at most {MAX_LISTED_PARTS})")
    return ParsedMessage(
        headers=headers,
        text=text,
        text_source=source,
        attachments=tuple(attachments),
        notes=tuple(notes),
        leaves=tuple((sec, p.get_content_type()) for sec, p in iter_parts(msg)),
    )


@dataclass(frozen=True, slots=True)
class RawPart:
    """One leaf part cut out of a message by this parser's numbering."""

    section: str
    content_type: str
    charset: str | None
    filename: str | None
    disposition: str | None
    content_id: str | None
    data: bytes
    """Decoded content (transfer encoding undone)."""


def extract_part(raw: bytes, section: str) -> RawPart | None:
    """The leaf at ``section`` (numbered like :func:`iter_parts`, which is also how
    :func:`parse_message` numbers attachments), or ``None``. For backends without a
    server-side structure (POP3): the parser's numbering is the authority there."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        for sec, part in iter_parts(msg):
            if sec != section:
                continue
            if part.get_content_maintype() == "message":
                # Cut from the original bytes: re-serialising would change line ends.
                body = _raw_part_body(raw, msg, sec)
                if body is not None:
                    data = decode_transfer(body, str(part.get("Content-Transfer-Encoding", "7bit")))
                else:
                    data = _serialized_body(part)
            else:
                data = _part_bytes(part)
            try:
                charset = part.get_content_charset()
            except Exception:  # noqa: BLE001 - malformed parameters
                charset = None
            cid = part.get("Content-ID")
            return RawPart(
                section=sec,
                content_type=part.get_content_type(),
                charset=charset,
                filename=_filename(part),
                disposition=_disposition(part),
                content_id=parse_msgid(str(cid)) if cid else None,
                data=data,
            )
    except RecursionError:
        return None
    return None


_MIME_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,60}/[a-z0-9][a-z0-9!#$&^_.+-]{0,60}$")


_PASSIVE_TYPES = frozenset(
    {
        "application/pdf",
        "application/zip",
        "application/gzip",
        "application/x-7z-compressed",
        "application/vnd.rar",
        "application/rtf",
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/message",
        "message/rfc822",
    }
)
_PASSIVE_PREFIXES = (
    "application/vnd.openxmlformats-officedocument.",
    "application/vnd.oasis.opendocument.",
    "audio/",
    "video/",
)


def safe_mime_type(declared: str) -> str:
    """Label for a returned file: the sender's type only if it is a well-formed
    member of an allowlist of passive types; everything else (every text-like,
    HTML, XML, SVG, script type …) is ``application/octet-stream``, so a client
    never gets a blob it might render or execute."""
    d = declared.lower()
    if _MIME_TYPE.match(d) and (d in _PASSIVE_TYPES or d.startswith(_PASSIVE_PREFIXES)):
        if not d.endswith(("+xml", "+json")):
            return d
    return "application/octet-stream"


# --------------------------------------------------------------------------- HTML view

RASTER_IMAGE_TYPES = frozenset({"image/png", "image/jpeg", "image/gif", "image/webp"})
"""Image types the viewer inlines (as ``data:`` URIs). Never SVG: it can carry markup."""


@dataclass(frozen=True, slots=True)
class HtmlViewParts:
    html: tuple[str, ...]
    """Decoded text of every inline ``text/html`` body part, in order."""
    images: dict[str, tuple[str, bytes]]
    """Normalised Content-ID -> (content type, bytes) of the raster images that carry one."""


def normalize_cid(value: str) -> str:
    """``<Abc@x>`` / ``cid:abc%40x`` -> ``abc@x`` for matching ``cid:`` references."""
    value = urllib.parse.unquote(value.strip()).strip()
    if value.lower().startswith("cid:"):
        value = value[4:]
    return value.strip().strip("<>").strip().lower()


def html_view_parts(
    raw: bytes, *, max_html_chars: int = 2_000_000, max_image_bytes: int, max_total_bytes: int
) -> HtmlViewParts:
    """The HTML bodies and the inline raster images of a message, for the sandboxed viewer.

    Images are collected up to ``max_image_bytes`` each and ``max_total_bytes`` in all;
    HTML up to ``max_html_chars`` in all (the rest is dropped). A structure too deep for the
    parser yields nothing."""
    html: list[str] = []
    images: dict[str, tuple[str, bytes]] = {}
    budget, total = max_html_chars, 0
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        for _section, part in iter_parts(msg):
            ctype = part.get_content_type()
            if _text_kind(part) == "html":
                if budget > 0:
                    text = part_text(part)
                    html.append(text[:budget])
                    budget -= len(text)
                continue
            cid = part.get("Content-ID")
            if cid and ctype in RASTER_IMAGE_TYPES:
                key = normalize_cid(str(cid))
                if not key or key in images:
                    continue
                data = _part_bytes(part)
                if len(data) <= max_image_bytes and total + len(data) <= max_total_bytes:
                    images[key] = (ctype, data)
                    total += len(data)
    except RecursionError:
        return HtmlViewParts((), {})
    return HtmlViewParts(tuple(html), images)
