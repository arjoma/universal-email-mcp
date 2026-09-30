"""Markdown rendering of tool results (§7.3 of the design plan).

Everything that reaches a table cell from a mailbox — subjects, names, addresses,
folder names, attachment names — is attacker-controlled. :func:`escape_cell` is
the single place that makes such text inert in Markdown: it cannot break the
table, create links or images (which a chat client might fetch: exfiltration),
render HTML, or hide text with invisible/bidi characters. Only links the server
generates itself go through :func:`server_link`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime

from universal_email_mcp.mail.mime import sanitize_line

DEFAULT_CELL_CHARS = 80

# URL-like tokens: anything with ``scheme://`` (no word boundary needed: ``_https://``
# and ``1https://`` autolink too), ``www.`` hosts, and bare host/path forms.
_URL = re.compile(
    r"(?i)(?:[a-z][a-z0-9+.\-]*://|www\.)[^\s|<>]*"
    r"|(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?/[^\s|<>]*"
)
_SCHEME = re.compile(r"(?i)([a-z][a-z0-9+.\-]*)://")
# ``mailto:x``, ``xmpp:x``, ``javascript:x`` … (a word glued to a colon and more text)
_SCHEME_COLON = re.compile(r"(?i)(?<![a-z0-9+.\-])([a-z][a-z0-9+.\-]*):(?=[^\s:/\[\d])")
_WWW = re.compile(r"(?i)www\.")
# Markdown characters that start links/images/emphasis/code/HTML/entities.
_MD_SPECIAL = str.maketrans(
    {
        "\\": "\\\\",
        "|": "\\|",
        "[": "\\[",
        "]": "\\]",
        "(": "\\(",
        ")": "\\)",
        "*": "\\*",
        "_": "\\_",
        "~": "\\~",
        "#": "\\#",
        "&": "\\&",
        "!": "\\!",
        "`": "ˋ",  # modifier grave: no code spans at all
        "<": "‹",  # no HTML tags, no <autolinks>
        ">": "›",
    }
)


def _defang_url(url: str) -> str:
    # hxxps[:]//example[.]com — readable, never clickable or fetchable.
    m = _SCHEME.search(url)
    if m:
        scheme = re.sub(r"(?i)^http", "hxxp", m.group(1))
        url = f"{url[: m.start()]}{scheme}[:]//{url[m.end() :]}"
    return url.replace(".", "[.]")


def defang(text: str) -> str:
    """Make links in untrusted text inert and readable (no Markdown escaping).

    URL-like tokens get ``hxxp``, ``[:]//`` and ``[.]``; then, unconditionally,
    every remaining ``://`` and ``www.``, every ``@`` (``＠``: no e-mail autolinks)
    and every ``word:`` scheme prefix glued to more text (``mailto:``, ``xmpp:``,
    ``javascript:`` …) is broken up, so no GFM autolink can form anywhere.
    """
    text = _URL.sub(lambda m: _defang_url(m.group(0)), text)
    text = text.replace("://", "[:]//")
    text = _WWW.sub(lambda m: m.group(0)[:3] + "[.]", text)
    text = text.replace("@", "＠")
    return _SCHEME_COLON.sub(r"\1[:]", text)


def escape_cell(value: object, max_chars: int = DEFAULT_CELL_CHARS) -> str:
    """Make untrusted text safe and compact for one Markdown table cell.

    Removes invisible/bidi/control characters and line breaks, defangs URLs,
    e-mail addresses and scheme prefixes (:func:`defang`), neutralises ``|``,
    backticks, link/image brackets, HTML ``<>``, emphasis and entity characters,
    and caps the length (``…``). The result renders as the literal text in any
    CommonMark/GFM renderer.
    """
    text = sanitize_line("" if value is None else str(value))
    if max_chars > 0 and len(text) > max_chars:
        text = text[: max_chars - 1].rstrip() + "…"
    return defang(text).translate(_MD_SPECIAL)


# --------------------------------------------------------------------------- bodies

_MD_IMAGE = re.compile(r"!\[([^\]\n]*)\]\s*(?:\([^)\n]*\)|\[[^\]\n]*\])")
_MD_LINK = re.compile(r"\[([^\]\n]*)\]\(\s*<?([^)\s>]*)>?(?:\s+[\"'(][^)\n]*)?\)")
_MD_REF_DEF = re.compile(r"(?m)^( {0,3})\[([^\]\n]+)\]:")
_HTML_IMG = re.compile(r"(?is)<img\b[^>]*>")
_HTML_ALT = re.compile(r"""(?is)\balt\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")


def _html_img(m: re.Match[str]) -> str:
    alt = _HTML_ALT.search(m.group(0))
    text = next((g for g in alt.groups() if g), "") if alt else ""
    return f"[image: {text.strip()}]" if text.strip() else "[image]"


def defang_body(text: str) -> str:
    """Make an untrusted message body inert as Markdown, keeping it readable.

    For text that is shown as quoted text (paragraphs and line breaks stay):
    images become ``[image: alt]``, inline links ``text (hxxps[:]//…)``, HTML tags
    lose their ``<>`` (``‹img …›``), reference-link definitions are broken up, and
    all URLs, addresses and scheme prefixes are defanged (:func:`defang`). Emphasis,
    lists and code are left alone — they cannot fetch or link anything.
    """
    text = _HTML_IMG.sub(_html_img, text)
    text = _MD_IMAGE.sub(
        lambda m: f"[image: {m.group(1).strip()}]" if m.group(1).strip() else "[image]", text
    )
    text = _MD_LINK.sub(
        lambda m: f"{m.group(1)} ({m.group(2)})" if m.group(2) else m.group(1), text
    )
    text = _MD_REF_DEF.sub(r"\1[\2] :", text)
    text = text.replace("](", "] (")  # whatever link syntax is left over
    text = text.replace("<", "‹").replace(">", "›")
    return defang(text)


def server_link(label: str, url: str) -> str:
    """A real Markdown link for a URL the server generated itself (viewer links)."""
    safe_url = url.replace(" ", "%20").replace(")", "%29").replace("(", "%28")
    return f"[{escape_cell(label, 40)}]({safe_url})"


def markdown_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    """A GFM table. Cells must already be escaped (headers are server text)."""
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(c if c else " " for c in row) + " |")
    return "\n".join(lines)


def fmt_datetime(dt: datetime | None) -> str:
    """Compact local-time rendering (``2026-09-28 09:14``)."""
    if dt is None:
        return "–"
    return dt.astimezone().strftime("%Y-%m-%d %H:%M")


def fmt_size(n: int | None) -> str:
    if n is None:
        return "–"
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def footer(parts: Sequence[str]) -> str:
    """One-line footer (server text; callers escape any untrusted pieces)."""
    return "_" + " · ".join(p for p in parts if p) + "_" if parts else ""
