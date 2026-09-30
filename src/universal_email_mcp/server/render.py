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

# URLs with a scheme (https://, ftp://, …), www. hosts, and bare host/path forms
# that some renderers autolink.
_URL = re.compile(
    r"(?i)\b(?:[a-z][a-z0-9+.\-]{1,15}://[^\s|]*|www\.[^\s|]+|"
    r"(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?/[^\s|]*)"
)
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
    m = re.match(r"(?i)([a-z][a-z0-9+.\-]*)://", url)
    if m:
        scheme = re.sub(r"(?i)^http", "hxxp", m.group(1))
        url = f"{scheme}[:]//{url[m.end() :]}"
    return url.replace(".", "[.]")


def escape_cell(value: object, max_chars: int = DEFAULT_CELL_CHARS) -> str:
    """Make untrusted text safe and compact for one Markdown table cell.

    Removes invisible/bidi/control characters and line breaks, defangs URLs,
    neutralises ``|``, backticks, link/image brackets, HTML ``<>``, emphasis and
    entity characters, and caps the length (``…``). The result renders as the
    literal text in any CommonMark/GFM renderer.
    """
    text = sanitize_line("" if value is None else str(value))
    if max_chars > 0 and len(text) > max_chars:
        text = text[: max_chars - 1].rstrip() + "…"
    text = _URL.sub(lambda m: _defang_url(m.group(0)), text)
    return text.translate(_MD_SPECIAL)


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
