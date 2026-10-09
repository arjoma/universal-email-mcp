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
#
# Performance: untrusted text can be hundreds of thousands of characters of one unbroken run,
# so every pattern may start only at the *beginning* of a run of the characters it consumes
# (look-behinds below); a failed attempt then costs O(run), never O(run^2). A scheme that is
# glued to digits (``1https://``) still matches: it starts at the run's beginning.
_URL = re.compile(
    r"(?i)(?<![a-z0-9+.\-])[0-9+.\-]*[a-z][a-z0-9+.\-]*://[^\s|<>]*"
    r"|www\.[^\s|<>]*"
    r"|(?<![a-z0-9-])(?<![a-z0-9-]\.)(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?/[^\s|<>]*"
)
# ``mailto:x``, ``xmpp:x``, ``javascript:x`` … (a word glued to a colon and more text)
_WWW = re.compile(r"(?i)www\.")
# Bare domains (``evil.com``, no scheme/``www.``/path): GFM leaves them alone, but
# renderers with fuzzy linkify (markdown-it) link them. Only well-known TLDs, so file
# names (``report.pdf``, ``main.py``, ``notes.md``) stay readable.
_TLDS = (
    "com|org|net|edu|gov|int|info|biz|io|co|me|ly|app|dev|xyz|top|online|site|shop|store|tech|"
    "cloud|club|live|link|click|work|support|email|eu|de|at|ch|li|uk|fr|it|es|nl|be|lu|dk|se|no|"
    "fi|pl|cz|sk|hu|ro|bg|gr|pt|ie|ru|ua|tr|us|ca|au|nz|cn|jp|kr|in|br|mx|ar|za|ng|ke|ir|il|"
    "tk|ml|ga|cf|gq|ws|su|cc|tv|sh|to|ai|pw|vip|icu|buzz|rest|cyou|zip|mov|tel|asia|pro|name|win|bid"
)
_BARE_DOMAIN = re.compile(
    rf"(?i)(?<![a-z0-9\-])(?<![a-z0-9\-]\.)(?:[a-z0-9-]+\.)+(?:{_TLDS})(?![a-z0-9_\-])"
)
# ``word:host.tld`` after the scheme prefix was broken up: the host's dots too.
_SCHEME_REST = re.compile(r"(?i)(?<![a-z0-9+.\-])([a-z][a-z0-9+.\-]*):(?=[^\s:/\[\d])([^\s|<>]*)")
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


_SCHEME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")


def _defang_url(url: str) -> str:
    # hxxps[:]//example[.]com - readable, never clickable or fetchable. The scheme is the
    # run of scheme characters before ``://`` from its first letter on (found by walking
    # back, not by a pattern: ``([a-z][a-z0-9+.-]*)://`` is quadratic on long runs).
    pos = url.find("://")
    while pos >= 0:
        start = pos
        while start > 0 and url[start - 1] in _SCHEME_CHARS:
            start -= 1
        while start < pos and not (url[start].isascii() and url[start].isalpha()):
            start += 1
        if start < pos:
            scheme = re.sub(r"(?i)^http", "hxxp", url[start:pos])
            url = f"{url[:start]}{scheme}[:]//{url[pos + 3 :]}"
            break
        pos = url.find("://", pos + 3)
    return url.replace(".", "[.]")


def _defang_match(m: re.Match[str]) -> str:
    # The pattern starts at the beginning of a run of scheme characters; what precedes the
    # first letter (``..``, ``1``) is not part of the URL and stays as it is.
    url = m.group(0)
    lead = len(url) - len(url.lstrip("0123456789+.-")) if url[:1] in "0123456789+.-" else 0
    if lead and "://" not in url[:lead] and url[lead : lead + 4].lower() != "www.":
        return url[:lead] + _defang_url(url[lead:])
    return _defang_url(url)


def defang(text: str, *, keep_address_domains: bool = False) -> str:
    """Make links in untrusted text inert and readable (no Markdown escaping).

    URL-like tokens get ``hxxp``, ``[:]//`` and ``[.]``; then, unconditionally,
    every remaining ``://`` and ``www.``, bare domains with a well-known top-level
    domain (``evil.com``: fuzzy-linkifying renderers link them), every ``@``
    (``＠``: no e-mail autolinks) and every ``word:`` scheme prefix glued to more
    text (``mailto:``, ``xmpp:``, ``javascript:`` …, with the dots of the host that
    follows) is broken up, so no autolink can form anywhere.

    ``keep_address_domains``: the domain right after an ``@`` keeps its dots (the
    ``＠`` already blocks the e-mail autolink) so addresses stay copyable.
    """
    text = _URL.sub(_defang_match, text)
    text = text.replace("://", "[:]//")
    text = _WWW.sub(lambda m: m.group(0)[:3] + "[.]", text)
    text = _BARE_DOMAIN.sub(
        lambda m: (
            m.group(0)
            if keep_address_domains and m.start() > 0 and text[m.start() - 1] == "@"
            else m.group(0).replace(".", "[.]")
        ),
        text,
    )
    text = text.replace("@", "＠")
    return _SCHEME_REST.sub(lambda m: f"{m.group(1)}[:]{_dots(m.group(2))}", text)


def _dots(rest: str) -> str:
    """Dots between letters/digits become ``[.]`` (``attacker.test``, not ``1.5``)."""
    return re.sub(r"(?<=[A-Za-z])\.(?=[A-Za-z0-9])", "[.]", rest)


def escape_cell(
    value: object, max_chars: int = DEFAULT_CELL_CHARS, *, address: bool = False
) -> str:
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
    return defang(text, keep_address_domains=address).translate(_MD_SPECIAL)


# --------------------------------------------------------------------------- bodies

# Bounded repeats (long link text or targets stay unconverted, but their ``](`` is broken up
# by the caller, so nothing can link): an unbounded ``[^\]\n]*`` is quadratic on ``[[[[...``.
_MD_IMAGE = re.compile(
    r"!\[([^\[\]\n]{0,500})\]\s{0,20}(?:\([^)\[\n]{0,2000}\)|\[[^\[\]\n]{0,500}\])"
)
_MD_LINK = re.compile(
    r"\[([^\[\]\n]{0,500})\]\(\s{0,20}<?([^)\s>\[]{0,2000})>?(?:\s{1,20}[\"'(][^)\n]{0,500})?\)"
)
_MD_REF_DEF = re.compile(r"(?m)^( {0,3})\[([^\[\]\n]{1,500})\]:")
_FENCE_RUN = re.compile(r"`{3,}|~{3,}")
_HTML_IMG = re.compile(r"(?is)<img\b[^>]{0,2000}>")
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
    text = _FENCE_RUN.sub(lambda m: "ˋ" * len(m.group(0)), text)  # no fake code fences
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
