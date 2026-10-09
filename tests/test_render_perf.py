"""Untrusted text must never make rendering super-linear: a mail with one 300 000-character
unbroken run reaches ``defang_body`` (message bodies) and ``escape_cell`` (any field) and must
not tie up the server for minutes."""

from __future__ import annotations

import time

import pytest

from universal_email_mcp.server import render

N = 300_000
LIMIT_SECONDS = 1.0

SHAPES = {
    "x": "x",
    "a.": "a.",
    "a.b.": "a.b.",
    "1.": "1.",
    "a@": "a@",
    "a:": "a:",
    "a-": "a-",
    "[": "[",
    "![": "![",
    "[a](": "[a](",
    "](": "](",
    "http://a": "http://a",
    "www.": "www.",
    "a.com": "a.com",
    "a.co/": "a.co/",
    "<img ": "<img ",
    "`": "`",
    "_x.": "_x.",
    "0": "0",
}


@pytest.mark.parametrize("unit", SHAPES.values(), ids=SHAPES.keys())
def test_defang_body_and_escape_cell_are_linear(unit: str):
    text = unit * (N // len(unit))
    for fn in (render.defang_body, lambda t: render.escape_cell(t, len(t) + 1)):
        start = time.perf_counter()
        fn(text)
        assert time.perf_counter() - start < LIMIT_SECONDS, unit


def test_the_defanging_itself_did_not_get_weaker():
    # leading punctuation and glued digits are kept as they were; schemes found from the first letter
    assert render.defang("see 1https://evil.example/x") == "see 1hxxps[:]//evil[.]example/x"
    assert render.defang("..ftp://a.b") == "..ftp[:]//a[.]b"
    assert render.defang("foo.evil.com/path") == "foo[.]evil[.]com/path"
    assert render.defang("visit www.evil.com now") == "visit www[.]evil[.]com now"
    assert render.defang("x evil.com y") == "x evil[.]com y"
    assert render.defang("mailto:a@b.co") == "mailto[:]a＠b[.]co"
    assert "](" not in render.defang_body(
        "[click](https://evil.example/x) and ![i](http://a/b.png)"
    )
