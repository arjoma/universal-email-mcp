"""The shared ``query`` parameter: wildcard patterns (case, umlauts, levels, ``?``,
literal metacharacters, hostile patterns in linear time) and the fuzzy fallback."""

from __future__ import annotations

import time

import pytest

from universal_email_mcp.errors import InvalidArgument
from universal_email_mcp.service.query import (
    MAX_QUERY_CHARS,
    WildcardPattern,
    is_wildcard,
    parse,
    similar,
)


def m(pattern: str, text: str) -> bool:
    return WildcardPattern.compile(pattern).match(text)


@pytest.mark.parametrize(
    ("pattern", "text"),
    [
        ("hub*", "Anna Huber"),  # any word may start the match
        ("HUB*", "anna huber"),  # case-insensitive
        ("*bau*", "anna.huber@huber-bau.example"),
        ("mü*", "Müller"),
        ("mü*", "Mueller"),  # umlaut-folded both ways
        ("mü*", "Muller"),
        ("mue*", "Müller"),
        ("m?ller", "Müller"),
        ("wei?", "Weiß"),  # ß stays one character
        ("weiss*", "Weiß"),
        ("strau*", "Strauß"),
        ("clients/*", "Clients/Müller KG/2025"),  # * crosses levels
        ("*/2025", "Clients/Aigner/2025"),
        ("clients/*/2026", "Clients/Aigner/2026"),
        ("*", "anything"),
        ("ann?", "Anna Huber"),  # a single word
        ("*gmbh", "Maier GmbH"),
        ("dvo*", "Dvořák"),  # accents
        ("öz*", "Öztürk"),
        ("a*b*c", "a xx b yy c"),
        ("re: *", "Re: Angebot"),
    ],
)
def test_matches(pattern: str, text: str):
    assert m(pattern, text), (pattern, text)


@pytest.mark.parametrize(
    ("pattern", "text"),
    [
        ("ub*", "Anna Huber"),  # not at a word start
        ("hub?", "Huber"),  # ? is exactly one character, and the match ends at a word end
        ("hub", "Anna Huber"),  # (only used as a pattern here: no wildcard → whole words)
        ("*/2025", "Clients/Aigner/20250"),
        ("clients/?", "Clients/Huber"),
        ("x*", ""),
        ("a*b*c", "a c b"),  # order matters
    ],
)
def test_no_match(pattern: str, text: str):
    assert not m(pattern, text), (pattern, text)


@pytest.mark.parametrize("meta", [".", "(", ")", "[", "]", "+", "^", "$", "|", "\\", "{2}"])
def test_regex_metacharacters_are_literal(meta: str):
    pattern = f"a{meta}b*"
    assert m(pattern, f"a{meta}bc")
    assert not m(pattern, "axbc")
    assert not m(pattern, "aab")  # e.g. "." is literal: "a.b*" does not match "aab"


def test_is_wildcard_and_parse():
    assert is_wildcard("hub*") and is_wildcard("m?ller") and not is_wildcard("huber")
    assert parse(None) is None and parse("   ") is None
    q = parse("  huber  ")
    assert q is not None and q.mode == "fuzzy" and q.text == "huber"
    q = parse("hub*")
    assert q is not None and q.mode == "wildcard" and q.literal == "hub"
    with pytest.raises(InvalidArgument):
        parse("a" * (MAX_QUERY_CHARS + 1))
    assert parse("＊huber") is not None and not is_wildcard("＊huber")  # fullwidth: fuzzy


def test_fuzzy_and_wildcard_scores():
    fz = parse("Hubr")
    assert fz is not None and fz.score(["Anna Huber"]) >= 75
    wc = parse("hub*")
    assert wc is not None and wc.score(["Anna Huber"]) == 100 and wc.score(["Maier"]) == 0


def test_similar_names():
    q = parse("Mülller*")
    assert q is not None
    names = ["Müller KG", "Mueller Consulting", "Huber Bau", "Maier GmbH"]
    out = similar(q, names)
    assert set(out[:2]) == {"Müller KG", "Mueller Consulting"} and "Huber Bau" not in out


def _timed(pattern: str, text: str) -> float:
    p = WildcardPattern.compile(pattern)
    t = time.perf_counter()
    p.match(text)
    return time.perf_counter() - t


@pytest.mark.parametrize(
    ("pattern", "text"),
    [
        ("*a" * 99 + "*b", "a" * 5000),  # classic catastrophic backtracking for regex globs
        ("a*" * 99 + "b", "a " * 2500),  # many word starts
        ("?" * 199 + "x", "a" * 5000),
        ("*" + "a" * 150 + "b*", ("a" * 149 + " ") * 30),  # near misses everywhere
        ("*" + "?a" * 99 + "*", "ba" * 2500),
    ],
)
def test_hostile_patterns_are_fast(pattern: str, text: str):
    pattern = pattern[:MAX_QUERY_CHARS]
    assert _timed(pattern, text) < 0.25


def test_huge_candidate_text_is_capped():
    # The text beyond the cap is not looked at (bounded work per candidate).
    text = "x " * 2000 + "needle"
    assert not m("needle*", text)
    assert m("needle*", "x " * 10 + "needle")


def test_hostile_pattern_text_is_not_interpreted():
    # A pattern built from mail-like text: regex syntax and Markdown stay literal.
    pattern = "*](https://evil.example)*"
    assert m(pattern, "Click [here](https://evil.example) now")
    assert not m(pattern, "Click here now")


def test_nfkd_expansion_is_bounded():
    # U+FDFA decomposes into 18 characters: 1000 of them must not mean 18 000
    # characters compared per spelling, nor a slow fuzzy score.
    from universal_email_mcp.service import fuzzy

    text = "\ufdfa" * 1000
    assert all(len(v) <= fuzzy.MAX_TEXT_CHARS for v in fuzzy.fold_variants(text))
    t = time.perf_counter()
    for pattern in ("?" * 200, "a?" * 100, "x*" + "?" * 150):
        WildcardPattern.compile(pattern).match(text)
    q = parse("huber gmbh")
    assert q is not None
    q.score([text] * 50)
    assert time.perf_counter() - t < 0.5
