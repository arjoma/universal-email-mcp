"""PKCE, redirect URI rules, rate limiter, addresses and pseudonyms."""

from __future__ import annotations

import pytest

from universal_email_mcp.errors import ConfigError
from universal_email_mcp.oauth import pkce
from universal_email_mcp.oauth.identity import AddressError, Pseudonyms, parse_address, short_id
from universal_email_mcp.oauth.ratelimit import RateLimiter
from universal_email_mcp.oauth.redirects import (
    RedirectError,
    display_host,
    host_allowed,
    redirect_matches,
    validate_redirect_uri,
)

# ---------------------------------------------------------------- PKCE


def test_pkce_rfc7636_example():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert pkce.s256(verifier) == challenge
    assert pkce.verify(verifier, challenge)
    assert not pkce.verify(verifier + "x", challenge)
    assert not pkce.verify("short", challenge)
    assert not pkce.verify("", challenge)


def test_pkce_shapes():
    assert pkce.valid_challenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    assert not pkce.valid_challenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=")
    assert not pkce.valid_challenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\n")
    assert not pkce.valid_challenge("a" * 42) and not pkce.valid_challenge("")
    assert not pkce.valid_verifier("a" * 129) and not pkce.valid_verifier("a" * 42)
    assert not pkce.valid_verifier("a" * 43 + "!")
    assert not pkce.verify("é" * 43, "a" * 43)  # non-ASCII must not raise


# ---------------------------------------------------------------- redirect URIs


@pytest.mark.parametrize(
    "uri",
    [
        "https://app.example.com/cb",
        "https://app.example.com:8443/cb?x=1",
        "http://127.0.0.1:8080/cb",
        "http://localhost/cb",
        "http://[::1]:9/cb",
        "com.example.app:/oauth2redirect",
        "cursor.mcp-client://callback",
    ],
)
def test_acceptable_redirects(uri):
    assert validate_redirect_uri(uri) == uri


@pytest.mark.parametrize(
    "uri",
    [
        "",
        "http://app.example.com/cb",
        "http://127.0.0.1.evil.com/cb",
        "http://localhost.evil.com/cb",
        "javascript:alert(1)",
        "data:text/html,x",
        "file:///etc/passwd",
        "app:/cb",  # no dot in the scheme
        "https://app.example.com/cb#frag",
        "https://user:pw@app.example.com/cb",
        "https://app.example.com/cb\r\nX: y",
        "https://app.example.com/cb d",
        "https://*/cb",
        "https://a.example,x/cb",
        "http://evil.com\\@127.0.0.1/cb",
        "https://app.example.com/é",
        "/relative",
        "https://",
        "https://app.example.com:99999/cb",
        "https://app.example.com/" + "a" * 2100,
    ],
)
def test_refused_redirects(uri):
    with pytest.raises(RedirectError):
        validate_redirect_uri(uri)


def test_redirect_matching():
    reg = ["https://app.example.com/cb", "http://127.0.0.1/cb", "com.example.app:/cb"]
    assert redirect_matches(reg, "https://app.example.com/cb")
    assert not redirect_matches(reg, "https://app.example.com/cb/")
    assert not redirect_matches(reg, "https://app.example.com:444/cb")
    assert not redirect_matches(reg, "https://APP.example.com/cb")
    assert redirect_matches(reg, "http://127.0.0.1:55555/cb")  # loopback port is free
    assert not redirect_matches(reg, "http://127.0.0.1:55555/other")
    assert not redirect_matches(reg, "http://localhost:55555/cb")  # different host spelling
    assert not redirect_matches(reg, "https://127.0.0.1:55555/cb")
    assert not redirect_matches(["https://app.example.com/cb"], "http://127.0.0.1:1/cb")


def test_display_and_host_helpers():
    assert display_host("https://user@app.example.com:8443/cb") == "app.example.com:8443"
    assert display_host("com.example.app:/cb") == "com.example.app:"
    assert host_allowed("https://a.example/cb", ())
    assert host_allowed("https://A.example/cb", ("a.example",))
    assert not host_allowed("https://b.example/cb", ("a.example",))
    assert host_allowed("http://127.0.0.1:1/cb", ("a.example",))
    assert not host_allowed("com.example.app:/cb", ("a.example",))


# ---------------------------------------------------------------- rate limiter


def test_rate_limiter_window_and_memory_bound():
    now = [0.0]
    rl = RateLimiter(2, 10, clock=lambda: now[0], max_keys=10)
    assert rl.allow("a") and rl.allow("a") and not rl.allow("a")
    assert rl.blocked("a") and rl.retry_after("a") == 11 - 0
    assert rl.allow("b")
    now[0] = 10.5
    assert not rl.blocked("a") and rl.allow("a")
    rl.reset("a")
    assert rl.allow("a") and rl.allow("a") and not rl.allow("a")
    for i in range(100):
        rl.add(f"k{i}")
    assert len(rl._events) <= 10  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------- addresses


def test_address_normalisation():
    a = parse_address("  Alice.Smith@Example.ORG ")
    assert a.login == "Alice.Smith@Example.ORG" and a.normal == "alice.smith@example.org"
    assert a.domain == "example.org"
    assert parse_address("x@bücher.example").domain == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "text",
    ["", "alice", "@example.org", "alice@", "a@b@example.org", "alice@localhost", "a b@example.org",
     "<a@example.org>", 'a"b@example.org', "a@" + "x" * 300 + ".org", "a\x00@example.org",
     "a" * 65 + "@example.org"],
)  # fmt: skip
def test_bad_addresses(text):
    with pytest.raises(AddressError):
        parse_address(text)


def test_pseudonyms_are_stable_keyed_and_short():
    p = Pseudonyms(b"a" * 32)
    uid = p.user_id("alice@example.org")
    assert uid == p.user_id("alice@example.org") and uid.startswith("u_") and len(uid) == 34
    assert uid != p.user_id("bob@example.org")
    assert uid != Pseudonyms(b"b" * 32).user_id("alice@example.org")
    assert "alice" not in uid and "alice" not in repr(p) and len(short_id(uid)) == 14
    with pytest.raises(ConfigError):
        Pseudonyms(b"short")


# ---------------------------------------------------------------- client names (review W4)


def test_clean_text_drops_every_format_character_and_the_fillers():
    import sys
    import unicodedata

    from universal_email_mcp.oauth.clients import clean_text

    # every Cf character of the Unicode version in use, one by one
    cf = [chr(c) for c in range(sys.maxunicode + 1) if unicodedata.category(chr(c)) == "Cf"]
    assert len(cf) > 100 and "؜" in cf and "­" in cf and "\U000e0041" in cf
    for ch in cf:
        assert clean_text(f"Bank{ch}ing") == "Banking", hex(ord(ch))
    for ch in ("ㅤ", "ᅟ", "ᅠ", "ﾠ", "⠀"):  # blank-looking fillers
        assert clean_text(f"A{ch}{ch}B") == "AB", hex(ord(ch))
    # the cases the review named
    assert clean_text("Claude᠎⁦evil⁩ \U000e0067\U000e007f Desktop") == "Claudeevil Desktop"
    assert clean_text("a‍b") == "ab"  # ZWJ goes too (emoji sequences fall apart)
    # ordinary text, other scripts, emoji and spacing survive
    assert (
        clean_text("  Müller \t& Söhne – 日本語 العربية 🙂\n")
        == "Müller & Söhne – 日本語 العربية 🙂"
    )
    assert clean_text(5) == "" and clean_text("x" * 500, 10) == "x" * 10


def test_clean_text_drops_selectors_private_use_and_unassigned():
    from universal_email_mcp.oauth.clients import clean_text

    for ch in (
        "\u034f",
        "\ufe0f",
        "\ufe00",
        "\U000e0100",
        "\U000e01ef",
        "\ue000",
        "\U000f0000",
        "\u0378",
        "\ud800",
    ):
        assert clean_text(f"A{ch}B") == "AB", hex(ord(ch))
    assert clean_text("\u034f\ufe0f\ue000\u0378") == ""


def test_client_document_name_of_invisible_characters_falls_back_to_host():
    import json

    from universal_email_mcp.oauth.clients import parse_client_document

    cid = "https://app.example.org/client.json"
    doc = {
        "client_id": cid,
        "client_name": "\u034f\ufe0f\ue000",
        "redirect_uris": ["https://app.example.org/cb"],
    }
    name, _ = parse_client_document(cid, json.dumps(doc).encode())
    assert name == "app.example.org"
    doc["client_name"] = "Real"
    assert parse_client_document(cid, json.dumps(doc).encode())[0] == "Real"
