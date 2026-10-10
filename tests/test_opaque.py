"""Sealed ids and content tokens: nothing readable in URLs, nothing forgeable (review M2, L1)."""

from __future__ import annotations

import json
import os

import pytest

from universal_email_mcp.b64 import b64u, unb64u
from universal_email_mcp.models import MessageRef
from universal_email_mcp.service.opaque import ContentTokens, SealBox, ViewerIds
from universal_email_mcp.store import KeyRing

K1, K2 = b"k" * 32, b"x" * 32
REF = MessageRef("Lawyer mailbox", "INBOX/Mandanten/Müller", 1700000000, 42).encode()


def test_sealbox_roundtrip_binding_and_tampering() -> None:
    box = SealBox([K1])
    tok = box.seal(b"payload", b"user-a")
    assert box.open(tok, b"user-a") == b"payload"
    assert box.seal(b"payload", b"user-a") == tok  # stable links
    assert box.open(tok, b"user-b") is None  # bound to its aad
    assert SealBox([K2]).open(tok, b"user-a") is None
    assert SealBox([K2, K1]).open(tok, b"user-a") == b"payload"  # rotation: old key still opens
    raw = bytearray(unb64u(tok))
    raw[-1] ^= 1
    assert box.open(b64u(bytes(raw)), b"user-a") is None
    for junk in ("", "x", "A" * 10, "!!!", "A" * 5000, "\x00"):
        assert box.open(junk, b"user-a") is None
    with pytest.raises(ValueError):
        SealBox([])


def test_viewer_id_reveals_nothing_and_is_bound_to_the_user() -> None:
    ids = ViewerIds([K1])
    sealed = ids.seal("u_alice", REF)
    assert ids.open("u_alice", sealed) == REF
    assert ids.open("u_bob", sealed) is None
    shown = sealed + unb64u(sealed).decode("latin-1")
    for secret in ("Lawyer", "Mandanten", "INBOX", "1700000000", "m1."):
        assert secret not in shown
    assert all(c.isalnum() or c in "-_" for c in sealed)
    assert len(sealed) <= (len(REF) + 28) * 4 // 3 + 1  # payload plus nonce and tag, base64
    # a plain message id is not a valid viewer id
    assert ids.open("u_alice", REF) is None


def test_content_token_roundtrip_expiry_and_opacity() -> None:
    now = [1000.0]
    t = ContentTokens([K1], ttl=60, clock=lambda: now[0])
    tok = t.issue("u_abc", "m1.xyz", True)
    assert t.verify(tok) == ("u_abc", "m1.xyz", True)
    assert t.verify(t.issue("u_abc", "m1.xyz", False)) == ("u_abc", "m1.xyz", False)
    shown = tok + unb64u(tok).decode("latin-1")
    assert "u_abc" not in shown and "xyz" not in shown  # no user id, no message id
    assert ContentTokens([K2], clock=lambda: now[0]).verify(tok) is None
    assert t.verify(tok[:-2] + "AA") is None
    for junk in ("", ".", "a.b", "\x00", "e30", tok + "x"):
        assert t.verify(junk) is None
    now[0] += 61
    assert t.verify(tok) is None


def test_content_token_expiry_is_capped_on_the_server() -> None:
    """Even a token made with the right key cannot live longer than the TTL."""
    now = [1000.0]
    long_lived = ContentTokens([K1], ttl=3600, clock=lambda: now[0]).issue("u", "m", False)
    strict = ContentTokens([K1], ttl=120, clock=lambda: now[0])
    assert strict.verify(long_lived) is None
    ok = ContentTokens([K1], ttl=120, clock=lambda: now[0]).issue("u", "m", False)
    assert strict.verify(ok) == ("u", "m", False)


def test_pseudonym_key_holder_cannot_forge_content_tokens() -> None:
    """The reviewer's proof (contenttoken.py): the log analyst's PSEUDONYM_KEY is not a
    key of the content origin any more; only the store key ring is."""
    ring = KeyRing({"k1": os.urandom(32)})
    server = ContentTokens(ring.derive("content-origin-v1"))
    pseudonym_key = os.urandom(32)  # what `audit --user` loads
    for forged_with in (
        ContentTokens([pseudonym_key]),
        ContentTokens(KeyRing({"k1": pseudonym_key}).derive("content-origin-v1")),
    ):
        assert server.verify(forged_with.issue("u_victim", REF, True)) is None
    # domain separation: a sealed viewer id is no content token and vice versa
    ids = ViewerIds(ring.derive("viewer-id-v1"))
    assert server.verify(ids.seal("u_victim", REF)) is None
    assert ids.open("u_victim", server.issue("u_victim", REF, True)) is None


def test_old_unsealed_token_shape_is_refused() -> None:
    """The former token was base64(JSON) + '.' + MAC; its shape never verifies."""
    payload = json.dumps(["u", "m", 1, 2**40]).encode()
    old = b64u(payload) + "." + b64u(b"\x00" * 16)
    assert ContentTokens([K1]).verify(old) is None
