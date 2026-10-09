"""Key ring, sealed blobs and token hashing."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from universal_email_mcp.errors import ConfigError
from universal_email_mcp.store import Aad, CryptoError, KeyRing, hash_token, new_token, tokens_equal

AAD = Aad("u_1", "accounts", "acc1", "sealed")


def key() -> bytes:
    return bytes(range(32))


def ring(**kw: bytes) -> KeyRing:
    return KeyRing(kw or {"k1": key()})


def swap(blob: str, index: int, value: str) -> str:
    parts = blob.split(".")
    parts[index] = value
    return ".".join(parts)


def test_roundtrip_and_format() -> None:
    r = ring()
    blob = r.seal(b"s3cret", AAD)
    assert blob.startswith("e1.k1.")
    assert b"s3cret" not in blob.encode()
    assert r.open(blob, AAD) == b"s3cret"
    assert r.seal(b"s3cret", AAD) != blob  # fresh nonce
    assert r.open_json(r.seal_json({"a": [1, "ü"]}, AAD), AAD) == {"a": [1, "ü"]}


def test_tamper_ciphertext_and_nonce() -> None:
    r = ring()
    blob = r.seal(b"s3cret", AAD)
    raw = bytearray(base64.urlsafe_b64decode(blob.split(".")[2] + "=="))
    for pos in (0, 5, len(raw) - 1):  # nonce, ciphertext, tag
        bad = bytearray(raw)
        bad[pos] ^= 1
        text = base64.urlsafe_b64encode(bytes(bad)).decode().rstrip("=")
        with pytest.raises(CryptoError):
            r.open(swap(blob, 2, text), AAD)


@pytest.mark.parametrize(
    "other",
    [
        Aad("u_2", "accounts", "acc1", "sealed"),
        Aad("u_1", "identities", "acc1", "sealed"),
        Aad("u_1", "accounts", "acc2", "sealed"),
        Aad("u_1", "accounts", "acc1", "other"),
    ],
)
def test_blob_bound_to_its_place(other: Aad) -> None:
    r = ring()
    with pytest.raises(CryptoError):
        r.open(r.seal(b"x", AAD), other)


def test_key_id_and_format_are_authenticated() -> None:
    r = ring(k1=key(), k2=bytes(reversed(range(32))))
    blob = KeyRing({"k1": key()}).seal(b"x", AAD)
    with pytest.raises(CryptoError):
        r.open(swap(blob, 1, "k2"), AAD)  # other key
    with pytest.raises(CryptoError):
        r.open(swap(blob, 1, "k9"), AAD)  # unknown key
    with pytest.raises(CryptoError):
        r.open(swap(blob, 0, "e2"), AAD)  # unknown format
    for junk in ("", "e1.k1", "e1.k1.!!!", "e1.k1.AAAA"):
        with pytest.raises(CryptoError):
            r.open(junk, AAD)


def test_rotation_old_blobs_open_new_seal_uses_active() -> None:
    old = KeyRing({"k1": key()}).seal(b"x", AAD)
    r = KeyRing({"k1": key(), "k2": bytes(range(1, 33))})
    assert r.active == "k2"
    assert r.open(old, AAD) == b"x"
    assert r.needs_rotation(old)
    assert not r.needs_rotation(r.seal(b"x", AAD))
    pinned = KeyRing({"k1": key(), "k2": bytes(range(1, 33))}, active="k1")
    assert pinned.seal(b"x", AAD).startswith("e1.k1.")


def test_no_key_material_in_repr_or_errors() -> None:
    r = ring()
    b64 = base64.b64encode(key()).decode()
    assert b64 not in repr(r)
    assert str(key()) not in repr(r)
    with pytest.raises(CryptoError) as e:
        r.open(KeyRing({"k7": bytes(32)}).seal(b"x", AAD), AAD)
    assert b64 not in str(e.value)


def test_parse_and_env(tmp_path: Path) -> None:
    k1, k2 = KeyRing.generate_key(), KeyRing.generate_key()
    r = KeyRing.parse(f"k1={k1}, k2={k2}\n# old\n")
    assert r.key_ids == ("k1", "k2") and r.active == "k2"
    assert (
        KeyRing.from_env({"STORE_KEYS": f"k1={k1},k2={k2}", "STORE_ACTIVE_KEY": "k1"}).active
        == "k1"
    )
    f = tmp_path / "keys"
    f.write_text(f"k1={k1}\n")
    assert KeyRing.from_env({"STORE_KEYS_FILE": str(f)}).key_ids == ("k1",)


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"STORE_KEYS": "k1=abc", "STORE_KEYS_FILE": "/x"},
        {"STORE_KEYS": "k1=%%%"},
        {"STORE_KEYS": "k1=" + base64.b64encode(b"short").decode()},
        {"STORE_KEYS": "key=" + base64.b64encode(bytes(32)).decode()},
        {"STORE_KEYS": "nonsense"},
        {"STORE_KEYS": "k01=" + base64.b64encode(bytes(32)).decode()},
        {"STORE_KEYS": "k0=" + base64.b64encode(bytes(32)).decode()},
        {"STORE_KEYS": "K1=" + base64.b64encode(bytes(32)).decode()},
        {"STORE_KEYS_FILE": "/nonexistent/keys"},
        {"STORE_KEYS": "k1=" + base64.b64encode(bytes(32)).decode(), "STORE_ACTIVE_KEY": "k2"},
    ],
)
def test_bad_key_config(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        KeyRing.from_env(env)


def test_duplicate_key_id() -> None:
    k = KeyRing.generate_key()
    with pytest.raises(ConfigError):
        KeyRing.parse(f"k1={k},k1={k}")


def test_tokens() -> None:
    t = new_token("uem_at")
    assert t.startswith("uem_at_") and len(t) > 40 and t != new_token("uem_at")
    h = hash_token(t)
    assert len(h) == 64 and t not in h and h == hash_token(t)
    assert tokens_equal(t, t) and not tokens_equal(t, t + "x")
