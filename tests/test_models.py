import base64
import json

import pytest

from universal_email_mcp.errors import InvalidRef
from universal_email_mcp.models import Address, MessageRef, TextSlice

WEIRD_FOLDERS = [
    "INBOX",
    "INBOX/Unterordner",
    "&AMQ-rger",  # modified UTF-7 wire name
    'Quote "and" back\\slash',
    "Emoji 📬 & Ümläut",
    "a" * 1000,
    "=/+?#%",
]


@pytest.mark.parametrize("folder", WEIRD_FOLDERS)
def test_ref_roundtrip(folder: str):
    ref = MessageRef("Work account", folder, 1234567890, 4294967295)
    encoded = ref.encode()
    assert encoded.startswith("m2.")
    assert all(c.isalnum() or c in "-_." for c in encoded)  # URL-safe, no padding
    assert MessageRef.decode(encoded) == ref
    assert ref.id == encoded


def _raw(payload: object) -> str:
    return "m1." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "m2.abc",
        "m1.",
        "m1.***",
        "m1.a",  # corrupted base64
        "m1." + "A" * 5000,
        _raw({"a": 1}),
        _raw(["acc", "INBOX", 1]),
        _raw(["acc", "INBOX", "1", 2]),
        _raw(["acc", "INBOX", True, 2]),
        _raw(["acc", "INBOX", 1, 0]),
        _raw(["acc", "INBOX", 1, 2**32]),
        _raw(["acc", "INBOX", 1.0, 2]),
        _raw(["", "INBOX", 1, 2]),
        _raw(["acc", "", 1, 2]),
        _raw(["acc", "IN\r\nBOX", 1, 2]),
        _raw(["acc\x00", "INBOX", 1, 2]),
        "m1." + base64.urlsafe_b64encode(b"\xff\xfe").decode().rstrip("="),
    ],
)
def test_ref_decode_rejects_malformed(bad: str):
    with pytest.raises(InvalidRef) as exc:
        MessageRef.decode(bad)
    assert exc.value.code == "INVALID_REF"
    assert exc.value.hint


def test_ref_decode_rejects_non_canonical():
    ref = MessageRef("a", "INBOX", 1, 2).encode()
    padded = ref + "=" * (-len(ref[3:]) % 4 or 4)
    with pytest.raises(InvalidRef):
        MessageRef.decode(padded)
    spaced = "m1." + base64.urlsafe_b64encode(b'["a", "INBOX", 1, 2]').decode().rstrip("=")
    with pytest.raises(InvalidRef):
        MessageRef.decode(spaced)


def test_ref_decode_non_string():
    with pytest.raises(InvalidRef):
        MessageRef.decode(123)  # pyright: ignore[reportArgumentType]


def test_ref_constructor_validates():
    with pytest.raises(InvalidRef):
        MessageRef("a", "INBOX", 0, 1)


def test_address_str_and_text_slice():
    assert str(Address("A B", "a@example.com")) == "A B <a@example.com>"
    assert str(Address("", "a@example.com")) == "a@example.com"
    assert not TextSlice("x", 0, 1, None).truncated
