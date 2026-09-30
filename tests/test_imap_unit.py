"""Unit tests for pure helpers of the IMAP backend (protocol behaviour is covered by
the container-based integration tests)."""

from datetime import date

import pytest

from universal_email_mcp.errors import FolderNotFound
from universal_email_mcp.mail.imap import (
    SearchCriteria,
    ServerFeatures,
    _astring,  # pyright: ignore[reportPrivateUsage]
    _imap_date,  # pyright: ignore[reportPrivateUsage]
    _wire_name,  # pyright: ignore[reportPrivateUsage]
    bodystructure_has_attachments,
)

TEXT_PLAIN = (b"text", b"plain", (b"charset", b"utf-8"), None, None, b"7bit", 10, 1)
HTML = (b"text", b"html", (b"charset", b"utf-8"), None, None, b"7bit", 20, 1)
PDF_ATTACHMENT = (
    b"application",
    b"pdf",
    (b"name", b"x.pdf"),
    None,
    None,
    b"base64",
    100,
    None,
    (b"attachment", (b"filename", b"x.pdf")),
    None,
    None,
)
INLINE_IMAGE = (b"image", b"png", None, b"<logo@x>", None, b"base64", 50, None, (b"inline", None))
TEXT_ATTACHMENT = (
    b"text",
    b"plain",
    (b"charset", b"utf-8", b"name", b"notes.txt"),
    None,
    None,
    b"7bit",
    10,
    1,
    None,
    (b"attachment", (b"filename", b"notes.txt")),
)


def multipart(*parts: object, subtype: bytes = b"mixed") -> tuple[object, ...]:
    return ([*parts], subtype, (b"boundary", b"x"), None, None)


@pytest.mark.parametrize(
    ("bs", "expected"),
    [
        (TEXT_PLAIN, False),
        (multipart(TEXT_PLAIN, HTML, subtype=b"alternative"), False),
        (multipart(TEXT_PLAIN, PDF_ATTACHMENT), True),
        (multipart(multipart(HTML, INLINE_IMAGE, subtype=b"related"), TEXT_PLAIN), False),
        (multipart(TEXT_PLAIN, TEXT_ATTACHMENT), True),
        ((b"application", b"pdf", None, None, None, b"base64", 100), True),
        ((b"image", b"jpeg", None, None, None, b"base64", 100), True),
        (None, False),
        ((), False),
    ],
)
def test_bodystructure_has_attachments(bs: object, expected: bool):
    assert bodystructure_has_attachments(bs) is expected


def test_astring_quotes_and_literals():
    assert _astring("hello world") == b'"hello world"'
    assert _astring('a"b\\c') == b'"a\\"b\\\\c"'
    assert _astring("Müller") == "Müller".encode()  # sent as literal by imapclient
    assert _astring("x)") == b'"x)"'  # never a bare atom


def test_search_value_cleaning():
    c = SearchCriteria(from_="  a\r\nA001 LOGOUT ", subject="", body="x\x00y")
    assert c.text_items() == [("FROM", "a A001 LOGOUT"), ("BODY", "x y")]


def test_imap_date():
    assert _imap_date(date(2026, 3, 5)) == b"05-Mar-2026"


def test_wire_name():
    assert _wire_name("INBOX.Sent") == "INBOX.Sent"
    assert _wire_name("Entwürfe") == "Entw&APw-rfe"
    for bad in ("", "a\r\nb", "x" * 1001):
        with pytest.raises(FolderNotFound):
            _wire_name(bad)


def test_server_features():
    f = ServerFeatures.from_capabilities(
        ["IMAP4REV1", "SORT", "THREAD=REFERENCES", "THREAD=ORDEREDSUBJECT", "QUOTA=RES-STORAGE"]
    )
    assert f.sort and f.quota and not f.move
    assert f.threads == ("ORDEREDSUBJECT", "REFERENCES")
