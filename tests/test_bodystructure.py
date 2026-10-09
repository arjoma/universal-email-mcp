"""Pure helpers for the server's view of a message structure and attachment names."""

import pytest

from universal_email_mcp.mail.bodystructure import (
    SECTION_RE,
    attachments_for,
    decoded_size,
    find,
    is_text_like,
    leaves,
)
from universal_email_mcp.mail.mime import (
    decode_transfer,
    display_filename,
    parse_message,
)

TEXT = (b"text", b"plain", (b"charset", b"utf-8"), None, None, b"7bit", 10, 1)
PDF = (
    b"application",
    b"pdf",
    (b"name", b"x.pdf"),
    None,
    None,
    b"base64",
    7800,
    None,
    (b"attachment", (b"filename", b"x.pdf")),
)
RFC822 = (b"message", b"rfc822", None, None, None, b"7bit", 300, None, None, 5, None, None)


def mp(*parts: object, sub: bytes = b"mixed") -> tuple[object, ...]:
    return ([*parts], sub, (b"boundary", b"x"), None, None)


def test_leaves_numbering_like_rfc3501():
    bs = mp(mp(TEXT, TEXT, sub=b"alternative"), PDF, RFC822)
    got = leaves(bs)
    assert got is not None
    assert [p.section for p in got] == ["1.1", "1.2", "2", "3"]
    assert got[0].in_alternative and not got[2].in_alternative
    assert got[2].filename == "x.pdf" and got[2].disposition == "attachment"
    assert got[3].content_type == "message/rfc822"


def test_single_part_is_section_1():
    got = leaves(TEXT)
    assert got is not None and got[0].section == "1" and got[0].is_body_text


def test_unusable_structures():
    assert leaves(None) is None
    assert leaves(b"nonsense") is None
    deep: object = TEXT
    for _ in range(60):
        deep = mp(deep)
    assert leaves(deep) is None
    assert leaves(mp(*[TEXT] * 2500)) is None


def test_rfc2231_filename_and_hostile_name():
    part = (
        b"application",
        b"octet-stream",
        None,
        None,
        None,
        b"base64",
        10,
        None,
        (b"attachment", (b"filename*", b"utf-8''%E2%80%AEfdp.exe%0D%0A..%2F..%2Fx.txt")),
    )
    got = leaves(part)
    assert got is not None and got[0].filename == "x.txt"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../.ssh/authorized_keys", "authorized_keys"),
        ("C:\\Windows\\evil.exe", "evil.exe"),
        ("a\u202eb\r\nc.txt", "ab c.txt"),
        ("invoice.pdf.exe", "invoice.pdf.exe"),
        ("   ", None),
        ("../", None),
    ],
)
def test_display_filename(raw: str, expected: str | None):
    assert display_filename(raw) == expected


def test_display_filename_long_keeps_extension():
    n = display_filename("a" * 500 + ".pdf")
    assert n is not None and len(n) <= 120 and n.endswith(".pdf")


def test_decode_transfer():
    assert decode_transfer(b"SGVs bG8h!!!\r\nIFdv\r\ncmxk", "base64") == b"Hello! World"
    assert decode_transfer(b"SGVsbG8", "BASE64") == b"Hello"
    assert decode_transfer(b"A", "base64") == b""
    assert decode_transfer(b"a=3Db=\r\nc", "quoted-printable") == b"a=bc"
    assert decode_transfer(b"raw", "8bit") == b"raw"
    assert decode_transfer(b"raw", "x-weird") == b"raw"


def test_decoded_size():
    assert decoded_size("base64", 78) == 57
    assert decoded_size("base64", 0) == 0
    assert decoded_size("7bit", 123) == 123


def test_is_text_like():
    got = leaves(mp(TEXT, PDF))
    assert got is not None
    text, pdf = got
    assert is_text_like(text, b"hello") and not is_text_like(text, b"a\x00b")
    assert not is_text_like(pdf, b"hello")
    utf16 = leaves((b"text", b"plain", (b"charset", b"utf-16"), None, None, b"base64", 10, 1))
    assert utf16 is not None and is_text_like(utf16[0], b"a\x00b\x00")


def test_section_regex():
    for ok in ("1", "2.1", "10.20.3"):
        assert SECTION_RE.match(ok)
    for bad in ("", "0", "01", "1.", ".1", "1.MIME", "TEXT", "1 2", "1\n", "1;x", "99999"):
        assert not SECTION_RE.match(bad), bad


def test_attachments_for_aligned_uses_parser_list():
    raw = (
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n"
        b"hi\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; "
        b'filename="x.pdf"\r\n\r\npdfbytes\r\n--b--\r\n'
    )
    parsed = parse_message(raw)
    server = leaves(mp(TEXT, PDF))
    atts, notes = attachments_for(parsed, server, truncated=False)
    assert notes == () and [(a.part_id, a.size, a.size_estimated) for a in atts] == [
        ("2", 8, False)
    ]


def test_attachments_for_mismatch_and_truncation_use_the_server_view():
    parsed = parse_message(b"Content-Type: multipart/mixed\r\n\r\ntext\r\n")
    server = leaves(mp(TEXT, PDF))
    atts, notes = attachments_for(parsed, server, truncated=False)
    assert [a.part_id for a in atts] == ["2"] and atts[0].size_estimated and notes
    atts, notes = attachments_for(parsed, server, truncated=True)
    assert atts[0].size_estimated and "larger" in notes[0]
    assert find(server or [], "2") is not None
    atts, notes = attachments_for(parsed, None, truncated=False)
    assert notes and "unusable" in notes[0]
