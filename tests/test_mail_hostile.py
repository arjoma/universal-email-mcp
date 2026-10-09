"""Robustness rules for hostile mail: no single message may crash the process, drop
an account from a listing or make a message unreadable (security review findings
H1, H2, M1, M5, M6, L5)."""

from __future__ import annotations

import itertools
import json
import re
import time

import pytest

from universal_email_mcp.mail import mime
from universal_email_mcp.mail.folders import decode_folder_name
from universal_email_mcp.mail.mime import (
    decode_text,
    extract_part,
    fence_untrusted,
    html_to_text,
    html_view_parts,
    parse_header_block,
    parse_message,
    sanitize_line,
    sanitize_text,
)
from universal_email_mcp.models import MessageRef

LONE = re.compile(r"[\ud800-\udfff]")


def _clean(value: object) -> None:
    """The JSON serialiser of the stdio transport must be able to encode it."""
    json.dumps(value, ensure_ascii=False, default=repr).encode("utf-8")


# H1 ------------------------------------------------------------------------


def test_sanitizers_remove_lone_surrogates():
    assert sanitize_line("a\ud83db") == "a�b"
    assert sanitize_text("a\ud83d\nb\udfff") == "a�\nb�"
    assert LONE.search(fence_untrusted("x\ud83dy")) is None


def test_utf7_header_with_lone_surrogate_is_clean():
    h = parse_header_block(b"Subject: =?utf-7?q?+2D0-?=\r\nFrom: =?utf-7?q?+2D0-?= <a@b.c>\r\n\r\n")
    assert not LONE.search(h.subject) and not LONE.search(h.from_[0].name)
    h.subject.encode("utf-8")


def test_utf7_body_with_lone_surrogate_is_clean():
    p = parse_message(
        b"From: a@b.c\r\nContent-Type: text/plain; charset=utf-7\r\n\r\nhi +2D0- x\r\n"
    )
    assert not LONE.search(p.text) and "hi" in p.text
    assert not LONE.search(decode_text(b"+2D0-", "utf-7"))


def test_utf7_attachment_name_is_clean():
    raw = (
        b"From: a@b.c\r\nContent-Type: text/plain\r\n"
        b"Content-Disposition: attachment; filename*=utf-7''+2D0-.pdf\r\n\r\nx\r\n"
    )
    for a in parse_message(raw).attachments:
        assert a.filename is None or not LONE.search(a.filename)


@pytest.mark.parametrize("wire", ["&2D0-", "&2D3cAA-", "A&-B", "&AAA-", "&Jjo-", "&2D3eAQ-"])
def test_folder_names_never_hold_surrogates(wire):
    _clean(decode_folder_name(wire))
    assert not LONE.search(decode_folder_name(wire))


def test_valid_surrogate_pair_in_folder_name_is_kept():
    assert decode_folder_name("&2D3eAQ-") == "\U0001f601"  # smiley as a UTF-16 pair


# H2 ------------------------------------------------------------------------

NASTY_CHARSETS = ["undefined", "idna", "punycode", "\x00", "rot13", "hex", "base64", "x" * 500]


@pytest.mark.parametrize("cs", NASTY_CHARSETS)
def test_nasty_charsets_in_encoded_words(cs):
    raw = f"Subject: =?{cs}?q?hi?=\r\nFrom: =?{cs}?q?Bob?= <a@b.c>\r\n\r\n".encode()
    h = parse_header_block(raw)
    assert h.from_[0].email == "a@b.c"
    _clean(h.subject)


@pytest.mark.parametrize("cs", NASTY_CHARSETS)
def test_nasty_charsets_in_bodies(cs):
    raw = f"From: a@b.c\r\nContent-Type: text/plain; charset={cs}\r\n\r\nhello\r\n".encode()
    assert "hello" in parse_message(raw).text
    _clean(decode_text(b"a" * 70, cs))


def test_decode_text_skips_bytes_to_bytes_codecs():
    assert decode_text(b"hello", "rot13") == "hello"
    assert decode_text(b"hello", "hex") == "hello"


def test_summary_placeholder_keeps_the_id():
    ref = MessageRef("Work", "INBOX", 1, 7)
    s = mime.unreadable_summary(ref, flags=("\\Seen",), size=10)
    assert s.id == ref.encode() and s.subject == mime.UNREADABLE_SUBJECT and s.seen


def test_pop3_summary_guard(monkeypatch):
    from universal_email_mcp.mail import pop3

    def boom(*_a, **_k):
        raise ValueError("boom")

    monkeypatch.setattr(pop3, "_summary_from_headers", boom)
    ref = MessageRef("P", "INBOX", 1, 3, "uidl")
    s = pop3.summary_from_headers(ref, b"Subject: x\r\n\r\n", 5)
    assert s.subject == mime.UNREADABLE_SUBJECT and s.ref == ref and s.size == 5


def test_imap_summaries_guard(monkeypatch):
    from universal_email_mcp.mail import imap

    session = imap.ImapSession.__new__(imap.ImapSession)
    session.account_name = "Work"
    fields = {1: {b"FLAGS": (b"\\Seen",), b"RFC822.SIZE": 12}, 2: {b"RFC822.SIZE": 5}}
    monkeypatch.setattr(session, "_fetch_raw", lambda _u, _i: fields, raising=False)

    def broken(_ref, flds, _headers):
        if flds is fields[1]:
            raise ValueError("boom")
        return "ok"

    monkeypatch.setattr(imap, "_summary", broken)
    out = session._summaries("INBOX", 1, [1, 2])
    assert out[0].subject == mime.UNREADABLE_SUBJECT and out[0].seen and out[0].size == 12
    assert out[1] == "ok"


# M1 ------------------------------------------------------------------------


def test_malformed_param_in_a_part_keeps_the_message_readable():
    raw = (
        b"From: a@b.c\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n"
        b"--XX\r\nContent-Type: text/plain\r\n\r\nvisible\r\n"
        b"--XX\r\nContent-Type: application/pdf; name*0*\r\n\r\nPDF\r\n--XX--\r\n"
    )
    p = parse_message(raw)
    assert "visible" in p.text and p.text_source == "plain"
    assert [a.part_id for a in p.attachments] == ["2"]
    assert extract_part(raw, "2") is not None
    assert html_view_parts(raw, max_image_bytes=10, max_total_bytes=10).html == ()


def test_malformed_top_level_content_type_is_still_text():
    p = parse_message(b"From: a@b.c\r\nContent-Type: text/plain; filename*0*\r\n\r\nbody\r\n")
    assert p.text == "body"


def test_unexpected_parser_failure_degrades_to_headers(monkeypatch):
    def boom(*_a, **_k):
        raise IndexError("stdlib")

    monkeypatch.setattr(mime, "_parse_body", boom)
    p = parse_message(b"From: a@b.c\r\nSubject: hello\r\n\r\nbody\r\n")
    assert p.text_source == "unparseable" and p.headers.subject == "hello" and p.notes


# M5 ------------------------------------------------------------------------


def test_mime_bomb_is_refused_before_parsing():
    n = 200_000
    raw = (
        b"From: a@b.c\r\nSubject: bomb\r\nContent-Type: multipart/mixed; boundary=X\r\n\r\n"
        + b"--X\r\n\r\n" * n
        + b"--X--\r\n"
    )
    started = time.monotonic()
    p = parse_message(raw)
    assert extract_part(raw, "1") is None
    assert html_view_parts(raw, max_image_bytes=10, max_total_bytes=10).html == ()
    assert time.monotonic() - started < 3
    assert p.text_source == "unparseable" and p.headers.subject == "bomb" and p.notes


def test_markdown_rules_in_plain_text_are_not_a_bomb():
    body = "\r\n".join(["-----"] * 3000)
    p = parse_message(f"From: a@b.c\r\nContent-Type: text/plain\r\n\r\n{body}\r\n".encode())
    assert p.text_source == "plain"


# M6 ------------------------------------------------------------------------


def test_many_ids_and_encoded_words_are_fast():
    started = time.monotonic()
    refs = b" ".join(b"<%d@b>" % i for i in range(80_000))
    h = parse_header_block(
        b"References: " + refs + b"\r\nSubject: " + b"=?utf-8?q?a?= " * 80_000 + b"\r\n\r\n"
    )
    assert time.monotonic() - started < 2
    assert len(h.subject) <= mime.MAX_HEADER_CHARS
    assert 0 < len(h.references) < 80_000


# L5 ------------------------------------------------------------------------


def test_deeply_nested_html_does_not_hide_text():
    notes: list[str] = []
    html = (
        "<p>start</p>" + "<div>" * 300 + "Pay invoice to IBAN XX" + "</div>" * 300 + "<p>tail</p>"
    )
    text = html_to_text(html, notes=notes)
    assert "Pay invoice to IBAN XX" in text and "tail" in text
    assert notes and "nested too deeply" in notes[0]
    raw = f"From: a@b.c\r\nContent-Type: text/html\r\n\r\n{html}".encode()
    p = parse_message(raw)
    assert "IBAN XX" in p.text and any("nested" in n for n in p.notes)


def test_normal_html_has_no_depth_note():
    notes: list[str] = []
    assert html_to_text("<div><p>hi</p></div>", notes=notes) == "hi"
    assert not notes


# property-style: every parsing entry point survives nasty input ------------

NASTY_VALUES = [
    "=?undefined?q?a?=",
    "=?\x00?q?a?=",
    "=?utf-7?q?+2D0-?=",
    "=?utf-16-be?b?2D0=?=",
    "=?utf-8?b?7aC9?=",
    "=?x?b?!!!?=",
    "=?utf-8?q?=FF=FE?=",
    "text/plain; filename*0*",
    "text/plain; charset=undefined",
    'multipart/mixed; boundary="a\\\x00"',
    "application/pdf; name*=utf-7''+2D0-",
    "name*0*=utf-8''%41; name*1=%",
    "\ud83d",
    "\xff\x80\x00",
    "<" * 100 + "a@b.c",
    "(" * 100,
    '"' * 501,
    "a@b.c, " * 50,
    "<a@b> " * 50,
    "",
]
HEADERS = [
    "Content-Type",
    "Content-Disposition",
    "Content-ID",
    "Content-Transfer-Encoding",
    "From",
    "To",
    "Cc",
    "Reply-To",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
]


@pytest.mark.parametrize("header", HEADERS)
def test_every_entry_point_survives_nasty_headers(header):
    for value in NASTY_VALUES:
        v = value.encode("utf-8", "surrogatepass")
        inner = b"Content-Type: " + v + b"\r\nContent-Disposition: " + v + b"\r\n\r\nbody\r\n"
        raw = (
            b"From: a@b.c\r\n"
            + header.encode()
            + b": "
            + v
            + b"\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\n"
            + inner
            + b"--XX\r\n"
            + inner
            + b"--XX--\r\n"
        )
        for raw_variant in (raw, raw.replace(b"multipart/mixed; boundary=XX", b"text/html")):
            parsed = parse_message(raw_variant)
            for sec in itertools.chain(["1", "2", "1.1"], (a.part_id for a in parsed.attachments)):
                extract_part(raw_variant, sec)
            html_view_parts(raw_variant, max_image_bytes=10**6, max_total_bytes=10**7)
            h = parse_header_block(raw_variant)
            _clean([parsed.text, parsed.headers.subject, h.subject, parsed.attachments, h.from_])
            for text in (parsed.text, parsed.headers.subject, h.subject):
                assert not LONE.search(text)


# L1 ------------------------------------------------------------------------


def test_structured_listing_items_cap_header_fields():
    from universal_email_mcp.models import Address, MessageSummary
    from universal_email_mcp.server import schemas

    ref = MessageRef("Work", "INBOX", 1, 7)
    many = tuple(Address("N" * 5000, f"a{i}@example.org" + "x" * 500) for i in range(5000))
    s = MessageSummary(
        ref=ref,
        date=None,
        received=None,
        from_=many,
        to=many,
        cc=many,
        reply_to=many,
        subject="S" * 100_000,
        flags=(),
        size=None,
        has_attachments=False,
        message_id=None,
        in_reply_to=None,
        references=(),
    )
    item = schemas.MessageItem.of(s)
    assert len(item.subject) <= schemas.MAX_SUBJECT_CHARS
    assert len(item.to) == len(item.cc) == schemas.MAX_LISTED_RECIPIENTS
    assert len(item.from_) <= 10
    assert item.recipients_omitted == 2 * (5000 - schemas.MAX_LISTED_RECIPIENTS)
    assert len(item.to[0].name) <= schemas.MAX_NAME_CHARS
    assert len(item.to[0].email) <= schemas.MAX_EMAIL_CHARS
    assert len(item.model_dump_json()) < 30_000


# review round: CR-only bombs, strip-tags DoS, slow codecs, false positives -----------


def test_cr_only_delimiter_bomb_is_refused():
    raw = b"From: a@b.c\rContent-Type: multipart/mixed; boundary=X\r\r" + b"--X\r\r" * 100_000
    started = time.monotonic()
    p = parse_message(raw)
    assert time.monotonic() - started < 3 and p.text_source == "unparseable"


def test_many_signature_lines_in_plain_text_are_not_a_bomb():
    body = "-- \n" * 15_000
    p = parse_message(f"From: a@b.c\r\nContent-Type: text/plain\r\n\r\n{body}".encode())
    assert p.text_source in ("plain", "none")


def test_deep_html_fallback_is_linear_on_unclosed_tags():
    html = "<div>" * 300 + "<script " * 20_000 + "<a" * 100_000
    started = time.monotonic()
    html_to_text(html, notes=[])
    assert time.monotonic() - started < 3


def test_quadratic_codecs_are_not_used():
    started = time.monotonic()
    out = decode_text(b"a" * 2_000_000, "punycode")
    assert time.monotonic() - started < 3 and out.startswith("a")


def test_forged_auth_headers_without_received_are_not_own():
    from universal_email_mcp.service.viewer import HeaderLine

    assert not HeaderLine("Authentication-Results", "x", False).authentication
    assert HeaderLine("Authentication-Results", "x", True).authentication
