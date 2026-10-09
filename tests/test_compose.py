"""The draft composer: every variant parsed back, header encoding, threading,
quoting, reply-all de-duplication, and refusal of header injection."""

from __future__ import annotations

import email
import email.policy
import re
from datetime import UTC, datetime
from email.message import EmailMessage

import pytest

from universal_email_mcp.errors import InvalidArgument
from universal_email_mcp.mail import compose
from universal_email_mcp.mail.compose import FileAttachment, Original, Request
from universal_email_mcp.models import Address, Identity

ME = Identity(
    name="Work",
    addresses=("me@example.org", "office@example.org"),
    display_name="Max Müller",
    signature="Max Müller\nExample GmbH",
    default=True,
)
NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def original(**kw: object) -> Original:
    base: dict[str, object] = {
        "message_id": "<abc.1@mail.example.com>",
        "in_reply_to": None,
        "references": ("<root@mail.example.com>", "<mid@mail.example.com>"),
        "subject": "Angebot",
        "from_": (Address("Anna Huber", "anna@huber.at"),),
        "reply_to": (),
        "to": (Address("", "me@example.org"), Address("Bob", "bob@example.net")),
        "cc": (Address("", "carol@example.net"),),
        "date": datetime(2026, 10, 1, 8, 30, tzinfo=UTC),
        "body": "Hallo,\nbitte um ein Angebot.\n\n> altes Zitat",
    }
    base.update(kw)
    return Original(**base)  # pyright: ignore[reportArgumentType]


def parse(raw: bytes) -> EmailMessage:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    assert isinstance(msg, EmailMessage)
    return msg


def text_of(msg: EmailMessage) -> str:
    body = msg.get_body(("plain",))
    assert body is not None
    return body.get_content().replace("\r\n", "\n")


def make(**kw: object) -> compose.Draft:
    req = Request(sender=ME, address="me@example.org", now=NOW, **kw)  # pyright: ignore[reportArgumentType]
    return compose.compose(req)


# ----------------------------------------------------------------- new mail


def test_new_message_round_trip() -> None:
    d = make(
        to=[Address("Anna Huber", "anna@huber.at")],
        cc=[Address("", "c@example.net")],
        bcc=[Address("", "b@example.net")],
        subject="Grüße aus Wien",
        body="Hallo Anna,\n\nschöne Grüße",
    )
    m = parse(d.raw)
    assert str(m["From"]) == "Max Müller <me@example.org>"
    assert m["To"].addresses[0].display_name == "Anna Huber"
    assert m["Cc"].addresses[0].addr_spec == "c@example.net"
    assert m["Bcc"].addresses[0].addr_spec == "b@example.net"
    assert m["Subject"] == "Grüße aus Wien"
    assert m["Message-ID"] == d.message_id
    assert d.message_id.endswith("@example.org>")
    assert m["Date"].datetime == NOW
    assert m["In-Reply-To"] is None
    assert text_of(m) == "Hallo Anna,\n\nschöne Grüße\n\n-- \nMax Müller\nExample GmbH\n"
    assert b"\r\n" in d.raw and re.search(rb"(?<!\r)\n", d.raw) is None
    # non-ASCII headers are encoded words, not raw 8-bit
    head = d.raw.split(b"\r\n\r\n", 1)[0]
    assert head.isascii()
    assert b"=?utf-8?" in head.lower()


def test_signature_separator_and_empty_signature() -> None:
    other = Identity(name="x", addresses=("x@example.org",))
    d = compose.compose(Request(sender=other, address="x@example.org", body="hi", now=NOW))
    assert text_of(parse(d.raw)) == "hi\n"


def test_message_id_uses_identity_domain() -> None:
    d = compose.compose(Request(sender=ME, address="office@example.org", body="x", now=NOW))
    assert d.message_id.endswith("@example.org>")
    assert parse(d.raw)["From"].addresses[0].addr_spec == "office@example.org"


# ----------------------------------------------------------------- reply


def test_reply_threading_and_quote() -> None:
    o = original()
    to, cc, _w = compose.reply_recipients(o, {"me@example.org"}, reply_all=False)
    d = make(
        kind="reply",
        to=to,
        cc=cc,
        subject=compose.reply_subject(o.subject),
        body="Gerne.",
        original=o,
    )
    m = parse(d.raw)
    assert m["Subject"] == "Re: Angebot"
    assert m["In-Reply-To"] == "<abc.1@mail.example.com>"
    assert (
        m["References"] == "<root@mail.example.com> <mid@mail.example.com> <abc.1@mail.example.com>"
    )
    body = text_of(m)
    assert body.startswith("Gerne.\n\n-- \nMax Müller")
    assert "On 2026-10-01 08:30 UTC, Anna Huber <anna@huber.at> wrote:" in body
    assert "> Hallo,\n> bitte um ein Angebot.\n>\n> > altes Zitat" in body
    assert d.quoted.startswith("On 2026-10-01")
    assert d.body.endswith("Example GmbH")


def test_reply_all_dedupes_and_drops_own_addresses() -> None:
    o = original(
        to=(
            Address("", "me@example.org"),
            Address("Bob", "BOB@example.net"),
            Address("", "anna@huber.at"),
        ),
        cc=(
            Address("", "bob@example.net"),
            Address("", "office@example.org"),
            Address("", "d@example.net"),
        ),
    )
    own = {"me@example.org", "office@example.org"}
    to, cc, _ = compose.reply_recipients(o, own, reply_all=True)
    assert [a.email for a in to] == ["anna@huber.at"]
    assert [a.email for a in cc] == ["BOB@example.net", "d@example.net"]
    to1, cc1, _ = compose.reply_recipients(o, own, reply_all=False)
    assert [a.email for a in to1] == ["anna@huber.at"] and cc1 == []


def test_reply_to_own_mail_goes_to_original_recipients() -> None:
    o = original(from_=(Address("", "me@example.org"),))
    to, _cc, _ = compose.reply_recipients(o, {"me@example.org"}, reply_all=False)
    assert [a.email for a in to] == ["bob@example.net"]


def test_reply_to_header_is_used_and_flagged_when_domain_differs() -> None:
    o = original(reply_to=(Address("Anna", "anna@elsewhere.example"),))
    to, _cc, warnings = compose.reply_recipients(o, set(), reply_all=False)
    assert [a.email for a in to] == ["anna@elsewhere.example"]
    assert any("Reply-To" in w and "elsewhere.example" in w for w in warnings)
    same = original(reply_to=(Address("Anna", "sekretariat@huber.at"),))
    _t, _c, warnings = compose.reply_recipients(same, set(), reply_all=False)
    assert not warnings


@pytest.mark.parametrize(
    ("subject", "expected"),
    [
        ("Angebot", "Re: Angebot"),
        ("Re: Angebot", "Re: Angebot"),
        ("RE: Re: AW: Angebot", "Re: Angebot"),
        ("Antw: Re[2]: Angebot", "Re: Angebot"),
        ("Fwd: Angebot", "Re: Fwd: Angebot"),
        ("", "Re: "),
    ],
)
def test_reply_subject(subject: str, expected: str) -> None:
    assert compose.reply_subject(subject) == expected


@pytest.mark.parametrize(
    ("subject", "expected"),
    [
        ("Angebot", "Fwd: Angebot"),
        ("Fwd: Angebot", "Fwd: Angebot"),
        ("WG: FW: Fwd: Angebot", "Fwd: Angebot"),
        ("Re: Angebot", "Fwd: Re: Angebot"),
    ],
)
def test_forward_subject(subject: str, expected: str) -> None:
    assert compose.forward_subject(subject) == expected


# ----------------------------------------------------------------- hostile originals


def test_huge_references_chain_is_bounded_and_validated() -> None:
    refs = tuple(f"<m{i}@x.example>" for i in range(500)) + (
        "<evil@x.example>\r\nBcc: spy@evil.example",
        "<no at sign>",
        "<" + "a" * 400 + "@x.example>",
        "not-an-id",
    )
    o = original(references=refs, message_id="<last@x.example>")
    parent, out = compose.thread_headers(o)
    assert parent == "<last@x.example>"
    assert len(out) == compose.MAX_REFERENCES
    assert out[0] == "<m0@x.example>" and out[-1] == "<last@x.example>"
    assert all(compose.valid_msgid(r) for r in out)
    d = make(kind="reply", original=o, subject="Re: x", body="x")
    m = parse(d.raw)
    assert m["Bcc"] is None
    assert len(m["References"].split()) == compose.MAX_REFERENCES


def test_forged_message_ids_are_dropped() -> None:
    o = original(message_id="<a b@x>\r\nBcc: spy@evil.example", references=("<ok@x.example>",))
    parent, refs = compose.thread_headers(o)
    assert parent is None and refs == ("<ok@x.example>",)
    d = make(kind="reply", original=o, subject="Re: x", body="x")
    assert parse(d.raw)["Bcc"] is None
    assert parse(d.raw)["In-Reply-To"] is None


def test_hostile_addresses_and_names_of_the_original() -> None:
    o = original(
        from_=(
            Address("=?utf-8?b?ZXZpbA==?= <x@y>", "anna@huber.at"),
            Address("Mallory", "mallory@evil.example\r\nBcc: spy@evil.example"),
            Address("", "no-at-sign"),
            Address('Quote"Name', "q@huber.at"),
        )
    )
    to, _cc, warnings = compose.reply_recipients(o, set(), reply_all=False)
    assert [a.email for a in to] == ["anna@huber.at", "q@huber.at"]
    assert to[0].name == ""  # encoded-word look-alike name dropped
    assert any("malformed" in w for w in warnings)
    d = make(kind="reply", to=to, original=o, subject="Re: x", body="x")
    m = parse(d.raw)
    assert m["Bcc"] is None
    assert [a.addr_spec for a in m["To"].addresses] == ["anna@huber.at", "q@huber.at"]
    assert m["To"].addresses[1].display_name == 'Quote"Name'


def test_crlf_in_original_subject_and_name_cannot_inject() -> None:
    o = original(
        subject="Hi\r\nBcc: spy@evil.example X-Evil: 1",
        from_=(Address("Anna\r\nBcc: spy@evil.example", "anna@huber.at"),),
        body="line\r\nBcc: spy@evil.example\r\n.\r\nQUIT",
    )
    to, _c, _w = compose.reply_recipients(o, set(), reply_all=False)
    d = make(kind="reply", to=to, original=o, subject=compose.reply_subject(o.subject), body="ok")
    m = parse(d.raw)
    assert m["Bcc"] is None and m["X-Evil"] is None
    assert "\n" not in str(m["Subject"])
    assert [str(h) for h in m.keys()].count("Subject") == 1
    # the hostile text only exists as inert quoted text
    assert "> Bcc: spy@evil.example" in text_of(m)


def test_forward_block_and_oversized_original_are_capped() -> None:
    o = original(body="x" * 50_000, subject="S\r\nBcc: a@b.example")
    d = make(kind="forward", original=o, subject=compose.forward_subject(o.subject), body="FYI")
    assert "---------- Forwarded message ----------" in d.quoted
    assert len(d.quoted) < compose.MAX_QUOTE_CHARS + 600
    assert "Subject: S Bcc: a@b.example" in d.quoted
    assert parse(d.raw)["Bcc"] is None
    assert parse(d.raw)["In-Reply-To"] is None


# ----------------------------------------------------------------- caller input


@pytest.mark.parametrize(
    "bad",
    [
        "a@b.example\r\nBcc: spy@evil.example",
        "a@b.example\nBcc: spy@evil.example",
        "a@b.example\x00",
        "Name  <a@b.example>",
        "not an address",
        "a@",
        "@b.example",
        "a@localhost",
        "a b@c.example",
        '"quoted"@c.example',
        "<a@b.example",
        "Jörg@b.example",
        "a@b.example, ",
    ],
)
def test_recipients_refuse_bad_input(bad: str) -> None:
    with pytest.raises(InvalidArgument):
        compose.parse_recipients([bad], "to")


def test_recipients_accept_and_normalise() -> None:
    got = compose.parse_recipients(
        ["Anna Huber <anna@huber.at>, bob@example.net", "Ünal <u@müller.example>"], "to"
    )
    assert [a.email for a in got] == ["anna@huber.at", "bob@example.net", "u@xn--mller-kva.example"]
    assert got[0].name == "Anna Huber"
    assert compose.parse_recipients(None, "to") == []


@pytest.mark.parametrize("bad", ["a\r\nb", "a\nb", "a\x00b", "a\rb", "a b"])
def test_subject_refuses_control_characters(bad: str) -> None:
    with pytest.raises(InvalidArgument):
        compose.header_text(bad, "subject")
    with pytest.raises(InvalidArgument):
        make(subject=bad, body="x")


def test_subject_length_cap() -> None:
    with pytest.raises(InvalidArgument):
        compose.header_text("x" * (compose.MAX_SUBJECT_CHARS + 1), "subject")


def test_display_name_that_looks_like_an_encoded_word_is_refused() -> None:
    with pytest.raises(InvalidArgument):
        compose.parse_recipients(["=?utf-8?q?x?= <a@b.example>"], "to")


def test_body_controls_are_neutralised_not_injected() -> None:
    d = make(body="a\x00b\r\nBcc: x@y.example\rEnd")
    m = parse(d.raw)
    assert m["Bcc"] is None
    assert "\x00" not in text_of(m)


# ----------------------------------------------------------------- attachments


def test_attachments_round_trip_and_hostile_names() -> None:
    atts = [
        FileAttachment("../../etc/pass\r\nwd.pdf", "application/pdf", b"%PDF-1.4 data"),
        FileAttachment('x"; y="z.txt', "text/plain", "Grüße".encode()),
        FileAttachment(
            "mail.eml", "message/rfc822", b"From: a@b.example\r\nSubject: inner\r\n\r\nhi\r\n"
        ),
        FileAttachment("evil", "text/html\r\nBcc: spy@x.example", b"<b>x</b>"),
        FileAttachment("", "multipart/mixed", b"junk"),
    ]
    d = make(kind="forward", original=original(), subject="Fwd: x", body="FYI", attachments=atts)
    m = parse(d.raw)
    assert m["Bcc"] is None
    parts = list(m.iter_attachments())
    assert len(parts) == 5
    assert parts[0].get_filename() == "_.._etc_pass wd.pdf"
    assert "/" not in (parts[0].get_filename() or "")
    assert parts[0].get_content() == b"%PDF-1.4 data"
    assert parts[1].get_content_type() == "text/plain"
    assert parts[1].get_payload(decode=True) == "Grüße".encode()
    assert parts[2].get_content_type() == "message/rfc822"
    assert parts[3].get_content_type() == "application/octet-stream"
    assert parts[4].get_content_type() == "application/octet-stream"
    assert d.attachments[0][2] == len(b"%PDF-1.4 data")
    for p in parts:
        assert "\n" not in (p.get_filename() or "")


def test_recipient_dedupe() -> None:
    got = compose.dedupe([Address("A", "a@x.example"), Address("", "A@X.example")])
    assert len(got) == 1
