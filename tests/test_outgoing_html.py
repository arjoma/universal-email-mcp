"""What the confirmation must show: every body the recipients get (HTML alternative too)."""

from __future__ import annotations

from email.message import EmailMessage

from universal_email_mcp.mail.outgoing import MAX_TEXT_CHARS, parse_outgoing
from universal_email_mcp.models import Identity
from universal_email_mcp.service.send import confirmation_text


def draft(plain: str | None, html: str | None) -> bytes:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "me@example.org", "alice@example.org", "s"
    m["Message-ID"] = "<x@example.org>"
    if plain is not None:
        m.set_content(plain)
        if html is not None:
            m.add_alternative(html, subtype="html")
    else:
        m.set_content(html or "", subtype="html")
    return m.as_bytes()


def prompt(raw: bytes) -> str:
    out = parse_outgoing(raw)
    return confirmation_text(Identity("me", ("me@example.org",)), out, [], [], text=out.preview)


def test_a_differing_html_part_is_shown_under_its_own_heading():
    p = prompt(draft("Guten Tag", "<p>Bitte ueberweisen Sie <b>5000 EUR</b> an IBAN XY</p>"))
    assert "> Guten Tag" in p and "HTML version (differs from the text above" in p
    assert "> Bitte ueberweisen Sie 5000 EUR an IBAN XY" in p


def test_an_identical_html_part_is_not_repeated():
    out = parse_outgoing(draft("Guten Tag\n\nzweite Zeile", "<p>Guten Tag</p><p>zweite  Zeile</p>"))
    assert not out.html_shown
    assert "HTML version" not in prompt(draft("Guten Tag", "<p>Guten   Tag</p>"))


def test_an_html_only_draft_shows_its_text():
    out = parse_outgoing(draft(None, "<p>Nur <i>HTML</i></p>"))
    assert out.html_shown and not out.has_text_body
    p = prompt(draft(None, "<p>Nur <i>HTML</i></p>"))
    assert "no plain text part" in p and "> Nur HTML" in p


def test_remote_images_are_warned_about():
    p = prompt(draft("Hi", '<p>Hi!</p><img src="https://track.example/p.gif" width=1>'))
    assert "1 remote image" in p
    assert "remote image" not in prompt(draft("Hi", "<p>Hi</p>"))


def test_oversize_text_is_cut_loudly():
    big = "x" * (MAX_TEXT_CHARS + 500)
    out = parse_outgoing(draft(big, None) if False else draft(big, "<p>kurz</p>"))
    assert out.preview_cut == 500
    assert "500 more characters beyond the first" in prompt(draft(big, "<p>kurz</p>"))
    html_big = "<p>" + "y" * (MAX_TEXT_CHARS + 700) + "</p>"
    out = parse_outgoing(draft("kurz", html_big))
    assert out.html_cut > 0 and "of the HTML version NOT shown" in prompt(draft("kurz", html_big))
