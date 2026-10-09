"""SMTP submission (mail/smtp.py) against the in-process sink."""

from __future__ import annotations

import ssl
import tempfile
from pathlib import Path

import pytest

from tests.smtp_sink import SmtpSink
from universal_email_mcp.errors import (
    AuthFailed,
    RecipientsRefused,
    SendOutcomeUnknown,
    TlsError,
    TooLarge,
)
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.mail.outgoing import has_header, strip_headers
from universal_email_mcp.mail.smtp import prepare_message, submit
from universal_email_mcp.models import Endpoint, TlsSettings

NET = NetPolicy(allow_private=True, connect_timeout=5, read_timeout=5)
INSECURE = TlsSettings(verify=False)
MSG = (
    b"From: alice@example.org\r\nTo: bob@example.net\r\nBcc: secret@example.com\r\n"
    b"Subject: Hi\r\nMessage-ID: <1@example.org>\r\n\r\nHello\r\n.\r\nstarts with a dot\r\n"
)


def run(sink: SmtpSink, *, mode: str = "starttls", host: str = "localhost", **kw: object):
    args: dict[str, object] = {
        "sender": "alice@example.org",
        "recipients": ["bob@example.net", "secret@example.com"],
        "raw": MSG,
        "max_bytes": 1_000_000,
        "tls": INSECURE,
        "net": NET,
    }
    args.update(kw)
    return submit(
        Endpoint(host, sink.port, "tls" if mode == "tls" else "starttls"),  # pyright: ignore[reportArgumentType]
        "alice",
        "secret",
        **args,  # pyright: ignore[reportArgumentType]
    )


@pytest.mark.parametrize("mode", ["starttls", "tls"])
def test_delivers_with_envelope_and_without_bcc_header(mode: str):
    with SmtpSink(implicit_tls=mode == "tls") as sink:
        receipt = run(sink, mode=mode)
        (got,) = sink.messages
    assert receipt.tls == ("implicit TLS" if mode == "tls" else "STARTTLS")
    assert got.mail_from == "alice@example.org"
    assert got.rcpt_to == ["bob@example.net", "secret@example.com"]  # Bcc is in the envelope
    assert got.authenticated and got.encrypted
    assert b"Bcc" not in got.data and b"secret@example.com" not in got.data
    assert got.data.startswith(b"From: alice@example.org\r\n")
    assert b"\r\n.\r\nstarts with a dot" in got.data  # dot-stuffing survives the round trip


def test_prepare_message_strips_folded_and_odd_case_bcc():
    raw = b"From: a@b.example\nBCC : x@y.example,\n z@y.example\nbcc: q@y.example\nTo: c@d.example\n\nBcc: in body\n"
    out = prepare_message(raw)
    assert out == b"From: a@b.example\r\nTo: c@d.example\r\n\r\nBcc: in body\r\n"
    assert has_header(raw, "Bcc") and not has_header(out, "bcc")
    assert strip_headers(b"no headers at all", frozenset({"bcc"})) == b"no headers at all"


def test_starttls_is_mandatory_and_nothing_secret_is_sent_without_it():
    with SmtpSink(offer_starttls=False) as sink:
        with pytest.raises(TlsError, match="STARTTLS"):
            run(sink)
        assert "AUTH" not in sink.commands and "MAIL" not in sink.commands


def test_certificate_is_verified_against_the_host_name():
    with SmtpSink() as sink:
        with pytest.raises(TlsError, match="certificate verification failed"):
            run(sink, tls=TlsSettings(verify=True))
        assert "AUTH" not in sink.commands


def test_a_trusted_ca_file_makes_verification_pass():
    # The sink's certificate is for "localhost"; trust it explicitly via a CA file.
    with SmtpSink() as sink:
        pem = Path(tempfile.mkdtemp()) / "ca.pem"
        pem.write_text(ssl.DER_cert_to_PEM_cert(_der(sink)))
        run(sink, tls=TlsSettings(verify=True, ca_file=str(pem)))
        assert len(sink.messages) == 1


def test_a_trusted_certificate_for_another_host_name_is_refused():
    with SmtpSink() as sink:
        pem = Path(tempfile.mkdtemp()) / "ca.pem"
        pem.write_text(ssl.DER_cert_to_PEM_cert(_der(sink)))
        with pytest.raises(TlsError, match="certificate verification failed"):
            run(sink, host="127.0.0.1", tls=TlsSettings(verify=True, ca_file=str(pem)))
        assert "AUTH" not in sink.commands


def _der(sink: SmtpSink) -> bytes:
    import socket

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", sink.port), timeout=5) as raw:
        raw.recv(100)
        raw.sendall(b"EHLO x\r\n")
        raw.recv(500)
        raw.sendall(b"STARTTLS\r\n")
        raw.recv(100)
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            der = tls.getpeercert(binary_form=True)
    assert der is not None
    return der


def test_wrong_password_is_auth_failed():
    with SmtpSink(password="other") as sink:
        with pytest.raises(AuthFailed):
            run(sink)
        assert sink.messages == [] and "MAIL" not in sink.commands


def test_no_auth_offered_is_refused():
    with SmtpSink(offer_auth=False) as sink:
        with pytest.raises(AuthFailed, match="no authentication"):
            run(sink)


def test_refused_recipient_aborts_before_data():
    with SmtpSink(refuse_rcpt=frozenset({"bob@example.net"})) as sink:
        with pytest.raises(RecipientsRefused) as ei:
            run(sink)
        assert list(ei.value.refused) == ["bob@example.net"]
        assert "550" in ei.value.refused["bob@example.net"]
        assert sink.messages == [] and "DATA" not in sink.commands


def test_message_larger_than_own_cap_or_server_size():
    with SmtpSink() as sink:
        with pytest.raises(TooLarge):
            run(sink, max_bytes=50)
    with SmtpSink(advertise_size=100) as sink:
        with pytest.raises(TooLarge, match="at most 100"):
            run(sink)
        assert "MAIL" not in sink.commands


def test_server_rejection_after_data_is_an_error_not_a_send():
    with SmtpSink(data_reply="554 5.7.1 spam") as sink:
        from universal_email_mcp.errors import ProtocolError

        with pytest.raises(ProtocolError, match="554"):
            run(sink)
        assert sink.messages == []
    with SmtpSink(data_reply="552 5.3.4 too big") as sink:
        with pytest.raises(TooLarge):
            run(sink)


def test_connection_lost_after_the_body_is_an_unknown_outcome():
    with SmtpSink(drop_after_data=True) as sink:
        with pytest.raises(SendOutcomeUnknown):
            run(sink)


def test_private_addresses_are_refused_when_not_allowed():
    from universal_email_mcp.errors import AddressNotAllowed

    with SmtpSink() as sink:
        with pytest.raises(AddressNotAllowed):
            run(sink, net=NetPolicy(allow_private=False))
