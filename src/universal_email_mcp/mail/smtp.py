"""SMTP submission over a checked, verified TLS connection (design section 5).

The socket comes from :mod:`universal_email_mcp.mail.net` (host resolved once, every
address checked, the connection goes to the checked IP, TLS is verified against the
*host name*), so the SSRF guard that protects IMAP protects outgoing mail too.
:mod:`smtplib` only speaks the protocol on top of it.

Rules that are not configurable:

- Implicit TLS (465) or STARTTLS (587), TLS >= 1.2. A server that does not offer
  STARTTLS is refused **before** any credentials are sent; there is no plain-text mode.
- Authentication is required (a submission server that offers none is refused).
- The envelope sender is the identity address, the recipients are given by the caller
  (To + Cc + Bcc). The transmitted message **never contains a Bcc header** (it is
  stripped here, whatever the caller passes).
- Every recipient is checked with ``RCPT TO`` first; if the server refuses any, the
  session is reset **before** ``DATA`` and nothing is sent (:class:`RecipientsRefused`).
- If the connection breaks after the message body went out, the outcome is unknown:
  :class:`SendOutcomeUnknown` (never retried).

Synchronous; run it in a worker thread.
"""

from __future__ import annotations

import re
import smtplib
import socket
import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from universal_email_mcp.errors import (
    AuthFailed,
    InvalidArgument,
    MailError,
    ProtocolError,
    RecipientsRefused,
    SendOutcomeUnknown,
    ServerUnreachable,
    TlsError,
    TooLarge,
)
from universal_email_mcp.mail.mime import sanitize_line
from universal_email_mcp.mail.net import (
    NetPolicy,
    Resolver,
    open_connection,
    tls_context,
    wrap_tls,
)
from universal_email_mcp.mail.outgoing import normalize_eol, strip_headers
from universal_email_mcp.models import Endpoint, TlsSettings

HELO_NAME = "localhost"
"""Name announced in EHLO (nothing about this machine is revealed)."""
_DOT_LINE = re.compile(rb"(?m)^\.")
SocketFactory = Callable[[], socket.socket]


@dataclass(frozen=True, slots=True)
class SmtpReceipt:
    reply: str
    """The server's final reply (sanitised, short) - for the user, not for parsing."""
    tls: str
    size: int
    """Bytes transmitted (after Bcc stripping)."""


def _text(msg: bytes | str) -> str:
    if isinstance(msg, bytes):
        msg = msg.decode("utf-8", "replace")
    return sanitize_line(msg)[:160]


class _Smtp(smtplib.SMTP):
    """``smtplib.SMTP`` over a socket we opened (see module docstring)."""

    def __init__(self, host: str, factory: SocketFactory) -> None:
        super().__init__(local_hostname=HELO_NAME)
        self._factory = factory
        self._host = host  # STARTTLS verifies the certificate against this name

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return self._factory()


def prepare_message(raw: bytes) -> bytes:
    """What goes on the wire: CRLF line ends, no Bcc header."""
    return strip_headers(normalize_eol(raw), frozenset({"bcc"}))


def submit(
    endpoint: Endpoint,
    username: str,
    password: str,
    *,
    sender: str,
    recipients: Sequence[str],
    raw: bytes,
    max_bytes: int,
    tls: TlsSettings = TlsSettings(),  # noqa: B008 - frozen dataclass
    net: NetPolicy | None = None,
    resolver: Resolver | None = None,
) -> SmtpReceipt:
    """Send ``raw`` from ``sender`` to ``recipients`` (the envelope; Bcc included).

    Raises :class:`MailError` subclasses: :class:`TlsError`, :class:`AuthFailed`,
    :class:`ServerUnreachable`, :class:`RecipientsRefused` (nothing sent),
    :class:`TooLarge`, :class:`ProtocolError` (rejected, nothing sent) and
    :class:`SendOutcomeUnknown` (the connection broke after the body went out).
    """
    net = net or NetPolicy()
    if not recipients:
        raise InvalidArgument("no recipients")
    data = prepare_message(raw)
    if len(data) > max_bytes:
        raise TooLarge(
            f"the message is {len(data)} bytes; the limit is {max_bytes}",
            hint="Send fewer or smaller attachments.",
        )
    host, implicit = endpoint.host, endpoint.tls == "tls"
    ctx = tls_context(verify=tls.verify, ca_file=tls.ca_file)

    def factory() -> socket.socket:
        sock = open_connection(host, endpoint.port, net, resolver)
        return wrap_tls(sock, ctx, host) if implicit else sock

    conn = _Smtp(host, factory)
    try:
        return _session(
            conn, endpoint, username, password, sender, recipients, data, max_bytes, ctx
        )
    except MailError:
        raise
    except ssl.SSLCertVerificationError as e:
        raise TlsError(f"certificate verification failed for {host}: {e.verify_message}") from e
    except ssl.SSLError as e:
        raise TlsError(f"TLS error talking to {host}: {e.reason or e}") from e
    except smtplib.SMTPServerDisconnected as e:
        raise ServerUnreachable(
            f"connection to {host}:{endpoint.port} lost: {_text(str(e))}"
        ) from e
    except smtplib.SMTPException as e:
        raise ProtocolError(f"the SMTP server answered unexpectedly: {_text(str(e))}") from e
    except OSError as e:
        raise ServerUnreachable(
            f"connection to {host}:{endpoint.port} failed: {_text(str(e))}"
        ) from e
    finally:
        _close(conn)


def _close(conn: smtplib.SMTP) -> None:
    try:
        conn.quit()
    except (smtplib.SMTPException, OSError):
        try:
            conn.close()
        except OSError:
            pass


def _session(
    conn: _Smtp,
    endpoint: Endpoint,
    username: str,
    password: str,
    sender: str,
    recipients: Sequence[str],
    data: bytes,
    max_bytes: int,
    ctx: ssl.SSLContext,
) -> SmtpReceipt:
    host = endpoint.host
    implicit = endpoint.tls == "tls"
    code, banner = conn.connect(host, endpoint.port)
    if code != 220:
        raise ServerUnreachable(f"{host} did not accept the connection: {code} {_text(banner)}")
    conn.ehlo()
    if not implicit:
        if not conn.has_extn("starttls"):
            raise TlsError(
                f"{host}:{endpoint.port} does not offer STARTTLS",
                hint="Refusing to log in without TLS. Use port 465 (implicit TLS).",
            )
        code, reply = conn.starttls(context=ctx)
        if code != 220:
            raise TlsError(f"STARTTLS with {host} was refused: {code} {_text(reply)}")
        conn.ehlo()
    if not conn.has_extn("auth"):
        raise AuthFailed(
            f"{host} offers no authentication",
            hint="A submission server must require a login; check host and port.",
        )
    try:
        conn.login(username, password)
    except smtplib.SMTPAuthenticationError as e:
        raise AuthFailed(
            f"login rejected by the server: {e.smtp_code} {_text(e.smtp_error)}"
        ) from e
    except UnicodeError as e:
        raise AuthFailed(
            "user name or password contains characters this server's AUTH cannot transmit"
        ) from e
    except smtplib.SMTPNotSupportedError as e:
        raise AuthFailed(f"no supported login mechanism: {_text(str(e))}") from e

    options: list[str] = []
    size_limit = _declared_size(conn)
    if size_limit is not None and len(data) > min(size_limit, max_bytes):
        raise TooLarge(
            f"the message is {len(data)} bytes; the server accepts at most {size_limit}",
            hint="Send fewer or smaller attachments.",
        )
    if conn.has_extn("size"):
        options.append(f"SIZE={len(data)}")
    if any(b > 127 for b in data):
        if not conn.has_extn("8bitmime"):
            raise InvalidArgument(
                "the message contains 8-bit data, but the server does not accept 8BITMIME"
            )
        options.append("BODY=8BITMIME")
    code, reply = conn.mail(sender, options)
    if code != 250:
        _reset(conn)
        raise _mail_error(code, reply, "the server rejected the sender address")

    refused: dict[str, str] = {}
    for rcpt in recipients:
        code, reply = conn.rcpt(rcpt)
        if code not in (250, 251):
            refused[rcpt] = f"{code} {_text(reply)}"
    if refused:
        _reset(conn)
        raise RecipientsRefused(
            f"the server refused {len(refused)} of {len(recipients)} recipient(s); nothing was sent",
            refused,
        )

    code, reply = conn.docmd("DATA")
    if code != 354:
        _reset(conn)
        raise _mail_error(code, reply, "the server did not accept the message")
    payload = _DOT_LINE.sub(b"..", data)
    if not payload.endswith(b"\r\n"):
        payload += b"\r\n"
    try:
        conn.send(payload + b".\r\n")
        code, reply = conn.getreply()
    except OSError as e:  # includes smtplib's SMTPException family
        raise SendOutcomeUnknown(
            "the connection broke while the message was handed to the server"
        ) from e
    if code != 250:
        _reset(conn)
        raise _mail_error(code, reply, "the server rejected the message")
    return SmtpReceipt(
        reply=f"{code} {_text(reply)}",
        tls="implicit TLS" if implicit else "STARTTLS",
        size=len(data),
    )


def _declared_size(conn: smtplib.SMTP) -> int | None:
    value = conn.esmtp_features.get("size", "")
    return int(value) if value.isdigit() and int(value) > 0 else None


def _reset(conn: smtplib.SMTP) -> None:
    try:
        conn.rset()
    except (smtplib.SMTPException, OSError):
        pass


def _mail_error(code: int, reply: bytes, what: str) -> MailError:
    text = f"{what}: {code} {_text(reply)}"
    if code == 552:
        return TooLarge(text, hint="The server's message size limit was exceeded.")
    if 400 <= code < 500:
        return ProtocolError(text, hint="A temporary failure; nothing was sent. Try again later.")
    return ProtocolError(text, hint="Nothing was sent.")
