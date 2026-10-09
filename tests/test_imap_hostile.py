"""A hostile IMAP server: oversized literals, response floods, STARTTLS injection."""

from __future__ import annotations

import sys
import time

import pytest

from universal_email_mcp.errors import MailError, ProtocolError, TlsError
from universal_email_mcp.mail.imap import (
    MAX_HEADER_FETCH,
    MAX_LITERAL_BYTES,
    MAX_UNTAGGED_BYTES,
    ImapSession,
)
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import Endpoint, TlsMode, TlsSettings

from .imap_server import ScriptedImapServer


def _connect(
    srv: ScriptedImapServer,
    mode: TlsMode,
    max_literal: int = MAX_LITERAL_BYTES,
    max_untagged: int = MAX_UNTAGGED_BYTES,
) -> ImapSession:
    return ImapSession.connect(
        Endpoint("localhost", srv.port, mode),
        "user",
        "secret",
        account_name="A",
        net=NetPolicy(allow_private=True, connect_timeout=5, read_timeout=10),
        tls=TlsSettings(verify=False),
        resolver=lambda _h, _p: ["127.0.0.1"],
        max_literal=max_literal,
        max_untagged=max_untagged,
    )


@pytest.mark.parametrize("mode", ["tls", "starttls"])
def test_huge_literal_in_the_greeting_is_refused(mode: TlsMode):
    with ScriptedImapServer(implicit_tls=mode == "tls", greeting_literal=400 * 1024 * 1024) as srv:
        t0 = time.monotonic()
        with pytest.raises(ProtocolError, match="too much data"):
            _connect(srv, mode)
        assert time.monotonic() - t0 < 5  # refused when announced, nothing downloaded


def test_huge_literal_after_login_ends_the_connection():
    with ScriptedImapServer(literal_after={"LIST": 100 * 1024 * 1024}) as srv:
        session = _connect(srv, "tls")
        with pytest.raises(ProtocolError, match="too much data"):
            session.list_folders()
        with pytest.raises(MailError):  # the stream is out of sync: the connection is gone
            session.list_folders()


def test_small_literal_below_the_cap_is_fine():
    with ScriptedImapServer(literal_after={"NOOP": 4096}) as srv:
        session = _connect(srv, "tls", max_literal=8192)
        session._client._imap.noop()  # pyright: ignore[reportPrivateUsage]


def test_response_flood_is_capped_per_command_and_resets_for_the_next():
    with ScriptedImapServer(flood_after={"LIST": 300_000, "NOOP": 150_000}) as srv:
        session = _connect(srv, "tls", max_untagged=200_000)
        session._client._imap.noop()  # pyright: ignore[reportPrivateUsage]  # 150 kB: under the cap
        session._client._imap.noop()  # pyright: ignore[reportPrivateUsage]  # counter was reset
        with pytest.raises(ProtocolError, match="too much data"):
            session.list_folders()


def test_flood_in_the_greeting_phase_of_login_is_capped():
    with ScriptedImapServer(flood_after={"AUTHENTICATE": 500_000}) as srv:
        with pytest.raises(ProtocolError, match="too much data"):
            _connect(srv, "tls", max_untagged=100_000)


def test_data_injected_before_starttls_does_not_survive_the_upgrade():
    """Python 3.14's imaplib kept bytes read before TLS and parsed them afterwards."""
    inj = b"* CAPABILITY IMAP4rev1 AUTH=PLAIN INJECTED-BY-MITM\r\n"
    with ScriptedImapServer(implicit_tls=False, starttls_inject=inj) as srv:
        if sys.version_info >= (3, 14):  # imaplib keeps the pre-TLS bytes: we refuse
            with pytest.raises(TlsError):
                _connect(srv, "starttls")
        else:  # imaplib drops them with the old file object
            session = _connect(srv, "starttls")
            assert "INJECTED-BY-MITM" not in session.capabilities


def test_header_fetch_is_partial():
    from universal_email_mcp.mail import imap

    assert f"<0.{MAX_HEADER_FETCH}>" in imap._HEADER_FIELDS  # pyright: ignore[reportPrivateUsage]
    assert f"<0.{MAX_HEADER_FETCH}>" in imap._RECIPIENT_FIELDS  # pyright: ignore[reportPrivateUsage]
