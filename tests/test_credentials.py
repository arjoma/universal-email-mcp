"""Credentials with control characters never reach a server (all three protocols)."""

from __future__ import annotations

import pytest

from universal_email_mcp.errors import AuthFailed
from universal_email_mcp.mail.credentials import check_credentials, imap_quote
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.mail.pop3 import Pop3Session
from universal_email_mcp.mail.smtp import check_login
from universal_email_mcp.models import Endpoint, TlsSettings

from .pop3_server import ScriptedPop3Server
from .smtp_sink import SmtpSink

BAD = ["a\r\nQUIT", "a\nb", "a\rb", "a\x00b", "a\x7fb"]


def test_imap_quote_escapes_backslash_and_quote():
    assert imap_quote('a"b\\c{1}*') == '"a\\"b\\\\c{1}*"'


@pytest.mark.parametrize("bad", BAD)
def test_check_credentials_refuses_control_characters(bad: str):
    for user, pw in ((bad, "x"), ("u", bad)):
        with pytest.raises(AuthFailed, match="control characters"):
            check_credentials(user, pw)
    with pytest.raises(AuthFailed):
        check_credentials("", "x")
    check_credentials('a"b\\{1}*@x.org', 'p"\\')


@pytest.mark.parametrize("bad", BAD)
def test_pop3_sends_nothing(bad: str):
    with ScriptedPop3Server([]) as srv:
        with pytest.raises(AuthFailed):
            Pop3Session.connect(
                Endpoint("localhost", srv.port, "tls"),
                bad,
                "secret",
                net=NetPolicy(allow_private=True, read_timeout=5),
                tls=TlsSettings(verify=False),
                resolver=lambda _h, _p: ["127.0.0.1"],
            )
        assert "USER" not in srv.names and "PASS" not in srv.names and "AUTH" not in srv.names


@pytest.mark.parametrize("bad", BAD)
def test_smtp_sends_no_auth(bad: str):
    with SmtpSink() as sink:
        with pytest.raises(AuthFailed, match="control characters"):
            check_login(
                Endpoint("localhost", sink.port, "starttls"),
                bad,
                "secret",
                tls=TlsSettings(verify=False),
                net=NetPolicy(allow_private=True, read_timeout=5),
                resolver=lambda _h, _p: ["127.0.0.1"],
            )
        assert not any(c.startswith("AUTH") for c in sink.commands)
