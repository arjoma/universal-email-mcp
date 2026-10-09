"""ImapSession against a scripted localhost server: aborts, TLS/login refusals."""

from __future__ import annotations

import threading
import time

import pytest

from universal_email_mcp.config import parse_config
from universal_email_mcp.errors import AccountTimeout, AuthFailed, MailError, TlsError
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import Account, Endpoint, TlsMode, TlsSettings
from universal_email_mcp.service.router import AccountRouter

from .imap_server import ScriptedImapServer


def _connect(srv: ScriptedImapServer, mode: TlsMode, read_timeout: float = 20.0) -> ImapSession:
    return ImapSession.connect(
        Endpoint("localhost", srv.port, mode),
        "user",
        "secret",
        account_name="A",
        net=NetPolicy(allow_private=True, read_timeout=read_timeout),
        tls=TlsSettings(verify=False),
        resolver=lambda _h, _p: ["127.0.0.1"],
    )


@pytest.mark.parametrize("mode", ["tls", "starttls"])
def test_abort_unblocks_a_stalled_read_promptly(mode: TlsMode):
    with ScriptedImapServer(implicit_tls=mode == "tls", stall=frozenset({"LIST"})) as srv:
        session = _connect(srv, mode)
        outcome: dict[str, object] = {}

        def worker() -> None:
            t0 = time.monotonic()
            try:
                session.list_folders()
            except MailError as e:
                outcome["error"] = e
            outcome["seconds"] = time.monotonic() - t0

        th = threading.Thread(target=worker, daemon=True)
        th.start()
        assert srv.stalled.wait(5)
        t0 = time.monotonic()
        session.abort()
        assert time.monotonic() - t0 < 1.0  # was ~read_timeout (imaplib closed file first)
        th.join(3)
        assert not th.is_alive()
        assert isinstance(outcome["error"], MailError)
        assert float(outcome["seconds"]) < 3  # pyright: ignore[reportArgumentType]
        t0 = time.monotonic()
        session.close()  # the owner's cleanup is fast too
        assert time.monotonic() - t0 < 1.0
        assert srv.peer_closed.wait(3)


async def test_router_deadline_does_not_block_the_event_loop():
    with ScriptedImapServer(stall=frozenset({"LIST"})) as srv:
        cfg = parse_config(
            {
                "accounts": [{"name": "A", "username": "u", "server": "localhost"}],
                "limits": {"account_timeout": 0.5},
            }
        )

        def connector(_acc: Account, _cfg: object) -> ImapSession:
            return _connect(srv, "tls")

        router = AccountRouter(cfg, connectors={"imap": connector})
        acc = router.account("A")

        async def work(a: Account) -> object:
            return await router.call(a, lambda s: s.list_folders())

        t0 = time.monotonic()
        with pytest.raises(AccountTimeout):
            await router.run_one(acc, work)
        assert time.monotonic() - t0 < 2.0
        assert srv.peer_closed.wait(3)  # the connection really went away
        await router.aclose()


def test_refuses_login_when_starttls_is_not_offered():
    with ScriptedImapServer(implicit_tls=False, pre_tls_caps=("AUTH=PLAIN",)) as srv:
        with pytest.raises(TlsError, match="STARTTLS"):
            _connect(srv, "starttls")
        assert "LOGIN" not in srv.commands and "AUTHENTICATE" not in srv.commands


def test_refuses_login_with_logindisabled_and_no_auth_plain():
    with ScriptedImapServer(post_tls_caps=("LOGINDISABLED", "AUTH=GSSAPI")) as srv:
        with pytest.raises(AuthFailed, match="password login"):
            _connect(srv, "tls")
        assert "LOGIN" not in srv.commands and "AUTHENTICATE" not in srv.commands


def test_login_works_against_the_scripted_server():
    with ScriptedImapServer(implicit_tls=False) as srv:
        with _connect(srv, "starttls") as s:
            assert s.login_info.tls == "STARTTLS"
            assert s.login_info.auth_mechanism == "AUTHENTICATE PLAIN"


# ----------------------------------------------------------------- login credentials


def _login_with(srv: ScriptedImapServer, username: str, password: str = "secret") -> ImapSession:
    return ImapSession.connect(
        Endpoint("localhost", srv.port, "tls"),
        username,
        password,
        net=NetPolicy(allow_private=True, read_timeout=5),
        tls=TlsSettings(verify=False),
        resolver=lambda _h, _p: ["127.0.0.1"],
    )


@pytest.mark.parametrize(
    "name", ['a"b@example.org', "a\\b@example.org", "x{1}@example.org", "a*%]@x.org"]
)
def test_login_name_is_sent_as_one_quoted_string(name: str):
    with ScriptedImapServer(post_tls_caps=()) as srv:  # no AUTH=PLAIN: plain LOGIN
        _login_with(srv, name, 'p"w\\d').close()
        (login,) = [ln for ln in srv.lines if " LOGIN " in ln]
        quoted = name.replace("\\", "\\\\").replace('"', '\\"')
        assert login.split(" ", 2)[2] == f'"{quoted}" "p\\"w\\\\d"'


@pytest.mark.parametrize("bad", ["a\r\nA2 DELETE INBOX", "a\nb", "a\x00b", "a\rb"])
@pytest.mark.parametrize("caps", [(), ("AUTH=PLAIN",)])
def test_credentials_with_control_characters_are_refused_before_sending(
    bad: str, caps: tuple[str, ...]
):
    for username, password in ((bad, "secret"), ("user", bad)):
        with ScriptedImapServer(post_tls_caps=caps) as srv:
            with pytest.raises(AuthFailed, match="control characters"):
                _login_with(srv, username, password)
            assert "LOGIN" not in srv.commands and "AUTHENTICATE" not in srv.commands
            assert not any("DELETE" in ln for ln in srv.lines)
