"""Portal connection tests: SSRF guards for servers a user names, SMTP login check, outcomes."""

from __future__ import annotations

import pytest

from tests.oauth_util import make_app, operator
from tests.portal_util import Browser, ids_in
from tests.smtp_sink import SmtpSink
from universal_email_mcp.errors import AuthFailed, TlsError
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.mail.smtp import check_login
from universal_email_mcp.models import Endpoint, TlsSettings
from universal_email_mcp.portal.connect import (
    AUTH,
    BLOCKED,
    OK,
    TIMEOUT,
    LiveTester,
    classify,
)
from universal_email_mcp.portal.service import CUSTOM_PORTS

INSECURE = TlsSettings(verify=False)
LOCAL = NetPolicy(allow_private=True, connect_timeout=5, read_timeout=5)


# ---------------------------------------------------------------- SMTP login check


def test_smtp_login_check_sends_nothing():
    with SmtpSink(implicit_tls=True, user="u", password="p") as sink:
        ext = check_login(
            Endpoint("localhost", sink.port, "tls"), "u", "p", tls=INSECURE, net=LOCAL
        )
        assert "8BITMIME" in ext
        assert sink.messages == [] and "MAIL" not in sink.commands and "DATA" not in sink.commands


def test_smtp_login_check_reports_a_wrong_password():
    with SmtpSink(implicit_tls=True, user="u", password="p") as sink, pytest.raises(AuthFailed):
        check_login(Endpoint("localhost", sink.port, "tls"), "u", "wrong", tls=INSECURE, net=LOCAL)


def test_smtp_login_check_refuses_login_without_tls():
    with SmtpSink(offer_starttls=False) as sink, pytest.raises(TlsError):
        check_login(
            Endpoint("localhost", sink.port, "starttls"), "alice", "secret", tls=INSECURE, net=LOCAL
        )


def test_smtp_login_check_verifies_the_certificate():
    with SmtpSink(implicit_tls=True) as sink, pytest.raises(TlsError):
        check_login(Endpoint("localhost", sink.port, "tls"), "alice", "secret", net=LOCAL)


async def test_the_live_tester_maps_results_to_codes():
    tester = LiveTester(tls=INSECURE)
    with SmtpSink(implicit_tls=True, user="u", password="p") as sink:
        ep = Endpoint("localhost", sink.port, "tls")
        ok = await tester.submission(ep, "u", "p", LOCAL)
        assert ok.status == OK and "8BITMIME" in ok.features
        assert (await tester.submission(ep, "u", "bad", LOCAL)).status == AUTH
    dead = await tester.submission(Endpoint("localhost", 1, "tls"), "u", "p", LOCAL)
    assert dead.status == "unreachable"
    strict = await LiveTester().submission(ep, "u", "p", LOCAL)  # self-signed: no trust
    assert strict.status == "tls"


def test_classify_is_defensive():
    assert classify(ValueError("x")) == "protocol"
    assert classify(TimeoutError()) == TIMEOUT


# ---------------------------------------------------------------- SSRF through the portal


class Resolving:
    """A resolver that answers from a table and records what was asked."""

    def __init__(self, table: dict[str, list[str]]) -> None:
        self.table = table
        self.asked: list[tuple[str, int]] = []

    def __call__(self, host: str, port: int) -> list[str]:
        self.asked.append((host, port))
        return self.table[host]


@pytest.mark.parametrize(
    "addresses",
    [
        ["169.254.169.254"],  # cloud metadata
        ["10.1.2.3"],
        ["192.168.0.10"],
        ["172.16.0.1"],
        ["127.0.0.1"],
        ["100.64.0.5"],  # CGNAT
        ["::1"],
        ["fd00:ec2::254"],
        ["::ffff:10.0.0.1"],
        ["93.184.216.34", "10.0.0.1"],  # one bad address among good ones refuses the host
        ["10.0.0.1", "93.184.216.34"],
    ],
)
async def test_a_user_named_server_must_resolve_to_public_addresses(addresses):
    resolver = Resolving({"mail.attacker.example": addresses})
    tester = LiveTester(tls=INSECURE, resolver=resolver)
    app = await make_app(tester=tester)
    with Browser(app) as b:
        b.signed_in()
        r = b.post(
            "/portal/accounts/new",
            {"name": "Evil", "protocol": "imap", "host": "mail.attacker.example",
             "username": "u", "password": "p"},
        )  # fmt: skip
        assert r.status_code == 400 and "server address is not allowed" in r.text
    assert resolver.asked == [("mail.attacker.example", 993)]  # resolved once, never connected


async def test_free_entry_is_limited_to_the_mail_ports():
    app = await make_app()
    portal = app.state.portal_service
    assert portal.custom_allowed and portal.custom_net.allowed_ports == CUSTOM_PORTS
    assert CUSTOM_PORTS == {993, 995, 465, 587}
    assert not portal.net.allow_private and portal.net.allowed_ports is None


async def test_listed_servers_are_trusted_with_any_port_and_private_addresses_follow_the_operator():
    from dataclasses import replace

    from universal_email_mcp.config import Settings
    from universal_email_mcp.presets import profile_for_host

    server = profile_for_host("imap.corp.example")
    op = operator(mail_servers=(server,))
    app = await make_app(op)
    assert not app.state.portal_service.custom_allowed
    assert not app.state.portal_service.net.allow_private
    op2 = replace(op, settings=Settings(allow_private_networks=True))
    app2 = await make_app(op2)
    assert app2.state.portal_service.net.allow_private


async def test_the_account_test_button_uses_the_servers_trust_class():
    from tests.portal_util import FakeTester
    from universal_email_mcp.presets import profile_for_host

    tester = FakeTester()
    server = profile_for_host("imap.corp.example")
    app = await make_app(
        operator(mail_servers=(server,), login_domains={"example.org": server}), tester=tester
    )
    with Browser(app) as b:
        b.signed_in()
        (aid,) = ids_in(b.page("/portal/accounts"), "accounts")
        r = b.post(f"/portal/accounts/{aid}/test")
        assert r.status_code == 200
        assert all(n.allowed_ports is None for n in tester.nets)  # preset account: operator-trusted
    app2 = await make_app(tester=tester)
    with Browser(app2) as b2:
        b2.signed_in()
        b2.post(
            "/portal/accounts/new",
            {"name": "Mine", "protocol": "imap", "host": "mail.mine.example",
             "username": "u", "password": "p"},
        )  # fmt: skip
        assert tester.nets[-1].allowed_ports == CUSTOM_PORTS


def test_blocked_is_a_code_the_pages_know():
    assert BLOCKED == "blocked"
