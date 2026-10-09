"""The portal against real servers: Dovecot (IMAP, POP3) and the SMTP sink, real logins."""

from __future__ import annotations

import uuid
from dataclasses import replace

import pytest

from tests.oauth_util import make_app, operator
from tests.portal_util import Browser, ids_in
from tests.smtp_sink import SmtpSink
from universal_email_mcp.config import Settings
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import Endpoint, ServerProfile, TlsSettings
from universal_email_mcp.oauth.identity import ImapLoginVerifier, Pseudonyms
from universal_email_mcp.portal.connect import LiveTester
from universal_email_mcp.store import Identity, MailAccount, MemoryBackend, Store, KeyRing

from .conftest import ImapServer

pytestmark = pytest.mark.integration


def profile(server: ImapServer, smtp_port: int, imap_port: int | None = None) -> ServerProfile:
    return ServerProfile(
        name="dovecot",
        label="Dovecot",
        imap=Endpoint(server.host, imap_port or server.imaps_port, "tls"),
        pop3=Endpoint(server.host, server.pop3s_port, "tls"),
        smtp=Endpoint("localhost", smtp_port, "tls"),
    )


async def build(server: ImapServer, sink: SmtpSink, store: Store, imap_port: int | None = None):
    prof = profile(server, sink.port, imap_port)
    op = operator(
        mail_servers=(prof,),
        login_domains={"example.org": prof},
        settings=Settings(allow_private_networks=True),
    )
    tester = LiveTester(tls=TlsSettings(verify=False))
    login = ImapLoginVerifier(
        NetPolicy(allow_private=True, connect_timeout=5, read_timeout=10), TlsSettings(verify=False)
    )
    return await make_app(op, store=store, login=login, tester=tester)


@pytest.fixture
def store() -> Store:
    return Store(MemoryBackend(), KeyRing({"k1": b"k" * 32}))


async def test_real_sign_in_account_tests_and_sending_login(imap_server: ImapServer, store: Store):
    user = f"portal{uuid.uuid4().hex[:8]}@example.org"
    uid = Pseudonyms(b"p" * 32).user_id(user)
    with SmtpSink(implicit_tls=True, user=user, password=imap_server.password) as sink:
        app = await build(imap_server, sink, store)
        with Browser(app, user) as b:
            assert b.sign_in(imap_server.password).status_code == 303
            (main,) = await store.list_for_user(MailAccount, uid)
            assert main.port == imap_server.imaps_port and main.password == imap_server.password

            # test button: real IMAP login + capabilities, real SMTP login
            r = b.post(f"/portal/accounts/{main.id}/test")
            assert r.status_code == 200
            assert "Receiving (IMAP)" in r.text and "Sending (SMTP)" in r.text
            assert r.text.count("Connected and signed in") == 2
            assert "UIDPLUS" in r.text and "MOVE" in r.text  # Dovecot's capabilities
            assert imap_server.password not in r.text

            # a second mailbox on the same server: the real login decides
            other = f"other{uuid.uuid4().hex[:8]}@example.org"
            good = b.post(
                "/portal/accounts/new",
                {"name": "Other", "protocol": "imap", "username": other,
                 "password": imap_server.password, "perm": ["read", "organize"]},
            )  # fmt: skip
            assert good.status_code == 303
            bad = b.post(
                "/portal/accounts/new",
                {"name": "Wrong", "protocol": "imap", "username": other, "password": "not-it"},
            )
            assert bad.status_code == 400 and "rejected the user name or password" in bad.text
            names = {a.name for a in await store.list_for_user(MailAccount, uid)}
            assert names == {"Main", "Other"}

            # POP3 against the same Dovecot
            pop = b.post(
                "/portal/accounts/new",
                {"name": "Pop", "protocol": "pop3", "username": other,
                 "password": imap_server.password},
            )  # fmt: skip
            assert pop.status_code == 303
            pop_acc = next(
                a for a in await store.list_for_user(MailAccount, uid) if a.name == "Pop"
            )
            assert pop_acc.protocol == "pop3" and pop_acc.port == imap_server.pop3s_port
            assert pop_acc.permissions == ("read",)
            r = b.post(f"/portal/accounts/{pop_acc.id}/test")
            assert "Receiving (POP3)" in r.text and "UIDL" in r.text

            # the identity's sending login, then with a wrong one
            (ident,) = [
                i
                for i in await store.list_for_user(Identity, uid)
                if i.copies_account_id == main.id
            ]
            r = b.post(f"/portal/identities/{ident.id}/test")
            assert "Connected and signed in" in r.text and "Sending (SMTP)" in r.text
            await store.update(replace(ident, smtp_password="stale"))
            r = b.post(f"/portal/identities/{ident.id}/test")
            assert "rejected the user name or password" in r.text
            # fixing the account password fixes the identity copy (reached via the account page)
            r = b.post(f"/portal/accounts/{main.id}/password", {"password": imap_server.password})
            assert r.status_code == 303
            r = b.post(f"/portal/identities/{ident.id}/test")
            assert "Connected and signed in" in r.text
        assert sink.auth_failures >= 1


async def test_unreachable_and_wrong_password_on_the_account_test(
    imap_server: ImapServer, store: Store
):
    user = f"portal{uuid.uuid4().hex[:8]}@example.org"
    uid = Pseudonyms(b"p" * 32).user_id(user)
    with SmtpSink(implicit_tls=True, user=user, password=imap_server.password) as sink:
        app = await build(imap_server, sink, store)
        with Browser(app, user) as b:
            b.sign_in(imap_server.password)
            (main,) = await store.list_for_user(MailAccount, uid)
            main = await store.update(replace(main, password="changed-meanwhile"))
            r = b.post(f"/portal/accounts/{main.id}/test")
            assert "rejected the user name or password" in r.text
            await store.update(replace(main, password=imap_server.password, port=1))
            r = b.post(f"/portal/accounts/{main.id}/test")
            assert "could not be reached" in r.text
            assert ids_in(b.page("/portal/accounts"), "accounts") == [main.id]
