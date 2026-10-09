"""The portal pages: sign-in, accounts, re-authentication (in-memory store, scripted tester)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tests.oauth_util import PASSWORD, FakeLogin, make_app, operator
from tests.portal_util import Browser, FakeTester, ids_in, text_of
from universal_email_mcp.oauth.identity import Pseudonyms
from universal_email_mcp.presets import profile_for_host
from universal_email_mcp.store import (
    Identity,
    KeyRing,
    MailAccount,
    MemoryBackend,
    SessionPolicy,
    Store,
    User,
)

ALICE = Pseudonyms(b"p" * 32).user_id("alice@example.org")


class Clock:
    def __init__(self) -> None:
        self.t = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw: float) -> None:
        self.t += timedelta(**kw)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(clock: Clock) -> Store:
    return Store(MemoryBackend(), KeyRing({"k1": b"k" * 32}), clock=clock, policy=SessionPolicy())


@pytest.fixture
def tester() -> FakeTester:
    return FakeTester()


@pytest.fixture
async def app(store: Store, tester: FakeTester):
    return await make_app(store=store, tester=tester)


@pytest.fixture
def alice(app):
    with Browser(app) as b:
        yield b.signed_in()


def add_account(b: Browser, **over: Any):
    data = {
        "name": "Work",
        "protocol": "imap",
        "host": "mail.example.net",
        "username": "alice@example.net",
        "password": "work-secret",
        "perm": ["read", "organize"],
        "identity": "1",
        **over,
    }
    return b.post("/portal/accounts/new", data)


# ---------------------------------------------------------------- sign-in


def test_portal_pages_need_a_session(app):
    with Browser(app) as b:
        for path in ("/portal/accounts", "/portal/identities", "/portal/clients"):
            r = b.get(path)
            assert r.status_code == 303 and r.headers["location"].startswith("/portal/signin")
        assert b.get("/portal").headers["location"] == "/portal/signin"


def test_sign_in_creates_the_main_account_and_identity(alice, store):
    page = alice.page("/portal/accounts")
    assert "Main" in page and "<code>imap.example.org</code>" in page
    assert "<h1>Mail accounts</h1>" in page
    ident = alice.page("/portal/identities")
    assert "alice@example.org" in ident
    assert PASSWORD not in page and PASSWORD not in ident


async def test_the_sign_in_mailbox_is_a_real_account(alice, store):
    (acc,) = await store.list_for_user(MailAccount, ALICE)
    assert acc.password == PASSWORD and acc.username == "alice@example.org"
    assert acc.protocol == "imap" and set(acc.permissions) == {"read", "organize", "drafts"}
    (ident,) = await store.list_for_user(Identity, ALICE)
    assert ident.copies_account_id == acc.id and ident.is_default and not ident.send
    assert ident.smtp_account_id == acc.id and ident.smtp_password == PASSWORD
    user = await store.get(User, ALICE)
    assert user is not None and user.default_identity_id == ident.id


def test_sign_in_failures(app):
    with Browser(app) as b:
        r = b.sign_in("wrong")
        assert r.status_code == 401 and "Sign-in failed" in r.text
        r = b.post("/portal/signin", {"address": "x@unknown.example", "password": PASSWORD})
        assert r.status_code == 401


def test_sign_in_next_cannot_leave_the_portal(app):
    with Browser(app) as b:
        r = b.sign_in(next_="https://evil.example/")
        assert r.headers["location"] == "/portal/accounts"
    with Browser(app) as b2:
        r = b2.sign_in(next_="//evil.example/portal")
        assert r.headers["location"] == "/portal/accounts"
    with Browser(app) as b3:
        r = b3.sign_in(next_="/portal/clients")
        assert r.headers["location"] == "/portal/clients"


def test_sign_out_ends_the_session(alice):
    r = alice.post("/portal/signout")
    assert r.status_code == 303
    assert alice.get("/portal/accounts").status_code == 303


async def test_later_sign_ins_refresh_the_stored_password(store, tester):
    login = FakeLogin()
    app = await make_app(store=store, tester=tester, login=login)
    with Browser(app) as b:
        b.signed_in()
        login.password = "changed-at-the-server"
        with Browser(app) as b2:
            assert b2.sign_in("changed-at-the-server").status_code == 303
    (acc,) = await store.list_for_user(MailAccount, ALICE)
    assert acc.password == "changed-at-the-server"
    (ident,) = await store.list_for_user(Identity, ALICE)
    assert (
        len(await store.list_for_user(MailAccount, ALICE)) == 1 and ident.smtp_account_id == acc.id
    )


async def test_a_removed_main_account_does_not_come_back(app, store):
    with Browser(app) as b:
        b.signed_in()
        (acc,) = await store.list_for_user(MailAccount, ALICE)
        assert b.post(f"/portal/accounts/{acc.id}/remove").status_code == 303
        assert await store.list_for_user(MailAccount, ALICE) == []
        with Browser(app) as b2:
            b2.signed_in()
            assert await store.list_for_user(MailAccount, ALICE) == []
            assert "no mail account yet" in b2.page("/portal/accounts")


# ---------------------------------------------------------------- adding accounts


def test_add_an_account_with_free_entry(alice, tester, store):
    r = add_account(alice)
    assert r.status_code == 303 and r.headers["location"].endswith("?notice=account_added")
    (call,) = tester.calls
    assert call[0] == "imap" and call[1].host == "mail.example.net" and call[1].port == 993
    page = alice.page("/portal/accounts")
    assert "Work" in page and "<code>mail.example.net</code>" in page
    assert "work-secret" not in page


async def test_added_account_is_stored_sealed_with_permissions(alice, store):
    add_account(alice, perm=["organize", "delete", "bogus"])
    accounts = await store.list_for_user(MailAccount, ALICE)
    work = next(a for a in accounts if a.name == "Work")
    assert work.permissions == ("read", "organize", "delete")
    assert work.password == "work-secret" and work.host == "mail.example.net"
    assert work.port == 993 and work.tls == "implicit" and work.preset == ""
    idents = await store.list_for_user(Identity, ALICE)
    assert any(i.addresses == ("alice@example.net",) and not i.is_default for i in idents)
    # the backend never holds the password in clear
    doc = await store.backend.get(MailAccount.KIND, work.id)
    assert doc is not None and "work-secret" not in repr(doc)


def test_connection_failures_are_reported_and_nothing_is_stored(alice, tester):
    for status, text in (
        ("auth", "rejected the user name or password"),
        ("unreachable", "could not be reached"),
        ("tls", "secure connection"),
        ("blocked", "not allowed"),
        ("unsupported", "lacks features"),
        ("timeout", "did not answer in time"),
        ("protocol", "unexpected way"),
    ):
        tester.script["bad"] = status
        r = add_account(alice, password="bad", username=f"{status}@x.org")
        assert r.status_code == 400 and text in r.text, status
        assert "bad" not in text_of(r.text)
    assert "Work" not in alice.page("/portal/accounts")


def test_form_validation(alice):
    assert "Give the account a name" in add_account(alice, name="  ").text
    for host in ("10.0.0.1", "localhost", "[::1]", "a b.example", "", "mail"):
        r = add_account(alice, host=host)
        assert r.status_code == 400 and "host name of the mail server" in r.text, host
    assert "Enter the user name" in add_account(alice, username="").text
    assert "without line breaks" in add_account(alice, password="a\nb").text
    assert "without line breaks" in add_account(alice, password="").text
    r = add_account(alice, username="a\r\nb@x.org")
    assert r.status_code == 400 and "Enter the user name" in r.text
    add_account(alice, name="Dup")
    assert "already have an account with this name" in add_account(alice, name="dup").text


def test_hostile_names_are_escaped(alice):
    add_account(alice, name='<script>alert(1)</script>"x', host="mail.example.org")
    page = alice.page("/portal/accounts")
    assert "<script>alert" not in page and "&lt;script&gt;alert(1)" in page


def test_account_limit(app, store, tester):
    import dataclasses

    op = operator()
    op = replace(op, oauth=dataclasses.replace(op.oauth, max_accounts=2))

    async def build():
        return await make_app(op, store=store, tester=tester)

    import asyncio

    app2 = asyncio.run(build())
    with Browser(app2) as b:
        b.signed_in()
        assert add_account(b, name="Two").status_code == 303
        r = add_account(b, name="Three")
        assert r.status_code == 400 and "limit" in r.text


def test_the_add_form_for_one_fixed_server(store, tester):
    import asyncio

    server = profile_for_host("imap.provider.example")
    op = operator(mail_servers=(server,), login_domains={"example.org": server})
    app = asyncio.run(make_app(op, store=store, tester=tester))
    with Browser(app) as b:
        b.signed_in()
        page = b.page("/portal/accounts/new")
        assert 'name="host"' not in page and 'name="server"' not in page
        assert "</strong> imap.provider.example</p>" in page
        # a host posted anyway is ignored: the operator's server is used
        r = add_account(b, host="evil.example")
        assert r.status_code == 303
        assert tester.calls[-1][1].host == "imap.provider.example"


def test_the_add_form_with_several_servers(store, tester):
    import asyncio

    one, two = profile_for_host("imap.one.example"), profile_for_host("imap.two.example")
    op = operator(mail_servers=(one, two), login_domains={"example.org": one})
    app = asyncio.run(make_app(op, store=store, tester=tester))
    with Browser(app) as b:
        b.signed_in()
        page = b.page("/portal/accounts/new")
        assert 'name="server"' in page and 'name="host"' not in page
        assert "Choose a mail server" in add_account(b, server="evil.example").text
        assert "Choose a mail server" in add_account(b, server="").text
        assert add_account(b, server="imap.two.example").status_code == 303
        assert tester.calls[-1][1].host == "imap.two.example"


def test_pop3_accounts_use_the_pop3_endpoint(alice, tester):
    r = add_account(alice, protocol="pop3", name="Old", perm=["read", "organize", "delete"])
    assert r.status_code == 303
    protocol, endpoint, *_ = tester.calls[-1]
    assert protocol == "pop3" and endpoint.port == 995
    assert "POP3" in alice.page("/portal/accounts")


async def test_pop3_permissions_are_capped(alice, store):
    add_account(alice, protocol="pop3", name="Old", perm=["read", "organize", "delete"])
    acc = next(a for a in await store.list_for_user(MailAccount, ALICE) if a.name == "Old")
    assert acc.permissions == ("read",)


# ---------------------------------------------------------------- the account page


def _account_id(b: Browser, name: str) -> str:
    page = b.page("/portal/accounts")
    for aid in ids_in(page, "accounts"):
        if name in b.page(f"/portal/accounts/{aid}"):
            return aid
    raise AssertionError(name)


def test_test_button_checks_incoming_and_sending(alice, tester):
    add_account(alice)
    aid = _account_id(alice, "Work")
    tester.calls.clear()
    r = alice.post(f"/portal/accounts/{aid}/test")
    assert r.status_code == 200
    assert "Receiving (IMAP)" in r.text and "Sending (SMTP)" in r.text
    assert "Connected and signed in" in r.text and "UIDPLUS" in r.text
    assert [c[0] for c in tester.calls] == ["imap", "smtp"]
    assert "work-secret" not in r.text


def test_test_button_reports_a_failing_login(alice, tester):
    add_account(alice)
    aid = _account_id(alice, "Work")
    tester.script["work-secret"] = "auth"
    r = alice.post(f"/portal/accounts/{aid}/test")
    assert "rejected the user name or password" in r.text


def test_other_users_accounts_do_not_exist_for_you(app, alice):
    add_account(alice)
    aid = _account_id(alice, "Work")
    with Browser(app, "bob@example.org") as bob:
        bob.signed_in()
        for path in (f"/portal/accounts/{aid}", f"/portal/accounts/{aid}/remove"):
            assert bob.get(path).status_code == 404
        assert bob.post(f"/portal/accounts/{aid}/test").status_code == 404
        assert bob.post(f"/portal/accounts/{aid}/remove").status_code == 404
        assert bob.get("/portal/accounts/a_nothing").status_code == 404


async def test_permissions_can_be_lowered_freely_and_raised_after_reauth(
    alice, store, clock, tester
):
    add_account(alice, perm=["read", "organize"])
    aid = _account_id(alice, "Work")
    r = alice.post(f"/portal/accounts/{aid}/permissions", {"perm": ["read"]})
    assert r.status_code == 303 and "permissions_saved" in r.headers["location"]
    acc = await store.get(MailAccount, aid)
    assert acc and acc.permissions == ("read",)
    clock.advance(minutes=10)  # the sign-in is no longer fresh
    r = alice.post(f"/portal/accounts/{aid}/permissions", {"perm": ["read", "delete"]})
    assert r.status_code == 303 and r.headers["location"].startswith("/portal/reauth")
    acc = await store.get(MailAccount, aid)
    assert acc and acc.permissions == ("read",)
    r = alice.post(f"/portal/accounts/{aid}/permissions", {"perm": []})  # lowering: still free
    assert r.headers["location"].endswith("permissions_saved")


async def test_permissions_cannot_exceed_the_operator_policy(store, tester):
    from universal_email_mcp.config import Policy

    op = operator(policy=Policy(read_only=True))
    app = await make_app(op, store=store, tester=tester)
    with Browser(app) as b:
        b.signed_in()
        add_account(b, perm=["read", "organize", "delete", "drafts"])
        acc = next(a for a in await store.list_for_user(MailAccount, ALICE) if a.name == "Work")
        assert acc.permissions == ("read",)


# ---------------------------------------------------------------- re-authentication


def test_sensitive_pages_ask_for_the_password_when_it_is_stale(alice, clock):
    assert alice.get("/portal/accounts/new").status_code == 200
    clock.advance(minutes=6)
    r = alice.get("/portal/accounts/new")
    assert r.status_code == 303 and r.headers["location"].startswith("/portal/reauth")
    assert "next=%2Fportal%2Faccounts%2Fnew" in r.headers["location"]
    r = add_account(alice)  # the POST is refused the same way, nothing is added
    assert r.status_code == 303 and r.headers["location"].startswith("/portal/reauth")
    assert "Work" not in alice.page("/portal/accounts")


def test_reauth_with_the_right_password_opens_the_window(alice, clock):
    clock.advance(minutes=6)
    page = alice.page("/portal/reauth?next=/portal/accounts/new")
    assert "Confirm your password" in page
    r = alice.post("/portal/reauth", {"password": "nope", "next": "/portal/accounts/new"})
    assert r.status_code == 401 and "not correct" in r.text
    r = alice.post("/portal/reauth", {"password": PASSWORD, "next": "/portal/accounts/new"})
    assert r.status_code == 303 and r.headers["location"] == "/portal/accounts/new"
    assert alice.get("/portal/accounts/new").status_code == 200
    assert add_account(alice).status_code == 303
    clock.advance(minutes=4)
    assert alice.get("/portal/accounts/new").status_code == 200
    clock.advance(minutes=2)  # the window is five minutes from the last password entry
    assert alice.get("/portal/accounts/new").status_code == 303


def test_reauth_next_is_sanitised(alice):
    r = alice.post("/portal/reauth", {"password": PASSWORD, "next": "https://evil.example"})
    assert r.headers["location"] == "/portal/accounts"


def test_reauth_wrong_passwords_are_rate_limited(alice):
    codes = [
        alice.post("/portal/reauth", {"password": "x", "next": "/portal"}).status_code
        for _ in range(7)
    ]
    assert codes[:5] == [401] * 5 and codes[-1] == 429
    # and the right one is refused while blocked
    assert (
        alice.post("/portal/reauth", {"password": PASSWORD, "next": "/portal"}).status_code == 429
    )


async def test_account_removal_needs_a_fresh_password(alice, clock, store):
    add_account(alice)
    aid = _account_id(alice, "Work")
    clock.advance(minutes=10)
    assert alice.get(f"/portal/accounts/{aid}/remove").status_code == 303
    assert alice.post(f"/portal/accounts/{aid}/remove").status_code == 303
    assert await store.get(MailAccount, aid) is not None
    alice.post("/portal/reauth", {"password": PASSWORD, "next": "/portal"})
    page = alice.page(f"/portal/accounts/{aid}/remove")
    assert "Remove this account?" in page
    r = alice.post(f"/portal/accounts/{aid}/remove")
    assert r.status_code == 303 and "account_removed" in r.headers["location"]
    assert await store.get(MailAccount, aid) is None


# ---------------------------------------------------------------- password change


async def test_password_change_is_checked_and_reaches_the_identity_copy(alice, tester, store):
    add_account(alice)
    aid = _account_id(alice, "Work")
    page = alice.page(f"/portal/accounts/{aid}/password")
    assert "work-secret" not in page
    tester.script["bad"] = "auth"
    r = alice.post(f"/portal/accounts/{aid}/password", {"password": "bad"})
    assert r.status_code == 400 and "rejected" in r.text
    acc = await store.get(MailAccount, aid)
    assert acc and acc.password == "work-secret"
    r = alice.post(f"/portal/accounts/{aid}/password", {"password": "new-secret"})
    assert r.status_code == 303 and "password_saved" in r.headers["location"]
    acc = await store.get(MailAccount, aid)
    assert acc and acc.password == "new-secret"
    copies = [i for i in await store.list_for_user(Identity, ALICE) if i.smtp_account_id == aid]
    assert copies and all(i.smtp_password == "new-secret" for i in copies)


# ---------------------------------------------------------------- connection test limits


async def test_connection_tests_are_rate_limited(store, tester):
    from universal_email_mcp.oauth.config import RateLimits

    app = await make_app(
        store=store, tester=tester, rate_limits=RateLimits(test_per_user=3, test_per_target=100)
    )
    with Browser(app) as b:
        b.signed_in()
        results = [
            add_account(
                b, name=f"A{i}", username=f"u{i}@x.org", host=f"h{i}.example.net"
            ).status_code
            for i in range(5)
        ]
        assert results[:3] == [303, 303, 303] and results[3:] == [429, 429]
        assert len(tester.calls) == 3  # throttled requests never reached the network


async def test_guessing_passwords_for_one_mailbox_is_throttled(store, tester):
    app = await make_app(store=store, tester=tester)
    with Browser(app) as b:
        b.signed_in()
        tester.script.update({f"p{i}": "auth" for i in range(10)})
        codes = [add_account(b, password=f"p{i}", name=f"N{i}").status_code for i in range(8)]
        assert codes.count(429) >= 3  # at most 5 per mailbox and 15 minutes


# ---------------------------------------------------------------- sign-in opt-in


def _stored(store: Store) -> str:
    return repr(store.backend._data)  # pyright: ignore[reportAttributeAccessIssue,reportPrivateUsage]


def test_sign_in_form_offers_a_preticked_checkbox(app):
    with Browser(app) as b:
        page = b.page("/portal/signin")
        assert 'name="store_password" value="1" checked' in page
        assert "Use this mailbox with AI clients (stores the password encrypted)" in page
        assert 'name="csrf_token"' in page


async def test_unticked_sign_in_stores_nothing(store, tester):
    app = await make_app(store=store, tester=tester)
    with Browser(app) as b:
        assert b.sign_in(store=False).status_code == 303
        assert b.get("/portal/accounts").status_code == 200  # still signed in
        assert await store.list_for_user(MailAccount, ALICE) == []
        assert await store.list_for_user(Identity, ALICE) == []
        user = await store.get(User, ALICE)
        assert user is not None and not user.settings.get("primary_account")
        assert PASSWORD not in _stored(store)
        assert ids_in(b.page("/portal/accounts"), "accounts") == []


async def test_a_later_ticked_sign_in_opts_in(store, tester):
    app = await make_app(store=store, tester=tester)
    with Browser(app) as b:
        b.sign_in(store=False)
    with Browser(app) as b2:
        b2.sign_in()
    (acc,) = await store.list_for_user(MailAccount, ALICE)
    assert acc.name == "Main" and acc.password == PASSWORD


async def test_unticked_later_sign_in_still_refreshes_an_existing_main(store, tester):
    login = FakeLogin()
    app = await make_app(store=store, tester=tester, login=login)
    with Browser(app) as b:
        b.signed_in()
        login.password = "changed-at-the-server"
        with Browser(app) as b2:
            assert b2.sign_in("changed-at-the-server", store=False).status_code == 303
    (acc,) = await store.list_for_user(MailAccount, ALICE)
    assert acc.password == "changed-at-the-server"


async def test_removed_main_does_not_come_back_by_signing_in(store, tester):
    app = await make_app(store=store, tester=tester)
    with Browser(app) as b:
        b.signed_in()
        (acc,) = await store.list_for_user(MailAccount, ALICE)
        await store.delete(MailAccount, acc.id)
        with Browser(app) as b2:
            b2.sign_in()  # ticked
    assert await store.list_for_user(MailAccount, ALICE) == []


async def test_sign_in_without_csrf_stores_nothing(store, tester):
    app = await make_app(store=store, tester=tester)
    with Browser(app) as b:
        r = b.client.post(
            "/portal/signin",
            data={"address": b.address, "password": PASSWORD, "store_password": "1"},
        )
        assert r.status_code == 403
    assert await store.list_for_user(MailAccount, ALICE) == []
    assert PASSWORD not in _stored(store)
