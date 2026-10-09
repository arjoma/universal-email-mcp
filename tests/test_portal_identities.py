"""Sender identities in the portal: validation, send permission, defaults, removal."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tests.oauth_util import PASSWORD, make_app, operator
from tests.portal_util import Browser, FakeTester, ids_in
from universal_email_mcp.config import Policy
from universal_email_mcp.oauth.identity import Pseudonyms
from universal_email_mcp.store import (
    Grant,
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
async def alice(store, tester):
    app = await make_app(store=store, tester=tester)
    with Browser(app) as b:
        yield b.signed_in()


async def main_account(store: Store) -> MailAccount:
    (acc,) = await store.list_for_user(MailAccount, ALICE)
    return acc


def form(acc: MailAccount, **over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "address": "office@example.org",
        "display_name": "Company Office",
        "signature": "Best regards\nOffice",
        "smtp_account": acc.id,
        "store_account": acc.id,
    }
    return {**base, **over}


async def test_add_edit_and_remove_an_identity(alice, store):
    acc = await main_account(store)
    r = alice.post("/portal/identities/new", form(acc))
    assert r.status_code == 303 and "identity_saved" in r.headers["location"]
    page = alice.page("/portal/identities")
    assert "Company Office (office@example.org)" in page
    assert len(ids_in(page, "identities")) == 2
    idents = await store.list_for_user(Identity, ALICE)
    office = next(i for i in idents if i.addresses == ("office@example.org",))
    assert office.signature == "Best regards\nOffice" and not office.send and not office.is_default
    assert office.smtp_host and office.smtp_username == "alice@example.org"  # copied
    assert office.smtp_account_id == acc.id and office.copies_account_id == acc.id
    r = alice.post(
        f"/portal/identities/{office.id}",
        form(acc, display_name="Office Team", address="OFFICE@example.org"),
    )
    assert r.status_code == 303
    again = await store.get(Identity, office.id)
    assert (
        again and again.display_name == "Office Team" and again.addresses == ("office@example.org",)
    )
    r = alice.post(f"/portal/identities/{office.id}/remove")
    assert r.status_code == 303 and "identity_removed" in r.headers["location"]
    assert await store.get(Identity, office.id) is None


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("address", "not-an-address", "valid e-mail address"),
        ("address", "a@b.example\r\nBcc: x@evil.example", "valid e-mail address"),
        ("address", "a b@example.org", "valid e-mail address"),
        ("address", "<a@example.org>", "valid e-mail address"),
        ("display_name", "Eve\r\nBcc: victim@example.org", "plain text"),
        ("display_name", "Eve <eve@evil.example>", "plain text"),
        ("display_name", '"quoted"', "plain text"),
        ("display_name", "=?utf-8?b?ZXZpbA==?=", "plain text"),
        ("display_name", "x" * 200, "plain text"),
        ("signature", "bad\x00nul", "signature"),
        ("signature", "bad\x1b[31mescape", "signature"),
        ("signature", "x" * 2100, "signature"),
        ("smtp_account", "a_0000000000000000", "whose server can send"),
        ("store_account", "a_0000000000000000", "IMAP account"),
    ],
    ids=lambda v: repr(v)[:24],
)
async def test_hostile_identity_values_are_refused(alice, store, field, value, message):
    acc = await main_account(store)
    before = len(await store.list_for_user(Identity, ALICE))
    r = alice.post("/portal/identities/new", form(acc, **{field: value}))
    assert r.status_code == 400 and message in r.text
    assert len(await store.list_for_user(Identity, ALICE)) == before


async def test_identity_text_is_escaped_in_the_pages(alice, store):
    acc = await main_account(store)
    alice.post(
        "/portal/identities/new",
        form(acc, signature="<script>alert(1)</script>", display_name="Tom & Jerry"),
    )
    assert "<script>alert" not in alice.page("/portal/identities")
    ident = next(
        i
        for i in await store.list_for_user(Identity, ALICE)
        if i.addresses == ("office@example.org",)
    )
    edit = alice.page(f"/portal/identities/{ident.id}")
    assert "<script>alert" not in edit and "&lt;script&gt;alert(1)" in edit
    assert "Tom &amp; Jerry" in edit


async def test_duplicate_addresses_are_refused(alice, store):
    acc = await main_account(store)
    r = alice.post("/portal/identities/new", form(acc, address="Alice@Example.org"))
    assert r.status_code == 400 and "already have an identity" in r.text


async def test_the_default_identity_moves_and_never_disappears(alice, store):
    acc = await main_account(store)
    (first,) = await store.list_for_user(Identity, ALICE)
    assert first.is_default
    alice.post("/portal/identities/new", form(acc, default="on"))
    idents = await store.list_for_user(Identity, ALICE)
    defaults = [i for i in idents if i.is_default]
    assert len(defaults) == 1 and defaults[0].addresses == ("office@example.org",)
    user = await store.get(User, ALICE)
    assert user and user.default_identity_id == defaults[0].id
    alice.post(f"/portal/identities/{first.id}/default")
    assert [i.id for i in await store.list_for_user(Identity, ALICE) if i.is_default] == [first.id]
    # removing the default hands the role to another identity
    alice.post(f"/portal/identities/{first.id}/remove")
    (left,) = await store.list_for_user(Identity, ALICE)
    assert left.is_default
    user = await store.get(User, ALICE)
    assert user and user.default_identity_id == left.id


async def test_allowing_send_needs_the_password_and_the_right_accounts(alice, store, clock):
    acc = await main_account(store)
    (ident,) = await store.list_for_user(Identity, ALICE)
    clock.advance(minutes=10)
    r = alice.post(
        f"/portal/identities/{ident.id}", form(acc, address="alice@example.org", send="on")
    )
    assert r.status_code == 303 and r.headers["location"].startswith("/portal/reauth")
    again = await store.get(Identity, ident.id)
    assert again and not again.send
    alice.post("/portal/reauth", {"password": PASSWORD, "next": "/portal"})
    r = alice.post(
        f"/portal/identities/{ident.id}", form(acc, address="alice@example.org", send="on")
    )
    assert r.status_code == 303 and "identity_saved" in r.headers["location"]
    again = await store.get(Identity, ident.id)
    assert again and again.send
    # sending needs a sending account and an IMAP account with the drafts permission
    r = alice.post(
        f"/portal/identities/{ident.id}",
        form(acc, address="alice@example.org", send="on", smtp_account=""),
    )
    assert r.status_code == 400 and "needs a sending account" in r.text
    r = alice.post(
        f"/portal/identities/{ident.id}",
        form(acc, address="alice@example.org", send="on", store_account=""),
    )
    assert r.status_code == 400 and "needs a sending account" in r.text


async def test_send_needs_the_drafts_permission_on_the_store_account(alice, store):
    acc = await main_account(store)
    alice.post(f"/portal/accounts/{acc.id}/permissions", {"perm": ["read"]})
    r = alice.post("/portal/identities/new", form(acc, send="on"))
    assert r.status_code == 400 and "drafts permission" in r.text


async def test_send_is_not_offered_when_the_operator_forbids_it(store, tester):
    app = await make_app(operator(policy=Policy(send="off")), store=store, tester=tester)
    with Browser(app) as b:
        b.signed_in()
        acc = await main_account(store)
        assert 'name="send"' not in b.page("/portal/identities/new")
        r = b.post("/portal/identities/new", form(acc, send="on"))
        assert r.status_code == 400 and "does not allow sending" in r.text


async def test_removing_an_identity_removes_the_right_to_send_as_it(alice, store):
    acc = await main_account(store)
    alice.post("/portal/identities/new", form(acc, send="on"))
    office = next(
        i
        for i in await store.list_for_user(Identity, ALICE)
        if i.addresses == ("office@example.org",)
    )
    keep = await store.create_grant(
        user_id=ALICE, client_id="c1", account_ids=[acc.id], account_scopes={acc.id: "read"},
        identity_ids=[office.id], scope="mail.read mail.send",
    )  # fmt: skip
    only = await store.create_grant(
        user_id=ALICE, client_id="c2", identity_ids=[office.id], scope="mail.read mail.send"
    )
    alice.post(f"/portal/identities/{office.id}/remove")
    g = await store.get(Grant, keep.id)
    assert g and g.identity_ids == () and g.scope == "mail.read"
    assert await store.get(Grant, only.id) is None  # nothing left of it


async def test_identity_login_test(alice, store, tester):
    (ident,) = await store.list_for_user(Identity, ALICE)
    r = alice.post(f"/portal/identities/{ident.id}/test")
    assert r.status_code == 200 and "Sending (SMTP)" in r.text and "Connected" in r.text
    assert tester.calls[-1][0] == "smtp" and tester.calls[-1][3] == PASSWORD
    assert PASSWORD not in r.text
    tester.script[PASSWORD] = "auth"
    r = alice.post(f"/portal/identities/{ident.id}/test")
    assert "rejected the user name or password" in r.text


async def test_removing_an_account_removes_identities_that_send_through_it(alice, store, tester):
    r = alice.post(
        "/portal/accounts/new",
        {
            "name": "Work", "protocol": "imap", "host": "mail.example.net",
            "username": "alice@example.net", "password": "w", "identity": "1",
        },
    )  # fmt: skip
    assert r.status_code == 303
    work = next(a for a in await store.list_for_user(MailAccount, ALICE) if a.name == "Work")
    assert any(i.smtp_account_id == work.id for i in await store.list_for_user(Identity, ALICE))
    alice.post(f"/portal/accounts/{work.id}/remove")
    idents = await store.list_for_user(Identity, ALICE)
    assert all(i.smtp_account_id != work.id for i in idents) and len(idents) == 1


async def test_other_users_identities_do_not_exist_for_you(store, tester, alice):
    (ident,) = await store.list_for_user(Identity, ALICE)
    app = alice.client.app
    with Browser(app, "bob@example.org") as bob:  # pyright: ignore[reportArgumentType]
        bob.signed_in()
        assert bob.get(f"/portal/identities/{ident.id}").status_code == 404
        assert bob.post(f"/portal/identities/{ident.id}/remove").status_code == 404
        assert bob.post(f"/portal/identities/{ident.id}/test").status_code == 404
        assert bob.post(f"/portal/identities/{ident.id}/default").status_code == 404
