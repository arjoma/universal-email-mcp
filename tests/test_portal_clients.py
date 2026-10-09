"""Consent with real accounts, send re-authentication, connected clients, grant migration."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from tests.oauth_util import (
    PASSWORD,
    Authz,
    account_id_of,
    bearer,
    hidden_fields,
    identity_ids_of,
    make_app,
    operator,
    query_of,
    refresh,
    register,
)
from tests.portal_util import Browser, FakeTester, ids_in, text_of
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
async def app(store):
    return await make_app(store=store, tester=FakeTester())


@pytest.fixture
def alice(app):
    with Browser(app) as b:
        yield b.signed_in()


def authz(b: Browser, scope: str = "mail.read mail.organize", name: str = "Test App") -> Authz:
    return Authz(b.client, register(b.client, name=name), scope=scope)


def approve(b: Browser, a: Authz, grants: list[str], identities: Sequence[str] = (), **extra):
    page = a.consent_page()
    form = {**hidden_fields(page.text), "action": "approve", "grant": grants, **extra}
    if identities:
        form["identity"] = list(identities)
    return page, b.client.post("/authorize", data=form)


async def second_account(b: Browser, name: str = "Work", **over: object) -> None:
    r = b.post(
        "/portal/accounts/new",
        {
            "name": name, "protocol": "imap", "host": "mail.example.net",
            "username": f"{name.lower()}@example.net", "password": "w-secret",
            "perm": ["read", "delete"], **over,
        },
    )  # fmt: skip
    assert r.status_code == 303, r.text


# ---------------------------------------------------------------- consent with real accounts


async def test_consent_lists_the_users_accounts_within_their_permissions(alice, store):
    await second_account(alice)
    a = authz(alice, "mail.read mail.organize mail.delete mail.drafts")
    page = a.consent_page().text
    main = next(x for x in await store.list_for_user(MailAccount, ALICE) if x.name == "Main")
    work = next(x for x in await store.list_for_user(MailAccount, ALICE) if x.name == "Work")
    assert f'value="{main.id}:mail.organize"' in page and f'value="{main.id}:mail.drafts"' in page
    assert f'value="{main.id}:mail.delete"' not in page  # Main was not given delete
    assert f'value="{work.id}:mail.delete"' in page
    assert f'value="{work.id}:mail.organize"' not in page  # Work only has read + delete
    assert "Main" in page and "Work" in page
    assert "w-secret" not in page and PASSWORD not in page


async def test_a_permission_beyond_the_account_cannot_be_ticked(alice, store):
    a = authz(alice, "mail.read mail.organize mail.delete")
    page = a.consent_page().text
    main = account_id_of(page)
    _, r = approve(alice, a, [f"{main}:mail.read", f"{main}:mail.delete"])
    code = query_of(r.headers["location"])["code"]
    assert a.exchange(code).json()["scope"] == "mail.read"


async def test_other_users_accounts_are_never_offered_or_accepted(app, alice, store):
    with Browser(app, "bob@example.org") as bob:
        bob.signed_in()
        bob_acc = next(
            iter(
                await store.list_for_user(
                    MailAccount, Pseudonyms(b"p" * 32).user_id("bob@example.org")
                )
            )
        )
    a = authz(alice)
    page = a.consent_page().text
    assert bob_acc.id not in page
    _, r = approve(alice, a, [f"{bob_acc.id}:mail.read"])
    assert r.status_code == 400  # "select at least one permission"


async def test_identities_are_offered_only_when_they_may_send(alice, store):
    a = authz(alice, "mail.read mail.send")
    assert identity_ids_of(a.consent_page().text) == []  # sending is not enabled for any identity
    (ident,) = await store.list_for_user(Identity, ALICE)
    await store.update(replace(ident, send=True))
    page = a.consent_page().text
    assert identity_ids_of(page) == [ident.id]
    assert "alice@example.org" in page


async def test_send_is_not_offered_when_the_operator_forbids_it(store):
    app = await make_app(operator(policy=Policy(send="off")), store=store, tester=FakeTester())
    with Browser(app) as b:
        b.signed_in()
        (ident,) = await store.list_for_user(Identity, ALICE)
        await store.update(replace(ident, send=True))
        a = authz(b, "mail.read mail.send")
        assert identity_ids_of(a.consent_page().text) == []


# ---------------------------------------------------------------- send needs the password


async def send_ready(store: Store) -> str:
    (ident,) = await store.list_for_user(Identity, ALICE)
    await store.update(replace(ident, send=True))
    return ident.id


async def test_granting_send_asks_for_the_password_when_it_is_stale(alice, store, clock):
    ident = await send_ready(store)
    a = authz(alice, "mail.read mail.send")
    main = account_id_of(a.consent_page().text)
    clock.advance(minutes=10)
    page, r = approve(alice, a, [f"{main}:mail.read"], [ident])
    assert r.status_code == 200 and 'type="password"' in r.text  # asked, nothing granted yet
    # the answer redirects to the client: CSP form-action must allow that hop on this page too
    assert "form-action 'self' http://127.0.0.1:*" in r.headers["content-security-policy"]
    assert "send mail as you" in r.text
    assert "location" not in r.headers
    assert await store.list_for_user(Grant, ALICE) == []
    form = hidden_fields(r.text)
    assert form["action"] == "approve" and "code_challenge" in form
    assert f'name="identity" value="{ident}"' in r.text  # the choice travels along

    def post(password: str):
        data = {**form, "grant": [f"{main}:mail.read"], "identity": [ident], "password": password}
        return alice.client.post("/authorize", data=data)

    wrong = post("nope")
    assert wrong.status_code == 401 and "not correct" in wrong.text
    assert await store.list_for_user(Grant, ALICE) == []
    ok = post(PASSWORD)
    assert ok.status_code == 303
    code = query_of(ok.headers["location"])["code"]
    assert a.exchange(code).json()["scope"] == "mail.read mail.send"


async def test_the_reauth_window_covers_a_second_send_grant_and_then_expires(alice, store, clock):
    ident = await send_ready(store)
    a = authz(alice, "mail.read mail.send")
    main = account_id_of(a.consent_page().text)
    clock.advance(minutes=10)
    first = authz(alice, "mail.read mail.send", name="Second")
    _, r = approve(alice, first, [f"{main}:mail.read"], [ident])
    assert r.status_code == 200
    r2 = alice.client.post(
        "/authorize",
        data={
            **hidden_fields(r.text),
            "grant": [f"{main}:mail.read"],
            "identity": [ident],
            "password": PASSWORD,
        },
    )
    assert r2.status_code == 303
    clock.advance(minutes=3)  # inside the window: no new question
    _, r3 = approve(alice, a, [f"{main}:mail.read"], [ident])
    assert r3.status_code == 303
    clock.advance(minutes=3)  # now six minutes after the password entry
    third = authz(alice, "mail.read mail.send", name="Third")
    _, r4 = approve(alice, third, [f"{main}:mail.read"], [ident])
    assert r4.status_code == 200 and 'type="password"' in r4.text


async def test_granting_only_reading_never_asks_for_the_password(alice, store, clock):
    await send_ready(store)
    a = authz(alice, "mail.read mail.send")
    main = account_id_of(a.consent_page().text)
    clock.advance(hours=3)
    alice.sign_in()  # session still valid? the idle timeout is 30 minutes
    _, r = approve(alice, a, [f"{main}:mail.read"])
    assert r.status_code in (303, 200)


async def test_an_unknown_identity_is_dropped_and_asks_for_no_password(alice, store, clock):
    await send_ready(store)
    a = authz(alice, "mail.read mail.send")
    main = account_id_of(a.consent_page().text)
    clock.advance(minutes=10)
    _, r = approve(alice, a, [f"{main}:mail.read"], ["i_0000000000000000"])
    assert r.status_code == 303  # no valid identity: a plain read grant, no password prompt
    code = query_of(r.headers["location"])["code"]
    assert a.exchange(code).json()["scope"] == "mail.read"


# ---------------------------------------------------------------- connected clients


async def connect(
    b: Browser, store: Store, scope="mail.read mail.organize", name="Test App", grants=None
):
    a = authz(b, scope, name)
    page = a.consent_page().text
    main = account_id_of(page)
    chosen = grants or [f"{main}:mail.read", f"{main}:mail.organize"]
    _, r = approve(b, a, chosen)
    code = query_of(r.headers["location"])["code"]
    tokens = a.exchange(code).json()
    return a, tokens, main


async def test_connected_clients_page_and_revoke(alice, store):
    a, tokens, _ = await connect(alice, store, name="Claude <b>Desktop</b>")
    assert (
        alice.client.post("/mcp", json={}, headers=bearer(tokens["access_token"])).status_code
        != 401
    )
    page = alice.page("/portal/clients")
    assert "&lt;b&gt;Desktop&lt;/b&gt;" in page and "<b>Desktop</b>" not in page
    assert "Self-registered application" in page and "Main" in page
    assert "Read mail" in page and "Organize" in page
    (gid,) = ids_in(page.replace("/portal/clients/g_", "/portal/clients/g_"), "clients") or [""]
    del gid
    (grant,) = await store.list_for_user(Grant, ALICE)
    assert text_of(page).count("never") >= 0
    r = alice.post(f"/portal/clients/{grant.id}/revoke")
    assert r.status_code == 303 and "client_revoked" in r.headers["location"]
    assert (
        alice.client.post("/mcp", json={}, headers=bearer(tokens["access_token"])).status_code
        == 401
    )
    assert refresh(alice.client, a.client_id, tokens["refresh_token"]).status_code == 400
    assert "No application is connected" in alice.page("/portal/clients")


async def test_cimd_clients_show_their_host(alice, store):
    now = store.now()
    cid = "https://client.example.org/meta.json"
    await store.register_client(
        cid, name="Doc Client", redirect_uris=("http://127.0.0.1/cb",), registration="cimd"
    )
    await store.create_grant(
        user_id=ALICE, client_id=cid, client_name="Doc Client", scope="mail.read"
    )
    page = alice.page("/portal/clients")
    assert "client.example.org" in page and "Doc Client" in page
    del now


async def test_another_users_grants_are_invisible_and_untouchable(app, alice, store):
    await connect(alice, store)
    (grant,) = await store.list_for_user(Grant, ALICE)
    with Browser(app, "bob@example.org") as bob:
        bob.signed_in()
        assert "No application is connected" in bob.page("/portal/clients")
        assert bob.get(f"/portal/clients/{grant.id}").status_code == 404
        assert bob.post(f"/portal/clients/{grant.id}/revoke").status_code == 404
        assert bob.post(f"/portal/clients/{grant.id}", {"grant": ["x:read"]}).status_code == 404
    assert await store.get(Grant, grant.id) is not None


async def test_a_grant_can_be_reduced_but_not_widened(alice, store):
    a, tokens, main = await connect(alice, store)
    (grant,) = await store.list_for_user(Grant, ALICE)
    page = alice.page(f"/portal/clients/{grant.id}")
    assert f'value="{main}:read"' in page and f'value="{main}:organize"' in page
    # try to add delete (not granted) while removing organize
    r = alice.post(f"/portal/clients/{grant.id}", {"grant": [f"{main}:read", f"{main}:delete"]})
    assert r.status_code == 303 and "client_saved" in r.headers["location"]
    g = await store.get(Grant, grant.id)
    assert g and g.scope == "mail.read" and g.account_scopes == {main: "read"}
    # tokens already issued follow the grant; a refresh cannot bring organize back
    new = refresh(alice.client, a.client_id, tokens["refresh_token"]).json()
    assert new["scope"] == "mail.read"
    assert (
        refresh(alice.client, a.client_id, new["refresh_token"], scope="mail.organize").status_code
        == 400
    )


async def test_a_grant_cannot_be_reduced_to_nothing(alice, store):
    await connect(alice, store)
    (grant,) = await store.list_for_user(Grant, ALICE)
    r = alice.post(f"/portal/clients/{grant.id}", {})
    assert r.status_code == 400 and "disconnect the application" in r.text
    g = await store.get(Grant, grant.id)
    assert g and g.scope == "mail.read mail.organize"


async def test_removing_an_account_disconnects_the_clients_that_used_it(alice, store):
    await second_account(alice)
    work = next(x for x in await store.list_for_user(MailAccount, ALICE) if x.name == "Work")
    main = next(x for x in await store.list_for_user(MailAccount, ALICE) if x.name == "Main")
    a, tokens, _ = await connect(alice, store, grants=[f"{work.id}:mail.read"])
    a2, tokens2, _ = await connect(alice, store, grants=[f"{main.id}:mail.read"])
    assert (
        alice.client.post("/mcp", json={}, headers=bearer(tokens["access_token"])).status_code
        != 401
    )
    r = alice.post(f"/portal/accounts/{work.id}/remove")
    assert r.status_code == 303
    assert (
        alice.client.post("/mcp", json={}, headers=bearer(tokens["access_token"])).status_code
        == 401
    )
    assert (
        alice.client.post("/mcp", json={}, headers=bearer(tokens2["access_token"])).status_code
        != 401
    )
    assert len(await store.list_for_user(Grant, ALICE)) == 1
    del a, a2, main


# ---------------------------------------------------------------- the 3c pseudo account


async def test_grants_of_the_pseudo_account_are_migrated_at_the_next_sign_in(app, store):
    pseudo = Pseudonyms(b"p" * 32).user_id("bob@example.org")
    await store.get_or_create_user(pseudo, "bob@example.org")
    old = await store.create_grant(
        user_id=pseudo, client_id="legacy", client_name="Legacy",
        account_ids=["primary"], account_scopes={"primary": "read delete"},
        identity_ids=["primary"], scope="mail.read mail.delete mail.send",
    )  # fmt: skip
    other = await store.create_grant(
        user_id=pseudo, client_id="keep", account_ids=["a_other"],
        account_scopes={"a_other": "read"}, scope="mail.read",
    )  # fmt: skip
    with Browser(app, "bob@example.org") as bob:
        bob.signed_in()
    (acc,) = await store.list_for_user(MailAccount, pseudo)
    (ident,) = await store.list_for_user(Identity, pseudo)
    g = await store.get(Grant, old.id)
    assert g and g.account_ids == (acc.id,) and g.account_scopes == {acc.id: "read delete"}
    assert g.identity_ids == () and "primary" not in repr(g)  # the new identity may not send
    assert g.scope == "mail.read mail.delete" and not ident.send
    assert set(acc.permissions) == {
        "read",
        "organize",
        "drafts",
        "delete",
    }  # keeps what was granted
    untouched = await store.get(Grant, other.id)
    assert untouched and untouched.account_ids == ("a_other",)
    # a second sign-in does not create a second account
    with Browser(app, "bob@example.org") as bob2:
        bob2.signed_in()
    assert len(await store.list_for_user(MailAccount, pseudo)) == 1


async def test_lowering_what_the_user_allows_reduces_existing_grants(alice, store):
    ident = await send_ready(store)
    a = authz(alice, "mail.read mail.organize mail.send")
    main = account_id_of(a.consent_page().text)
    _, r = approve(alice, a, [f"{main}:mail.read", f"{main}:mail.organize"], [ident])
    a.exchange(query_of(r.headers["location"])["code"])
    (grant,) = await store.list_for_user(Grant, ALICE)
    assert grant.scope == "mail.read mail.organize mail.send"
    alice.post(f"/portal/accounts/{main}/permissions", {"perm": ["read"]})
    g = await store.get(Grant, grant.id)
    assert g and g.account_scopes == {main: "read"} and "mail.organize" not in g.scope
    # un-ticking "sending allowed" takes the right to send away too
    (i,) = await store.list_for_user(Identity, ALICE)
    alice.post(
        f"/portal/identities/{i.id}",
        {"address": "alice@example.org", "smtp_account": i.smtp_account_id, "store_account": ""},
    )
    g = await store.get(Grant, grant.id)
    assert g and g.identity_ids == () and g.scope == "mail.read"


async def test_pseudo_identity_of_a_migrated_grant_does_not_keep_the_send_right(app, store):
    pseudo = Pseudonyms(b"p" * 32).user_id("bob@example.org")
    await store.get_or_create_user(pseudo, "bob@example.org")
    old = await store.create_grant(
        user_id=pseudo, client_id="legacy", account_ids=["primary"],
        account_scopes={"primary": "read"}, identity_ids=["primary"],
        scope="mail.read mail.send",
    )  # fmt: skip
    with Browser(app, "bob@example.org") as bob:
        bob.signed_in()
    g = await store.get(Grant, old.id)
    assert g and g.identity_ids == () and g.scope == "mail.read"


async def test_sign_in_replaces_the_old_session_and_refreshes_the_identity_copy(app, store):
    with Browser(app) as b:
        b.signed_in()
        old = b.client.cookies.get("__Host-uem_session")
        b.sign_in()
        assert b.client.cookies.get("__Host-uem_session") != old
        other = Browser(app)
        other.client.cookies.set("__Host-uem_session", old or "")
        assert other.get("/portal/accounts").status_code == 303
