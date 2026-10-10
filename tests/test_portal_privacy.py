"""The portal's privacy page: what is stored, export, delete everything."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tests.oauth_util import PASSWORD, Authz, bearer, make_app, register
from tests.portal_util import Browser, FakeTester
from universal_email_mcp.oauth.identity import Pseudonyms
from universal_email_mcp.portal.privacy import EXPORT_VERSION, duration_view
from universal_email_mcp.store import (
    ActivityEntry,
    Grant,
    Identity,
    KeyRing,
    MailAccount,
    MemoryBackend,
    PendingApproval,
    PortalSession,
    SessionPolicy,
    Store,
    Token,
    User,
)

PSEUDO = Pseudonyms(b"p" * 32)
ALICE = PSEUDO.user_id("alice@example.org")
BOB = PSEUDO.user_id("bob@example.org")
WORK_PASSWORD = "work-secret-pw"
HOSTILE = "<img src=x onerror=alert(1)></script><script>alert(2)</script>\r\nX-Evil: 1 " + "A" * 300


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
async def app(store: Store):
    return await make_app(store=store, tester=FakeTester())


def connect_app(b: Browser) -> dict[str, Any]:
    """Run the OAuth flow in the signed-in browser; returns the token response."""
    a = Authz(b.client, register(b.client))
    r = a.exchange(a.code())
    assert r.status_code == 200, r.text
    return r.json()


def add_work(b: Browser) -> None:
    r = b.post(
        "/portal/accounts/new",
        {
            "name": "Work",
            "protocol": "imap",
            "host": "mail.example.net",
            "username": "alice@example.net",
            "password": WORK_PASSWORD,
            "perm": ["read"],
            "identity": "1",
        },
    )
    assert r.status_code == 303, r.text


@pytest.fixture
def alice(app):
    with Browser(app) as b:
        yield b.signed_in()


# ---------------------------------------------------------------- the page


def test_navigation_links_to_the_page(alice):
    assert 'href="/portal/privacy"' in alice.page("/portal/accounts")


def test_page_needs_a_session(app):
    with Browser(app) as b:
        for method, path in (("get", "/portal/privacy"), ("get", "/portal/privacy/delete")):
            r = getattr(b, method)(path)
            assert r.status_code == 303 and r.headers["location"].startswith("/portal/signin")
        assert b.post("/portal/privacy/export").status_code == 303
        assert b.post("/portal/privacy/delete", {"confirm": "alice@example.org"}).status_code == 303


async def test_page_shows_live_counts_and_the_policy_values(clock):
    store = Store(
        MemoryBackend(),
        KeyRing({"k1": b"k" * 32}),
        clock=clock,
        policy=SessionPolicy(activity_ttl=timedelta(days=7), access_ttl=timedelta(minutes=20)),
    )
    app = await make_app(store=store, tester=FakeTester())
    with Browser(app) as b:
        b.signed_in()
        add_work(b)
        connect_app(b)
        page = b.page("/portal/privacy")
    assert "7 days" in page and "20 minutes" in page and "30 days" not in page.split("Access")[0]
    accounts = len(await store.list_for_user(MailAccount, ALICE))
    assert accounts == 2
    assert f"<td>{accounts}</td>" in page
    assert WORK_PASSWORD not in page and PASSWORD not in page


def test_duration_view():
    assert duration_view(timedelta(days=30)) == {"n": 30, "unit": "day"}
    assert duration_view(timedelta(hours=1)) == {"n": 1, "unit": "hour"}
    assert duration_view(timedelta(minutes=10)) == {"n": 10, "unit": "minute"}
    assert duration_view(timedelta(0))["unit"] == "none"
    assert duration_view(timedelta(seconds=90)) == {"n": 1, "unit": "minute"}


# ---------------------------------------------------------------- export


async def _hostile_records(store: Store, clock: Clock, uid: str, tag: str) -> None:
    now = clock()
    await store.create(
        MailAccount(
            id="a_" + tag * 16,
            user_id=uid,
            name=HOSTILE,
            host="h.example",
            port=993,
            username=HOSTILE,
            password="x",
            created_at=now,
        )  # fmt: skip
    )
    await store.create(
        Identity(
            id="i_" + tag * 16,
            user_id=uid,
            addresses=("a@example.org",),
            display_name=HOSTILE,
            signature=HOSTILE,
            smtp_password="smtp-secret-pw",
            created_at=now,
        )  # fmt: skip
    )


async def test_export_has_all_own_records_and_no_secrets(alice, store, clock):
    add_work(alice)
    tokens = connect_app(alice)
    await store.create_approval(user_id=ALICE, grant_id="g_x", identity_id="i_x", content_hash="HASH-OF-MAIL", draft_ref="DRAFT-REF-SECRET")  # fmt: skip
    await store.claim_send(ALICE, "marker-hash", timedelta(minutes=10))
    await _hostile_records(store, clock, ALICE, "a")
    session_cookie = alice.client.cookies.get("__Host-uem_session")
    csrf = alice.csrf
    r = alice.post("/portal/privacy/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers["content-disposition"].startswith("attachment;")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    doc = json.loads(r.text)
    assert doc["format"] == "universal-email-mcp-export" and doc["version"] == EXPORT_VERSION
    assert doc["user"]["primary_address"] == "alice@example.org"
    names = {a["name"] for a in doc["mail_accounts"]}
    assert {"Main", "Work", HOSTILE} <= names
    work = next(a for a in doc["mail_accounts"] if a["name"] == "Work")
    assert work["username"] == "alice@example.net" and work["host"] == "mail.example.net"
    assert set(work["permissions"]) == {"read"}
    assert any(i["display_name"] == HOSTILE for i in doc["sender_identities"])
    (grant,) = doc["connected_applications"]
    assert grant["client_name"] == "Test App" and grant["scope"]
    assert [a["status"] for a in doc["pending_approvals"]] == ["pending"]  # no send marker
    assert any(e["event"] == "auth.sign_in" for e in doc["activity"])
    assert doc["not_exported"]["tokens"] >= 2 and doc["not_exported"]["portal_sessions"] >= 1
    # nothing secret anywhere in the raw body
    secrets = [
        PASSWORD, WORK_PASSWORD, "smtp-secret-pw", "DRAFT-REF-SECRET", "HASH-OF-MAIL",
        "marker-hash", session_cookie, csrf, store.secret_id(PortalSession, session_cookie),
        tokens["access_token"], tokens["refresh_token"], store.secret_id(Token, tokens["access_token"]),
        store.secret_id(Token, tokens["refresh_token"]), "_sealed", "e1.k1", "password", "b\"k\"",
        "k" * 32, "auth_failed_mark", "draft_ref", "content_hash", ALICE,
    ]  # fmt: skip
    for secret in secrets:
        assert secret not in r.text, secret
    # JSON keeps the hostile text inert: it is data inside quoted strings, no raw line breaks
    assert "\r" not in r.text and "\\r\\n" in r.text
    assert doc["user"]["log_pseudonym"] == ALICE[:14]


async def test_export_never_contains_another_users_data(app, store, clock):
    with Browser(app, "bob@example.org") as bob:
        bob.signed_in()
        connect_app(bob)
        await _hostile_records(store, clock, BOB, "b")
        await store.create_approval(user_id=BOB, grant_id="g", identity_id="i", content_hash="h", draft_ref="BOB-DRAFT")  # fmt: skip
        with Browser(app) as alice:
            alice.signed_in()
            body = alice.post("/portal/privacy/export").text
        assert "bob@example.org" not in body and HOSTILE not in body and BOB not in body
        assert "BOB-DRAFT" not in body
        doc = json.loads(body)
        assert all("Bob" not in str(v) for v in doc["connected_applications"])
        # bob's own export is his
        mine = json.loads(bob.post("/portal/privacy/export").text)
        assert mine["user"]["primary_address"] == "bob@example.org"
        assert "alice@example.org" not in json.dumps(mine)


def test_export_needs_csrf(alice):
    r = alice.client.post("/portal/privacy/export", data={})
    assert r.status_code == 403
    assert alice.client.get("/portal/privacy/export").status_code == 405
    r = alice.client.post(
        "/portal/privacy/export",
        data={"csrf_token": alice.csrf},
        headers={"sec-fetch-site": "cross-site"},
    )
    assert r.status_code == 403


async def test_hostile_names_are_escaped_in_pages(alice, store, clock):
    await _hostile_records(store, clock, ALICE, "a")
    for path in ("/portal/privacy", "/portal/accounts", "/portal/identities", "/portal/activity"):
        page = alice.page(path)
        assert "<img src=x" not in page and "<script>" not in page, path


async def test_export_is_audited_and_in_the_feed(alice, store, caplog):
    caplog.set_level(logging.INFO, logger="universal_email_mcp.audit")
    alice.post("/portal/privacy/export")
    events = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "universal_email_mcp.audit"
    ]
    (ev,) = [e for e in events if e["event"] == "portal.export"]
    assert ev["accounts"] == 1 and ev["identities"] == 1
    assert "alice@example.org" not in json.dumps(events)
    assert "You exported your data." in alice.page("/portal/activity")


# ---------------------------------------------------------------- delete everything


async def _count(store: Store, uid: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for cls in (MailAccount, Identity, Grant, Token, PortalSession, PendingApproval, ActivityEntry):
        out[cls.KIND] = len(await store.backend.find(cls.KIND, "user_id", uid))
    out["users"] = int(await store.get(User, uid) is not None)
    return out


def test_delete_page_needs_a_fresh_password(alice, clock):
    clock.advance(minutes=10)
    r = alice.get("/portal/privacy/delete")
    assert r.status_code == 303 and r.headers["location"].startswith("/portal/reauth")
    alice.post("/portal/reauth", {"password": PASSWORD, "next": "/portal/privacy/delete"})
    page = alice.page("/portal/privacy/delete")
    assert "alice@example.org" in page and 'name="confirm"' in page


async def test_delete_is_refused_without_csrf_reauth_or_confirmation(alice, store, clock):
    before = await _count(store, ALICE)
    r = alice.client.post("/portal/privacy/delete", data={"confirm": "alice@example.org"})
    assert r.status_code == 403
    r = alice.post("/portal/privacy/delete", {"confirm": "bob@example.org"})
    assert r.status_code == 400 and "does not match" in r.text
    r = alice.post("/portal/privacy/delete", {})
    assert r.status_code == 400
    clock.advance(minutes=10)  # stale password entry
    r = alice.post("/portal/privacy/delete", {"confirm": "alice@example.org"})
    assert r.status_code == 303 and r.headers["location"].startswith("/portal/reauth")
    assert await _count(store, ALICE) == before


async def test_delete_removes_everything_of_one_user_and_nothing_else(app, store, clock, caplog):
    caplog.set_level(logging.INFO, logger="universal_email_mcp.audit")
    with Browser(app, "bob@example.org") as bob:
        bob.signed_in()
        bob_tokens = connect_app(bob)
        bob_before = await _count(store, BOB)
        with Browser(app) as alice:
            alice.signed_in()
            add_work(alice)
            tokens = connect_app(alice)
            await store.create_approval(user_id=ALICE, grant_id="g", identity_id="i", content_hash="h", draft_ref="d")  # fmt: skip
            await store.claim_send(ALICE, "hash", timedelta(minutes=10))
            await _hostile_records(store, clock, ALICE, "a")
            assert alice.client.post("/mcp", json={}, headers=bearer(tokens["access_token"])).status_code != 401  # fmt: skip
            r = alice.post("/portal/privacy/delete", {"confirm": " Alice@Example.org "})
            assert r.status_code == 200 and "Your data was deleted" in r.text
            assert "__Host-uem_session" not in alice.client.cookies
            assert alice.get("/portal/accounts").status_code == 303  # session gone
            # tokens stop working at once; refreshing fails too
            gone = alice.client.post("/mcp", json={}, headers=bearer(tokens["access_token"]))
            assert gone.status_code == 401
            refreshed = alice.client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": (await store.backend.find("oauth_clients", "name", "Test App"))[0][
                        0
                    ],
                },
            )
            assert refreshed.status_code == 400
        assert await _count(store, ALICE) == dict.fromkeys(await _count(store, ALICE), 0)
        # nothing of alice is left in any collection
        for col in list(store.backend._data):  # pyright: ignore[reportPrivateUsage]
            for doc in store.backend.raw(col).values():  # pyright: ignore[reportAttributeAccessIssue]
                assert doc.get("user_id") != ALICE, col
        # bob is untouched and keeps working
        assert await _count(store, BOB) == bob_before
        assert bob.client.post("/mcp", json={}, headers=bearer(bob_tokens["access_token"])).status_code != 401  # fmt: skip
        assert "Main" in bob.page("/portal/accounts")
    events = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "universal_email_mcp.audit"
    ]
    (done,) = [e for e in events if e["event"] == "portal.delete_all"]
    assert done["deleted"]["accounts"] == 3 and done["deleted"]["users"] == 1
    assert "alice@example.org" not in json.dumps(events)
    # no feed entry is written for the deletion (the feed is gone with the user)
    assert await store.list_activity(ALICE) == []


async def test_delete_can_sign_up_again_afterwards(app, store):
    with Browser(app) as alice:
        alice.signed_in()
        assert alice.post("/portal/privacy/delete", {"confirm": "alice@example.org"}).status_code == 200  # fmt: skip
        assert alice.sign_in().status_code == 303
        assert "Main" in alice.page("/portal/accounts")
        assert len(await store.list_for_user(MailAccount, ALICE)) == 1
