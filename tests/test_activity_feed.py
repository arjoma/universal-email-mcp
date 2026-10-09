"""The own-activity feed and the portal's Activity page (design section 9)."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import timedelta
from typing import Any

import pytest

from tests.oauth_util import Authz, account_id_of, hidden_fields, make_app, query_of, register
from tests.portal_util import Browser, FakeTester, text_of
from universal_email_mcp import audit
from universal_email_mcp.portal.i18n import Catalog
from universal_email_mcp.store import ActivityEntry, Store, User

GERMAN = {
    "You signed in to the portal.": "Sie haben sich im Portal angemeldet.",
    "Activity": "Aktivitaet",
}


@pytest.fixture
async def app():
    return await make_app(tester=FakeTester())


def store_of(app: Any) -> Store:
    return app.state.oauth_service.store


async def uid_of(app: Any, address: str = "alice@example.org") -> str:
    svc = app.state.oauth_service
    return svc.pseudonyms.user_id(address)


async def entries(app: Any, address: str = "alice@example.org") -> list[ActivityEntry]:
    return await store_of(app).list_activity(await uid_of(app, address), 100)


def connect_client(b: Browser, name: str = "Test App") -> str:
    """Run the consent flow for a registered client; returns the grant id."""
    a = Authz(b.client, register(b.client, name=name))
    page = a.consent_page()
    form = {
        **hidden_fields(page.text),
        "action": "approve",
        "grant": [f"{account_id_of(page.text)}:mail.read"],
    }
    query_of(b.client.post("/authorize", data=form).headers["location"])
    return b.page("/portal/clients").split("/portal/clients/")[1].split('"')[0].split("/")[0]


# ---------------------------------------------------------------- what gets recorded


async def test_sign_in_account_and_grant_changes_land_in_the_feed(app):
    with Browser(app) as b:
        b.signed_in()
        add = b.post(
            "/portal/accounts/new",
            {"name": "Work", "protocol": "imap", "host": "mail.example.org",
             "username": "alice", "password": "pw", "identity": "1"},
        )  # fmt: skip
        aid = add.headers["location"].split("?")[0].rsplit("/", 1)[1]
        b.post(f"/portal/accounts/{aid}/test")
        gid = connect_client(b)
        b.post(f"/portal/clients/{gid}/revoke")
        b.post(f"/portal/accounts/{aid}/remove")
    names = [e.event for e in await entries(app)]
    for expected in (
        "auth.sign_in",
        "portal.account_add",
        "portal.account_test",
        "auth.consent",
        "portal.grant_revoke",
        "portal.account_remove",
    ):
        assert expected in names, names


async def test_entries_hold_ids_and_counts_only(app):
    with Browser(app) as b:
        b.signed_in()
        b.post(
            "/portal/accounts/new",
            {"name": "Private Name", "protocol": "imap", "host": "mail.secret-host.example",
             "username": "very.private@secret-host.example", "password": "s3cr3t-pw"},
        )  # fmt: skip
    blob = json.dumps([asdict(e) for e in await entries(app)], default=str)
    for secret in ("s3cr3t-pw", "very.private", "secret-host", "alice@example.org", "Private Name"):
        assert secret not in blob


async def test_failed_sign_ins_are_logged_but_create_no_feed_entries(app):
    with Browser(app) as b:
        r = b.post("/portal/signin", {"address": "mallory@example.org", "password": "wrong"})
        assert r.status_code in (200, 401, 403)
    uid = await uid_of(app, "mallory@example.org")
    assert await store_of(app).list_activity(uid, 10) == []
    assert await store_of(app).get(User, uid) is None


async def test_a_failing_feed_never_breaks_the_action(app, caplog):
    audit.configure(strict=False)

    async def broken(*a: Any, **k: Any) -> None:
        raise RuntimeError("store down alice@example.org")

    audit.configure_feed(broken)
    with caplog.at_level(logging.WARNING):
        with Browser(app) as b:
            assert b.sign_in().status_code == 303
    assert "alice@example.org" not in caplog.text
    assert "activity entry not stored" in caplog.text


# ---------------------------------------------------------------- the page


async def test_activity_page_lists_own_entries_in_human_terms(app):
    with Browser(app) as b:
        b.signed_in()
        gid = connect_client(b, "My Assistant")
        page = b.page("/portal/activity")
        text = text_of(page)
        assert "You signed in to the portal." in text
        assert "You connected My Assistant." in text
        b.post(f"/portal/clients/{gid}/revoke")
        text = text_of(b.page("/portal/activity"))
        # the grant is gone: the name cannot be resolved any more
        assert "You disconnected an application that is no longer connected." in text
        assert "30 days" in text
        assert 'href="/portal/activity"' in page


async def test_activity_page_never_shows_other_users_entries(app):
    store = store_of(app)
    with Browser(app, "alice@example.org") as a, Browser(app, "bob@example.org") as bob:
        a.signed_in()
        bob.signed_in()
        connect_client(bob, "Bobs Secret Assistant")
        bob_uid = await uid_of(app, "bob@example.org")
        await store.record_activity(bob_uid, "tool.call", tool="find_messages", outcome="ok")
        assert "Bobs Secret Assistant" in text_of(bob.page("/portal/activity"))
        alice_page = text_of(a.page("/portal/activity"))
        assert "Bobs Secret Assistant" not in alice_page
        assert "searched" not in alice_page
        assert alice_page.count("You signed in to the portal.") == 1


async def test_activity_page_needs_a_session(app):
    with Browser(app) as b:
        r = b.get("/portal/activity")
        assert r.status_code == 303 and "/portal/signin" in r.headers["location"]


async def test_names_are_resolved_at_render_time(app):
    store = store_of(app)
    with Browser(app) as b:
        b.signed_in()
        gid = connect_client(b, "Old Name")
        uid = await uid_of(app)
        await store.record_activity(uid, "tool.call", client=gid, tool="find_messages", outcome="ok",
                                    counts={"calls": 3})  # fmt: skip
        await store.record_activity(uid, "tool.call", client=gid, tool="move_messages", outcome="ok",
                                    counts={"succeeded": 2})  # fmt: skip
        text = text_of(b.page("/portal/activity"))
        assert "Old Name searched your mail 3 times." in text
        assert "Old Name moved 2 messages." in text


async def test_hostile_labels_are_escaped_and_failures_marked(app):
    store = store_of(app)
    with Browser(app) as b:
        b.signed_in()
        uid = await uid_of(app)
        await store.record_activity(uid, "<script>alert(1)</script>", outcome="error")
        await store.record_activity(uid, "portal.account_add", account="<b>x</b>")
        page = b.page("/portal/activity")
        assert "<script>alert(1)" not in page and "<b>x</b>" not in page
        assert "Other activity." in page


async def test_activity_page_is_translated_and_templates_have_no_literal_text(app):
    app.state.oauth_service.portal.translator.catalogs["de"] = Catalog(GERMAN)
    with Browser(app) as b:
        b.signed_in()
        b.client.cookies.set("uem_lang", "de")
        text = text_of(b.page("/portal/activity"))
        assert "Sie haben sich im Portal angemeldet." in text
        assert "Aktivitaet" in text
    # (tests/test_portal_i18n.py::test_templates_have_no_literal_visible_text covers
    # activity.html like every other template)


# ---------------------------------------------------------------- retention


async def test_entries_expire_with_the_activity_ttl(app):
    store = store_of(app)
    uid = await uid_of(app)
    now = store.now()
    assert store.policy.activity_ttl == timedelta(days=30)
    entry = await store.record_activity(uid, "auth.sign_in")
    assert entry.expires_at - now >= timedelta(days=29, hours=23)
