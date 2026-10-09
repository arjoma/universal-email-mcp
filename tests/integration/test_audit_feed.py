"""Audit events and the own-activity feed for tool calls, sends and the viewer, against the
real app and Dovecot (WP 3h)."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import Client, StdioServerParameters

from tests.integration import test_per_user as pu
from tests.integration.conftest import ImapServer, Mailbox
from tests.integration.remote_send_util import NEW, Answers, remote
from tests.integration.remote_send_util import post as portal_post
from tests.integration.test_drafts import seed
from tests.integration.test_per_user import first_id, text, world
from tests.integration.test_remote_send import data_of, send
from universal_email_mcp.audit import LOGGER_NAME
from universal_email_mcp.store import MailAccount, PendingApproval

pytestmark = pytest.mark.integration

box_a = pu.box_a  # the fixtures of the per-user tests, reused
box_b = pu.box_b


def audit_lines(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == LOGGER_NAME]


# ---------------------------------------------------------------- tool calls


async def test_tool_calls_are_audited_and_land_in_the_feed(
    imap_server: ImapServer,
    box_a: Mailbox,
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    async with world(imap_server) as w:
        acc = await w.account("alice", "Work", box_a, ("read", "organize"))
        token, gid = await w.token("alice", {acc.id: "read organize"})
        async with w.client(token) as c:
            r = None
            for _ in range(3):
                r = await c.call_tool("find_messages", {"subject": "ALPHA-ONLY"})
                assert not r.is_error, text(r)
            assert r is not None
            mid = first_id(r, "ALPHA-ONLY subject")
            await c.call_tool("get_message", {"id": mid})
            marked = await c.call_tool("mark_messages", {"ids": [mid], "seen": True})
            assert not marked.is_error, text(marked)
            await c.call_tool("delete_messages", {"ids": [mid]})  # not granted
            await c.call_tool("no_such_tool_alice@example.org", {})
        uid = w.users["alice"]
        feed = {(e.tool, e.outcome): e for e in await w.store.list_activity(uid)}
        finds = feed[("find_messages", "ok")]
        assert finds.event == "tool.call" and finds.client == gid
        assert finds.counts["calls"] == 3  # merged within the hour
        assert feed[("get_message", "ok")].counts["calls"] == 1
        assert feed[("mark_messages", "ok")].counts["succeeded"] == 1
        assert ("delete_messages", "error") in feed or ("unknown", "error") in feed
        blob = repr(await w.store.list_activity(uid))
        for secret in ("ALPHA-ONLY", box_a.user, "alice@example.org"):
            assert secret not in blob

    events = [e for e in audit_lines(caplog) if e["event"] == "tool.call"]
    assert [e["tool"] for e in events].count("find_messages") == 3
    assert all(e["user"].startswith("u_") and e["grant"].startswith("g_") for e in events)
    assert all(e["dur"].startswith("<") or e["dur"].startswith(">=") for e in events)
    bad = [e for e in events if e["outcome"] == "error"]
    assert bad and all("code" in e for e in bad)
    assert "unknown" in [e["tool"] for e in events]  # a client-chosen tool name is never logged
    blob = json.dumps(audit_lines(caplog))
    for secret in ("ALPHA-ONLY", box_a.user, "alice@example.org", "no_such_tool", gid):
        assert secret not in blob, secret


async def test_a_batch_with_failures_and_successes_is_audited_as_partial(
    imap_server: ImapServer,
    box_a: Mailbox,
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    async with world(imap_server) as w:
        acc = await w.account("alice", "Work", box_a, ("read", "organize"))
        token, _ = await w.token("alice", {acc.id: "read organize"})
        async with w.client(token) as c:
            found = await c.call_tool("find_messages", {"subject": "ALPHA-ONLY"})
            mid = first_id(found, "ALPHA-ONLY subject")
            r = await c.call_tool("mark_messages", {"ids": [mid, "m1.nonsense"], "seen": True})
            assert r.structured_content["succeeded"] == 1 and r.structured_content["failed"] == 1
        feed = [
            e for e in await w.store.list_activity(w.users["alice"]) if e.tool == "mark_messages"
        ]
        assert [e.outcome for e in feed] == ["partial"]
        assert feed[0].counts["succeeded"] == 1 and feed[0].counts["failed"] == 1
    line = next(e for e in audit_lines(caplog) if e.get("tool") == "mark_messages")
    assert line["outcome"] == "partial" and line["severity"] == "WARNING"


async def test_a_users_feed_holds_only_their_own_calls(
    imap_server: ImapServer,
    box_a: Mailbox,
    box_b: Mailbox,
):
    async with world(imap_server) as w:
        a = await w.account("alice", "Work", box_a)
        b = await w.account("bob", "Work", box_b)
        ta, ga = await w.token("alice", {a.id: "read"})
        tb, gb = await w.token("bob", {b.id: "read"})
        async with w.client(ta) as c:
            await c.call_tool("list_folders", {})
        async with w.client(tb) as c:
            await c.call_tool("find_messages", {})
        alice = await w.store.list_activity(w.users["alice"])
        bob = await w.store.list_activity(w.users["bob"])
        assert {e.client for e in alice} == {ga} and {e.client for e in bob} == {gb}
        assert {e.tool for e in alice} == {"list_folders"}


# ---------------------------------------------------------------- sends


async def test_a_send_writes_exactly_one_send_entry(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, gid = await r.token(u)
        assert data_of(await send(r, token, answers=Answers()))["status"] == "sent"
        feed = await r.store.list_activity(u.id)
        sends = [e for e in feed if e.event == "send"]
        assert len(sends) == 1 and sends[0].client == gid and sends[0].outcome == "sent"
        # no second record of the same send from the audit pipeline
        assert [e.event for e in feed if e.event.startswith("send.")] == []
        assert not [e for e in feed if e.event == "tool.call" and e.tool == "send_message"]


async def test_declined_and_pending_sends_are_in_the_feed_and_the_page(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        await send(r, token, NEW, answers=Answers(action="decline"))
        await send(r, token, {**NEW, "to": ["stranger@nowhere.example"]}, mode="legacy")
        feed = await r.store.list_activity(u.id)
        assert {"send.declined", "send.approval_requested"} <= {e.event for e in feed}
        # the send events carry the account's id like every other event, never its name
        ids = {a.id for a in await r.store.list_for_user(MailAccount, u.id)}
        declined = next(e for e in feed if e.event == "send.declined")
        assert declined.account in ids
        approval = (await r.store.list_for_user(PendingApproval, u.id))[0]
        browser = await r.portal(u)
        await portal_post(browser, f"/portal/approvals/{approval.id}", action="reject")
        page = (await browser.get("/portal/activity")).text
        assert "You declined a message that Test Client wanted to send." in page
        assert "Test Client asked for your approval to send a message." in page
        assert "You rejected a message." in page
        assert "stranger@nowhere.example" not in page


# ---------------------------------------------------------------- viewer


async def test_viewer_use_is_in_the_feed(imap_server: ImapServer, box_a: Mailbox):
    async with world(imap_server) as w:
        acc = await w.account("alice", "Work", box_a, ("read",))
        token, _ = await w.token("alice", {acc.id: "read"})
        async with w.client(token) as c:
            r = await c.call_tool("find_messages", {"subject": "Ihre Rechnung"})
            mid = (r.structured_content or {})["messages"][0]["id"]
        import httpx2

        raw, _rec = await w.store.create_portal_session(w.users["alice"], fresh_login=True)
        async with httpx2.AsyncClient(base_url=w.url, timeout=60) as browser:
            browser.cookies.set("uem_session", raw)
            assert (await browser.get(f"/m/{mid}")).status_code == 200
            assert (await browser.get(f"/m/{mid}/eml")).status_code == 200
        events = [e.event for e in await w.store.list_activity(w.users["alice"])]
        assert "viewer.open" in events and "viewer.raw" in events


# ---------------------------------------------------------------- local stdio mode


async def test_local_stdio_server_never_writes_audit_lines_to_stdout(
    imap_server: ImapServer, tmp_path: Path
):
    """The stdio server speaks MCP on stdout: audit events (here: a draft-kept send attempt)
    must go to stderr only - any stray line would break the protocol framing."""
    box = Mailbox(imap_server, f"stdio{os.getpid()}@example.org")
    seed(box)
    cfg = tmp_path / "c.toml"
    cfg.write_text(
        f"""
[policy]
send = "draft"
[[accounts]]
name = "Work"
username = "{box.user}"
password_env = "UEM_STDIO_PW"
tls_verify = false
permissions = ["read", "drafts"]
[accounts.imap]
host = "{imap_server.host}"
port = {imap_server.imaps_port}
[accounts.smtp]
host = "localhost"
port = 1
tls = "starttls"
[[identities]]
name = "Me"
address = "me@example.org"
account = "Work"
send = true
default = true
"""
    )
    errlog = tmp_path / "stderr.log"
    params = StdioServerParameters(
        command="sh",
        args=[
            "-c",
            f'exec "{sys.executable}" -m universal_email_mcp local --config "{cfg}" 2>"{errlog}"',
        ],
        env={**os.environ, "UEM_STDIO_PW": imap_server.password, "XDG_STATE_HOME": str(tmp_path)},
    )
    async with Client(params) as c:
        r = await c.call_tool("send_message", {**NEW})
        assert not r.is_error, text(r)  # a protocol line broken by audit output would fail here
    lines = [json.loads(x) for x in errlog.read_text().splitlines() if x.startswith("{")]
    names = [e["event"] for e in lines]
    assert "send.requested" in names and "send.draft_kept" in names, errlog.read_text()
    assert all("user" not in e for e in lines)
    blob = json.dumps(lines)
    for secret in ("Work", "me@example.org", "alice@example.org", NEW["subject"]):
        assert secret not in blob
    assert (tmp_path / "universal-email-mcp" / "audit.key").exists()
