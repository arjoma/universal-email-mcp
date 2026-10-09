"""Tool-call rate limits end to end: real app, real MCP client, Dovecot behind it."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any

import pytest

from tests.http_util import running
from tests.integration.test_per_user import World, first_id, make_world, seeded, text
from tests.oauth_util import FakeLogin
from universal_email_mcp.audit import LOGGER_NAME
from universal_email_mcp.models import TlsSettings
from universal_email_mcp.oauth.app import build_oauth_app
from universal_email_mcp.oauth.config import Rate, RateLimits

from .conftest import ImapServer, Mailbox

pytestmark = pytest.mark.integration


@pytest.fixture
def box_a(imap_server: ImapServer) -> Mailbox:
    return seeded(imap_server, "ALPHA-ONLY")


@pytest.fixture
def box_b(imap_server: ImapServer) -> Mailbox:
    return seeded(imap_server, "BRAVO-SECRET")


LOOSE = Rate(10_000, timedelta(minutes=10))


def rates(**changes: Rate) -> RateLimits:
    """Everything loose except what a test tightens."""
    base = {
        f: LOOSE
        for f in (
            "tool_user_burst",
            "tool_user",
            "tool_grant_burst",
            "tool_grant",
            "tool_write_burst",
            "tool_write",
        )
    }
    return RateLimits(**{**base, **changes})


@asynccontextmanager
async def limited_world(imap_server: ImapServer, limits: RateLimits) -> AsyncIterator[World]:
    sock, store, op = make_world(imap_server)
    app = await build_oauth_app(
        op, store=store, login=FakeLogin(), mail_tls=TlsSettings(verify=False), rate_limits=limits
    )
    async with running(app, sock) as url:
        yield World(store, url, imap_server, app.state.user_pool)


def error_of(result: Any) -> dict[str, Any]:
    assert result.is_error
    return (result.structured_content or {})["error"]


async def test_user_burst_limit_refuses_without_touching_mail(
    imap_server: ImapServer, box_a: Mailbox, monkeypatch: pytest.MonkeyPatch
):
    async with limited_world(
        imap_server, rates(tool_user_burst=Rate(3, timedelta(minutes=1)))
    ) as w:
        acc = await w.account("alice", "Work", box_a, ("read",))
        token, _ = await w.token("alice", {acc.id: "read"})
        slots = 0
        real = w.pool.call_slot

        def counting(ctx: Any) -> Any:
            nonlocal slots
            slots += 1
            return real(ctx)

        monkeypatch.setattr(w.pool, "call_slot", counting)
        async with w.client(token) as c:
            for _ in range(3):
                assert not (await c.call_tool("account_info", {})).is_error
            assert slots == 3
            r = await c.call_tool("find_messages", {"subject": "Big one"})
            err = error_of(r)
            assert err["code"] == "RATE_LIMITED"
            assert isinstance(err["retry_after"], int) and 1 <= err["retry_after"] <= 61
            assert "Wait" in text(r) and "Error [RATE_LIMITED]" in text(r)
            assert slots == 3  # the refused call never took a pool slot, never reached IMAP


async def test_limit_is_per_user_and_recovers(
    imap_server: ImapServer, box_a: Mailbox, box_b: Mailbox
):
    async with limited_world(
        imap_server, rates(tool_user_burst=Rate(1, timedelta(seconds=1)))
    ) as w:
        a = await w.account("alice", "Work", box_a, ("read",))
        b = await w.account("bob", "Work", box_b, ("read",))
        ta, _ = await w.token("alice", {a.id: "read"})
        tb, _ = await w.token("bob", {b.id: "read"})
        async with w.client(ta) as ca, w.client(tb) as cb:
            assert not (await ca.call_tool("account_info", {})).is_error
            assert error_of(await ca.call_tool("account_info", {}))["code"] == "RATE_LIMITED"
            assert not (await cb.call_tool("account_info", {})).is_error  # bob has his own
            await asyncio.sleep(1.2)
            assert not (await ca.call_tool("account_info", {})).is_error  # window passed


async def test_limit_is_also_per_grant(imap_server: ImapServer, box_a: Mailbox):
    async with limited_world(
        imap_server, rates(tool_grant_burst=Rate(2, timedelta(minutes=1)))
    ) as w:
        acc = await w.account("alice", "Work", box_a, ("read",))
        t1, _ = await w.token("alice", {acc.id: "read"})
        t2, _ = await w.token("alice", {acc.id: "read"})  # a second connected client
        async with w.client(t1) as c1, w.client(t2) as c2:
            for _ in range(2):
                assert not (await c1.call_tool("account_info", {})).is_error
            assert error_of(await c1.call_tool("account_info", {}))["code"] == "RATE_LIMITED"
            assert not (await c2.call_tool("account_info", {})).is_error


async def test_write_tools_have_a_tighter_limit(imap_server: ImapServer, box_a: Mailbox):
    async with limited_world(
        imap_server, rates(tool_write_burst=Rate(1, timedelta(minutes=1)))
    ) as w:
        acc = await w.account("alice", "Work", box_a, ("read", "organize"))
        token, _ = await w.token("alice", {acc.id: "read organize"})
        async with w.client(token) as c:
            found = await c.call_tool("find_messages", {"subject": "Big one"})
            mid = first_id(found, "Big one")
            for _ in range(5):  # reads are not affected
                assert not (await c.call_tool("find_messages", {"subject": "Big one"})).is_error
            first = await c.call_tool("mark_messages", {"ids": [mid], "seen": True})
            assert not first.is_error, text(first)
            second = await c.call_tool("mark_messages", {"ids": [mid], "seen": False})
            assert error_of(second)["code"] == "RATE_LIMITED"


async def test_hits_are_audited_without_content(
    imap_server: ImapServer, box_a: Mailbox, caplog: pytest.LogCaptureFixture
):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    async with limited_world(
        imap_server, rates(tool_user_burst=Rate(1, timedelta(minutes=1)))
    ) as w:
        acc = await w.account("alice", "Work", box_a, ("read",))
        token, _ = await w.token("alice", {acc.id: "read"})
        async with w.client(token) as c:
            await c.call_tool("account_info", {})
            await c.call_tool("find_messages", {"subject": "SECRET-SUBJECT"})
    lines = [json.loads(r.getMessage()) for r in caplog.records if r.name == LOGGER_NAME]
    hits = [e for e in lines if e["event"] == "ratelimit.hit"]
    assert len(hits) == 1 and hits[0]["scope"] == "tool_user" and hits[0]["severity"] == "WARNING"
    assert "SECRET-SUBJECT" not in json.dumps(lines)
    # the refused call is audited as ratelimit.hit only (no tool.call, so no feed write)
    calls = [e for e in lines if e["event"] == "tool.call"]
    assert [e["outcome"] for e in calls] == ["ok"]
