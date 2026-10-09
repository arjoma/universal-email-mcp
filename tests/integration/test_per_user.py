"""OAuth mode end to end (WP 3e): the per-user service behind ``/mcp``.

Users, accounts and grants are written to the in-memory store through the store API (not
through the portal pages), tokens come from ``Store.issue_tokens``; the MCP SDK's client then
talks to the real app (uvicorn) and Dovecot answers - protocol 2026-07-28 and legacy.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest
from mcp import Client

from tests.http_util import mcp_client, running
from tests.oauth_util import FakeLogin, operator
from universal_email_mcp.config import Settings
from universal_email_mcp.models import MessageRef, TlsSettings
from universal_email_mcp.oauth.app import build_oauth_app
from universal_email_mcp.operator import PoolSettings
from universal_email_mcp.store import Identity, KeyRing, MailAccount, MemoryBackend, Store

from .conftest import (  # pyright: ignore[reportPrivateUsage]
    ImapServer,
    Mailbox,
    _msg,
    seed_messages,
)

pytestmark = pytest.mark.integration

READ_TOOLS = {
    "account_info",
    "list_folders",
    "find_messages",
    "get_message",
    "get_attachment",
    "find_contacts",
}
ORGANIZE_TOOLS = {"mark_messages", "move_messages", "create_folder"}
MODES = ["auto", "2026-07-28", "legacy"]
WRONG = "wrong-Password-4711"


def seeded(server: ImapServer, marker: str) -> Mailbox:
    mb = Mailbox(server, f"pu{uuid.uuid4().hex[:10]}@example.org")
    c = mb.admin()
    try:
        for raw, when, flags in seed_messages():
            c.append("INBOX", raw, flags=flags, msg_time=when)
        c.append("INBOX", _msg(f"{marker} subject", "x@example.com", f"{marker} body"))
        for folder in ("Archiv", "Projekte"):
            c.create_folder(folder)
    finally:
        c.logout()
    return mb


@pytest.fixture
def box_a(imap_server: ImapServer) -> Mailbox:
    return seeded(imap_server, "ALPHA-ONLY")


@pytest.fixture
def box_a2(imap_server: ImapServer) -> Mailbox:
    return seeded(imap_server, "ALPHA-TWO")


@pytest.fixture
def box_b(imap_server: ImapServer) -> Mailbox:
    return seeded(imap_server, "BRAVO-SECRET")


@dataclass
class World:
    store: Store
    url: str
    server: ImapServer
    pool: Any
    users: dict[str, str] = field(default_factory=dict[str, str])

    async def user(self, name: str) -> str:
        uid = self.users.setdefault(name, "u_" + uuid.uuid4().hex[:12])
        await self.store.get_or_create_user(uid, f"{name}@example.org")
        return uid

    async def account(
        self,
        user: str,
        name: str,
        mb: Mailbox,
        perms: tuple[str, ...] = ("read",),
        *,
        password: str | None = None,
    ) -> MailAccount:
        return await self.store.create(
            MailAccount(
                id="a_" + uuid.uuid4().hex[:12],
                user_id=await self.user(user),
                name=name,
                host=self.server.host,
                port=self.server.imaps_port,
                username=mb.user,
                password=password or self.server.password,
                permissions=perms,
                created_at=datetime.now(UTC),
            )
        )

    async def token(
        self, user: str, grants: dict[str, str], *, scope: str | None = None
    ) -> tuple[str, str]:
        """Access token for a new grant; ``grants`` maps account id -> granted permissions."""
        names = {p for g in grants.values() for p in g.split()}
        grant = await self.store.create_grant(
            user_id=await self.user(user),
            client_id="test-client",
            client_name="Test Client",
            account_ids=list(grants),
            account_scopes=grants,
            scope=scope or " ".join(f"mail.{p}" for p in sorted(names)),
        )
        issued = await self.store.issue_tokens(grant, resource=self.url + "/mcp")
        return issued.access_token, grant.id

    @asynccontextmanager
    async def client(self, token: str, mode: str = "auto") -> AsyncIterator[Client]:
        async with mcp_client(self.url + "/mcp", token, mode=mode) as c:
            yield c


def make_world(
    imap_server: ImapServer, *, pool: PoolSettings | None = None
) -> tuple[Any, Store, Any]:
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    store = Store(MemoryBackend(), KeyRing({"k1": b"k" * 32}))
    op = operator(
        public_url=f"http://127.0.0.1:{port}",
        allowed_hosts=("127.0.0.1",),
        allowed_origins=(f"http://127.0.0.1:{port}",),
        settings=Settings(allow_private_networks=True, connect_timeout=5, read_timeout=15),
        pool=pool or PoolSettings(),
    )
    return sock, store, op


@asynccontextmanager
async def world(
    imap_server: ImapServer, *, pool: PoolSettings | None = None
) -> AsyncIterator[World]:
    sock, store, op = make_world(imap_server, pool=pool)
    app = await build_oauth_app(
        op, store=store, login=FakeLogin(), mail_tls=TlsSettings(verify=False)
    )
    async with running(app, sock) as url:
        yield World(store, url, imap_server, app.state.user_pool)


async def stored(
    store: Store, account_id: str, ready: Callable[[MailAccount], bool]
) -> MailAccount:
    """The account record once ``ready`` holds (the MCP side writes it in the background)."""
    for _ in range(100):
        rec = await store.get(MailAccount, account_id)
        if rec is not None and ready(rec):
            return rec
        await asyncio.sleep(0.05)
    raise AssertionError("the account record did not change")


def text(result: Any) -> str:
    return "\n".join(b.text for b in result.content if hasattr(b, "text"))


def first_id(result: Any, subject: str) -> str:
    for m in (result.structured_content or {})["messages"]:
        if m["subject"] == subject:
            return m["id"]
    raise AssertionError(f"no message {subject!r}")


# ---------------------------------------------------------------- tool surface


@pytest.mark.parametrize("mode", MODES)
async def test_read_grant_offers_six_read_tools_and_reads(
    imap_server: ImapServer, box_a: Mailbox, mode: str
):
    async with world(imap_server) as w:
        acc = await w.account("alice", "Work", box_a, ("read", "organize", "delete"))
        token, _ = await w.token("alice", {acc.id: "read"})
        async with w.client(token, mode) as c:
            assert {t.name for t in (await c.list_tools()).tools} == READ_TOOLS
            r = await c.call_tool("find_messages", {"subject": "Big one"})
            assert not r.is_error, text(r)
            got = await c.call_tool("get_message", {"id": first_id(r, "Big one")})
            assert not got.is_error and "xxxx" in text(got)
            # a tool the grant lacks is not just hidden: calling it fails
            bad = await c.call_tool("delete_messages", {"ids": [first_id(r, "Big one")]})
            assert bad.is_error
            bad = await c.call_tool(
                "mark_messages", {"ids": [first_id(r, "Big one")], "seen": True}
            )
            assert bad.is_error


async def test_tool_results_carry_portal_viewer_links(imap_server: ImapServer, box_a: Mailbox):
    """Remote mode: message results link into the portal (``PUBLIC_URL/m/...``); the links carry
    no token - the portal session authorises."""
    async with world(imap_server) as w:
        acc = await w.account("alice", "Work", box_a, ("read",))
        token, _ = await w.token("alice", {acc.id: "read"})
        async with w.client(token) as c:
            r = await c.call_tool("find_messages", {"subject": "Ihre Rechnung"})
            assert not r.is_error, text(r)
            hit = (r.structured_content or {})["messages"][0]
            mid = hit["id"]
            assert hit["viewer_url"] == f"{w.url}/m/{mid}"
            got = await c.call_tool("get_message", {"id": mid})
            assert not got.is_error, text(got)
            data = got.structured_content or {}
            assert data["message"]["viewer_url"] == f"{w.url}/m/{mid}"
            assert data["eml_url"] == f"{w.url}/m/{mid}/eml"
            urls = [a["download_url"] for a in data["attachments"]]
            assert urls and all(u and u.startswith(f"{w.url}/m/{mid}/a/") for u in urls)
            assert f"{w.url}/m/{mid}" in text(got)
            for u in (data["message"]["viewer_url"], data["eml_url"], *urls):
                assert "token" not in u and "?" not in u


async def test_grant_scope_caps_the_account_permissions(imap_server: ImapServer, box_a: Mailbox):
    """Effective permission = account ∩ grant ∩ token scope: a grant cannot exceed the account."""
    async with world(imap_server) as w:
        acc = await w.account("alice", "Work", box_a, ("read",))  # the account itself is read-only
        token, _ = await w.token("alice", {acc.id: "read organize delete drafts"})
        async with w.client(token) as c:
            assert {t.name for t in (await c.list_tools()).tools} == READ_TOOLS


async def test_organize_on_one_account_only(
    imap_server: ImapServer, box_a: Mailbox, box_a2: Mailbox
):
    async with world(imap_server) as w:
        work = await w.account("alice", "Work", box_a, ("read", "organize", "delete"))
        other = await w.account("alice", "Other", box_a2, ("read", "organize", "delete"))
        token, _ = await w.token("alice", {work.id: "read organize", other.id: "read"})
        async with w.client(token) as c:
            names = {t.name for t in (await c.list_tools()).tools}
            assert names == READ_TOOLS | ORGANIZE_TOOLS
            r = await c.call_tool("find_messages", {"query": "Alpha*", "accounts": ["Work"]})
            r2 = await c.call_tool("find_messages", {"subject": "ALPHA-TWO", "accounts": ["Other"]})
            assert not r2.is_error, text(r2)
            mine = first_id(r2, "ALPHA-TWO subject")
            # the write on the read-only account is refused ...
            refused = await c.call_tool("mark_messages", {"ids": [mine], "flagged": True})
            assert "NOT_PERMITTED" in text(refused) or refused.is_error
            flags_after = await c.call_tool("get_message", {"id": mine})
            assert "flagged" not in text(flags_after).lower().split("flags")[-1][:80]
            # ... and the same write on the organize account works
            work_hit = await c.call_tool("find_messages", {"subject": "ALPHA-ONLY"})
            wid = first_id(work_hit, "ALPHA-ONLY subject")
            ok = await c.call_tool("mark_messages", {"ids": [wid], "flagged": True})
            assert not ok.is_error, text(ok)
            moved = await c.call_tool("move_messages", {"ids": [wid], "to": "Projekte"})
            assert not moved.is_error, text(moved)
            made = await c.call_tool("create_folder", {"account": "Work", "name": "Neu"})
            assert not made.is_error, text(made)
            nope = await c.call_tool("create_folder", {"account": "Other", "name": "Neu"})
            assert nope.is_error or "NOT_PERMITTED" in text(nope)
        del r


async def test_forged_scope_in_a_stale_token_cannot_widen(imap_server: ImapServer, box_a: Mailbox):
    """Operator policy read_only overrides what a grant says."""
    sock, store, op = make_world(imap_server)
    from dataclasses import replace

    from universal_email_mcp.config import Policy

    op = replace(op, policy=Policy(read_only=True))
    app = await build_oauth_app(
        op, store=store, login=FakeLogin(), mail_tls=TlsSettings(verify=False)
    )
    async with running(app, sock) as url:
        w = World(store, url, imap_server, app.state.user_pool)
        acc = await w.account("alice", "Work", box_a, ("read", "organize"))
        token, _ = await w.token("alice", {acc.id: "read organize"})
        async with w.client(token) as c:
            assert {t.name for t in (await c.list_tools()).tools} == READ_TOOLS


# ---------------------------------------------------------------- instructions


async def test_instructions_are_per_user_with_their_folder_map(
    imap_server: ImapServer, box_a: Mailbox, box_b: Mailbox
):
    async with world(imap_server) as w:
        a = await w.account("alice", "AlphaBox", box_a)
        b = await w.account("bob", "BravoBox", box_b)
        ta, _ = await w.token("alice", {a.id: "read"})
        tb, _ = await w.token("bob", {b.id: "read"})
        for mode in ("auto", "legacy"):  # a client pinned to 2026-07-28 never asks for them
            async with w.client(ta, mode) as ca:
                ins = ca.instructions or ""
                assert "AlphaBox" in ins and "Archiv" in ins
                assert "BravoBox" not in ins
            async with w.client(tb, mode) as cb:
                ins = cb.instructions or ""
                assert "BravoBox" in ins and "AlphaBox" not in ins


# ---------------------------------------------------------------- revocation


async def test_revoked_grant_stops_working_immediately(imap_server: ImapServer, box_a: Mailbox):
    async with world(imap_server) as w:
        acc = await w.account("alice", "Work", box_a)
        token, grant_id = await w.token("alice", {acc.id: "read"})
        async with w.client(token) as c:
            assert not (await c.call_tool("find_messages", {"subject": "Big one"})).is_error
            await w.store.revoke_grant(grant_id)
            with pytest.raises(Exception):  # noqa: B017, PT011 - 401 surfaces as a transport error
                await c.call_tool("find_messages", {"subject": "Big one"})
        async with httpx2.AsyncClient() as http:
            r = await http.post(
                w.url + "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 401


async def test_removed_account_disappears_on_the_next_request(
    imap_server: ImapServer, box_a: Mailbox, box_a2: Mailbox
):
    async with world(imap_server) as w:
        one = await w.account("alice", "One", box_a)
        two = await w.account("alice", "Two", box_a2)
        token, _ = await w.token("alice", {one.id: "read", two.id: "read"})
        async with w.client(token) as c:
            r = await c.call_tool("account_info", {})
            assert "One" in text(r) and "Two" in text(r)
            await w.store.delete(MailAccount, two.id)
            r = await c.call_tool("account_info", {})
            assert "One" in text(r) and "Two" not in text(r)
            gone = await c.call_tool("find_messages", {"accounts": ["Two"]})
            assert gone.is_error


# ---------------------------------------------------------------- reauth


async def test_changed_password_means_reauth_required_without_retry_storm(
    imap_server: ImapServer, box_a: Mailbox, box_a2: Mailbox, monkeypatch: pytest.MonkeyPatch
):
    from universal_email_mcp.service import router as router_mod

    attempts: list[str] = []
    real = router_mod.connect_imap

    def counting(account: Any, config: Any) -> Any:
        attempts.append(account.name)
        return real(account, config)

    monkeypatch.setitem(router_mod.DEFAULT_CONNECTORS, "imap", counting)  # pyright: ignore
    async with world(imap_server) as w:
        good = await w.account("alice", "Good", box_a2)
        bad = await w.account("alice", "Rotated", box_a, password=WRONG)
        token, _ = await w.token("alice", {good.id: "read", bad.id: "read"})
        async with w.client(token) as c:
            r = await c.call_tool("find_messages", {"subject": "Big one"})
            # the other account keeps working, the broken one is reported with its code
            assert [m["subject"] for m in (r.structured_content or {})["messages"]] == ["Big one"]
            body = text(r)
            assert "REAUTH_REQUIRED" in body and "Rotated" in body
            problems = (r.structured_content or {})["problems"]
            assert [p["code"] for p in problems] == ["REAUTH_REQUIRED"]
            assert "/portal/accounts" in problems[0]["hint"]
            # the account is flagged in the store ...
            rec = await stored(w.store, bad.id, lambda r: r.auth_failed_at is not None)
            assert rec.needs_reauth
            assert (await w.store.get(MailAccount, good.id)).auth_failed_at is None  # pyright: ignore
            # ... and not tried again
            tries = attempts.count("Rotated")
            for _ in range(3):
                r = await c.call_tool("find_messages", {"subject": "Big one"})
                assert "REAUTH_REQUIRED" in text(r)
            assert attempts.count("Rotated") == tries
            # re-entering the password (any change of the login) lifts the flag at once
            fixed = await w.store.get(MailAccount, bad.id)
            assert fixed is not None
            from dataclasses import replace

            await w.store.update(replace(fixed, password=imap_server.password))
            r = await c.call_tool("find_messages", {"subject": "Big one", "accounts": ["Rotated"]})
            assert not r.is_error and "REAUTH_REQUIRED" not in text(r)
            rec = await stored(w.store, bad.id, lambda r: r.auth_failed_at is None)
            assert not rec.needs_reauth


# ---------------------------------------------------------------- isolation


async def test_two_users_cannot_reach_each_other(
    imap_server: ImapServer, box_a: Mailbox, box_b: Mailbox
):
    async with world(imap_server) as w:
        # the same account name for both users: ids that name "Work" must stay inside the caller
        a = await w.account("alice", "Work", box_a, ("read", "organize"))
        b = await w.account("bob", "Work", box_b, ("read", "organize"))
        secret = await w.account("bob", "Vault", box_b, ("read", "organize"))
        ta, _ = await w.token("alice", {a.id: "read organize"})
        tb, _ = await w.token("bob", {b.id: "read organize", secret.id: "read"})

        async with w.client(tb) as cb:
            rb = await cb.call_tool("find_messages", {"subject": "BRAVO-SECRET"})
            bravo_id = first_id(rb, "BRAVO-SECRET subject")
            rv = await cb.call_tool(
                "find_messages", {"subject": "BRAVO-SECRET", "accounts": ["Vault"]}
            )
            vault_id = first_id(rv, "BRAVO-SECRET subject")
            cursor_hit = await cb.call_tool("find_messages", {"limit": 2, "accounts": ["Work"]})
            cursor = (cursor_hit.structured_content or {}).get("next_cursor")

        async with w.client(ta) as ca:
            seen = await ca.call_tool("find_messages", {"limit": 50})
            assert "BRAVO" not in text(seen) and "ALPHA-ONLY" in text(seen)
            assert not (
                await ca.call_tool("find_messages", {"subject": "BRAVO-SECRET"})
            ).structured_content["messages"]  # pyright: ignore
            # B's ids in A's hands: the other account name does not exist for A ...
            for forged in (vault_id,):
                r = await ca.call_tool("get_message", {"id": forged})
                assert r.is_error and "BRAVO" not in text(r)
            # ... and the same name "Work" resolves to A's own mailbox, never to B's
            r = await ca.call_tool("get_message", {"id": bravo_id})
            assert "BRAVO" not in text(r)
            ref = MessageRef.decode(bravo_id)
            assert ref.account == "Work"
            r = await ca.call_tool("mark_messages", {"ids": [bravo_id, vault_id], "flagged": True})
            assert "BRAVO" not in text(r)
            # B's cursor is void for A (signed with B's key)
            if cursor:
                r = await ca.call_tool("find_messages", {"limit": 2, "cursor": cursor})
                assert r.is_error or "BRAVO" not in text(r)
        # B's flagged state did not change by A's attempt
        async with w.client(tb) as cb:
            g = await cb.call_tool("get_message", {"id": bravo_id})
            assert "BRAVO-SECRET" in text(g)


async def test_grant_naming_a_foreign_account_gets_nothing(
    imap_server: ImapServer, box_a: Mailbox, box_b: Mailbox
):
    """A grant (or a bug elsewhere) listing another user's account id: ignored."""
    async with world(imap_server) as w:
        a = await w.account("alice", "Work", box_a)
        b = await w.account("bob", "Work", box_b)
        token, _ = await w.token("alice", {a.id: "read", b.id: "read"})
        async with w.client(token) as c:
            r = await c.call_tool("find_messages", {"subject": "BRAVO-SECRET"})
            assert "BRAVO" not in text(r)
            info = text(await c.call_tool("account_info", {}))
            assert info.count("Work") >= 1 and box_b.user not in info
        only_b_token, _ = await w.token("alice", {b.id: "read"})
        async with w.client(only_b_token) as c:
            r = await c.call_tool("find_messages", {"subject": "BRAVO-SECRET"})
            assert "BRAVO" not in text(r)
            assert r.is_error  # no account at all


# ---------------------------------------------------------------- credentials in logs


async def test_credentials_never_reach_the_logs(
    imap_server: ImapServer,
    box_a: Mailbox,
    box_a2: Mailbox,
    caplog: pytest.LogCaptureFixture,
):
    with caplog.at_level(logging.DEBUG):
        async with world(imap_server) as w:
            good = await w.account("alice", "Good", box_a)
            bad = await w.account("alice", "Bad", box_a2, password=WRONG)
            token, _ = await w.token("alice", {good.id: "read", bad.id: "read"})
            for mode in MODES:
                async with w.client(token, mode) as c:
                    await c.call_tool("find_messages", {"limit": 5})
                    await c.call_tool("account_info", {})
    blob = "\n".join(
        [r.getMessage() + str(r.exc_text) + str(getattr(r, "fields", "")) for r in caplog.records]
    )
    assert imap_server.password not in blob
    assert WRONG not in blob
    assert token not in blob
    assert re.search(r"uem_at_[A-Za-z0-9_-]{20,}", blob) is None


# ---------------------------------------------------------------- concurrency


@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"])
async def test_interleaved_concurrent_requests_never_cross_users(
    imap_server: ImapServer, box_a: Mailbox, box_b: Mailbox, mode: str
):
    """The principal travels in a ContextVar into the SDK's per-request tasks: hammer it
    with interleaved calls of two users (same account name, different mailboxes, different
    tool sets) and check every answer."""
    async with world(imap_server, pool=PoolSettings(max_concurrent_calls_per_user=100)) as w:
        a = await w.account("alice", "Work", box_a, ("read", "organize"))
        b = await w.account("bob", "Work", box_b, ("read",))
        ta, _ = await w.token("alice", {a.id: "read organize"})
        tb, _ = await w.token("bob", {b.id: "read"})

        async def one(user: str, c: Client, n: int) -> None:
            mine, other = ("ALPHA", "BRAVO") if user == "a" else ("BRAVO", "ALPHA")
            subject = "ALPHA-ONLY subject" if user == "a" else "BRAVO-SECRET subject"
            kind = n % 4
            if kind == 0:
                names = {t.name for t in (await c.list_tools()).tools}
                assert names == READ_TOOLS | (ORGANIZE_TOOLS if user == "a" else set()), (
                    user,
                    names,
                )
            elif kind == 1:
                body = text(await c.call_tool("account_info", {}))
                assert (box_b if user == "a" else box_a).user not in body
            elif kind == 2:
                body = text(await c.call_tool("find_messages", {"subject": subject}))
                assert subject.split()[0] in body and other not in body
            else:
                r = await c.call_tool("find_messages", {"subject": subject})
                got = text(await c.call_tool("get_message", {"id": first_id(r, subject)}))
                assert mine in got and other not in got

        async with (
            w.client(ta, mode) as a1,
            w.client(ta, mode) as a2,
            w.client(tb, mode) as b1,
            w.client(tb, mode) as b2,
        ):
            jobs: list[Any] = []
            for n in range(20):
                jobs.append(one("a", a1 if n % 2 else a2, n))
                jobs.append(one("b", b1 if n % 2 else b2, n))
            await asyncio.gather(*jobs)


# ---------------------------------------------------------------- drafts, send


async def test_drafts_work_and_send_is_not_offered(imap_server: ImapServer, box_a: Mailbox):
    async with world(imap_server) as w:
        acc = await w.account("alice", "Work", box_a, ("read", "drafts"))
        await w.store.create(
            Identity(
                id="i_" + uuid.uuid4().hex[:8],
                user_id=await w.user("alice"),
                addresses=(box_a.user,),
                display_name="Alice",
                copies_account_id=acc.id,
                is_default=True,
                created_at=datetime.now(UTC),
            )
        )
        token, _ = await w.token(
            "alice", {acc.id: "read drafts"}, scope="mail.read mail.drafts mail.send"
        )
        async with w.client(token) as c:
            names = {t.name for t in (await c.list_tools()).tools}
            assert "save_draft" in names and "send_message" not in names
            r = await c.call_tool(
                "save_draft", {"to": ["anna@example.net"], "subject": "Hello", "body": "Hi Anna"}
            )
            assert not r.is_error, text(r)
            assert "NOT been sent" in text(r)
        c2 = box_a.admin()
        try:
            c2.select_folder("Drafts")
            assert c2.search(["SUBJECT", "Hello"])  # pyright: ignore
        finally:
            c2.logout()


async def test_drafts_without_any_identity_fail_clearly(imap_server: ImapServer, box_a: Mailbox):
    async with world(imap_server) as w:
        acc = await w.account("alice", "Work", box_a, ("read", "drafts"))
        token, _ = await w.token("alice", {acc.id: "read drafts"})
        async with w.client(token) as c:
            r = await c.call_tool(
                "save_draft", {"to": ["a@example.net"], "subject": "x", "body": "y"}
            )
            assert r.is_error and "no identities" in text(r).lower() and "portal" in text(r)


# ---------------------------------------------------------------- stale cache


async def test_changed_permissions_take_effect_on_the_next_request(
    imap_server: ImapServer, box_a: Mailbox
):
    from dataclasses import replace

    async with world(imap_server) as w:
        acc = await w.account("alice", "Work", box_a, ("read", "organize"))
        token, _ = await w.token("alice", {acc.id: "read organize"})
        async with w.client(token) as c:
            assert ORGANIZE_TOOLS <= {t.name for t in (await c.list_tools()).tools}
            fresh = await w.store.get(MailAccount, acc.id)
            assert fresh is not None
            await w.store.update(replace(fresh, permissions=("read",)))
            assert {t.name for t in (await c.list_tools()).tools} == READ_TOOLS
