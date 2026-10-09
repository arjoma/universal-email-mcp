"""The per-user pool (WP 3e): effective permissions, configuration from store records,
connection and call caps with idle eviction, rebuilds, sweeping (fake backends)."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from tests.fakes import Connector, FakeSession
from tests.oauth_util import operator
from universal_email_mcp.config import Policy
from universal_email_mcp.errors import Busy
from universal_email_mcp.oauth.bearer import Principal
from universal_email_mcp.operator import PoolSettings
from universal_email_mcp.service.userpool import (
    UserContext,
    UserPool,
    build_user_config,
    effective_permissions,
)
from universal_email_mcp.store import Identity, KeyRing, MailAccount, MemoryBackend, Store

ALL = "mail.read mail.organize mail.delete mail.drafts"


def record(user: str, name: str, *, perms: tuple[str, ...] = ("read",), **kw: Any) -> MailAccount:
    return MailAccount(
        id="a_" + uuid.uuid4().hex[:10],
        user_id=user,
        name=name,
        host="imap.example.org",
        port=993,
        username=f"{name}@example.org",
        password=f"pw-{name}-SECRET",
        permissions=perms,
        created_at=datetime.now(UTC),
        **kw,
    )


def principal(user: str, accounts: dict[str, str], scopes: str = ALL) -> Principal:
    return Principal(
        user_id=user,
        grant_id="g_" + user,
        client_id="c",
        client_name="C",
        scopes=tuple(scopes.split()),
        account_scopes=accounts,
        identity_ids=(),
    )


# ---------------------------------------------------------------- permissions


@pytest.mark.parametrize(
    ("account", "grant", "token", "policy", "expected"),
    [
        (
            ("read", "organize"),
            "read organize",
            "mail.read mail.organize",
            Policy(),
            {"read", "organize"},
        ),
        (("read",), "read organize delete", ALL, Policy(), {"read"}),
        (("read", "organize"), "read", "mail.read mail.organize", Policy(), {"read"}),
        (("read", "organize"), "read organize", "mail.read", Policy(), {"read"}),
        (("read", "organize"), "read organize", ALL, Policy(read_only=True), {"read"}),
        (("read", "organize"), "organize", ALL, Policy(), None),
        (("organize",), "read organize", ALL, Policy(), None),
    ],
)
def test_effective_permissions(account, grant, token, policy, expected):  # noqa: ANN001
    rec = record("u", "A", perms=account)
    got = effective_permissions(rec, grant, token.split(), policy)
    if expected is None:
        assert got is None
    else:
        assert got is not None
        assert {n for n in ("read", "organize", "delete", "drafts") if getattr(got, n)} == expected


def test_pop3_stays_read_only():
    rec = record("u", "P", perms=("read", "organize"), protocol="pop3")
    got = effective_permissions(rec, "read organize", ["mail.read", "mail.organize"], Policy())
    assert got is not None and got.read and not got.organize


# ---------------------------------------------------------------- configuration


def test_config_uses_only_own_granted_records_and_hides_passwords():
    mine = record("alice", "Work", perms=("read", "organize"))
    dup = record("alice", "work", perms=("read",))
    odd = record("alice", "<script>", perms=("read",))
    foreign = record("bob", "Vault")
    ungranted = record("alice", "Secret")
    grants = {
        mine.id: "read organize",
        dup.id: "read",
        odd.id: "read",
        foreign.id: "read",
        "a_gone": "read",
    }
    cfg, records = build_user_config(
        operator(), principal("alice", grants), [mine, dup, odd, foreign, ungranted], []
    )
    assert [a.name for a in cfg.accounts] == ["Work", "work (2)", "Account 3"]
    assert set(records) == {"Work", "work (2)", "Account 3"}
    assert foreign.id not in {r.id for r in records.values()}
    assert cfg.account("Work").permissions.organize
    assert not cfg.account("work (2)").permissions.organize
    assert "SECRET" not in repr(cfg) and "SECRET" not in repr(cfg.accounts[0].credential)
    assert cfg.accounts[0].credential.secret == "pw-Work-SECRET"


def test_identities_follow_grant_and_drafts_accounts():
    acc = record("alice", "Work", perms=("read", "drafts"))
    ro = record("alice", "Ro", perms=("read",))
    now = datetime.now(UTC)

    def ident(addr: str, copies: str, *, default: bool = False) -> Identity:
        return Identity(
            id="i_" + uuid.uuid4().hex[:8],
            user_id="alice",
            addresses=(addr,),
            copies_account_id=copies,
            is_default=default,
            created_at=now,
        )

    via_drafts = ident("a@example.org", acc.id)
    via_ro = ident("b@example.org", ro.id)
    granted = ident("c@example.org", "", default=True)
    other_user = replace(ident("d@example.org", acc.id), user_id="bob")
    p = replace(
        principal("alice", {acc.id: "read drafts", ro.id: "read"}), identity_ids=(granted.id,)
    )
    cfg, _ = build_user_config(operator(), p, [acc, ro], [via_drafts, via_ro, granted, other_user])
    assert [i.addresses[0] for i in cfg.identities] == ["a@example.org", "c@example.org"]
    assert [i.default for i in cfg.identities] == [False, True]
    assert cfg.identities[0].store_account == "Work"
    assert all(not i.send for i in cfg.identities)


# ---------------------------------------------------------------- pool


class Harness:
    def __init__(self, pool_settings: PoolSettings, clock: list[float]) -> None:
        self.store = Store(MemoryBackend(), KeyRing({"k1": b"k" * 32}))
        self.op = operator(pool=pool_settings)
        self.clock = clock
        self.pool = UserPool(
            self.store,
            self.op,
            lambda service, maps: SimpleNamespace(instructions="", maps=maps),
            clock=lambda: clock[0],
        )
        self.connectors: dict[str, Connector] = {}

    async def context(self, user: str, names: list[str]) -> UserContext:
        recs = [await self.store.create(record(user, n)) for n in names]
        return await self.attach(user, {r.id: "read" for r in recs}, names)

    async def attach(self, user: str, grant: dict[str, str], names: list[str]) -> UserContext:
        ctx = await self.pool.acquire(principal(user, grant))
        conn = Connector({n: FakeSession(n, {"INBOX": [1]}) for n in names})
        self.connectors[user] = conn
        ctx.router._connectors = {"imap": conn}  # pyright: ignore
        ctx.router._clock = lambda: self.clock[0]  # pyright: ignore[reportPrivateUsage]
        return ctx

    async def use(self, ctx: UserContext, name: str, hang: float = 0.0) -> None:
        acc = ctx.router.account(name)
        self.connectors[ctx.user_id].sessions[name].hang = hang
        await ctx.router.call(acc, lambda s: s.list_folders())


async def test_connection_caps_evict_idle_then_refuse():
    h = Harness(PoolSettings(max_connections_per_user=2, max_connections=3), [0.0])
    alice = await h.context("alice", ["A1", "A2", "A3"])
    bob = await h.context("bob", ["B1", "B2"])
    await h.use(alice, "A1")
    h.clock[0] += 1
    await h.use(alice, "A2")
    assert h.pool.open_connections("alice") == 2
    # a third mailbox: the longest idle connection of this user makes room
    await h.use(alice, "A3")
    assert h.pool.open_connections("alice") == 2
    assert h.connectors["alice"].connects == ["A1", "A2", "A3"]
    # instance cap (3): bob gets one, the second evicts someone's idle connection
    await h.use(bob, "B1")
    await h.use(bob, "B2")
    assert h.pool.open_connections() <= 3
    # nothing idle: both of alice's connections busy -> BUSY for a new one
    h.clock[0] += 1
    busy = [asyncio.ensure_future(h.use(alice, n, hang=0.5)) for n in ("A2", "A3")]
    await asyncio.sleep(0.1)
    with pytest.raises(Busy):
        await h.use(alice, "A1")
    for n in ("A2", "A3"):
        h.connectors["alice"].sessions[n].hang = 0.0
    await asyncio.gather(*busy)
    await h.pool.aclose()


async def test_instance_cap_is_enforced_across_users():
    h = Harness(PoolSettings(max_connections_per_user=5, max_connections=2), [0.0])
    alice = await h.context("alice", ["A1", "A2"])
    bob = await h.context("bob", ["B1"])
    busy = [asyncio.ensure_future(h.use(alice, n, hang=0.5)) for n in ("A1", "A2")]
    await asyncio.sleep(0.1)
    with pytest.raises(Busy, match="limit"):
        await h.use(bob, "B1")
    for n in ("A1", "A2"):
        h.connectors["alice"].sessions[n].hang = 0.0
    await asyncio.gather(*busy)
    await h.use(bob, "B1")  # idle connections of alice make room now
    assert h.pool.open_connections() == 2
    await h.pool.aclose()


async def test_parallel_call_cap_per_user():
    h = Harness(PoolSettings(max_concurrent_calls_per_user=2), [0.0])
    alice = await h.context("alice", ["A1"])
    bob = await h.context("bob", ["B1"])
    async with h.pool.call_slot(alice), h.pool.call_slot(alice):
        with pytest.raises(Busy):
            async with h.pool.call_slot(alice):
                pass
        async with h.pool.call_slot(bob):  # other users are not affected
            pass
    async with h.pool.call_slot(alice):  # slots are released
        pass
    await h.pool.aclose()


async def test_changed_record_rebuilds_the_context_and_closes_old_connections():
    h = Harness(PoolSettings(), [0.0])
    rec = await h.store.create(record("alice", "Work"))
    ctx = await h.attach("alice", {rec.id: "read"}, ["Work"])
    await h.use(ctx, "Work")
    session = h.connectors["alice"].sessions["Work"]
    assert not session.closed
    same = await h.pool.acquire(principal("alice", {rec.id: "read"}))
    assert same is ctx
    await h.store.update(replace(rec, password="new-password"))
    fresh = await h.pool.acquire(principal("alice", {rec.id: "read"}))
    assert fresh is not ctx and fresh.config.accounts[0].credential.secret == "new-password"
    for _ in range(50):
        if session.closed:
            break
        await asyncio.sleep(0.02)
    assert session.closed and ctx.retired
    await h.pool.aclose()


async def test_sweep_closes_idle_connections_and_drops_idle_contexts():
    h = Harness(PoolSettings(connection_idle_ttl=60, user_idle_ttl=300), [0.0])
    ctx = await h.context("alice", ["A1"])
    await h.use(ctx, "A1")
    session = h.connectors["alice"].sessions["A1"]
    h.clock[0] = 30
    await h.pool.sweep()
    assert not session.closed
    h.clock[0] = 100
    await h.pool.sweep()
    for _ in range(50):
        if session.closed:
            break
        await asyncio.sleep(0.02)
    assert session.closed and h.pool.open_connections() == 0
    assert ("alice", ctx.grant_id) in h.pool._contexts  # pyright: ignore[reportPrivateUsage]
    h.clock[0] = 1000
    await h.pool.sweep()
    assert ("alice", ctx.grant_id) not in h.pool._contexts  # pyright: ignore[reportPrivateUsage]
    await h.pool.aclose()


async def test_context_cache_is_bounded():
    h = Harness(PoolSettings(max_cached_users=2), [0.0])
    for i, user in enumerate(("u1", "u2", "u3")):
        h.clock[0] = float(i)
        await h.context(user, [f"N{i}"])
    assert len(h.pool._contexts) == 2  # pyright: ignore[reportPrivateUsage]
    assert ("u1", "g_u1") not in h.pool._contexts  # pyright: ignore[reportPrivateUsage]
    await h.pool.aclose()
