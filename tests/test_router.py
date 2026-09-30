"""Account router: fan-out, deadlines, partial failures, reconnects (fake backends)."""

from __future__ import annotations

import asyncio
import time

import pytest

from universal_email_mcp.config import parse_config
from universal_email_mcp.errors import (
    AccountTimeout,
    AuthFailed,
    ConfigError,
    NotPermitted,
    NotSupportedYet,
    ProtocolError,
    ServerUnreachable,
)
from universal_email_mcp.service.router import AccountRouter

from .fakes import Connector, FakeSession, config


def _router(*names: str, timeout: float = 2.0, **kw: object) -> tuple[AccountRouter, Connector]:
    conn = Connector({n: FakeSession(n, {"INBOX": [1, 2]}) for n in names})
    return AccountRouter(config(*names, timeout=timeout, **kw), connectors={"imap": conn}), conn


async def test_fanout_parallel_with_partial_failures():
    router, conn = _router("A", "B", "C", "D", timeout=0.5)
    conn.fail["B"] = AuthFailed("login rejected")
    conn.sessions["C"].hang = 5.0
    accounts, problems = router.select(None)
    assert problems == []

    async def work(acc):  # noqa: ANN001, ANN202
        return await router.call(acc, lambda s: s.search("INBOX").uids)

    t0 = time.monotonic()
    fan = await router.fanout(accounts, work)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0  # the slow account does not hold up the others
    assert set(fan.results) == {"A", "D"}
    codes = {p.account: p.code for p in fan.problems}
    assert codes == {"B": "AUTH_FAILED", "C": "TIMEOUT"}
    # the hung connection was torn down so its worker thread stops
    assert conn.sessions["C"].aborted.wait(2.0)
    await router.aclose()


async def test_timeout_discards_session_and_reconnects_next_time():
    router, conn = _router("A", timeout=0.3)
    acc = router.account("A")
    conn.sessions["A"].hang = 5.0

    async def work(a):  # noqa: ANN001, ANN202
        return await router.call(a, lambda s: s.search("INBOX").uids)

    with pytest.raises(AccountTimeout):
        await router.run_one(acc, work)
    conn.sessions["A"].hang = 0.0
    assert await router.run_one(acc, work) == (2, 1)
    assert conn.connects == ["A", "A"]


async def test_dropped_connection_reconnects_once():
    router, conn = _router("A")
    acc = router.account("A")
    assert await router.call(acc, lambda s: s.search("INBOX").total) == 2
    conn.sessions["A"].fail_next = True  # reused connection turns out dead
    assert await router.call(acc, lambda s: s.search("INBOX").total) == 2
    assert conn.connects == ["A", "A"]


async def test_fresh_connection_failure_is_not_retried():
    router, conn = _router("A")
    acc = router.account("A")
    conn.sessions["A"].fail_next = True
    with pytest.raises(ServerUnreachable):
        await router.call(acc, lambda s: s.search("INBOX"))
    assert conn.connects == ["A"]


async def test_unexpected_exception_becomes_protocol_error():
    router, _conn = _router("A")
    acc = router.account("A")

    def boom(_s: object) -> None:
        raise KeyError("x")

    with pytest.raises(ProtocolError):
        await router.call(acc, boom)


async def test_calls_per_account_are_serialised():
    router, conn = _router("A")
    acc = router.account("A")
    active = 0
    peak = 0

    def fn(_s: object) -> None:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        time.sleep(0.05)
        active -= 1

    await asyncio.gather(*(router.call(acc, fn) for _ in range(4)))
    assert peak == 1 and conn.connects == ["A"]


async def test_idle_session_is_reopened():
    now = [0.0]
    conn = Connector({"A": FakeSession("A", {"INBOX": [1]})})
    router = AccountRouter(
        config("A"), connectors={"imap": conn}, idle_ttl=60, clock=lambda: now[0]
    )
    acc = router.account("A")
    await router.call(acc, lambda s: None)
    now[0] = 30
    await router.call(acc, lambda s: None)
    now[0] = 200
    await router.call(acc, lambda s: None)
    assert conn.connects == ["A", "A"]


def test_select_permissions_pop3_and_caps():
    cfg = parse_config(
        {
            "accounts": [
                {"name": "A", "username": "a", "server": "imap.example.org"},
                {"name": "B", "username": "b", "server": "imap.example.org"},
                {"name": "C", "username": "c", "server": "imap.example.org"},
                {"name": "P", "kind": "pop3", "username": "p", "server": "pop.example.org"},
            ],
            "limits": {"max_accounts_per_call": 2},
        }
    )
    router = AccountRouter(cfg, connectors={"imap": Connector({})})
    accounts, problems = router.select(None)
    assert [a.name for a in accounts] == ["A", "B"]
    assert {p.account: p.code for p in problems} == {"P": "NOT_SUPPORTED_YET", "C": "SKIPPED"}
    with pytest.raises(ConfigError):
        router.select(["nope"])
    with pytest.raises(NotSupportedYet):
        router.account("P")
    with pytest.raises(NotPermitted):
        router.account("A", "organize")
    accounts, problems = router.select(["a", "A"])
    assert [a.name for a in accounts] == ["A"] and problems == []
