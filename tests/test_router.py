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
    await asyncio.sleep(0.1)
    assert all(not s.called_on_loop for s in conn.sessions.values())


async def test_deadline_abort_never_runs_on_the_event_loop():
    router, conn = _router("A", timeout=0.2)
    acc = router.account("A")
    s = conn.sessions["A"]
    s.hang = 5.0
    s.close_delay = 1.0  # a blocking close/abort would stall the loop for a second

    async def work(a):  # noqa: ANN001, ANN202
        return await router.call(a, lambda x: x.search("INBOX").uids)

    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.02)
            ticks += 1

    t = asyncio.create_task(ticker())
    t0 = time.monotonic()
    with pytest.raises(AccountTimeout):
        await router.run_one(acc, work)
    assert time.monotonic() - t0 < 0.6
    await asyncio.sleep(0.3)
    t.cancel()
    assert ticks >= 15  # the loop kept running during abort and cleanup
    assert s.called_on_loop == []
    assert s.aborted.wait(3.0)


async def test_retries_share_one_in_flight_connect():
    router, conn = _router("A", timeout=0.1)
    conn.delay = 0.6  # tarpit: every connect outlives the deadline
    acc = router.account("A")

    async def work(a):  # noqa: ANN001, ANN202
        return await router.call(a, lambda s: s.search("INBOX").uids)

    for _ in range(4):
        with pytest.raises(AccountTimeout):
            await router.run_one(acc, work)
    assert conn.connects == ["A"] and conn.peak == 1
    await asyncio.sleep(0.7)  # the attempt finishes; its session is adopted
    conn.delay = 0.0
    assert await router.run_one(acc, work) == (2, 1)
    assert conn.connects == ["A"]
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


def test_hanging_worker_does_not_delay_process_exit():
    """A server that hangs keeps only a daemon thread: asyncio.run and the
    interpreter exit do not wait for it (they join executor threads)."""
    import subprocess
    import sys
    import time

    code = (
        "import asyncio, time\n"
        "from universal_email_mcp.service.router import _run_daemon\n"
        "async def main():\n"
        "    fut = _run_daemon(asyncio.get_running_loop(), time.sleep, 60)\n"
        "    try:\n"
        "        await asyncio.wait_for(asyncio.shield(fut), 0.2)\n"
        "    except TimeoutError:\n"
        "        pass\n"
        "asyncio.run(main())\n"
    )
    t0 = time.monotonic()
    subprocess.run([sys.executable, "-c", code], check=True, timeout=30)
    assert time.monotonic() - t0 < 15


async def test_run_daemon_delivers_results_and_errors():
    import asyncio

    from universal_email_mcp.service.router import _run_daemon

    loop = asyncio.get_running_loop()
    assert await _run_daemon(loop, lambda a, b: a + b, 1, b=2) == 3

    def boom() -> None:
        raise ValueError("x")

    with pytest.raises(ValueError):
        await _run_daemon(loop, boom)
