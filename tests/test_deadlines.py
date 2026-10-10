"""Absolute deadlines: a tarpitting mail server cannot hold a thread or starve other work.

Per-read socket timeouts never fire against a server that sends one byte at a time, so
every blocking mail call runs on its own daemon thread under a watchdog that shuts the
sockets down (``Deadline``), never on asyncio's default executor.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any, cast

import pytest

from tests.fakes import config
from universal_email_mcp.bounded import run_deadline
from universal_email_mcp.errors import RateLimited, ServerUnreachable, TlsError
from universal_email_mcp.mail import smtp
from universal_email_mcp.mail.net import Deadline, NetPolicy, open_connection
from universal_email_mcp.models import CredentialRef, Endpoint, TlsSettings
from universal_email_mcp.oauth.identity import Address, ImapLoginVerifier
from universal_email_mcp.portal import connect as portal_connect
from universal_email_mcp.portal.connect import TIMEOUT, LiveTester
from universal_email_mcp.service.send import Sender

from .imap_server import ScriptedImapServer

INSECURE = TlsSettings(verify=False)


def _workers() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "uem-worker" and t.is_alive()]


async def _no_workers_left(within: float = 3.0) -> bool:
    end = time.monotonic() + within
    while time.monotonic() < end:
        if not _workers():
            return True
        await asyncio.sleep(0.05)
    return not _workers()


@pytest.fixture
def one_thread_default_executor():  # noqa: ANN201
    """Make any use of asyncio's default executor by mail code visible: a single worker."""

    async def install() -> ThreadPoolExecutor:
        pool = ThreadPoolExecutor(1, thread_name_prefix="default-executor")
        asyncio.get_running_loop().set_default_executor(pool)
        return pool

    return install


async def _unrelated_call_is_prompt() -> float:
    t0 = time.monotonic()
    assert await asyncio.wait_for(asyncio.to_thread(lambda: "ok"), 2) == "ok"
    return time.monotonic() - t0


# --------------------------------------------------------------------- Deadline itself


def test_deadline_shuts_a_blocked_read_down():
    srv = socket.create_server(("127.0.0.1", 0))
    held: list[socket.socket] = []
    threading.Thread(target=lambda: held.append(srv.accept()[0]), daemon=True).start()
    outcome: dict[str, object] = {}

    def client() -> None:
        with Deadline(0.3) as d:
            sock = open_connection(
                "localhost",
                srv.getsockname()[1],
                NetPolicy(allow_private=True, read_timeout=30),
                lambda _h, _p: ["127.0.0.1"],
            )
            t0 = time.monotonic()
            try:
                outcome["data"] = sock.recv(10)  # the server never answers: EOF after shutdown
            except OSError as e:
                outcome["error"] = e
            outcome["seconds"] = time.monotonic() - t0
            outcome["expired"] = d.expired
        sock.close()

    th = threading.Thread(target=client, daemon=True)
    th.start()
    th.join(5)
    srv.close()
    assert not th.is_alive()
    assert outcome["expired"] is True
    assert float(cast(float, outcome["seconds"])) < 2


def test_deadline_cancel_leaves_the_real_socket_alone():
    srv = socket.create_server(("127.0.0.1", 0))
    threading.Thread(target=lambda: srv.accept(), daemon=True).start()
    with Deadline(30) as d:
        sock = open_connection(
            "localhost",
            srv.getsockname()[1],
            NetPolicy(allow_private=True),
            lambda _h, _p: ["127.0.0.1"],
        )
    assert not d.expired
    sock.sendall(b"still open")  # the watchdog released its duplicate only
    sock.close()
    srv.close()


# --------------------------------------------------------------------- portal test / sign-in


async def test_trickling_servers_stall_neither_each_other_nor_the_default_executor(
    monkeypatch: pytest.MonkeyPatch, one_thread_default_executor: Any
):
    monkeypatch.setattr(portal_connect, "TEST_TIMEOUT", 1.0)
    pool = await one_thread_default_executor()
    net = NetPolicy(allow_private=True, connect_timeout=2, read_timeout=2)
    tester = LiveTester(tls=INSECURE, resolver=lambda _h, _p: ["127.0.0.1"])
    # TLS handshake completes, then the greeting trickles a byte every 0.1 s (28 bytes).
    with ScriptedImapServer(trickle_greeting=0.1) as srv:
        ep = Endpoint("localhost", srv.port, "tls")
        t0 = time.monotonic()
        tests = [asyncio.create_task(tester.incoming("imap", ep, "u", "p", net)) for _ in range(6)]
        await asyncio.sleep(0.3)
        assert await _unrelated_call_is_prompt() < 0.5  # mail tests are not on the default pool
        outcomes = await asyncio.gather(*tests)
        elapsed = time.monotonic() - t0
    assert {o.status for o in outcomes} == {TIMEOUT}
    assert elapsed < 3.5  # the deadline (1 s) ended every one of them
    assert await _no_workers_left()  # and the threads are free again
    pool.shutdown(wait=False)


async def test_sign_in_check_ends_at_its_deadline(one_thread_default_executor: Any):
    pool = await one_thread_default_executor()
    net = NetPolicy(allow_private=True, connect_timeout=2, read_timeout=2, total_timeout=1.0)
    verifier = ImapLoginVerifier(net, tls=INSECURE, resolver=lambda _h, _p: ["127.0.0.1"])
    with ScriptedImapServer(trickle_greeting=0.1) as srv:
        profile = SimpleNamespace(imap=Endpoint("localhost", srv.port, "tls"))
        t0 = time.monotonic()
        task = asyncio.create_task(
            verifier.verify(
                Address("u@x.example", "u@x.example", "x.example"), "p", cast(Any, profile)
            )
        )
        await asyncio.sleep(0.3)
        assert await _unrelated_call_is_prompt() < 0.5
        with pytest.raises(ServerUnreachable):
            await task
        assert time.monotonic() - t0 < 3.5
    assert await _no_workers_left()
    pool.shutdown(wait=False)


async def test_a_tarpit_during_the_tls_handshake_is_cut_too():
    """The server accepts the connection and never speaks TLS."""
    srv = socket.create_server(("127.0.0.1", 0))
    held: list[socket.socket] = []

    def accept() -> None:
        while True:
            try:
                held.append(srv.accept()[0])
            except OSError:
                return

    threading.Thread(target=accept, daemon=True).start()
    net = NetPolicy(allow_private=True, connect_timeout=2, read_timeout=30, total_timeout=0.5)
    verifier = ImapLoginVerifier(net, tls=INSECURE, resolver=lambda _h, _p: ["127.0.0.1"])
    profile = SimpleNamespace(imap=Endpoint("localhost", srv.getsockname()[1], "tls"))
    t0 = time.monotonic()
    with pytest.raises((ServerUnreachable, TlsError)):
        await verifier.verify(
            Address("u@x.example", "u@x.example", "x.example"), "p", cast(Any, profile)
        )
    assert time.monotonic() - t0 < 3
    assert await _no_workers_left()
    srv.close()


async def test_run_deadline_gives_up_on_a_thread_that_ignores_the_watchdog(
    monkeypatch: pytest.MonkeyPatch,
):
    import universal_email_mcp.bounded as bounded

    monkeypatch.setattr(bounded, "GRACE", 0.2)
    release = threading.Event()
    t0 = time.monotonic()
    with pytest.raises(TimeoutError):
        await run_deadline(lambda: release.wait(10), seconds=0.2)
    assert time.monotonic() - t0 < 2
    release.set()
    assert await _no_workers_left()


# --------------------------------------------------------------------- SMTP submission


def _trickling_smtp(interval: float) -> tuple[socket.socket, int]:
    srv = socket.create_server(("127.0.0.1", 0))

    def serve(conn: socket.socket) -> None:
        try:
            for b in b"220 trickle ESMTP ready\r\n":
                conn.sendall(bytes([b]))
                time.sleep(interval)
        except OSError:
            pass
        finally:
            conn.close()

    def accept() -> None:
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(c,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return srv, srv.getsockname()[1]


async def test_smtp_submit_against_a_trickling_server_ends_at_the_deadline(
    one_thread_default_executor: Any,
):
    pool = await one_thread_default_executor()
    srv, port = _trickling_smtp(0.1)
    net = NetPolicy(allow_private=True, connect_timeout=2, read_timeout=5, total_timeout=1.0)

    def send() -> smtp.SmtpReceipt:
        return smtp.submit(
            Endpoint("localhost", port, "starttls"),
            "u",
            "p",
            sender="a@example.org",
            recipients=["b@example.net"],
            raw=b"Subject: x\r\n\r\nbody\r\n",
            max_bytes=10_000,
            tls=INSECURE,
            net=net,
            resolver=lambda _h, _p: ["127.0.0.1"],
        )

    t0 = time.monotonic()
    task = asyncio.create_task(run_deadline(send, seconds=net.total_timeout))
    await asyncio.sleep(0.3)
    assert await _unrelated_call_is_prompt() < 0.5
    with pytest.raises(ServerUnreachable):
        await task
    assert time.monotonic() - t0 < 3.5
    assert await _no_workers_left()
    srv.close()
    pool.shutdown(wait=False)


async def test_a_slow_submission_neither_holds_the_sender_lock_nor_hides_from_the_rate_limit():
    """Sender._deliver used to keep its lock across the whole SMTP conversation."""
    started = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def submit(*_a: object, **kw: Any) -> smtp.SmtpReceipt:
        calls.append(kw["sender"])
        started.set()
        release.wait(10)
        return smtp.SmtpReceipt("250 queued", "TLS", 10)

    cfg = config("A")
    sender = Sender.__new__(Sender)
    sender.config = cfg
    sender.remote = None
    sender._submit = submit  # pyright: ignore[reportPrivateUsage]
    sender._lock = asyncio.Lock()  # pyright: ignore[reportPrivateUsage]
    sender._sent = set()  # pyright: ignore[reportPrivateUsage]
    sender._in_flight = set()  # pyright: ignore[reportPrivateUsage]
    from universal_email_mcp.service.send import SendLimiter

    sender.limiter = SendLimiter(per_hour=1, per_day=10)

    async def afterwards(_p: object, _r: object) -> None:
        return None

    sender._afterwards = afterwards  # type: ignore[method-assign]  # pyright: ignore[reportPrivateUsage]

    def prepared(mid: str) -> Any:
        acc = SimpleNamespace(
            name="smtp",
            username="u",
            tls=INSECURE,
            credential=CredentialRef("inline", "smtp", "pw"),
            server=SimpleNamespace(smtp=Endpoint("smtp.example.org", 587, "starttls")),
            public_only=True,
        )
        sender_addr = SimpleNamespace(email="me@example.org")
        out = SimpleNamespace(
            message_id=mid,
            recipients=[SimpleNamespace(email="you@example.net")],
            sender=sender_addr,
            raw=b"x",
        )
        return SimpleNamespace(out=out, smtp_account=acc, ref=None)

    result = SimpleNamespace(status="", receipt=None, draft_id=None)

    first = asyncio.create_task(sender._deliver(prepared("<1@x>"), result, {}))  # pyright: ignore[reportPrivateUsage,reportArgumentType]
    assert await asyncio.to_thread(started.wait, 3)
    # While the first submission is on the wire the lock is free and the budget is reserved.
    assert not sender._lock.locked()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(RateLimited):
        await asyncio.wait_for(sender._deliver(prepared("<2@x>"), result, {}), 2)  # pyright: ignore[reportPrivateUsage,reportArgumentType]
    release.set()
    await first
    assert calls == ["me@example.org"]  # the refused one never reached the server


async def test_sign_in_check_waiting_for_a_slot_gives_up_as_busy():
    from universal_email_mcp.errors import Busy
    from universal_email_mcp.oauth.identity import bounded_slot

    net = NetPolicy(allow_private=True, total_timeout=5.0)
    verifier = ImapLoginVerifier(net, slot_wait=0.2)
    for _ in range(16):  # every slot held, like 16 tarpitted sign-ins
        await verifier._slots.acquire()  # pyright: ignore[reportPrivateUsage]
    profile = SimpleNamespace(imap=Endpoint("localhost", 1, "tls"))
    t0 = time.monotonic()
    with pytest.raises(Busy):
        await verifier.verify(
            Address("u@x.example", "u@x.example", "x.example"), "p", cast(Any, profile)
        )
    assert time.monotonic() - t0 < 2
    sem = asyncio.Semaphore(1)
    async with bounded_slot(sem, 0.1):
        with pytest.raises(Busy):
            async with bounded_slot(sem, 0.1):
                pass
    async with bounded_slot(sem, 0.1):  # the slot came back
        pass
