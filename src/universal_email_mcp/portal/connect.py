"""Connection tests of the portal: log in to a mailbox / submission server and report.

A test opens an outbound connection to a host a *user* named, so everything here is built
to leak nothing: the outcome is a short code (``ok``, ``auth``, ``unreachable`` ...) and,
on success, a few capability keywords - never the server's own text, which an attacker
running the server could use to carry content into the page. The connections go through
the SSRF-safe connector of :mod:`universal_email_mcp.mail.net` (resolve once, check every
address, connect to the checked IP, verify TLS for the host name).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from universal_email_mcp.bounded import run_deadline
from universal_email_mcp.errors import (
    AddressNotAllowed,
    AuthFailed,
    MailError,
    ServerUnreachable,
    TlsError,
    UnsupportedByServer,
)
from universal_email_mcp.mail import smtp
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.mail.net import NetPolicy, Resolver, current_deadline
from universal_email_mcp.mail.pop3 import Pop3Session
from universal_email_mcp.models import Endpoint, TlsSettings

TEST_TIMEOUT = 45.0
"""Overall deadline of one test (the socket timeouts are shorter; this is the backstop)."""
MAX_CONCURRENT_TESTS = 8

OK = "ok"
AUTH = "auth"
UNREACHABLE = "unreachable"
TLS = "tls"
BLOCKED = "blocked"
UNSUPPORTED = "unsupported"
PROTOCOL = "protocol"
TIMEOUT = "timeout"

_INTERESTING = {
    "imap": ("MOVE", "UIDPLUS", "SPECIAL-USE", "SORT", "CONDSTORE", "IDLE", "QUOTA"),
    "pop3": ("UIDL", "TOP", "PIPELINING", "STLS"),
    "smtp": ("STARTTLS", "SIZE", "8BITMIME", "PIPELINING"),
}


@dataclass(frozen=True, slots=True)
class TestOutcome:
    """Result of one test; ``status`` is one of the codes above."""

    __test__ = False  # not a pytest class

    status: str
    features: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status == OK


def classify(error: BaseException) -> str:
    """Map a connection error to a status code. Order matters (subclasses first)."""
    if isinstance(error, AuthFailed):
        return AUTH
    if isinstance(error, AddressNotAllowed):
        return BLOCKED
    if isinstance(error, TlsError):
        return TLS
    if isinstance(error, UnsupportedByServer):
        return UNSUPPORTED
    if isinstance(error, ServerUnreachable):
        return UNREACHABLE
    if isinstance(error, TimeoutError):
        return TIMEOUT
    return PROTOCOL


class ConnectionTester(Protocol):
    async def incoming(
        self, protocol: str, endpoint: Endpoint, username: str, password: str, net: NetPolicy
    ) -> TestOutcome: ...

    async def submission(
        self, endpoint: Endpoint, username: str, password: str, net: NetPolicy
    ) -> TestOutcome: ...


@dataclass(slots=True)
class LiveTester:
    """Real connections. ``tls`` / ``resolver`` are only changed by tests."""

    tls: TlsSettings = TlsSettings()  # noqa: RUF009 - frozen dataclass
    resolver: Resolver | None = None
    _slots: asyncio.Semaphore | None = None

    def _limit(self) -> asyncio.Semaphore:
        if self._slots is None:
            self._slots = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
        return self._slots

    async def _run(self, fn: Callable[[], TestOutcome]) -> TestOutcome:
        """On a daemon thread of its own under an absolute deadline: a server that
        trickles bytes cannot keep the thread (or any shared pool) busy past it."""

        def attempt() -> TestOutcome:
            outcome = fn()
            deadline = current_deadline()
            if deadline is not None and deadline.expired and not outcome.ok:
                return TestOutcome(TIMEOUT)  # the cut connection's error is not the story
            return outcome

        try:
            async with self._limit():
                return await run_deadline(attempt, seconds=TEST_TIMEOUT)
        except TimeoutError:
            return TestOutcome(TIMEOUT)

    async def incoming(
        self, protocol: str, endpoint: Endpoint, username: str, password: str, net: NetPolicy
    ) -> TestOutcome:
        def attempt() -> TestOutcome:
            try:
                if protocol == "pop3":
                    with Pop3Session.connect(
                        endpoint,
                        username,
                        password,
                        account_name="test",
                        net=net,
                        tls=self.tls,
                        resolver=self.resolver,
                    ) as p:
                        caps = tuple(c.upper() for c in p.capabilities)
                else:
                    with ImapSession.connect(
                        endpoint,
                        username,
                        password,
                        account_name="test",
                        net=net,
                        tls=self.tls,
                        resolver=self.resolver,
                    ) as i:
                        caps = tuple(c.upper() for c in i.capabilities)
            except (MailError, OSError, ValueError) as e:
                return TestOutcome(classify(e))
            kind = "pop3" if protocol == "pop3" else "imap"
            return TestOutcome(OK, tuple(c for c in _INTERESTING[kind] if c in caps))

        return await self._run(attempt)

    async def submission(
        self, endpoint: Endpoint, username: str, password: str, net: NetPolicy
    ) -> TestOutcome:
        def attempt() -> TestOutcome:
            try:
                ext = smtp.check_login(
                    endpoint,
                    username,
                    password,
                    tls=self.tls,
                    net=net,
                    resolver=self.resolver,
                )
            except (MailError, OSError, ValueError) as e:
                return TestOutcome(classify(e))
            return TestOutcome(OK, tuple(c for c in _INTERESTING["smtp"] if c in ext))

        return await self._run(attempt)
