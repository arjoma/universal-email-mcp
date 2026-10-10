"""Who is signing in: address normalisation, pseudonyms, and the mailbox login check.

The portal identity of v1 is the user's primary mailbox (design section 6): address plus
password, verified by an IMAP login against the server **the operator assigned to the
address's domain** (``LOGIN_DOMAINS``) - never a server the user names.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Protocol

from universal_email_mcp.bounded import run_deadline
from universal_email_mcp.errors import AuthFailed, Busy, ConfigError, MailError, ServerUnreachable
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.mail.net import NetPolicy, Resolver
from universal_email_mcp.models import ServerProfile, TlsSettings
from universal_email_mcp.presets import normalize_hostname

MAX_ADDRESS = 254
MIN_PSEUDONYM_KEY_BYTES = 32
MAX_CONCURRENT_CHECKS = 16
SLOT_WAIT = 5.0
"""Longest a sign-in waits for a free login check before it is answered as busy."""


@asynccontextmanager
async def bounded_slot(slots: asyncio.Semaphore, wait: float = SLOT_WAIT) -> AsyncIterator[None]:
    """Hold one slot of ``slots``; raises :class:`Busy` if none is free within ``wait`` seconds
    (tarpitting servers must not park every later sign-in until the long deadline)."""
    try:
        await asyncio.wait_for(slots.acquire(), wait)
    except TimeoutError:
        raise Busy("too many sign-in checks are running") from None
    try:
        yield
    finally:
        slots.release()


class AddressError(ValueError):
    """Not a usable e-mail address."""


@dataclass(frozen=True, slots=True)
class Address:
    login: str
    """As typed (trimmed); used as the IMAP login name."""
    normal: str
    """Lower-cased; the basis of the pseudonym."""
    domain: str
    """IDNA/ASCII lower-case domain."""


def parse_address(text: str) -> Address:
    t = text.strip()
    if not t or len(t) > MAX_ADDRESS:
        raise AddressError("empty or too long")
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in t) or any(c in t for c in '<>(),;:"\\'):
        raise AddressError("contains characters that are not allowed")
    local, sep, domain = t.rpartition("@")
    if not sep or not local or len(local) > 64 or "@" in local:
        raise AddressError("not an e-mail address")
    try:
        ascii_domain = normalize_hostname(domain)
    except ConfigError:
        raise AddressError("invalid domain") from None
    if "." not in ascii_domain:
        raise AddressError("invalid domain")
    return Address(login=t, normal=f"{local.lower()}@{ascii_domain}", domain=ascii_domain)


class Pseudonyms:
    """``user id = HMAC-SHA256(key, normalised primary address)`` (design section 9)."""

    def __init__(self, key: bytes) -> None:
        if len(key) < MIN_PSEUDONYM_KEY_BYTES:
            raise ConfigError(f"the pseudonym key needs at least {MIN_PSEUDONYM_KEY_BYTES} bytes")
        self._key = key

    def __repr__(self) -> str:
        return "Pseudonyms(...)"

    def user_id(self, normal_address: str) -> str:
        mac = hmac.new(self._key, b"uem-user-v1\0" + normal_address.encode(), hashlib.sha256)
        return "u_" + mac.hexdigest()[:32]


def short_id(user_id: str) -> str:
    """The form used in audit events."""
    return user_id[:14]


class LoginVerifier(Protocol):
    async def verify(self, address: Address, password: str, profile: ServerProfile) -> None:
        """Return normally if the credentials are valid. Raises ``AuthFailed`` for wrong
        credentials and another ``MailError`` when the server cannot be asked."""
        ...


@dataclass(frozen=True, slots=True)
class ImapLoginVerifier:
    """Login check by connecting to the operator-assigned IMAP server.

    ``net`` carries the SSRF policy (public addresses only unless the operator allows
    private networks); ``tls`` is only relaxed by tests.
    """

    net: NetPolicy
    tls: TlsSettings = TlsSettings()
    resolver: Resolver | None = None
    slot_wait: float = SLOT_WAIT
    _slots: asyncio.Semaphore = field(
        default_factory=lambda: asyncio.Semaphore(MAX_CONCURRENT_CHECKS), repr=False, compare=False
    )

    async def verify(self, address: Address, password: str, profile: ServerProfile) -> None:
        if profile.imap is None:
            raise MailError("the login server has no IMAP endpoint")
        endpoint = profile.imap

        def attempt() -> None:
            session = ImapSession.connect(
                endpoint,
                address.login,
                password,
                account_name="login",
                net=self.net,
                tls=self.tls,
                resolver=self.resolver,
            )
            session.close()

        # Own daemon thread under an absolute deadline (never the shared default executor),
        # and at most a few checks at a time (a wait for a free slot ends in :class:`Busy`).
        try:
            async with bounded_slot(self._slots, self.slot_wait):
                await run_deadline(attempt, seconds=self.net.total_timeout, expired_as_timeout=True)
        except TimeoutError:
            raise ServerUnreachable("the mail server did not answer in time") from None


__all__ = [
    "Address",
    "AddressError",
    "AuthFailed",
    "bounded_slot",
    "ImapLoginVerifier",
    "LoginVerifier",
    "Pseudonyms",
    "parse_address",
    "short_id",
]
