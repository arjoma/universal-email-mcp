"""Settings of the authorization server and the scope vocabulary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

MCP_PATH = "/mcp"

SCOPE_READ = "mail.read"
SCOPE_ORGANIZE = "mail.organize"
SCOPE_DELETE = "mail.delete"
SCOPE_DRAFTS = "mail.drafts"
SCOPE_SEND = "mail.send"
SCOPES: tuple[str, ...] = (SCOPE_READ, SCOPE_ORGANIZE, SCOPE_DELETE, SCOPE_DRAFTS, SCOPE_SEND)
"""Everything a client can be granted, least to most dangerous. ``mail.read`` is the base:
without it nothing else is granted. ``mail.send`` is granted over *identities*, the others
over *accounts* (design sections 5 and 6.1)."""

ACCOUNT_SCOPES: tuple[str, ...] = (SCOPE_READ, SCOPE_ORGANIZE, SCOPE_DELETE, SCOPE_DRAFTS)
"""Scopes that map to an account permission of the same name (``mail.read`` = ``read``)."""


def permission_of(scope: str) -> str:
    """``mail.organize`` -> ``organize`` (the permission name used by accounts)."""
    return scope.removeprefix("mail.")


@dataclass(frozen=True, slots=True)
class Rate:
    """At most ``count`` events per ``window``."""

    count: int
    window: timedelta

    def __post_init__(self) -> None:
        if self.count < 1 or self.window.total_seconds() < 1:
            raise ValueError("a rate needs at least one event and a window of one second")

    @property
    def seconds(self) -> float:
        return self.window.total_seconds()

    def __str__(self) -> str:
        secs = int(self.seconds)
        for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
            if secs % size == 0:
                return f"{self.count}/{secs // size}{unit}"
        return f"{self.count}/{secs}s"


def _r(count: int, **window: int) -> Rate:
    return Rate(count, timedelta(**window))


@dataclass(frozen=True, slots=True)
class RateLimits:
    """Every in-memory limit of OAuth mode in one place (``Rate`` = count per window).

    All are per instance (the send limit is the one shared limit, counted in the store).
    ``UEM_RATE_<NAME>`` in the operator environment overrides the field of that name; the
    table in ``docs/operator-env.md`` is checked against :data:`RATE_VARIABLES` by a test.
    """

    # sign-in and re-authentication (a password check = a brute-force surface)
    signin_address: Rate = _r(5, minutes=15)
    """Wrong passwords per address / user (sign-in and portal re-authentication share it)."""
    signin_ip: Rate = _r(20, minutes=15)
    """Sign-in and re-authentication attempts per network."""
    # authorization server
    authorize_ip: Rate = _r(120, minutes=10)
    """POSTs to ``/authorize`` (sign-in, consent, deny, sign-out) per network."""
    register_ip: Rate = _r(10, hours=1)
    register_global: Rate = _r(200, hours=1)
    token_ip: Rate = _r(300, minutes=1)
    """``/token`` and ``/revoke`` per network."""
    client_fetch_ip: Rate = _r(30, minutes=1)
    """Client ID Metadata Document downloads per network."""
    client_fetch_global: Rate = _r(120, hours=1)
    """The same for the whole instance: every download that is not served from the cache also
    writes a client record, so many networks together must not fill the store or make the
    instance a fetch cannon."""
    # portal
    portal_user: Rate = _r(60, minutes=10)
    """State-changing portal requests (any POST) per signed-in user."""
    portal_ip: Rate = _r(120, minutes=10)
    """The same per network."""
    test_user: Rate = _r(10, minutes=10)
    """Connection tests (they open outbound connections and try logins) per user."""
    test_ip: Rate = _r(30, minutes=10)
    test_target: Rate = _r(5, minutes=15)
    """Tests / logins against one mailbox (host, port, user name)."""
    viewer_user: Rate = _r(120, minutes=1)
    """Message pages and HTML frames of the viewer per user."""
    download_user: Rate = _r(60, minutes=10)
    """Raw ``.eml`` and attachment downloads per user."""
    # tool calls (MCP)
    tool_user_burst: Rate = _r(30, seconds=10)
    tool_user: Rate = _r(600, minutes=10)
    """All tool calls of one user, all grants together."""
    tool_grant_burst: Rate = _r(20, seconds=10)
    tool_grant: Rate = _r(300, minutes=10)
    """All tool calls of one grant (one connected client)."""
    tool_write_burst: Rate = _r(10, seconds=10)
    tool_write: Rate = _r(60, minutes=10)
    """Extra, tighter limit on the tools that change something (``audit.WRITE_TOOLS``)."""


RATE_PREFIX = "UEM_RATE_"
RATE_VARIABLES: dict[str, str] = {RATE_PREFIX + f.upper(): f for f in RateLimits.__slots__}
"""Environment variable -> ``RateLimits`` field."""


@dataclass(frozen=True, slots=True)
class OAuthConfig:
    issuer: str
    """The public origin (``PUBLIC_URL``), also the ``iss`` value."""
    offered_scopes: tuple[str, ...] = SCOPES
    """Scopes the operator's policy lets a client obtain at all."""
    default_language: str = "en"
    dcr_enabled: bool = True
    dcr_redirect_hosts: tuple[str, ...] = ()
    """Non-loopback hosts a dynamically registered redirect URI may use (empty = any)."""
    portal_idle: timedelta = timedelta(minutes=30)
    portal_max: timedelta = timedelta(hours=12)
    trusted_proxy_hops: int = 0
    reauth_window: timedelta = timedelta(minutes=5)
    max_accounts: int = 10
    max_identities: int = 10
    cimd_cache_ttl: timedelta = timedelta(hours=1)
    rate_limits: RateLimits = field(default_factory=RateLimits)

    @property
    def resource(self) -> str:
        """The protected resource (RFC 8707 / 9728): the MCP endpoint."""
        return self.issuer + MCP_PATH

    @property
    def secure_cookies(self) -> bool:
        return self.issuer.startswith("https://")

    def url(self, path: str) -> str:
        return self.issuer + path
