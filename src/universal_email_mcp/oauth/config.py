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
class RateLimits:
    """Attempts per window; all in-memory per instance (see TODO for multi-instance)."""

    signin_per_address: int = 5
    signin_per_ip: int = 20
    signin_window: timedelta = timedelta(minutes=15)
    register_per_ip: int = 10
    register_global: int = 200
    register_window: timedelta = timedelta(hours=1)
    token_per_ip: int = 300
    token_window: timedelta = timedelta(minutes=1)
    client_fetch_per_ip: int = 30
    client_fetch_window: timedelta = timedelta(minutes=1)


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
