"""The authorization server's shared state: store, clients, sign-in, limiters, portal."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from starlette.responses import JSONResponse

from universal_email_mcp import audit
from universal_email_mcp.models import ServerProfile
from universal_email_mcp.oauth.clients import ClientRegistry
from universal_email_mcp.oauth.config import OAuthConfig, Rate
from universal_email_mcp.oauth.identity import LoginVerifier, Pseudonyms
from universal_email_mcp.oauth.ratelimit import RateLimiter
from universal_email_mcp.portal.web import Portal
from universal_email_mcp.store import Store


def _limiter(rate: Rate) -> RateLimiter:
    return RateLimiter(rate.count, rate.seconds)


@dataclass(slots=True)
class Limiters:
    """The limiters of the authorization server and the portal (tool calls have their own,
    :class:`~universal_email_mcp.service.toolrate.ToolRateLimiter`). Per instance."""

    signin_address: RateLimiter
    signin_ip: RateLimiter
    authorize_ip: RateLimiter
    register_ip: RateLimiter
    register_global: RateLimiter
    token_ip: RateLimiter
    client_fetch: RateLimiter
    client_fetch_global: RateLimiter
    portal_user: RateLimiter
    portal_ip: RateLimiter
    test_user: RateLimiter
    test_ip: RateLimiter
    test_target: RateLimiter
    viewer_user: RateLimiter
    download_user: RateLimiter

    @classmethod
    def from_config(cls, cfg: OAuthConfig) -> Limiters:
        r = cfg.rate_limits
        return cls(
            signin_address=_limiter(r.signin_address),
            signin_ip=_limiter(r.signin_ip),
            authorize_ip=_limiter(r.authorize_ip),
            register_ip=_limiter(r.register_ip),
            register_global=_limiter(r.register_global),
            token_ip=_limiter(r.token_ip),
            client_fetch=_limiter(r.client_fetch_ip),
            client_fetch_global=_limiter(r.client_fetch_global),
            portal_user=_limiter(r.portal_user),
            portal_ip=_limiter(r.portal_ip),
            test_user=_limiter(r.test_user),
            test_ip=_limiter(r.test_ip),
            test_target=_limiter(r.test_target),
            viewer_user=_limiter(r.viewer_user),
            download_user=_limiter(r.download_user),
        )


@dataclass(slots=True)
class OAuthService:
    cfg: OAuthConfig
    store: Store
    clients: ClientRegistry
    pseudonyms: Pseudonyms
    login: LoginVerifier
    login_domains: Mapping[str, ServerProfile]
    portal: Portal
    limits: Limiters
    login_slots: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(16))
    """Bounds the threads the mailbox login checks (sign-in, re-authentication) can occupy."""

    async def audit(self, name: str, **fields: Any) -> None:
        """Audit event plus the user's own-activity entry (see :mod:`universal_email_mcp.audit`)."""
        await audit.record(name, **fields)


def oauth_error(
    error: str,
    description: str = "",
    *,
    status: int = 400,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """RFC 6749 section 5.2 error body; never cached."""
    body = {"error": error}
    if description:
        body["error_description"] = description
    return JSONResponse(
        body,
        status_code=status,
        headers={"cache-control": "no-store", "pragma": "no-cache", **(headers or {})},
    )


def same_resource(a: str, b: str) -> bool:
    """RFC 8707 resource comparison, tolerant of one trailing slash."""
    return a.rstrip("/") == b.rstrip("/")
