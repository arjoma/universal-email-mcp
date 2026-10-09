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
from universal_email_mcp.oauth.config import OAuthConfig
from universal_email_mcp.oauth.identity import LoginVerifier, Pseudonyms
from universal_email_mcp.oauth.ratelimit import RateLimiter
from universal_email_mcp.portal.web import Portal
from universal_email_mcp.store import Store


@dataclass(slots=True)
class Limiters:
    signin_address: RateLimiter
    signin_ip: RateLimiter
    register_ip: RateLimiter
    register_global: RateLimiter
    token_ip: RateLimiter
    client_fetch: RateLimiter
    test_user: RateLimiter
    test_ip: RateLimiter
    test_target: RateLimiter

    @classmethod
    def from_config(cls, cfg: OAuthConfig) -> Limiters:
        r = cfg.rate_limits
        return cls(
            signin_address=RateLimiter(r.signin_per_address, r.signin_window.total_seconds()),
            signin_ip=RateLimiter(r.signin_per_ip, r.signin_window.total_seconds()),
            register_ip=RateLimiter(r.register_per_ip, r.register_window.total_seconds()),
            register_global=RateLimiter(r.register_global, r.register_window.total_seconds()),
            token_ip=RateLimiter(r.token_per_ip, r.token_window.total_seconds()),
            client_fetch=RateLimiter(r.client_fetch_per_ip, r.client_fetch_window.total_seconds()),
            test_user=RateLimiter(r.test_per_user, r.test_window.total_seconds()),
            test_ip=RateLimiter(r.test_per_ip, r.test_window.total_seconds()),
            test_target=RateLimiter(r.test_per_target, r.signin_window.total_seconds()),
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
