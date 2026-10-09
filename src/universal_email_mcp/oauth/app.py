"""OAuth mode: assemble the store, the authorization server and ``/mcp`` into one app."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import replace

from starlette.applications import Starlette

from universal_email_mcp import audit
from universal_email_mcp.config import Policy
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import TlsSettings
from universal_email_mcp.oauth.bearer import StoreTokenVerifier
from universal_email_mcp.oauth.clients import ClientRegistry
from universal_email_mcp.oauth.config import (
    ACCOUNT_SCOPES,
    MCP_PATH,
    SCOPE_READ,
    SCOPE_SEND,
    OAuthConfig,
    RateLimits,
)
from universal_email_mcp.oauth.endpoints import oauth_group
from universal_email_mcp.oauth.fetch import FetchPolicy
from universal_email_mcp.oauth.identity import ImapLoginVerifier, LoginVerifier, Pseudonyms
from universal_email_mcp.oauth.service import Limiters, OAuthService
from universal_email_mcp.operator import OperatorConfig
from universal_email_mcp.portal.connect import ConnectionTester, LiveTester
from universal_email_mcp.portal.pages import portal_group
from universal_email_mcp.portal.service import CONNECT_TIMEOUT, READ_TIMEOUT, PortalService
from universal_email_mcp.portal.viewer import viewer_group
from universal_email_mcp.portal.web import Portal
from universal_email_mcp.server.app import build_server
from universal_email_mcp.server.http import RouteGroup, create_app
from universal_email_mcp.server.peruser import (
    PerUserServer,
    request_state_security,
    wrap_routes,
)
from universal_email_mcp.service.userpool import UserPool
from universal_email_mcp.store import Backend, MemoryBackend, SessionPolicy, Store, User

log = logging.getLogger(__name__)

PURGE_INTERVAL = 600.0
CORS_PATHS = (MCP_PATH, "/.well-known", "/register", "/token", "/revoke")
"""Cookie-less endpoints that browser-based MCP clients may call cross-origin."""


def offered_scopes(policy: Policy) -> tuple[str, ...]:
    """What the operator's policy lets any client obtain (read-only deployments offer
    only reading; sending is offered unless the send policy is ``off``)."""
    if policy.read_only:
        return (SCOPE_READ,)
    scopes = list(ACCOUNT_SCOPES)
    if policy.send != "off":
        scopes.append(SCOPE_SEND)
    return tuple(scopes)


def make_backend(op: OperatorConfig) -> Backend:
    assert op.store is not None
    if op.store.backend == "memory":
        return MemoryBackend()
    from universal_email_mcp.store.firestore import FirestoreBackend  # optional extra "gcp"

    return FirestoreBackend(
        project=op.store.firestore_project,
        database=op.store.firestore_database,
        prefix=op.store.prefix,
    )


def make_store(op: OperatorConfig) -> Store:
    assert op.store is not None
    o = op.oauth
    policy = SessionPolicy(
        access_ttl=o.access_ttl,
        refresh_ttl=o.refresh_ttl,
        absolute_max=o.absolute_max,
        approval_ttl=o.approval_ttl,
    )
    return Store(make_backend(op), op.store.keys, policy=policy)


def make_config(op: OperatorConfig, *, rate_limits: RateLimits | None = None) -> OAuthConfig:
    assert op.public_url is not None
    o = op.oauth
    return OAuthConfig(
        issuer=op.public_url,
        offered_scopes=offered_scopes(op.policy),
        default_language=o.default_language,
        dcr_enabled=o.dcr_enabled,
        dcr_redirect_hosts=o.dcr_redirect_hosts,
        portal_idle=o.portal_idle,
        portal_max=o.portal_max,
        trusted_proxy_hops=o.trusted_proxy_hops,
        reauth_window=o.reauth_window,
        max_accounts=o.max_accounts,
        max_identities=o.max_identities,
        rate_limits=rate_limits or RateLimits(),
    )


def build_service(
    op: OperatorConfig,
    store: Store,
    cfg: OAuthConfig,
    *,
    fetch_policy: FetchPolicy | None = None,
    login: LoginVerifier | None = None,
) -> OAuthService:
    limits = Limiters.from_config(cfg)
    net = NetPolicy(allow_private=op.settings.allow_private_networks)
    return OAuthService(
        cfg=cfg,
        store=store,
        clients=ClientRegistry(store, cfg, fetch_policy, fetch_limiter=limits.client_fetch),
        pseudonyms=Pseudonyms(op.pseudonym_key),
        login=login or ImapLoginVerifier(net),
        login_domains=op.login_domains,
        portal=Portal(cfg),
        limits=limits,
    )


async def build_oauth_app(
    op: OperatorConfig,
    *,
    store: Store | None = None,
    fetch_policy: FetchPolicy | None = None,
    login: LoginVerifier | None = None,
    rate_limits: RateLimits | None = None,
    tester: ConnectionTester | None = None,
    mail_tls: TlsSettings | None = None,
) -> Starlette:
    """The app of OAuth mode. The keyword arguments are injection points for tests
    (``mail_tls``: TLS settings for the users' mail servers, e.g. a self-signed test server)."""
    from universal_email_mcp.server.serve import http_settings, mcp_group

    store = store or make_store(op)
    audit.configure(key=op.pseudonym_key or None, log_ip=op.audit_log_client_ip)
    audit.configure_feed(store.record_activity)
    cfg = make_config(op, rate_limits=rate_limits)
    svc = build_service(op, store, cfg, fetch_policy=fetch_policy, login=login)
    pool = UserPool(store, op, build_server, tls=mail_tls or TlsSettings())
    assert op.store is not None
    mcp = mcp_group(
        PerUserServer(pool, request_state_security(op.store.keys)),
        op,
        lambda routes: wrap_routes(routes, pool),
    )
    portal = PortalService(
        oauth=svc,
        mail_servers=op.mail_servers,
        tester=tester or LiveTester(),
        net=NetPolicy(
            allow_private=op.settings.allow_private_networks,
            connect_timeout=CONNECT_TIMEOUT,
            read_timeout=READ_TIMEOUT,
        ),
        pool=pool,
        max_download_bytes=op.max_download_bytes,
        content_origin=op.content_origin,
        content_key=op.pseudonym_key,
    )

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        # Firestore expires records itself (TTL policies); the memory backend needs a sweeper.
        purger = (
            asyncio.create_task(_purge_loop(store))
            if isinstance(store.backend, MemoryBackend)
            else None
        )
        pool.start()
        try:
            yield
        finally:
            audit.configure_feed(None)
            await pool.aclose()
            if purger is not None:
                purger.cancel()
                with suppress(asyncio.CancelledError):
                    await purger
            await store.close()

    async def store_ready() -> bool:
        await store.get(User, "ready-probe")  # a read round trip; absent is fine
        return True

    settings = replace(
        http_settings(op),
        ready_checks={"store": store_ready},
        cors_paths=CORS_PATHS,
        resource_metadata_url=cfg.url("/.well-known/oauth-protected-resource" + MCP_PATH),
    )
    app = create_app(
        settings,
        [
            oauth_group(svc),
            portal_group(portal),
            viewer_group(portal),
            mcp,
            RouteGroup([], lifespan),
        ],
        token_check=StoreTokenVerifier(store, cfg),
    )
    app.state.oauth_service = svc  # for tests
    app.state.portal_service = portal
    app.state.user_pool = pool
    return app


async def _purge_loop(store: Store) -> None:
    while True:
        await asyncio.sleep(PURGE_INTERVAL)
        try:
            await store.purge_expired()
        except Exception:
            log.exception("purging expired records failed")
