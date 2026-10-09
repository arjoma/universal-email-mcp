"""``universal-email-mcp serve``: the MCP server over HTTP.

Two modes. **OAuth mode** (the default, ``STORE_BACKEND`` set): the server is its own
OAuth 2.1 authorization server (WP 3c) and ``/mcp`` needs an access token issued for it; until
the per-user service (3e) it offers only ``account_info``. **Dev/test mode** (WP 3a): the
accounts come from a local TOML config and ``/mcp`` is guarded by one static bearer token
(``UEM_DEV_TOKEN``) - or, with the explicit ``--insecure-local`` flag, left open on
127.0.0.1. Temporary: the per-user service (3e) replaces the TOML accounts.

``/mcp`` is the SDK's Streamable HTTP endpoint in *stateless* mode: protocol
2026-07-28 clients get the sessionless transport, older clients (<= 2025-11-25)
the legacy transport without session state (no back-channel, hence no in-chat
confirmation for them).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import Any

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

from universal_email_mcp.config import Config, Downloads
from universal_email_mcp.jsonlog import setup_json_logging
from universal_email_mcp.operator import OperatorConfig
from universal_email_mcp.server.app import build_server
from universal_email_mcp.server.http import (
    MCP_PATH,
    HttpSettings,
    RouteGroup,
    create_app,
    static_token_check,
)
from universal_email_mcp.service.mail import MailService
from universal_email_mcp.service.router import AccountRouter

log = logging.getLogger(__name__)

GRACEFUL_SHUTDOWN_SECONDS = 8
"""Cloud Run sends SIGTERM and kills the container after 10 s."""


def transport_security(op: OperatorConfig) -> TransportSecuritySettings:
    """The SDK's own Host/Origin check (defence in depth behind our middleware)."""
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[p for h in op.allowed_hosts for p in (h, f"{h}:*")],
        allowed_origins=list(op.allowed_origins)
        + [f"{o}:*" for o in op.allowed_origins if o.count(":") == 1],
    )


def mcp_group(server: MCPServer, op: OperatorConfig) -> RouteGroup:
    """``/mcp`` from the SDK, stateless, and the lifespan its session manager needs."""
    sdk_app = server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        json_response=False,
        max_request_body_size=op.max_request_bytes,
        transport_security=transport_security(op),
        host=op.host,
    )

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with sdk_app.router.lifespan_context(sdk_app):
            yield

    return RouteGroup(list(sdk_app.routes), lifespan)


def http_settings(op: OperatorConfig) -> HttpSettings:
    return HttpSettings(
        allowed_hosts=op.allowed_hosts,
        allowed_origins=op.allowed_origins,
        max_request_bytes=op.max_request_bytes,
        hsts=op.hsts,
    )


async def build_http_app(op: OperatorConfig, config: Config) -> Starlette:
    """Assemble the dev-mode app: TOML accounts, no download listener (the
    loopback links of local mode make no sense behind a public URL)."""
    config = replace(
        config,
        limits=op.limits,
        policy=op.policy,
        settings=op.settings,
        downloads=Downloads(enabled=False),
    )
    service = MailService(config, router=AccountRouter(config), download_status="off (remote mode)")
    try:
        maps = await service.startup_folder_maps()
        server = build_server(service, maps)
        mcp = mcp_group(server, op)
    except BaseException:
        await service.aclose()
        raise

    @asynccontextmanager
    async def service_lifespan(_: Starlette) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await service.aclose()

    token_check = static_token_check(op.dev_token) if op.dev_token else None
    return create_app(
        http_settings(op),
        [mcp, RouteGroup([], service_lifespan)],
        token_check=token_check,
    )


def uvicorn_config(app: Any, op: OperatorConfig, **extra: Any) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=op.host,
        port=op.port,
        log_config=None,  # our JSON handler on the root logger
        access_log=False,  # RequestContextMiddleware logs requests
        server_header=False,
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS,
        lifespan="on",
        **extra,
    )


async def serve_oauth(op: OperatorConfig) -> None:
    from universal_email_mcp.oauth.app import build_oauth_app

    setup_json_logging(op.log_level)
    assert op.store is not None
    if op.store.ephemeral_keys:
        log.warning("STORE_BACKEND=memory without STORE_KEYS: state and keys are lost on restart")
    app = await build_oauth_app(op)
    log.info(
        "OAuth mode: issuer %s, store %s, %d login domain(s)",
        op.public_url,
        op.store.backend,
        len(op.login_domains),
    )
    await uvicorn.Server(uvicorn_config(app, op)).serve()


def run_serve_oauth(op: OperatorConfig) -> None:
    asyncio.run(serve_oauth(op))


async def serve(op: OperatorConfig, config: Config) -> None:
    setup_json_logging(op.log_level)
    if op.dev_token is None:
        log.warning("INSECURE dev mode: /mcp is open; listening on %s only", op.host)
    else:
        log.warning("dev mode: /mcp requires the static bearer token UEM_DEV_TOKEN (temporary)")
    app = await build_http_app(op, config)
    log.info(
        "serving %d account(s) on http://%s:%d%s", len(config.accounts), op.host, op.port, MCP_PATH
    )
    await uvicorn.Server(uvicorn_config(app, op)).serve()


def run_serve(op: OperatorConfig, config: Config) -> None:
    asyncio.run(serve(op, config))
