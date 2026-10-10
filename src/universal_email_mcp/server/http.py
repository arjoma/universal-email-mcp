"""The HTTP application of ``serve``: app factory, route groups, middleware.

The app is assembled from *route groups* (``/health``, ``/mcp``; later the OAuth
endpoints, the portal and the message viewer add theirs) behind one middleware
stack that applies to everything:

1. request context: request id, JSON access log, no stack traces in responses,
   security headers (only set when a route did not set its own),
2. Host and Origin validation (DNS rebinding protection; ``/health`` and
   ``/ready`` are exempt because platform probes use arbitrary Host values), then the
   content-origin host check (that host serves ``/c/*`` and the probes only),
3. bearer authentication for the protected prefixes (``/mcp``),
4. request body size limit.

CORS is off by default: no ``Access-Control-*`` header is sent, so browsers cannot call
the endpoints cross-origin. OAuth mode switches it on for the **cookie-less** endpoints
only (``HttpSettings.cors_paths``: metadata, ``/register``, ``/token``, ``/revoke``,
``/mcp``), so browser-based MCP clients can work. Those endpoints authenticate with bearer
tokens or not at all, never with cookies, so ``Access-Control-Allow-Origin: *`` (without
credentials) gives a foreign page nothing it could not get with a plain HTTP client. The
pages that use cookies keep the strict ``Origin`` check and answer no preflight.
"""

from __future__ import annotations

import hmac
import inspect
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Sequence
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from universal_email_mcp.jsonlog import log_event, request_id_var, safe_trace

log = logging.getLogger("universal_email_mcp.http")

MCP_PATH = "/mcp"
CONTENT_PREFIX = "/c/"
UNGUARDED_PATHS = frozenset({"/health", "/ready"})
"""Probe endpoints: no Host/Origin check (probes use pod IPs), nothing sensitive."""

SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("x-content-type-options", "nosniff"),
    ("cache-control", "no-store"),
)
PAGE_HEADERS: tuple[tuple[str, str], ...] = (
    ("content-security-policy", "default-src 'none'; frame-ancestors 'none'"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-resource-policy", "same-origin"),
)
HSTS = ("strict-transport-security", "max-age=63072000; includeSubDomains")

CORS_ALLOW_HEADERS = (
    "authorization, content-type, accept, mcp-protocol-version, mcp-session-id, "
    "last-event-id, mcp-method, mcp-name"
)
CORS_EXPOSE_HEADERS = "www-authenticate, mcp-session-id, mcp-protocol-version"
CORS_METHODS = "GET, POST, DELETE, OPTIONS"
CORS_MAX_AGE = "600"

ReadinessCheck = Callable[[], Awaitable[bool]]
"""Returns True when the dependency is usable. The store check plugs in here (3b)."""
TokenCheck = Callable[[str], Any]
"""Decides whether a presented bearer token is valid. Sync or async. A falsy result (``False``,
``None``) refuses; ``True`` accepts; any other object is accepted *and* is the principal of the
request, available as ``principal_var`` and ``scope["uem.principal"]`` (OAuth mode)."""

principal_var: ContextVar[object | None] = ContextVar("uem_principal", default=None)


@dataclass(frozen=True, slots=True)
class RouteGroup:
    """Routes of one feature plus the lifespan it needs (sessions, pools, ...)."""

    routes: Sequence[BaseRoute]
    lifespan: Callable[[Starlette], AbstractAsyncContextManager[None]] | None = None


@dataclass(frozen=True, slots=True)
class HttpSettings:
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...] = ()
    max_request_bytes: int = 4 * 1024 * 1024
    hsts: bool = False
    protected_prefixes: tuple[str, ...] = (MCP_PATH,)
    realm: str = "universal-email-mcp"
    cors_paths: tuple[str, ...] = ()
    """Path prefixes (cookie-less endpoints) that answer CORS preflights and may be called
    from any origin. Empty = no CORS at all."""
    resource_metadata_url: str | None = None
    """RFC 9728 URL advertised in ``WWW-Authenticate`` so clients can discover the
    authorization server."""
    ready_checks: dict[str, ReadinessCheck] = field(default_factory=dict[str, ReadinessCheck])
    content_host: str | None = None
    """Host name of the content origin (``CONTENT_ORIGIN``): on this host only ``/c/*`` and
    the probes are served, everything else is 404 (it serves untrusted mail HTML and must not
    offer the portal's sign-in, OAuth pages or ``/mcp``)."""


# ---------------------------------------------------------------- helpers


async def _send_json(
    send: Send, status: int, body: dict[str, Any], headers: Iterable[tuple[str, str]] = ()
) -> None:
    payload = json.dumps(body, separators=(",", ":")).encode()
    raw = [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]
    raw += [(k.lower().encode(), v.encode()) for k, v in headers]
    await send({"type": "http.response.start", "status": status, "headers": raw})
    await send({"type": "http.response.body", "body": payload})


def _first_segment(path: str) -> str:
    return "/" + path.lstrip("/").split("/", 1)[0]


def under(path: str, prefixes: Iterable[str]) -> bool:
    """Is ``path`` one of the prefixes or below one (``/mcp`` matches ``/mcp/x``, not ``/mcpx``)?"""
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def _host_only(value: str) -> str:
    """``Host`` header without the port (IPv6 literals keep their brackets)."""
    v = value.strip().lower()
    if v.startswith("["):
        return v[: v.find("]") + 1] if "]" in v else v
    return v.rsplit(":", 1)[0] if ":" in v else v


# ---------------------------------------------------------------- middleware


class RequestContextMiddleware:
    """Request id, access log, security headers, and a generic 500 on any bug."""

    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        self.app = app
        self._hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        rid = uuid.uuid4().hex
        token = request_id_var.set(rid)
        started = time.monotonic()
        status = 0
        is_mcp = scope["path"].startswith(MCP_PATH)

        async def wrapped_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                present = Headers(raw=message["headers"])
                wanted = SECURITY_HEADERS + (() if is_mcp else PAGE_HEADERS)
                if self._hsts:
                    wanted += (HSTS,)
                extra = [("x-request-id", rid)] + [(k, v) for k, v in wanted if k not in present]
                message = {
                    **message,
                    "headers": [*message["headers"], *((k.encode(), v.encode()) for k, v in extra)],
                }
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        except Exception as e:
            log.error("unhandled error: %s", safe_trace(e))
            if status == 0:
                await _send_json(wrapped_send, 500, {"error": "internal_error", "request_id": rid})
        finally:
            log_event(
                log,
                logging.INFO,
                "request",
                event="http_request",
                method=scope["method"],
                route=_first_segment(scope["path"]),
                status=status,
                duration_ms=round((time.monotonic() - started) * 1000, 1),
            )
            request_id_var.reset(token)


class HostOriginMiddleware:
    """Refuse requests whose ``Host`` is not ours or whose ``Origin`` is foreign."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        hosts: Iterable[str],
        origins: Iterable[str],
        origin_exempt: Sequence[str] = (),
    ) -> None:
        self.app = app
        self._hosts = frozenset(h.lower() for h in hosts)
        self._origins = frozenset(o.lower().rstrip("/") for o in origins)
        self._exempt = tuple(origin_exempt)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in UNGUARDED_PATHS:
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        host = headers.get("host")
        if not host or _host_only(host) not in self._hosts:
            await _send_json(send, 421, {"error": "invalid_host"})
            return
        origin = headers.get("origin")
        if (
            origin is not None
            and origin.lower().rstrip("/") not in self._origins
            and not under(scope["path"], self._exempt)
        ):
            await _send_json(send, 403, {"error": "invalid_origin"})
            return
        await self.app(scope, receive, send)


class ContentHostMiddleware:
    """On the content-origin host only ``/c/*`` and the probes answer; any other path is 404."""

    def __init__(self, app: ASGIApp, *, host: str) -> None:
        self.app = app
        self._host = host.lower()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] not in UNGUARDED_PATHS:
            host = Headers(scope=scope).get("host")
            if (
                host
                and _host_only(host) == self._host
                and not scope["path"].startswith(CONTENT_PREFIX)
            ):
                await _send_json(send, 404, {"error": "not_found"})
                return
        await self.app(scope, receive, send)


class CorsMiddleware:
    """CORS for the cookie-less endpoints: answers preflights, marks responses.

    No credentials mode: ``Access-Control-Allow-Origin: *`` and never
    ``Allow-Credentials``, so browsers withhold cookies and the response is of no use to a
    page that is not holding a bearer token itself. Runs after the Host check and before
    bearer authentication (a preflight carries no token)."""

    def __init__(self, app: ASGIApp, *, prefixes: Sequence[str]) -> None:
        self.app = app
        self._prefixes = tuple(prefixes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not under(scope["path"], self._prefixes):
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        if (
            scope["method"] == "OPTIONS"
            and "origin" in headers
            and "access-control-request-method" in headers
        ):
            await send(
                {
                    "type": "http.response.start",
                    "status": 204,
                    "headers": [
                        (b"access-control-allow-origin", b"*"),
                        (b"access-control-allow-methods", CORS_METHODS.encode()),
                        (b"access-control-allow-headers", CORS_ALLOW_HEADERS.encode()),
                        (b"access-control-max-age", CORS_MAX_AGE.encode()),
                        (b"content-length", b"0"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return

        async def wrapped_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                message = {
                    **message,
                    "headers": [
                        *message["headers"],
                        (b"access-control-allow-origin", b"*"),
                        (b"access-control-expose-headers", CORS_EXPOSE_HEADERS.encode()),
                    ],
                }
            await send(message)

        await self.app(scope, receive, wrapped_send)


class BearerAuthMiddleware:
    """401 with ``WWW-Authenticate`` unless the request carries a valid bearer token."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        check: TokenCheck,
        prefixes: Sequence[str],
        realm: str,
        resource_metadata_url: str | None = None,
    ) -> None:
        self.app = app
        self._check = check
        self._prefixes = tuple(prefixes)
        self._realm = realm
        self._metadata = resource_metadata_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith(self._prefixes):
            await self.app(scope, receive, send)
            return
        auth = Headers(scope=scope).get("authorization", "")
        scheme, _, token = auth.partition(" ")
        presented = scheme.lower() == "bearer" and bool(token.strip())
        if presented:
            result = self._check(token.strip())
            if inspect.isawaitable(result):
                result = await result
            if result:
                principal = None if result is True else result
                scope["uem.principal"] = principal
                ctx = principal_var.set(principal)
                try:
                    await self.app(scope, receive, send)
                finally:
                    principal_var.reset(ctx)
                return
        challenge = f'Bearer realm="{self._realm}"'
        if presented:
            challenge += ', error="invalid_token"'
        if self._metadata:
            challenge += f', resource_metadata="{self._metadata}"'
        await _send_json(send, 401, {"error": "unauthorized"}, [("www-authenticate", challenge)])


class _BodyTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """413 for bodies over the limit (declared, or counted while streaming)."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self._max = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self._max
            except ValueError:
                await _send_json(send, 400, {"error": "bad_content_length"})
                return
            if too_big:
                await _send_json(send, 413, {"error": "payload_too_large"})
                return
        seen = 0
        started = False

        async def counted_receive() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self._max:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted_receive, tracking_send)
        except _BodyTooLarge:
            if not started:
                await _send_json(send, 413, {"error": "payload_too_large"})


# ---------------------------------------------------------------- route groups


def health_group(ready_checks: dict[str, ReadinessCheck]) -> RouteGroup:
    """``/health`` (liveness, no dependencies) and ``/ready`` (all checks pass)."""

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    async def ready(_: Request) -> JSONResponse:
        results: dict[str, bool] = {"config": True}
        for name, check in ready_checks.items():
            try:
                results[name] = await check()
            except Exception as e:
                log.error("readiness check %r raised: %s", name, safe_trace(e))
                results[name] = False
        ok = all(results.values())
        return JSONResponse(
            {"status": "ready" if ok else "unavailable", "checks": results},
            status_code=200 if ok else 503,
        )

    return RouteGroup([Route("/health", health), Route("/ready", ready)])


async def _not_found(_: Request, __: Exception) -> JSONResponse:
    return JSONResponse({"error": "not_found"}, status_code=404)


async def _method_not_allowed(_: Request, __: Exception) -> JSONResponse:
    return JSONResponse({"error": "method_not_allowed"}, status_code=405)


def create_app(
    settings: HttpSettings,
    groups: Sequence[RouteGroup],
    *,
    token_check: TokenCheck | None = None,
) -> Starlette:
    """Combine route groups (plus ``/health`` and ``/ready``) behind the common
    middleware stack.

    ``token_check`` guards ``settings.protected_prefixes``; ``None`` leaves them
    open (only the explicit ``--insecure-local`` mode on loopback does that).
    """
    all_groups = [*groups, health_group(settings.ready_checks)]
    routes: list[BaseRoute] = [r for g in all_groups for r in g.routes]

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            for g in all_groups:
                if g.lifespan is not None:
                    await stack.enter_async_context(g.lifespan(app))
            yield

    middleware = [
        Middleware(RequestContextMiddleware, hsts=settings.hsts),
        Middleware(
            HostOriginMiddleware,
            hosts=settings.allowed_hosts,
            origins=settings.allowed_origins,
            origin_exempt=settings.cors_paths,
        ),
    ]
    if settings.content_host:
        middleware.append(Middleware(ContentHostMiddleware, host=settings.content_host))
    if settings.cors_paths:
        middleware.append(Middleware(CorsMiddleware, prefixes=settings.cors_paths))
    if token_check is not None:
        middleware.append(
            Middleware(
                BearerAuthMiddleware,
                check=token_check,
                prefixes=settings.protected_prefixes,
                realm=settings.realm,
                resource_metadata_url=settings.resource_metadata_url,
            )
        )
    middleware.append(Middleware(BodyLimitMiddleware, max_bytes=settings.max_request_bytes))
    return Starlette(
        debug=False,
        routes=routes,
        middleware=middleware,
        lifespan=lifespan,
        exception_handlers={404: _not_found, 405: _method_not_allowed},
    )


def static_token_check(token: str) -> TokenCheck:
    """Constant-time comparison against one configured token (dev/test mode)."""
    expected = token.encode()

    def check(presented: str) -> bool:
        return hmac.compare_digest(presented.encode(), expected)

    return check
