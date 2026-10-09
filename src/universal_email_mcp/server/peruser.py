"""The MCP server of OAuth mode: one tool surface per connected client (WP 3e).

The transport (one stateless SDK session manager) is shared by everybody, the *content* is
per principal. Three seams make the SDK serve a different server to each caller:

* :class:`UserContextMiddleware` (ASGI, around the SDK's ``/mcp`` routes) turns the verified
  bearer principal into a :class:`~universal_email_mcp.service.userpool.UserContext` -
  built from the store, see that module - and publishes it in :data:`user_context_var` for
  the duration of the request. No principal, no context, no tools.
* :class:`PerUserServer` is the ``MCPServer`` the SDK runs. It owns no tools itself:
  ``tools/list`` and ``tools/call`` are answered by the context's own server (built by
  ``build_server`` from the grant's effective configuration), so a client sees exactly the
  tools its grant allows and a call to anything else is "unknown tool". Every call also
  passes the per-user concurrency cap.
* The server ``instructions`` (handshake and discovery) are read from the context as well;
  an SDK middleware reads the user's folder maps just before ``initialize`` / ``server/discover``
  so the instructions carry the mailbox structure, exactly like local mode.

Enforcement does not rely on the tool list: the router of the context checks the permission
of each account on every call (see ``service/userpool.py``).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from contextvars import ContextVar
from typing import Any

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.lowlevel.server import Server
from mcp.server.mcpserver import Context, MCPServer
from mcp.types import CallToolResult, TextContent
from starlette.routing import BaseRoute, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from universal_email_mcp import __version__
from universal_email_mcp.errors import Busy
from universal_email_mcp.oauth.bearer import Principal
from universal_email_mcp.server.app import (  # pyright: ignore[reportPrivateUsage]
    SERVER_NAME,
    _error_result,
)
from universal_email_mcp.server.http import _send_json  # pyright: ignore[reportPrivateUsage]
from universal_email_mcp.service.userpool import UserContext, UserPool

log = logging.getLogger(__name__)

user_context_var: ContextVar[UserContext | None] = ContextVar("uem_user_context", default=None)

DISCOVERY_METHODS = frozenset({"initialize", "server/discover"})

NO_TOOLS_INSTRUCTIONS = "Not authenticated."


class _DynamicInstructionsServer(Server[Any]):
    """The SDK reads ``Server.instructions`` for the handshake and for discovery. Here it is
    the instructions of the context serving the current request."""

    @property
    def instructions(self) -> str | None:  # pyright: ignore[reportIncompatibleVariableOverride]
        ctx = user_context_var.get()
        return None if ctx is None else ctx.server.instructions

    @instructions.setter
    def instructions(self, value: str | None) -> None:
        pass  # set once by the base class constructor; the value is per user


class PerUserServer(MCPServer):
    """An ``MCPServer`` whose tools, schemas and instructions come from the current user."""

    def __init__(self, pool: UserPool) -> None:
        super().__init__(
            SERVER_NAME,
            title="Universal e-mail (IMAP)",
            version=__version__,
            middleware=[self._discovery_middleware],
        )
        self.pool = pool
        self._lowlevel_server.__class__ = _DynamicInstructionsServer

    # --- the tool surface of the current user ------------------------------------------

    @staticmethod
    def _current() -> UserContext | None:
        return user_context_var.get()

    async def list_tools(self):  # pyright: ignore[reportIncompatibleMethodOverride]
        ctx = self._current()
        return [] if ctx is None else await ctx.server.list_tools()

    def _tool_input_schema(self, name: str) -> dict[str, Any] | None:
        ctx = self._current()
        return None if ctx is None else ctx.server._tool_input_schema(name)  # pyright: ignore[reportPrivateUsage]

    async def call_tool(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, name: str, arguments: dict[str, Any], context: Context[Any, Any] | None = None
    ) -> Any:
        ctx = self._current()
        if ctx is None:
            return CallToolResult(
                content=[TextContent(type="text", text="Not authenticated.")], is_error=True
            )
        try:
            async with self.pool.call_slot(ctx):
                return await ctx.server.call_tool(name, arguments, context)
        except Busy as e:
            return _error_result(e)

    async def _discovery_middleware(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        if ctx.method in DISCOVERY_METHODS:
            user = self._current()
            if user is not None:
                await self.pool.ensure_instructions(user)
        return await call_next(ctx)


class UserContextMiddleware:
    """ASGI wrapper of the SDK endpoint: lease the principal's context for the request."""

    def __init__(self, app: ASGIApp, pool: UserPool) -> None:
        self.app = app
        self.pool = pool

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        principal = scope.get("uem.principal")
        if not isinstance(principal, Principal):
            # The bearer middleware always sets one in OAuth mode; fail closed.
            await _send_json(send, 401, {"error": "unauthorized"})
            return
        if scope["method"] != "POST":  # stateless transport: nothing else to serve
            await self.app(scope, receive, send)
            return
        try:
            ctx = await self.pool.lease(principal)
        except Exception:
            log.exception("could not build the per-user service")
            await _send_json(send, 503, {"error": "temporarily_unavailable"})
            return
        token = user_context_var.set(ctx)
        try:
            await self.app(scope, receive, send)
        finally:
            user_context_var.reset(token)
            self.pool.release(ctx)


def wrap_routes(routes: Sequence[BaseRoute], pool: UserPool) -> list[BaseRoute]:
    """The SDK's routes with :class:`UserContextMiddleware` around every endpoint."""
    out: list[BaseRoute] = []
    for r in routes:
        if isinstance(r, Route):
            out.append(
                Route(
                    r.path,
                    UserContextMiddleware(r.app, pool),
                    methods=sorted(r.methods or ()),
                    name=r.name,
                )
            )
        else:  # pragma: no cover - the SDK app only has plain routes here
            out.append(r)
    return out
