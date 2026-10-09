"""Run an ASGI app on a real loopback socket for tests (uvicorn, random port)."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client  # pyright: ignore[reportPrivateUsage]

from universal_email_mcp.operator import OperatorConfig


def operator_for_tests(**kw: Any) -> OperatorConfig:
    base: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": 0,
        "insecure_local": False,
        "allowed_hosts": ("127.0.0.1",),
    }
    return OperatorConfig(**{**base, **kw})


@asynccontextmanager
async def running(app: Any, sock: socket.socket | None = None) -> AsyncIterator[str]:
    """Serve ``app`` (lifespan included) and yield its base URL. ``sock`` is a pre-bound
    listening socket (when the app must know its own port beforehand)."""
    if sock is None:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(
        uvicorn.Config(app, log_config=None, access_log=False, lifespan="on", ws="none")
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(500):
            if server.started or task.done():
                break
            await asyncio.sleep(0.01)
        if not server.started:
            await task  # surfaces the startup error
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        server.should_exit = True
        await task
        sock.close()


def mcp_client(
    url: str,
    token: str | None,
    *,
    mode: str = "auto",
    auth: Any = None,
    elicitation_callback: Any = None,
    transport: Any = None,
) -> Client:
    """An MCP client on the streamable HTTP transport. ``transport`` is an optional httpx2
    transport (a spy or a tamperer between the SDK client and the server)."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if transport is None:
        http = create_mcp_http_client(headers=headers, auth=auth)
    else:
        http = httpx2.AsyncClient(transport=transport, headers=headers, auth=auth, timeout=60)
    return Client(
        streamable_http_client(url, http_client=http),  # pyright: ignore[reportArgumentType]
        mode=mode,  # pyright: ignore[reportArgumentType]
        elicitation_callback=elicitation_callback,
    )
