"""Run an ASGI app on a real loopback socket for tests (uvicorn, random port)."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

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
async def running(app: Any) -> AsyncIterator[str]:
    """Serve ``app`` (lifespan included) and yield its base URL."""
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


def mcp_client(url: str, token: str | None, *, mode: str = "auto") -> Client:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    transport = streamable_http_client(url, http_client=create_mcp_http_client(headers=headers))
    return Client(transport, mode=mode)  # pyright: ignore[reportArgumentType]
