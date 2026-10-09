"""Canary for the SDK seams ``server/peruser.py`` relies on. If one of these fails after an
SDK upgrade, re-check ``server/peruser.py`` before anything else: per-user tools and
instructions (and with them user isolation) depend on exactly these internals."""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any

from mcp.server.lowlevel.server import Server
from mcp.server.mcpserver import MCPServer

from universal_email_mcp.server import peruser
from universal_email_mcp.server.peruser import PerUserServer, user_context_var

HINT = " - the SDK changed a seam used by universal_email_mcp/server/peruser.py"


def make() -> PerUserServer:
    return PerUserServer(SimpleNamespace())  # pyright: ignore


def test_lowlevel_server_class_swap_and_dynamic_instructions():
    server = make()
    low = server._lowlevel_server  # pyright: ignore
    assert type(low) is not Server and isinstance(low, Server), "class swap failed" + HINT
    assert low.instructions is None  # no user context: fail closed
    ctx = SimpleNamespace(server=SimpleNamespace(instructions="mine"))
    token = user_context_var.set(ctx)  # pyright: ignore
    try:
        assert low.instructions == "mine", "instructions are not read dynamically" + HINT
        assert low.create_initialization_options().instructions == "mine", HINT
    finally:
        user_context_var.reset(token)


def test_overridden_methods_still_exist_with_the_same_shape():
    for name, params in (
        ("list_tools", ["self"]),
        ("call_tool", ["self", "name", "arguments", "context"]),
        ("_tool_input_schema", ["self", "name"]),
    ):
        base = getattr(MCPServer, name, None)
        assert base is not None, f"MCPServer.{name} is gone" + HINT
        assert list(inspect.signature(base).parameters) == params, name + HINT
    assert isinstance(make()._lowlevel_server.middleware, list), "middleware list" + HINT  # pyright: ignore


def test_discovery_middleware_is_registered_and_gets_method_names():
    server = make()
    mws: list[Any] = server._lowlevel_server.middleware  # pyright: ignore
    assert any(getattr(m, "__name__", "") == "_discovery_middleware" for m in mws), HINT
    params = list(inspect.signature(PerUserServer._discovery_middleware).parameters)  # pyright: ignore
    assert params == ["self", "ctx", "call_next"], HINT
    assert peruser.DISCOVERY_METHODS == {"initialize", "server/discover"}
