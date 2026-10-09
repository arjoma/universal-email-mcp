"""The HTTP app: routes, auth, Host/Origin, limits, headers, and the MCP transport
(protocol 2026-07-28 and the legacy stateless one) against a tiny in-memory server."""

from __future__ import annotations

import json
import logging
import secrets
from collections.abc import AsyncIterator
from dataclasses import replace

import httpx2
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import TextContent
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from tests.http_util import mcp_client, operator_for_tests, running
from universal_email_mcp.jsonlog import JsonFormatter, request_id_var
from universal_email_mcp.operator import OperatorConfig
from universal_email_mcp.server.http import (
    ReadinessCheck,
    RouteGroup,
    create_app,
    static_token_check,
)
from universal_email_mcp.server.serve import http_settings, mcp_group

TOKEN = secrets.token_urlsafe(32)
ORIGIN = "https://mcp.example.com"


def make_server() -> MCPServer:
    server = MCPServer("test")

    @server.tool()
    def echo(text: str) -> str:
        """Echo."""
        return f"echo:{text}"

    return server


async def boom(_: Request) -> PlainTextResponse:
    raise RuntimeError("secret internal detail")


async def sized(request: Request) -> PlainTextResponse:
    return PlainTextResponse(str(len(await request.body())))


def build(
    op: OperatorConfig, *, token: str | None = TOKEN, ready: dict[str, ReadinessCheck] | None = None
):
    settings = http_settings(op)
    if ready:
        settings = replace(settings, ready_checks=ready)
    extra = RouteGroup([Route("/boom", boom), Route("/sized", sized, methods=["POST"])])
    return create_app(
        settings,
        [mcp_group(make_server(), op), extra],
        token_check=static_token_check(token) if token else None,
    )


@pytest.fixture
async def base() -> AsyncIterator[str]:
    op = operator_for_tests(allowed_origins=(ORIGIN,), max_request_bytes=2000)
    async with running(build(op)) as url:
        yield url


def auth(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def get(url: str, path: str, **kw: object) -> httpx2.Response:
    async with httpx2.AsyncClient() as c:
        return await c.get(url + path, **kw)  # pyright: ignore[reportArgumentType]


# ---------------------------------------------------------------- plain routes


async def test_health_and_ready(base: str):
    r = await get(base, "/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    r = await get(base, "/ready")
    assert r.status_code == 200 and r.json()["status"] == "ready"


async def test_ready_reports_failing_check_without_details():
    async def down() -> bool:
        return False

    async def broken() -> bool:
        raise RuntimeError("password=hunter2")

    op = operator_for_tests()
    async with running(build(op, ready={"store": down, "other": broken})) as url:
        r = await get(url, "/ready")
        assert r.status_code == 503
        assert r.json()["checks"] == {"config": True, "store": False, "other": False}
        assert "hunter2" not in r.text
        assert (await get(url, "/health")).status_code == 200  # liveness is independent


async def test_probes_work_with_any_host_header(base: str):
    assert (await get(base, "/health", headers={"Host": "10.1.2.3:8080"})).status_code == 200
    assert (await get(base, "/ready", headers={"Host": "10.1.2.3"})).status_code == 200


async def test_unknown_route_and_method_are_json(base: str):
    r = await get(base, "/nope")
    assert r.status_code == 404 and r.json() == {"error": "not_found"}
    async with httpx2.AsyncClient() as c:
        r = await c.post(base + "/health")
    assert r.status_code == 405 and r.json() == {"error": "method_not_allowed"}


async def test_errors_hide_the_stack_trace_and_carry_a_request_id(
    base: str, caplog: pytest.LogCaptureFixture
):
    with caplog.at_level(logging.ERROR):
        r = await get(base, "/boom")
    assert r.status_code == 500
    body = r.json()
    assert body["error"] == "internal_error" and body["request_id"] == r.headers["x-request-id"]
    assert "secret internal detail" not in r.text and "Traceback" not in r.text
    assert any(
        "secret internal detail" in (rec.exc_text or "") or rec.exc_info for rec in caplog.records
    )


async def test_security_headers_and_no_cors(base: str):
    r = await get(base, "/health", headers={"Origin": ORIGIN})
    h = r.headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["referrer-policy"] == "no-referrer" and h["cache-control"] == "no-store"
    assert not [k for k in h if k.startswith("access-control-")]
    assert "strict-transport-security" not in h  # plain http here
    async with httpx2.AsyncClient() as c:
        pre = await c.options(
            base + "/mcp",
            headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST", **auth()},
        )
    assert not [k for k in pre.headers if k.startswith("access-control-")]


async def test_mcp_responses_get_only_the_basic_headers(base: str):
    async with httpx2.AsyncClient() as c:
        r = await c.post(base + "/mcp", content=b"{", headers=auth())
    assert "x-content-type-options" in r.headers and "x-request-id" in r.headers
    assert "content-security-policy" not in r.headers


# ---------------------------------------------------------------- auth


async def test_mcp_requires_bearer_token(base: str):
    async with httpx2.AsyncClient() as c:
        r = await c.post(base + "/mcp", json={})
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == 'Bearer realm="universal-email-mcp"'
        r = await c.post(base + "/mcp", json={}, headers=auth("wrong" * 10))
        assert r.status_code == 401
        assert 'error="invalid_token"' in r.headers["www-authenticate"]
        r = await c.post(base + "/mcp", json={}, headers={"Authorization": "Basic Zm9vOmJhcg=="})
        assert r.status_code == 401
        r = await c.get(base + "/mcp/anything", headers={"Authorization": "Bearer"})
        assert r.status_code == 401


async def test_without_token_check_mcp_is_open():
    op = operator_for_tests()
    async with running(build(op, token=None)) as url, mcp_client(url + "/mcp", None) as c:
        assert [t.name for t in (await c.list_tools()).tools] == ["echo"]


# ---------------------------------------------------------------- host / origin / size


async def test_wrong_host_is_refused(base: str):
    r = await get(base, "/mcp", headers={**auth(), "Host": "evil.example"})
    assert r.status_code == 421
    r = await get(base, "/mcp", headers={**auth(), "Host": "127.0.0.1.evil.example:80"})
    assert r.status_code == 421
    assert (await get(base, "/boom", headers={"Host": "evil.example"})).status_code == 421


async def test_foreign_origin_is_refused_but_ours_and_none_pass(base: str):
    r = await get(base, "/boom", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json() == {"error": "invalid_origin"}
    r = await get(base, "/mcp", headers={**auth(), "Origin": "null"})
    assert r.status_code == 403
    assert (await get(base, "/boom", headers={"Origin": ORIGIN})).status_code == 500
    assert (await get(base, "/boom")).status_code == 500


async def test_body_size_limit(base: str):
    async with httpx2.AsyncClient() as c:
        ok = await c.post(base + "/sized", content=b"x" * 1500)
        assert ok.status_code == 200 and ok.text == "1500"
        big = await c.post(base + "/sized", content=b"x" * 5000)
        assert big.status_code == 413 and big.json() == {"error": "payload_too_large"}

        async def chunks():  # no Content-Length: counted while streaming
            for _ in range(10):
                yield b"y" * 500

        streamed = await c.post(base + "/sized", content=chunks())
        assert streamed.status_code == 413
        mcp_big = await c.post(
            base + "/mcp",
            content=b"z" * 5000,
            headers={**auth(), "content-type": "application/json"},
        )
        assert mcp_big.status_code == 413


async def test_hsts_only_with_https_public_url():
    op = operator_for_tests(public_url=ORIGIN, allowed_hosts=("127.0.0.1",))
    async with running(build(op)) as url:
        r = await get(url, "/health")
    assert "max-age" in r.headers["strict-transport-security"]


# ---------------------------------------------------------------- MCP transport


@pytest.mark.parametrize("mode", ["auto", "2026-07-28", "legacy"])
async def test_mcp_client_lists_and_calls_tools(base: str, mode: str):
    async with mcp_client(base + "/mcp", TOKEN, mode=mode) as c:
        assert [t.name for t in (await c.list_tools()).tools] == ["echo"]
        r = await c.call_tool("echo", {"text": "hi"})
        block = r.content[0]
        assert isinstance(block, TextContent) and block.text == "echo:hi"


async def test_mcp_client_with_wrong_token_fails(base: str):
    with pytest.raises(Exception):  # noqa: B017 - transport error type is SDK-internal
        async with mcp_client(base + "/mcp", "x" * 40) as c:
            await c.list_tools()


async def test_legacy_server_issues_no_session(base: str):
    """Stateless legacy mode: initialize answers without an Mcp-Session-Id."""
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    }
    headers = {**auth(), "Accept": "application/json, text/event-stream"}
    async with httpx2.AsyncClient() as c:
        r = await c.post(base + "/mcp", json=init, headers=headers)
    assert r.status_code == 200
    assert "mcp-session-id" not in r.headers
    assert "protocolVersion" in r.text


# ---------------------------------------------------------------- logging


def test_json_formatter_adds_request_id_and_fields():
    token = request_id_var.set("abc123")
    try:
        rec = logging.LogRecord("x.y", logging.WARNING, __file__, 1, "hello %s", ("w",), None)
        rec.fields = {"status": 200}  # pyright: ignore[reportAttributeAccessIssue]
        line = JsonFormatter().format(rec)
    finally:
        request_id_var.reset(token)
    data = json.loads(line)
    assert data["severity"] == "WARNING" and data["message"] == "hello w"
    assert data["request_id"] == "abc123" and data["status"] == 200


async def test_access_log_has_route_not_full_path_or_query(
    base: str, caplog: pytest.LogCaptureFixture
):
    with caplog.at_level(logging.INFO, logger="universal_email_mcp.http"):
        await get(base, "/health?token=secret-query")
    fields = [r.fields for r in caplog.records if hasattr(r, "fields")]  # pyright: ignore
    assert fields and fields[-1]["route"] == "/health" and fields[-1]["status"] == 200
    assert "secret-query" not in json.dumps(fields)


async def test_mcp_client_context_is_usable_as_plain_client():
    # sanity: the helper returns the SDK Client type
    assert isinstance(mcp_client("http://127.0.0.1:1/mcp", None), Client)
