"""``serve`` end to end: the real HTTP app (uvicorn, dev token) with the MCP SDK's
client over Streamable HTTP, against Dovecot - protocol 2026-07-28 and legacy."""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from mcp.types import TextContent

from tests.http_util import mcp_client, operator_for_tests, running
from universal_email_mcp.config import Config, Settings, parse_config
from universal_email_mcp.server.serve import build_http_app

from .conftest import ImapServer, Mailbox, seed_messages

pytestmark = pytest.mark.integration

TOKEN = secrets.token_urlsafe(32)


@pytest.fixture(scope="module")
def served(imap_server: ImapServer) -> Iterator[Config]:
    mb = Mailbox(imap_server, f"h{uuid.uuid4().hex[:10]}@example.org")
    c = mb.admin()
    try:
        for raw, when, flags in seed_messages():
            c.append("INBOX", raw, flags=flags, msg_time=when)
    finally:
        c.logout()
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("UEM_IT_PASSWORD", imap_server.password)
        yield parse_config(
            {
                "accounts": [
                    {
                        "name": "Work",
                        "username": mb.user,
                        "password_env": "UEM_IT_PASSWORD",
                        "tls_verify": False,
                        "imap": {"host": imap_server.host, "port": imap_server.imaps_port},
                    }
                ],
            }
        )


@pytest.mark.parametrize("mode", ["auto", "2026-07-28", "legacy"])
async def test_tools_over_http_against_dovecot(served: Config, mode: str):
    op = operator_for_tests(dev_token=TOKEN, settings=Settings(allow_private_networks=True))
    app = await build_http_app(op, served)
    async with running(app) as url, mcp_client(url + "/mcp", TOKEN, mode=mode) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert {"account_info", "find_messages", "get_message"} <= names
        r = await c.call_tool("find_messages", {"subject": "Big one"})
        assert not r.is_error
        data: dict[str, Any] = r.structured_content or {}
        assert [m["subject"] for m in data["messages"]] == ["Big one"]
        block = r.content[0]
        assert isinstance(block, TextContent)
        got = await c.call_tool("get_message", {"id": data["messages"][0]["id"]})
        assert not got.is_error and "xxxx" in got.content[0].text  # pyright: ignore[reportAttributeAccessIssue]


async def test_http_app_serves_health_and_refuses_unauthenticated(served: Config):
    import httpx2

    op = operator_for_tests(dev_token=TOKEN)
    app = await build_http_app(op, served)
    async with running(app) as url, httpx2.AsyncClient() as http:
        assert (await http.get(url + "/health")).status_code == 200
        assert (await http.get(url + "/ready")).status_code == 200
        r = await http.post(url + "/mcp", json={})
        assert r.status_code == 401 and "www-authenticate" in r.headers
