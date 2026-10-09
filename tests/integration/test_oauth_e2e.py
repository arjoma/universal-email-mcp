"""OAuth mode end to end: the MCP SDK's own OAuth client against the real server (uvicorn),
signing in with a real IMAP login (Dovecot)."""

from __future__ import annotations

import json
import socket
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import (
    AuthorizationCodeResult,
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)

from tests.http_util import mcp_client, running
from tests.https_server import Reply, doc_server, resolver
from tests.oauth_util import account_id_of, hidden_fields, operator
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import Endpoint, ServerProfile, TlsSettings
from universal_email_mcp.oauth.app import build_oauth_app
from universal_email_mcp.oauth.fetch import FetchPolicy
from universal_email_mcp.oauth.identity import ImapLoginVerifier

from .conftest import ImapServer

pytestmark = pytest.mark.integration

REDIRECT = "http://127.0.0.1:34567/callback"


class MemoryTokens:
    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None
        self.info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self.info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self.info = client_info


class Browser:
    """Plays the user: signs in with the mailbox login and presses Allow (or Deny)."""

    def __init__(self, user: str, password: str, *, action: str = "approve") -> None:
        self.user, self.password, self.action = user, password, action
        self.result: AuthorizationCodeResult | None = None
        self.seen_consent = ""

    async def redirect(self, url: str) -> None:
        async with httpx2.AsyncClient(follow_redirects=False) as http:
            page = await http.get(url)
            form = hidden_fields(page.text)
            assert form["action"] == "signin", page.text
            r = await http.post(
                urlsplit(url)._replace(path="/authorize", query="").geturl(),
                data={
                    **form,
                    "address": self.user,
                    "password": self.password,
                    "store_password": "1",
                },
            )
            assert r.status_code == 303, r.text
            consent = await http.get(
                urlsplit(url)._replace(path="", query="").geturl() + r.headers["location"]
            )
            self.seen_consent = consent.text
            form = hidden_fields(consent.text)
            r = await http.post(
                urlsplit(url)._replace(path="/authorize", query="").geturl(),
                data={
                    **form,
                    "action": self.action,
                    "grant": [f"{account_id_of(consent.text)}:mail.read"],
                },
            )
            assert r.status_code == 303
            q = {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}
            assert r.headers["location"].startswith(REDIRECT)
            self.result = AuthorizationCodeResult(
                code=q.get("code", ""), state=q.get("state"), iss=q.get("iss")
            )

    async def callback(self) -> AuthorizationCodeResult:
        assert self.result is not None
        return self.result


@pytest.fixture
def login_profile(imap_server: ImapServer) -> ServerProfile:
    return ServerProfile(
        name="dovecot", imap=Endpoint(imap_server.host, imap_server.imaps_port, "tls")
    )


def verifier() -> ImapLoginVerifier:
    return ImapLoginVerifier(
        NetPolicy(allow_private=True, connect_timeout=5, read_timeout=10), TlsSettings(verify=False)
    )


def provider(url: str, browser: Browser, **kw: object) -> OAuthClientProvider:
    return OAuthClientProvider(
        server_url=url + "/mcp",
        client_metadata=OAuthClientMetadata(
            client_name="E2E Client",
            redirect_uris=[REDIRECT],  # pyright: ignore[reportArgumentType]
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="mail.read",
            token_endpoint_auth_method="none",
        ),
        storage=MemoryTokens(),
        redirect_handler=browser.redirect,
        callback_handler=browser.callback,
        **kw,  # pyright: ignore[reportArgumentType]
    )


def prebound() -> tuple[socket.socket, int]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock, sock.getsockname()[1]


async def test_sdk_oauth_client_with_dynamic_registration(
    imap_server: ImapServer, login_profile: ServerProfile
):
    sock, port = prebound()
    user = f"e2e{uuid.uuid4().hex[:8]}@example.org"
    op = operator(
        public_url=f"http://127.0.0.1:{port}",
        allowed_hosts=("127.0.0.1",),
        allowed_origins=(f"http://127.0.0.1:{port}",),
        login_domains={"example.org": login_profile},
    )
    app = await build_oauth_app(op, login=verifier())
    browser = Browser(user, imap_server.password)
    async with running(app, sock) as url:
        auth = provider(url, browser)
        async with mcp_client(url + "/mcp", None, auth=auth) as c:
            tools = {t.name for t in (await c.list_tools()).tools}
            assert {"account_info", "find_messages"} <= tools
            # the first sign-in created the real account "Main"; the per-user service serves it
            # (the operator forbids private addresses here, so the server itself is refused)
            r = await c.call_tool("account_info", {})
            assert "Main" in str(r.content[0])
        assert "E2E Client" in browser.seen_consent
        token = auth.context.current_tokens
        assert token is not None and token.refresh_token
        # refresh through the SDK path: expire the access token locally and call again
        token.expires_in = 0
        auth.context.token_expiry_time = 0
        async with mcp_client(url + "/mcp", None, auth=auth) as c:
            assert (await c.list_tools()).tools


async def test_wrong_password_and_unreachable_server(
    imap_server: ImapServer, login_profile: ServerProfile
):
    sock, port = prebound()
    dead = ServerProfile(name="dead", imap=Endpoint("127.0.0.1", 1, "tls"))
    op = operator(
        public_url=f"http://127.0.0.1:{port}",
        allowed_hosts=("127.0.0.1",),
        allowed_origins=(f"http://127.0.0.1:{port}",),
        login_domains={"example.org": login_profile, "dead.example": dead},
    )
    app = await build_oauth_app(op, login=verifier())
    async with running(app, sock) as url, httpx2.AsyncClient(base_url=url) as http:
        reg = await http.post("/register", json={"redirect_uris": [REDIRECT]})
        params = {
            "response_type": "code", "client_id": reg.json()["client_id"], "redirect_uri": REDIRECT,
            "code_challenge": "a" * 43, "code_challenge_method": "S256", "state": "s",
        }  # fmt: skip
        page = await http.get("/authorize", params=params)
        form = hidden_fields(page.text)
        bad = await http.post(
            "/authorize", data={**form, "address": "x@example.org", "password": "nope"}
        )
        assert bad.status_code == 401 and "Sign-in failed" in bad.text
        form = hidden_fields((await http.get("/authorize", params=params)).text)
        down = await http.post(
            "/authorize", data={**form, "address": "x@dead.example", "password": "nope"}
        )
        assert down.status_code == 503


async def test_sdk_oauth_client_with_client_id_metadata_document(
    imap_server: ImapServer, login_profile: ServerProfile, tmp_path: Path
):
    sock, port = prebound()
    user = f"e2e{uuid.uuid4().hex[:8]}@example.org"
    op = operator(
        public_url=f"http://127.0.0.1:{port}",
        allowed_hosts=("127.0.0.1",),
        allowed_origins=(f"http://127.0.0.1:{port}",),
        login_domains={"example.org": login_profile},
    )
    with doc_server(tmp_path) as docs:
        cid = docs.url("/client.json")
        docs.routes["/client.json"] = Reply(
            body=json.dumps(
                {"client_id": cid, "client_name": "CIMD Client", "redirect_uris": [REDIRECT]}
            ).encode()
        )
        fetch = FetchPolicy(
            net=NetPolicy(allow_private=True, connect_timeout=3, read_timeout=3),
            ca_file=docs.ca_file,
            resolver=resolver,
        )
        app = await build_oauth_app(op, login=verifier(), fetch_policy=fetch)
        browser = Browser(user, imap_server.password)
        async with running(app, sock) as url:
            auth = provider(url, browser, client_metadata_url=cid)
            async with mcp_client(url + "/mcp", None, auth=auth) as c:
                assert {t.name for t in (await c.list_tools()).tools} >= {"account_info"}
            assert (
                auth.context.client_info is not None and auth.context.client_info.client_id == cid
            )
            assert docs.hits == ["/client.json"]
        assert "CIMD Client" in browser.seen_consent
