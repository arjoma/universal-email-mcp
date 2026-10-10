"""Helpers for the portal tests: a scripted connection tester and a browser-like client."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Any

import httpx2
from starlette.applications import Starlette
from starlette.testclient import TestClient

from tests.oauth_util import PASSWORD, new_client
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import Endpoint
from universal_email_mcp.portal.connect import TestOutcome


@dataclass
class FakeTester:
    """Answers connection tests from a script: the *password* picks the outcome."""

    script: dict[str, str] = field(default_factory=dict[str, str])
    calls: list[tuple[str, Endpoint, str, str]] = field(
        default_factory=list[tuple[str, Endpoint, str, str]]
    )
    nets: list[NetPolicy] = field(default_factory=list[NetPolicy])

    def _outcome(self, password: str) -> TestOutcome:
        status = self.script.get(password, "ok")
        return TestOutcome(status, ("MOVE", "UIDPLUS") if status == "ok" else ())

    async def incoming(
        self, protocol: str, endpoint: Endpoint, username: str, password: str, net: NetPolicy
    ) -> TestOutcome:
        self.calls.append((protocol, endpoint, username, password))
        self.nets.append(net)
        return self._outcome(password)

    async def submission(
        self, endpoint: Endpoint, username: str, password: str, net: NetPolicy
    ) -> TestOutcome:
        self.calls.append(("smtp", endpoint, username, password))
        self.nets.append(net)
        return self._outcome(password)


class Browser:
    """A (signed-in) browser session on the portal."""

    def __init__(self, app: Starlette, address: str = "alice@example.org") -> None:
        self.client: TestClient = new_client(app)
        self.address = address
        self.app = app

    def link(self, message_id: Any) -> str:
        """The id of a message in this user's viewer URLs (``/m/<id>``): the message id (or
        a ``MessageRef``) sealed for the user, as the service builds links."""
        mid = message_id if isinstance(message_id, str) else message_id.encode()
        uid = self.app.state.oauth_service.pseudonyms.user_id(self.address)
        return self.app.state.user_pool.viewer_ids.seal(uid, mid)

    # No ``with client`` here: the lifespan (MCP session manager) may only run once per app,
    # and several browsers can share one app.
    def __enter__(self) -> Browser:
        return self

    def __exit__(self, *exc: object) -> None:
        self.client.close()

    @property
    def csrf(self) -> str:
        if "__Host-uem_csrf" not in self.client.cookies:
            self.client.get("/portal/signin")
        return self.client.cookies.get("__Host-uem_csrf") or ""

    def get(self, path: str, **kw: Any) -> httpx2.Response:
        return self.client.get(path, **kw)

    def post(self, path: str, data: dict[str, Any] | None = None, **kw: Any) -> httpx2.Response:
        body = {"csrf_token": self.csrf, **(data or {})}
        return self.client.post(path, data=body, **kw)

    def sign_in(
        self, password: str = PASSWORD, next_: str = "/portal/accounts", store: bool = True
    ) -> httpx2.Response:
        data = {"address": self.address, "password": password, "next": next_}
        if store:
            data["store_password"] = "1"
        return self.post("/portal/signin", data)

    def signed_in(self) -> Browser:
        r = self.sign_in()
        assert r.status_code == 303, r.text
        return self

    def page(self, path: str) -> str:
        r = self.get(path)
        assert r.status_code == 200, (path, r.status_code, r.text[:300])
        return r.text


def ids_in(page: str, prefix: str) -> list[str]:
    """Ids from links ``/portal/<prefix>/<id>`` on a page (not ``new``), unique, in order."""
    found = re.findall(rf'href="/portal/{prefix}/([a-z]_[0-9a-f]+)"', page)
    return list(dict.fromkeys(found))


def text_of(page: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", page))
