"""Helpers for the OAuth tests: an app with the in-memory store, a scripted browser."""

from __future__ import annotations

import html
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2
from starlette.applications import Starlette
from starlette.testclient import TestClient

from tests.http_util import operator_for_tests
from universal_email_mcp.errors import AuthFailed
from universal_email_mcp.oauth import pkce
from universal_email_mcp.oauth.app import build_oauth_app
from universal_email_mcp.oauth.config import RateLimits
from universal_email_mcp.oauth.fetch import FetchPolicy
from universal_email_mcp.oauth.identity import Address
from universal_email_mcp.operator import OAuthSettings, OperatorConfig, StoreSettings
from universal_email_mcp.presets import profile_for_host
from universal_email_mcp.store import KeyRing, Store

ISSUER = "https://mcp.test"
RESOURCE = ISSUER + "/mcp"
REDIRECT = "http://127.0.0.1:7777/callback"
PSEUDONYM_KEY = b"p" * 32
PASSWORD = "correct horse"


class FakeLogin:
    """Accepts ``PASSWORD`` for any address of a known user, counts attempts."""

    def __init__(self, users: set[str] | None = None) -> None:
        self.users = users if users is not None else {"alice@example.org", "bob@example.org"}
        self.attempts = 0
        self.broken = False

    async def verify(self, address: Address, password: str, profile: Any) -> None:
        self.attempts += 1
        if self.broken:
            from universal_email_mcp.errors import ServerUnreachable

            raise ServerUnreachable("down")
        if address.normal not in self.users or password != PASSWORD:
            raise AuthFailed("nope")


def operator(**kw: Any) -> OperatorConfig:
    keys = KeyRing({"k1": b"k" * 32})
    base: dict[str, Any] = {
        "public_url": ISSUER,
        "allowed_hosts": ("mcp.test",),
        "allowed_origins": (ISSUER,),
        "store": StoreSettings(backend="memory", keys=keys),
        "pseudonym_key": PSEUDONYM_KEY,
        "login_domains": {"example.org": profile_for_host("imap.example.org")},
        "oauth": OAuthSettings(),
    }
    return operator_for_tests(**{**base, **kw})


async def make_app(
    op: OperatorConfig | None = None,
    *,
    login: Any = None,
    store: Store | None = None,
    fetch_policy: FetchPolicy | None = None,
    rate_limits: RateLimits | None = None,
) -> Starlette:
    return await build_oauth_app(
        op or operator(),
        store=store,
        login=login or FakeLogin(),
        fetch_policy=fetch_policy,
        rate_limits=rate_limits,
    )


def new_client(app: Starlette) -> TestClient:
    return TestClient(app, base_url=ISSUER, follow_redirects=False)


def challenge_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    return verifier, pkce.s256(verifier)


def hidden_fields(page: str) -> dict[str, str]:
    """name -> value of all hidden inputs of the first form on a page."""
    first = page.split("</form>")[0]
    return {
        m.group(1): html.unescape(m.group(2))
        for m in re.finditer(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', first)
    }


def grant_values(page: str) -> list[str]:
    """The ``account:scope`` values of the consent page's checkboxes, in page order."""
    return [html.unescape(v) for v in re.findall(r'name="grant" value="([^"]+)"', page)]


def account_id_of(page: str) -> str:
    """Id of the first account on a consent page (the sign-in mailbox, ``a_...``)."""
    return grant_values(page)[0].split(":")[0]


def query_of(location: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}


@dataclass
class Authz:
    """One authorization request driven through the pages like a browser would."""

    client: TestClient
    client_id: str
    redirect_uri: str = REDIRECT
    scope: str = "mail.read mail.organize"
    state: str = field(default_factory=lambda: secrets.token_urlsafe(8))
    resource: str | None = RESOURCE
    verifier: str = ""
    challenge: str = ""
    extra: dict[str, str] = field(default_factory=dict[str, str])

    def __post_init__(self) -> None:
        if not self.verifier:
            self.verifier, self.challenge = challenge_pair()

    def params(self) -> dict[str, str]:
        p = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": self.state,
            "code_challenge": self.challenge,
            "code_challenge_method": "S256",
            "scope": self.scope,
        }
        if self.resource is not None:
            p["resource"] = self.resource
        return {**p, **self.extra}

    def open(self) -> httpx2.Response:
        return self.client.get("/authorize", params=self.params())

    def sign_in(
        self, address: str = "alice@example.org", password: str = PASSWORD
    ) -> httpx2.Response:
        page = self.open()
        assert page.status_code == 200, page.text
        form = hidden_fields(page.text)
        return self.client.post(
            "/authorize", data={**form, "address": address, "password": password}
        )

    def consent_page(self) -> httpx2.Response:
        page = self.open()
        if hidden_fields(page.text).get("action") == "signin":
            r = self.sign_in()
            assert r.status_code == 303, r.text
            page = self.client.get(r.headers["location"])
        assert page.status_code == 200
        return page

    def decide(
        self, action: str = "approve", grants: list[str] | None = None, **extra: Any
    ) -> httpx2.Response:
        page = self.consent_page()
        form: dict[str, Any] = {**hidden_fields(page.text), "action": action}
        account = account_id_of(page.text)
        form["grant"] = (
            [f"{account}:mail.read"]
            if grants is None
            else [g.replace("primary:", f"{account}:", 1) for g in grants]
        )
        form.update(extra)
        return self.client.post("/authorize", data=form)

    def code(self, **kw: Any) -> str:
        r = self.decide(**kw)
        assert r.status_code == 303, r.text
        q = query_of(r.headers["location"])
        assert q["state"] == self.state and q["iss"] == ISSUER
        return q["code"]

    def exchange(self, code: str, **override: str) -> httpx2.Response:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "code_verifier": self.verifier,
        }
        data.update(override)
        return self.client.post("/token", data=data)


def register(client: TestClient, redirect: str = REDIRECT, name: str = "Test App") -> str:
    r = client.post("/register", json={"redirect_uris": [redirect], "client_name": name})
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def refresh(client: TestClient, client_id: str, token: str, **extra: str) -> httpx2.Response:
    return client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token,
            "client_id": client_id,
            **extra,
        },
    )


def bearer(token: str) -> Mapping[str, str]:
    return {"Authorization": f"Bearer {token}"}


def identity_ids_of(page: str) -> list[str]:
    return [html.unescape(v) for v in re.findall(r'name="identity" value="([^"]+)"', page)]


async def allow_sending(store: Store, user_address: str = "alice@example.org") -> str:
    """Turn on ``send`` for the user's sign-in identity; returns the identity id."""
    from dataclasses import replace

    from universal_email_mcp.oauth.identity import Pseudonyms
    from universal_email_mcp.store import Identity

    user_id = Pseudonyms(PSEUDONYM_KEY).user_id(user_address)
    (ident,) = await store.list_for_user(Identity, user_id)
    await store.update(replace(ident, send=True))
    return ident.id
