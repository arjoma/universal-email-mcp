"""Portal HTTP behaviour: CORS on cookie-less endpoints only, CSRF, headers, language, audit."""

from __future__ import annotations

import json
import logging

import pytest

from tests.http_util import operator_for_tests
from tests.oauth_util import ISSUER, make_app
from tests.portal_util import Browser, FakeTester, ids_in
from universal_email_mcp.config import Config
from universal_email_mcp.portal.i18n import Catalog
from universal_email_mcp.server.serve import build_http_app

FOREIGN = "https://app.inspector.example"
GERMAN = {
    "Sign in": "Anmelden",
    "Mail accounts": "E-Mail-Konten",
    "The language was changed.": "Die Sprache wurde geaendert.",
}


@pytest.fixture
async def app():
    return await make_app(tester=FakeTester())


# ---------------------------------------------------------------- CORS


@pytest.mark.parametrize(
    "path",
    [
        "/mcp",
        "/token",
        "/register",
        "/revoke",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource/mcp",
    ],
)
def test_preflight_is_answered_on_cookie_less_endpoints(app, path):
    with Browser(app) as b:
        r = b.client.options(
            path,
            headers={
                "Origin": FOREIGN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type,mcp-protocol-version",
            },
        )
        assert r.status_code == 204
        assert r.headers["access-control-allow-origin"] == "*"
        allowed = r.headers["access-control-allow-headers"].lower()
        for h in ("authorization", "content-type", "mcp-protocol-version"):
            assert h in allowed
        assert "POST" in r.headers["access-control-allow-methods"]
        assert "access-control-allow-credentials" not in r.headers


def test_responses_of_cookie_less_endpoints_carry_the_cors_headers(app):
    with Browser(app) as b:
        meta = b.client.get("/.well-known/oauth-authorization-server", headers={"Origin": FOREIGN})
        assert meta.status_code == 200 and meta.headers["access-control-allow-origin"] == "*"
        # a browser client must be able to read the discovery challenge
        r = b.client.post("/mcp", json={}, headers={"Origin": FOREIGN})
        assert r.status_code == 401
        assert r.headers["access-control-allow-origin"] == "*"
        assert "www-authenticate" in r.headers["access-control-expose-headers"]
        reg = b.client.post(
            "/register",
            json={"redirect_uris": ["http://127.0.0.1:1/cb"], "client_name": "Inspector"},
            headers={"Origin": FOREIGN},
        )
        assert reg.status_code == 201 and reg.headers["access-control-allow-origin"] == "*"
        tok = b.client.post("/token", data={"grant_type": "x"}, headers={"Origin": FOREIGN})
        assert tok.status_code == 400 and tok.headers["access-control-allow-origin"] == "*"
        assert "access-control-allow-credentials" not in tok.headers


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/portal/accounts"),
        ("POST", "/portal/accounts/new"),
        ("POST", "/portal/signin"),
        ("POST", "/portal/language"),
        ("GET", "/authorize"),
        ("POST", "/authorize"),
        ("GET", "/portal/assets/portal.css"),
    ],
)
def test_cookie_routes_keep_the_strict_origin_check_and_never_send_cors(app, method, path):
    with Browser(app) as b:
        r = b.client.request(method, path, headers={"Origin": FOREIGN})
        assert r.status_code == 403 and r.json() == {"error": "invalid_origin"}
        assert not [h for h in r.headers if h.startswith("access-control-")]
        pre = b.client.options(
            path,
            headers={"Origin": FOREIGN, "Access-Control-Request-Method": method},
        )
        assert pre.status_code == 403
        assert not [h for h in pre.headers if h.startswith("access-control-")]


def test_the_own_origin_still_works_on_portal_routes(app):
    with Browser(app) as b:
        r = b.client.get("/portal/signin", headers={"Origin": ISSUER})
        assert r.status_code == 200


def test_a_foreign_host_is_still_refused_on_cors_paths(app):
    with Browser(app) as b:
        r = b.client.get("/.well-known/oauth-authorization-server", headers={"Host": "evil.test"})
        assert r.status_code == 421


async def test_dev_mode_has_no_cors_at_all():
    op = operator_for_tests(dev_token="t" * 40, allowed_hosts=("127.0.0.1",), public_url=None)
    dev = await build_http_app(op, Config())
    from starlette.testclient import TestClient

    with TestClient(dev, base_url="http://127.0.0.1") as c:
        r = c.options(
            "/mcp",
            headers={"Origin": FOREIGN, "Access-Control-Request-Method": "POST"},
        )
        assert r.status_code == 403
        assert not [h for h in r.headers if h.startswith("access-control-")]


# ---------------------------------------------------------------- CSRF and headers


POSTS = [
    "/portal/signout",
    "/portal/accounts/new",
    "/portal/accounts/a_0123456789abcdef/test",
    "/portal/accounts/a_0123456789abcdef/permissions",
    "/portal/accounts/a_0123456789abcdef/password",
    "/portal/accounts/a_0123456789abcdef/remove",
    "/portal/identities/new",
    "/portal/identities/i_0123456789abcdef",
    "/portal/identities/i_0123456789abcdef/default",
    "/portal/identities/i_0123456789abcdef/test",
    "/portal/identities/i_0123456789abcdef/remove",
    "/portal/clients/g_0123456789abcdef01234567",
    "/portal/clients/g_0123456789abcdef01234567/revoke",
    "/portal/reauth",
    "/portal/language",
]


@pytest.mark.parametrize("path", POSTS)
def test_every_portal_post_needs_the_csrf_token(app, path):
    with Browser(app) as b:
        b.signed_in()
        for data in ({}, {"csrf_token": "x" * 43}):
            r = b.client.post(path, data=data)
            assert r.status_code == 403, (path, data)
            assert "location" not in r.headers
        r = b.client.post(
            path, data={"csrf_token": b.csrf}, headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert r.status_code == 403


def test_signin_post_needs_csrf_too(app):
    with Browser(app) as b:
        r = b.client.post("/portal/signin", data={"address": "alice@example.org", "password": "x"})
        assert r.status_code == 403 and "form has expired" in r.text


async def test_state_changing_routes_do_not_answer_get(app):
    with Browser(app) as b:
        b.signed_in()
        for path in (
            "/portal/signout",
            "/portal/language",
            "/portal/accounts/a_0123456789abcdef/test",
        ):
            assert b.client.get(path).status_code == 405


def test_pages_have_the_strict_headers_and_no_scripts(app):
    with Browser(app) as b:
        b.signed_in()
        for path in ("/portal/accounts", "/portal/accounts/new", "/portal/identities",
                     "/portal/clients", "/portal/identities/new"):  # fmt: skip
            r = b.client.get(path)
            csp = r.headers["content-security-policy"]
            assert "default-src 'none'" in csp and "script-src" not in csp
            assert "form-action 'self'" in csp and "frame-ancestors 'none'" in csp
            assert (
                r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"
            )
            assert "<script" not in r.text.lower() and " style=" not in r.text
            assert " onclick=" not in r.text and "javascript:" not in r.text.lower()


def test_cookies_are_host_prefixed_secure_and_httponly(app):
    with Browser(app) as b:
        r = b.sign_in()
        cookies = r.headers.get_list("set-cookie")
        session = next(c for c in cookies if c.startswith("__Host-uem_session="))
        for flag in ("Secure", "HttpOnly", "Path=/", "SameSite=lax"):
            assert flag.lower() in session.lower()
        assert "domain" not in session.lower() and "max-age" not in session.lower()


# ---------------------------------------------------------------- language switch


async def test_the_language_switch_sets_the_cookie_and_changes_the_pages():
    app = await make_app(tester=FakeTester())
    app.state.oauth_service.portal.translator.catalogs["de"] = Catalog(GERMAN)
    with Browser(app) as b:
        page = b.page("/portal/signin")
        assert 'name="lang"' in page and "Deutsch" in page and "Anmelden" not in page
        r = b.post("/portal/language", {"lang": "de", "next": "/portal/signin"})
        assert r.status_code == 303 and r.headers["location"] == "/portal/signin"
        cookie = r.headers["set-cookie"]
        assert "uem_lang=de" in cookie and "HttpOnly" in cookie and "Secure" in cookie
        assert "Anmelden" in b.page("/portal/signin")
        b.signed_in()
        assert "E-Mail-Konten" in b.page("/portal/accounts")
        # unknown languages and hostile redirects are ignored
        b.post("/portal/language", {"lang": "xx"})
        assert "E-Mail-Konten" in b.page("/portal/accounts")
        r = b.post("/portal/language", {"lang": "en", "next": "https://evil.example/"})
        assert r.headers["location"] == "/portal"
        assert "Mail accounts" in b.page("/portal/accounts")


def test_the_switch_is_hidden_while_only_one_language_ships(app):
    with Browser(app) as b:
        assert 'name="lang"' not in b.page("/portal/signin")


# ---------------------------------------------------------------- audit trail


def audit_events(caplog) -> list[dict]:
    return [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "universal_email_mcp.audit"
    ]


def test_portal_actions_are_audited_without_personal_data(app, caplog):
    caplog.set_level(logging.INFO, logger="universal_email_mcp.audit")
    with Browser(app) as b:
        b.signed_in()
        add = b.post(
            "/portal/accounts/new",
            {"name": "Private Name", "protocol": "imap", "host": "mail.secret-host.example",
             "username": "very.private@secret-host.example", "password": "s3cr3t-pw", "identity": "1"},
        )  # fmt: skip
        aid = add.headers["location"].split("?")[0].rsplit("/", 1)[1]
        b.post(f"/portal/accounts/{aid}/test")
        b.post(f"/portal/accounts/{aid}/permissions", {"perm": ["read"]})
        b.post(f"/portal/accounts/{aid}/password", {"password": "other-pw"})
        ident = ids_in(b.page("/portal/identities"), "identities")[-1]
        b.post(f"/portal/identities/{ident}", {"address": "very.private@secret-host.example",
               "display_name": "Mr Private", "smtp_account": aid, "store_account": aid})  # fmt: skip
        b.post(f"/portal/identities/{ident}/remove")
        b.post(f"/portal/accounts/{aid}/remove")
    events = audit_events(caplog)
    names = [e["event"] for e in events]
    for expected in (
        "portal.account_add",
        "portal.account_test",
        "portal.account_permissions",
        "portal.account_password",
        "portal.identity_edit",
        "portal.identity_remove",
        "portal.account_remove",
    ):
        assert expected in names, names
    blob = json.dumps(events)
    for secret in ("s3cr3t-pw", "other-pw", "very.private", "secret-host", "Private Name",
                   "Mr Private", "alice@example.org", "example.org"):  # fmt: skip
        assert secret not in blob, secret
    assert all(e.get("user", "u_").startswith("u_") for e in events)


async def test_revocation_is_audited(app, caplog):
    from tests.oauth_util import Authz, account_id_of, hidden_fields, query_of, register

    caplog.set_level(logging.INFO, logger="universal_email_mcp.audit")
    with Browser(app) as b:
        b.signed_in()
        a = Authz(b.client, register(b.client))
        page = a.consent_page()
        form = {**hidden_fields(page.text), "action": "approve",
                "grant": [f"{account_id_of(page.text)}:mail.read"]}  # fmt: skip
        query_of(b.client.post("/authorize", data=form).headers["location"])
        gid = b.page("/portal/clients").split("/portal/clients/")[1].split('"')[0].split("/")[0]
        b.post(f"/portal/clients/{gid}/revoke")
    assert "portal.grant_revoke" in [e["event"] for e in audit_events(caplog)]
