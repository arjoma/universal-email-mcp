"""The authorization code flow through the real pages (in-memory store, scripted login)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tests.oauth_util import (
    ISSUER,
    PASSWORD,
    RESOURCE,
    Authz,
    FakeLogin,
    bearer,
    challenge_pair,
    hidden_fields,
    make_app,
    new_client,
    query_of,
    refresh,
    register,
)
from universal_email_mcp.store import (
    KeyRing,
    MemoryBackend,
    SessionPolicy,
    Store,
    hash_token,
)


class Clock:
    def __init__(self) -> None:
        self.t = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw: float) -> None:
        self.t += timedelta(**kw)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
async def store(clock: Clock) -> Store:
    return Store(MemoryBackend(), KeyRing({"k1": b"k" * 32}), clock=clock, policy=SessionPolicy())


@pytest.fixture
async def client(store: Store):
    app = await make_app(store=store)
    with new_client(app) as c:
        yield c


def connect(client, scope: str = "mail.read mail.organize", **kw) -> tuple[Authz, dict]:
    a = Authz(client, register(client), scope=scope, **kw)
    r = a.exchange(a.code())
    assert r.status_code == 200, r.text
    return a, r.json()


# ---------------------------------------------------------------- metadata


def test_metadata_documents(client):
    r = client.get("/.well-known/oauth-authorization-server")
    meta = r.json()
    assert meta["issuer"] == ISSUER
    assert meta["authorization_endpoint"] == ISSUER + "/authorize"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert meta["authorization_response_iss_parameter_supported"] is True
    assert meta["client_id_metadata_document_supported"] is True
    assert meta["registration_endpoint"] == ISSUER + "/register"
    assert meta["token_endpoint_auth_methods_supported"] == ["none"]
    for path in (
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ):
        prm = client.get(path).json()
        assert prm["resource"] == RESOURCE and prm["authorization_servers"] == [ISSUER]


def test_unauthenticated_mcp_points_to_the_metadata(client):
    r = client.post("/mcp", json={})
    assert r.status_code == 401
    challenge = r.headers["www-authenticate"]
    assert f'resource_metadata="{ISSUER}/.well-known/oauth-protected-resource/mcp"' in challenge
    bad = client.post("/mcp", json={}, headers=bearer("x" * 40))
    assert bad.status_code == 401 and 'error="invalid_token"' in bad.headers["www-authenticate"]


async def test_dcr_can_be_disabled():
    from dataclasses import replace

    from tests.oauth_util import operator

    op = operator()
    op = replace(op, oauth=replace(op.oauth, dcr_enabled=False))
    with new_client(await make_app(op)) as c:
        assert (
            "registration_endpoint" not in c.get("/.well-known/oauth-authorization-server").json()
        )
        assert c.post("/register", json={"redirect_uris": ["http://127.0.0.1/cb"]}).status_code in (
            404,
            405,
        )


# ---------------------------------------------------------------- happy path


def test_full_flow_and_tokens(client):
    a, body = connect(client)
    assert body["token_type"] == "Bearer" and body["scope"] == "mail.read"
    assert body["expires_in"] == 3600 and body["refresh_token"].startswith("uem_rt")
    assert client.post("/mcp", json={}).status_code == 401
    assert client.post("/mcp", json={}, headers=bearer(body["access_token"])).status_code != 401


def test_consent_scopes_follow_the_checkboxes(client):
    a = Authz(client, register(client), scope="mail.read mail.organize mail.delete")
    code = a.code(grants=["primary:mail.organize", "primary:mail.send", "primary:mail.bogus"])
    body = a.exchange(code).json()
    # reading is implied by organizing; delete was not ticked, send was not requested
    assert body["scope"] == "mail.read mail.organize"


def test_a_scope_the_client_did_not_ask_for_cannot_be_ticked(client):
    a = Authz(client, register(client), scope="mail.read")
    body = a.exchange(a.code(grants=["primary:mail.read", "primary:mail.organize"])).json()
    assert body["scope"] == "mail.read"


def test_send_is_granted_over_identities(client):
    a = Authz(client, register(client), scope="mail.read mail.send")
    page = a.consent_page()
    assert 'name="identity"' in page.text
    form = {**hidden_fields(page.text), "action": "approve", "grant": ["primary:mail.read"]}
    form["identity"] = ["primary"]
    code = query_of(client.post("/authorize", data=form).headers["location"])["code"]
    assert a.exchange(code).json()["scope"] == "mail.read mail.send"


def test_nothing_ticked_asks_again(client):
    a = Authz(client, register(client))
    r = a.decide(grants=[])
    assert r.status_code == 400 and "Select at least one permission" in r.text


def test_deny_redirects_with_access_denied(client):
    a = Authz(client, register(client))
    r = a.decide(action="deny")
    q = query_of(r.headers["location"])
    assert r.status_code == 303 and r.headers["location"].startswith(a.redirect_uri)
    assert q == {"error": "access_denied", "state": a.state, "iss": ISSUER}


def test_no_scope_requested_offers_everything(client):
    a = Authz(client, register(client), scope="")
    page = a.consent_page().text
    for label in ("Read mail", "Delete (move to Trash)", "Write drafts"):
        assert label in page


def test_unknown_scopes_are_dropped_but_not_alone(client):
    a = Authz(client, register(client), scope="offline_access mail.read")
    assert a.exchange(a.code()).json()["scope"] == "mail.read"
    b = Authz(client, register(client), scope="offline_access")
    r = b.open()
    assert r.status_code == 400 and "location" not in r.headers


# ---------------------------------------------------------------- authorize errors


def test_unknown_client_and_redirect_are_pages_not_redirects(client):
    cid = register(client)
    r = Authz(client, cid, redirect_uri="http://127.0.0.1:7777/other").open()
    assert r.status_code == 400 and "location" not in r.headers
    r = Authz(client, "dcr_unknown").open()
    assert r.status_code == 400 and "location" not in r.headers
    r = client.get("/authorize", params={"redirect_uri": "http://127.0.0.1/cb"})
    assert r.status_code == 400


def test_loopback_port_is_free_for_native_clients(client):
    cid = register(client, "http://127.0.0.1:1/callback")
    a = Authz(client, cid, redirect_uri="http://127.0.0.1:49152/callback")
    assert a.exchange(a.code()).status_code == 200
    r = Authz(client, cid, redirect_uri="http://127.0.0.1:49152/evil").open()
    assert r.status_code == 400


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"extra": {"response_type": "token"}}, "unsupported_response_type"),
        ({"extra": {"code_challenge": ""}}, "invalid_request"),
        ({"extra": {"code_challenge_method": "plain"}}, "invalid_request"),
        ({"extra": {"code_challenge": "short"}}, "invalid_request"),
        ({"resource": "https://other.example/mcp"}, "invalid_target"),
    ],
)
def test_protocol_errors_are_pages_never_redirects(client, change, error):
    # RFC 9700 4.11.2: anyone can register a client, so /authorize must not redirect errors
    a = Authz(client, register(client), **change)
    r = a.open()
    assert r.status_code == 400 and "location" not in r.headers


def test_open_redirect_is_closed(client):
    cid = register(client, "https://evil.example/landing")
    r = Authz(client, cid, redirect_uri="https://evil.example/landing",
              extra={"response_type": "token"}).open()  # fmt: skip
    assert r.status_code == 400 and "location" not in r.headers


@pytest.mark.parametrize(
    "uri",
    ["http://evil.com\\@127.0.0.1/cb", "http://u@127.0.0.1:5/cb", "http://127.0.0.1:5/cb#x"],
)
def test_loopback_parser_tricks_are_refused(client, uri):
    cid = register(client, "http://127.0.0.1/cb")
    assert Authz(client, cid, redirect_uri=uri).open().status_code == 400


def test_send_only_grant_still_includes_reading(client):
    a = Authz(client, register(client), scope="mail.read mail.send")
    page = a.consent_page()
    form = {**hidden_fields(page.text), "action": "approve", "identity": ["primary"]}
    code = query_of(client.post("/authorize", data=form).headers["location"])["code"]
    assert a.exchange(code).json()["scope"] == "mail.read mail.send"


def test_redirect_uri_is_optional_at_the_token_endpoint(client):
    cid = register(client)
    a = Authz(client, cid)
    assert a.exchange(a.code(), redirect_uri="").status_code != 500
    b = Authz(client, cid)
    code = b.code()
    data = {"grant_type": "authorization_code", "code": code, "client_id": cid,
            "code_verifier": b.verifier}  # fmt: skip
    assert client.post("/token", data=data).status_code == 200


def test_missing_resource_defaults_to_the_mcp_endpoint(client):
    a = Authz(client, register(client), resource=None)
    body = a.exchange(a.code()).json()
    assert client.post("/mcp", json={}, headers=bearer(body["access_token"])).status_code != 401


# ---------------------------------------------------------------- /token


def test_wrong_verifier_is_refused_and_burns_the_code(client):
    a = Authz(client, register(client))
    code = a.code()
    r = a.exchange(code, code_verifier=challenge_pair()[0])
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
    assert a.exchange(code).json()["error"] == "invalid_grant"


@pytest.mark.parametrize("missing", ["code_verifier", "client_id"])
def test_token_request_needs_every_binding(client, missing):
    a = Authz(client, register(client))
    r = a.exchange(a.code(), **{missing: ""})
    assert r.status_code == 400 and r.json()["error"] in ("invalid_grant", "invalid_request")


def test_code_is_bound_to_redirect_uri_and_client(client):
    a = Authz(client, register(client))
    r = a.exchange(a.code(), redirect_uri="http://127.0.0.1:7777/elsewhere")
    assert r.json()["error"] == "invalid_grant"
    other = register(client)
    b = Authz(client, register(client))
    assert b.exchange(b.code(), client_id=other).json()["error"] == "invalid_grant"


def test_token_resource_must_match(client):
    a = Authz(client, register(client))
    r = a.exchange(a.code(), resource="https://other.example/mcp")
    assert r.json()["error"] == "invalid_target"


def test_confidential_clients_are_refused(client):
    a = Authz(client, register(client))
    code = a.code()
    assert a.exchange(code, client_secret="x").status_code == 401
    r = client.post(
        "/token",
        data={"grant_type": "x", "client_id": a.client_id},
        headers={"authorization": "Basic eDp5"},
    )
    assert r.status_code == 401


def test_token_endpoint_input_validation(client):
    assert client.post("/token", json={}).json()["error"] == "invalid_request"
    r = client.post("/token", data={"grant_type": "password", "client_id": "x"})
    assert r.json()["error"] == "unsupported_grant_type"
    assert client.post("/token", data={"grant_type": "authorization_code"}).status_code == 400
    assert client.get("/token").status_code == 405


async def test_code_expires_after_a_minute(client, clock):
    a = Authz(client, register(client))
    code = a.code()
    clock.advance(seconds=61)
    assert a.exchange(code).json()["error"] == "invalid_grant"


async def test_code_replay_revokes_the_tokens_issued_from_it(client, store):
    a = Authz(client, register(client))
    code = a.code()
    first = a.exchange(code).json()
    assert client.post("/mcp", json={}, headers=bearer(first["access_token"])).status_code != 401
    again = a.exchange(code)
    assert again.status_code == 400 and again.json()["error"] == "invalid_grant"
    assert client.post("/mcp", json={}, headers=bearer(first["access_token"])).status_code == 401
    assert refresh(client, a.client_id, first["refresh_token"]).json()["error"] == "invalid_grant"
    assert await store.backend.find("grants", "client_id", a.client_id) == []


async def test_a_pending_grant_never_gets_tokens_after_a_failed_exchange(client, store):
    a = Authz(client, register(client))
    a.exchange(a.code(), code_verifier=challenge_pair()[0])
    assert await store.backend.find("grants", "client_id", a.client_id) == []


# ---------------------------------------------------------------- refresh


def test_refresh_rotates_and_the_new_tokens_work(client):
    a, first = connect(client)
    r = refresh(client, a.client_id, first["refresh_token"])
    assert r.status_code == 200, r.text
    second = r.json()
    assert second["refresh_token"] != first["refresh_token"]
    assert second["access_token"] != first["access_token"]
    assert second["scope"] == first["scope"]
    assert client.post("/mcp", json={}, headers=bearer(second["access_token"])).status_code != 401


def test_refresh_replay_revokes_the_whole_grant(client):
    a, first = connect(client)
    second = refresh(client, a.client_id, first["refresh_token"]).json()
    replay = refresh(client, a.client_id, first["refresh_token"])
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
    for tok in (second["access_token"],):
        assert client.post("/mcp", json={}, headers=bearer(tok)).status_code == 401
    assert refresh(client, a.client_id, second["refresh_token"]).json()["error"] == "invalid_grant"


def test_refresh_is_bound_to_the_client(client):
    a, first = connect(client)
    other = register(client)
    assert refresh(client, other, first["refresh_token"]).json()["error"] == "invalid_grant"
    # the right client still works: a stranger's attempt did not burn the token
    assert refresh(client, a.client_id, first["refresh_token"]).status_code == 200


def test_refresh_cannot_widen_the_scope(client):
    a, first = connect(client)
    r = refresh(client, a.client_id, first["refresh_token"], scope="mail.read mail.send")
    assert r.json()["error"] == "invalid_scope"
    ok = refresh(client, a.client_id, first["refresh_token"], scope="mail.read")
    assert ok.status_code == 200


def test_access_token_cannot_be_used_as_refresh_token(client):
    a, first = connect(client)
    r = refresh(client, a.client_id, first["access_token"])
    assert r.json()["error"] == "invalid_grant"


async def test_lifetimes(client, clock):
    a, first = connect(client)
    clock.advance(minutes=61)
    assert client.post("/mcp", json={}, headers=bearer(first["access_token"])).status_code == 401
    second = refresh(client, a.client_id, first["refresh_token"]).json()
    assert client.post("/mcp", json={}, headers=bearer(second["access_token"])).status_code != 401
    # sliding refresh: 29 days later still fine, each use extends it ...
    token = second
    r = None
    for _ in range(4):
        clock.advance(days=25)
        r = refresh(client, a.client_id, token["refresh_token"])
        if r.status_code != 200:
            break
        token = r.json()
    # ... but the absolute limit of 90 days ends the session
    assert r is not None and r.status_code == 400
    assert refresh(client, a.client_id, token["refresh_token"]).status_code == 400


async def test_refresh_expires_when_unused(client, clock):
    a, first = connect(client)
    clock.advance(days=31)
    assert refresh(client, a.client_id, first["refresh_token"]).json()["error"] == "invalid_grant"


# ---------------------------------------------------------------- audience


async def test_token_for_another_resource_is_refused_on_mcp(client, store):
    a = Authz(client, register(client))
    a.exchange(a.code())
    grant = await store.create_grant(user_id="u_x", client_id="c", scope="mail.read")
    issued = await store.issue_tokens(grant, resource="https://other.example/mcp")
    assert client.post("/mcp", json={}, headers=bearer(issued.access_token)).status_code == 401
    good = await store.create_grant(user_id="u_x", client_id="c", scope="mail.read")
    ok = await store.issue_tokens(good, resource=RESOURCE)
    assert client.post("/mcp", json={}, headers=bearer(ok.access_token)).status_code != 401
    empty = await store.create_grant(user_id="u_x", client_id="c", scope="mail.read")
    no_aud = await store.issue_tokens(empty)
    assert client.post("/mcp", json={}, headers=bearer(no_aud.access_token)).status_code == 401


def test_tokens_are_stored_hashed(client, store):
    _, body = connect(client)
    raw = store.backend.raw("tokens")  # type: ignore[attr-defined]
    assert hash_token(body["access_token"]) in raw
    assert body["access_token"] not in str(raw) and body["refresh_token"] not in str(raw)


# ---------------------------------------------------------------- /revoke


def test_revoking_an_access_token_keeps_the_session(client):
    a, tok = connect(client)
    r = client.post("/revoke", data={"token": tok["access_token"], "client_id": a.client_id})
    assert r.status_code == 200
    assert client.post("/mcp", json={}, headers=bearer(tok["access_token"])).status_code == 401
    assert refresh(client, a.client_id, tok["refresh_token"]).status_code == 200


def test_revoking_a_refresh_token_ends_the_grant(client):
    a, tok = connect(client)
    assert client.post("/revoke", data={"token": tok["refresh_token"]}).status_code == 200
    assert client.post("/mcp", json={}, headers=bearer(tok["access_token"])).status_code == 401
    assert refresh(client, a.client_id, tok["refresh_token"]).status_code == 400


def test_revoke_ignores_unknown_and_foreign_tokens(client):
    a, tok = connect(client)
    other = register(client)
    assert client.post("/revoke", data={"token": "nonsense" * 5}).status_code == 200
    assert (
        client.post("/revoke", data={"token": tok["refresh_token"], "client_id": other}).status_code
        == 200
    )
    assert refresh(client, a.client_id, tok["refresh_token"]).status_code == 200
    assert client.post("/revoke", data={}).status_code == 400


# ---------------------------------------------------------------- sessions and sign-in


def test_the_second_authorization_reuses_the_session(client):
    a = Authz(client, register(client))
    a.code()
    b = Authz(client, a.client_id)
    page = b.open()
    assert page.status_code == 200 and "Allow access to your mail?" in page.text


def test_sign_out_returns_to_the_sign_in_page(client):
    a = Authz(client, register(client))
    page = a.consent_page()
    form = {**hidden_fields(page.text), "action": "signout"}
    r = client.post("/authorize", data=form)
    assert r.status_code == 303
    assert "Sign in" in client.get(r.headers["location"]).text


async def test_portal_session_idle_timeout(client, clock):
    a = Authz(client, register(client))
    a.consent_page()
    clock.advance(minutes=29)
    assert "Allow access" in a.open().text
    clock.advance(minutes=31)
    assert "E-mail address" in a.open().text


async def test_portal_session_absolute_timeout(client, clock):
    a = Authz(client, register(client))
    a.consent_page()
    page = ""
    for _ in range(26):
        clock.advance(minutes=29)
        page = a.open().text
    assert "E-mail address" in page


@pytest.mark.parametrize(
    ("address", "password"),
    [
        ("alice@example.org", "wrong"),
        ("mallory@example.org", PASSWORD),
        ("alice@other.example", PASSWORD),
        ("not an address", PASSWORD),
        ("alice@example.org", ""),
    ],
)
def test_failed_sign_in_says_nothing_specific(client, address, password):
    a = Authz(client, register(client))
    r = a.sign_in(address, password)
    assert r.status_code == 401
    assert "Sign-in failed. Check your e-mail address and password." in r.text
    assert "location" not in r.headers


def test_sign_in_is_rate_limited_per_address(client):
    a = Authz(client, register(client))
    for _ in range(5):
        assert a.sign_in(password="wrong").status_code == 401
    r = a.sign_in(password=PASSWORD)
    assert r.status_code == 429 and "Too many attempts" in r.text
    assert a.sign_in("bob@example.org").status_code == 303  # other addresses are not affected


def test_sign_in_is_rate_limited_per_ip(client):
    a = Authz(client, register(client))
    for i in range(20):
        a.sign_in(f"user{i}@example.org", "wrong")
    assert a.sign_in("bob@example.org").status_code == 429


async def test_unreachable_mail_server():
    login = FakeLogin()
    login.broken = True
    with new_client(await make_app(login=login)) as c:
        a = Authz(c, register(c))
        r = a.sign_in()
        assert r.status_code == 503 and "could not be reached" in r.text


# ---------------------------------------------------------------- CSRF, headers, cookies


def test_post_without_csrf_cookie_or_field_is_refused(client):
    a = Authz(client, register(client))
    page = a.open()
    form = {**hidden_fields(page.text), "address": "alice@example.org", "password": PASSWORD}
    form["csrf_token"] = "x" * 43
    r = client.post("/authorize", data=form)
    assert r.status_code == 403 and "form has expired" in r.text
    del form["csrf_token"]
    assert client.post("/authorize", data=form).status_code == 403
    fresh = new_client(client.app)
    assert fresh.post("/authorize", data=form).status_code == 403


def test_cross_site_post_is_refused_even_with_valid_token(client):
    a = Authz(client, register(client))
    page = a.open()
    form = {**hidden_fields(page.text), "address": "alice@example.org", "password": PASSWORD}
    r = client.post("/authorize", data=form, headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 403
    assert (
        client.post("/authorize", data=form, headers={"sec-fetch-site": "same-origin"}).status_code
        == 303
    )


def test_consent_post_needs_csrf_too(client):
    a = Authz(client, register(client))
    page = a.consent_page()
    form = {**hidden_fields(page.text), "action": "approve", "grant": ["primary:mail.read"]}
    form["csrf_token"] = "y" * 43
    r = client.post("/authorize", data=form)
    assert r.status_code == 403 and "location" not in r.headers


def test_cookies_are_host_prefixed_and_hardened(client):
    a = Authz(client, register(client))
    first = a.open()
    csrf = first.headers.get_list("set-cookie")[0]
    assert csrf.startswith("__Host-uem_csrf=")
    for flag in ("HttpOnly", "Secure", "Path=/", "SameSite=lax"):
        assert flag in csrf
    assert "Domain" not in csrf
    form = {**hidden_fields(first.text), "address": "alice@example.org", "password": PASSWORD}
    cookies = client.post("/authorize", data=form).headers.get_list("set-cookie")
    session = next(c for c in cookies if c.startswith("__Host-uem_session="))
    for flag in ("HttpOnly", "Secure", "Path=/", "SameSite=lax"):
        assert flag in session
    assert "Max-Age" not in session and "expires" not in session.lower()


def test_pages_carry_a_strict_csp_and_no_inline_script(client):
    a = Authz(client, register(client))
    page = a.open()
    csp = page.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert "script-src" not in csp and "unsafe-inline" not in csp
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["cache-control"] == "no-store"
    assert (
        page.headers["referrer-policy"] == "same-origin"
    )  # "no-referrer" would make browsers send Origin: null
    assert "<script" not in page.text.lower() and " style=" not in page.text.lower()
    assert "onclick" not in page.text.lower()
    css = client.get("/portal/assets/portal.css")
    assert css.status_code == 200 and css.headers["content-type"].startswith("text/css")


def test_consent_page_allows_the_redirect_target_in_form_action(client):
    a = Authz(client, register(client))
    csp = a.consent_page().headers["content-security-policy"]
    assert "form-action 'self' http://127.0.0.1:*" in csp
    cid = register(client, "https://app.example.com/cb")
    b = Authz(client, cid, redirect_uri="https://app.example.com/cb")
    assert (
        "form-action 'self' https://app.example.com"
        in b.consent_page().headers["content-security-policy"]
    )


def test_hostile_client_name_is_escaped_and_cleaned(client):
    name = '<script>alert(1)</script>"><img src=x onerror=alert(1)>‮ evil'
    cid = register(client, name=name)
    a = Authz(client, cid)
    for page in (a.open().text, a.consent_page().text):
        assert "<script>" not in page and "<img" not in page
        assert "&lt;script&gt;" in page
        assert "‮" not in page


def test_hidden_fields_cannot_break_out(client):
    a = Authz(client, register(client), state='"><script>x</script>')
    page = a.open().text
    assert "<script>" not in page
    assert hidden_fields(page)["state"] == a.state


def test_error_pages_do_not_reflect_input(client):
    r = client.get("/authorize", params={"client_id": "<script>evil</script>"})
    assert r.status_code == 400 and "evil" not in r.text


# ---------------------------------------------------------------- DCR


def test_dcr_validates_and_limits(client):
    bad = [
        {"redirect_uris": ["javascript:alert(1)"]},
        {"redirect_uris": ["http://evil.example/cb"]},
        {"redirect_uris": ["https://ok.example/cb#frag"]},
        {"redirect_uris": []},
        {
            "redirect_uris": ["https://ok.example/cb"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
        {"redirect_uris": ["https://ok.example/cb"], "grant_types": ["implicit"]},
        {"client_name": "no redirects"},
    ]
    for body in bad:
        r = client.post("/register", json=body)
        assert r.status_code == 400, body
        assert r.json()["error"] in ("invalid_redirect_uri", "invalid_client_metadata")
    assert client.post("/register", content=b"not json").status_code == 400
    assert client.post("/register", content=b"{" + b" " * 9000 + b"}").status_code == 413
    ok = client.post(
        "/register",
        json={
            "redirect_uris": ["https://ok.example/cb"],
            "client_name": "  My\x00 App  ",
            "extra": 1,
        },
    )
    meta = ok.json()
    assert ok.status_code == 201 and meta["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in meta and meta["client_name"] == "My App"


def test_dcr_is_rate_limited(client):
    codes = [
        client.post("/register", json={"redirect_uris": ["https://ok.example/cb"]}).status_code
        for _ in range(12)
    ]
    assert codes[:10] == [201] * 10 and codes[10:] == [429, 429]


async def test_dcr_redirect_host_allowlist():
    from dataclasses import replace

    from tests.oauth_util import operator

    op = operator()
    op = replace(op, oauth=replace(op.oauth, dcr_redirect_hosts=("claude.example",)))
    with new_client(await make_app(op)) as c:
        body = {"redirect_uris": ["https://evil.example/cb"]}
        assert c.post("/register", json=body).status_code == 400
        assert (
            c.post("/register", json={"redirect_uris": ["https://claude.example/cb"]}).status_code
            == 201
        )
        assert (
            c.post("/register", json={"redirect_uris": ["http://127.0.0.1/cb"]}).status_code == 201
        )


# ---------------------------------------------------------------- readiness, host checks


def test_ready_checks_the_store(client):
    r = client.get("/ready")
    assert r.status_code == 200 and r.json()["checks"] == {"config": True, "store": True}


def test_host_header_is_enforced_on_oauth_endpoints(client):
    r = client.get("/.well-known/oauth-authorization-server", headers={"host": "evil.example"})
    assert r.status_code == 421


def test_origin_header_of_browser_posts(client):
    a = Authz(client, register(client))
    form = {**hidden_fields(a.open().text), "address": "alice@example.org", "password": PASSWORD}
    assert client.post("/authorize", data=form, headers={"origin": "null"}).status_code == 403
    assert (
        client.post("/authorize", data=form, headers={"origin": "https://evil.example"}).status_code
        == 403
    )
    assert client.post("/authorize", data=form, headers={"origin": ISSUER}).status_code == 303
