"""The content-origin host serves only ``/c/*`` and the probes (security review L2/W2)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from tests.oauth_util import make_app, operator

PATHS = (
    "/portal/signin",
    "/portal/privacy",
    "/portal/accounts",
    "/authorize",
    "/token",
    "/register",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource/mcp",
    "/mcp",
    "/m/abc",
    "/m/abc/html",
    "/static/portal.css",
    "/",
)


@pytest.fixture
async def app():
    op = operator(allowed_hosts=("mcp.test", "content.test"), content_origin="https://content.test")
    return await make_app(op)


@pytest.mark.parametrize("path", PATHS)
def test_everything_but_c_and_probes_is_404_on_the_content_host(app, path):
    with TestClient(app, base_url="https://content.test", follow_redirects=False) as c:
        for method in ("GET", "POST", "OPTIONS"):
            r = c.request(method, path)
            assert r.status_code == 404, (method, path, r.status_code)
            assert "set-cookie" not in r.headers
            assert "location" not in r.headers


def test_the_content_host_still_answers_probes_and_its_own_route(app):
    with TestClient(app, base_url="https://content.test", follow_redirects=False) as c:
        assert c.get("/health").status_code == 200
        assert c.get("/ready").status_code == 200
        # a token that does not verify: the route answers (404 text), not the generic JSON
        r = c.get("/c/not-a-token")
        assert r.status_code == 404 and r.text == "Not found.\n"
        # nothing outside /c/ even with look-alike prefixes
        assert c.get("/cx/y").status_code == 404
        assert c.get("/c").status_code == 404


def test_the_main_host_is_unaffected(app):
    with TestClient(app, base_url="https://mcp.test", follow_redirects=False) as c:
        assert c.get("/portal/signin").status_code == 200
        assert c.get("/.well-known/oauth-authorization-server").status_code == 200
        # and /c/ is answered by the route's own host check there
        assert c.get("/c/not-a-token").status_code == 404


async def test_without_a_content_origin_nothing_changes():
    app = await make_app(operator())
    with TestClient(app, base_url="https://mcp.test", follow_redirects=False) as c:
        assert c.get("/portal/signin").status_code == 200
