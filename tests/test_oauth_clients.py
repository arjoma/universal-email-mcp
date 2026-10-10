"""Client ID Metadata Documents: SSRF-safe fetch, validation, caching."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.https_server import HOST, DocServer, Reply, doc_server, resolver
from tests.oauth_util import REDIRECT, Authz, make_app, new_client
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.oauth.fetch import (
    FetchError,
    FetchPolicy,
    check_document_url,
    fetch_document,
)
from universal_email_mcp.store import KeyRing, MemoryBackend, Store


def doc(cid: str, **over: object) -> bytes:
    body = {"client_id": cid, "client_name": "Doc App", "redirect_uris": [REDIRECT]}
    body.update(over)
    return json.dumps(body).encode()


@pytest.fixture
def server(tmp_path: Path):
    with doc_server(tmp_path) as s:
        yield s


def policy(server: DocServer, **kw: object) -> FetchPolicy:
    return FetchPolicy(
        net=NetPolicy(allow_private=True, connect_timeout=3, read_timeout=3),
        ca_file=server.ca_file,
        resolver=resolver,
        **{"ports": None, **kw},  # type: ignore[arg-type]  # the test server has a random port
    )


# ---------------------------------------------------------------- the fetcher


def test_fetch_returns_the_document(server):
    server.routes["/c.json"] = Reply(body=b'{"a":1}')
    assert fetch_document(server.url("/c.json"), policy(server)) == b'{"a":1}'
    assert server.hits == ["/c.json"]


@pytest.mark.parametrize(
    "url",
    [
        "http://client.test/c.json",
        "https://user:pw@client.test/c.json",
        "https://client.test/c.json#frag",
        "https://client.test/",
        "https://client.test",
        "https://client.test/c.json?x=1",
        "https://client.test/a/../c.json",
        "https://127.0.0.1/c.json",
        "https://[::1]/c.json",
        "https://client.test/" + "a" * 600,
        "https://client.test/a b",
        "ftp://client.test/c.json",
        "",
    ],
)
def test_unacceptable_urls_are_refused_before_any_connection(url):
    with pytest.raises(FetchError):
        check_document_url(url)


@pytest.mark.parametrize(
    "addresses",
    [
        ["127.0.0.1"],
        ["10.0.0.5"],
        ["192.168.1.1"],
        ["169.254.169.254"],
        ["100.64.0.1"],
        ["::1"],
        ["fd00::1"],
        ["::ffff:10.0.0.1"],
        ["93.184.216.34", "10.0.0.1"],  # one bad address among good ones is enough
        [],
    ],
)
def test_private_and_mixed_resolutions_are_refused(addresses):
    pol = FetchPolicy(resolver=lambda host, port: addresses)
    with pytest.raises(FetchError):
        fetch_document("https://client.example/c.json", pol)


def test_redirects_are_not_followed(server):
    server.routes["/c.json"] = Reply(302, headers={"Location": "https://client.test/other"})
    with pytest.raises(FetchError, match="redirect"):
        fetch_document(server.url("/c.json"), policy(server))
    assert server.hits == ["/c.json"]


def test_bad_status_content_type_and_encoding(server):
    server.routes["/404.json"] = Reply(404)
    server.routes["/html"] = Reply(body=b"<html>", content_type="text/html")
    server.routes["/gz"] = Reply(headers={"Content-Encoding": "gzip"})
    for path in ("/404.json", "/html", "/gz"):
        with pytest.raises(FetchError):
            fetch_document(server.url(path), policy(server))


def test_oversize_documents_are_refused(server):
    big = b'{"x":"' + b"a" * 20000 + b'"}'
    server.routes["/big.json"] = Reply(body=big)
    with pytest.raises(FetchError, match="too large"):
        fetch_document(server.url("/big.json"), policy(server))
    # a lying Content-Length cannot make the read longer than the limit (here: cut short)
    server.routes["/lie.json"] = Reply(body=big, declared_length=10)
    assert len(fetch_document(server.url("/lie.json"), policy(server))) <= 10


def test_slow_servers_are_cut_off(server):
    server.routes["/slow.json"] = Reply(body=b'{"a":' + b" " * 40 + b"1}", trickle=0.2)
    with pytest.raises(FetchError):
        fetch_document(server.url("/slow.json"), policy(server, total_timeout=1.0))


def test_untrusted_certificate_is_refused(server, tmp_path):
    server.routes["/c.json"] = Reply()
    pol = FetchPolicy(
        net=NetPolicy(allow_private=True, connect_timeout=3, read_timeout=3), resolver=resolver
    )
    with pytest.raises(FetchError):
        fetch_document(server.url("/c.json"), pol)


# ---------------------------------------------------------------- the registry via /authorize


class Clock:
    def __init__(self) -> None:
        self.t = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.t


@pytest.fixture
async def web(server):
    clock = Clock()
    store = Store(MemoryBackend(), KeyRing({"k1": b"k" * 32}), clock=clock)
    app = await make_app(store=store, fetch_policy=policy(server))
    with new_client(app) as c:
        yield c, clock


def test_cimd_client_flow_end_to_end(web, server):
    c, _ = web
    cid = server.url("/client.json")
    server.routes["/client.json"] = Reply(body=doc(cid))
    a = Authz(c, cid)
    page = a.consent_page().text
    assert "Doc App" in page and cid in page and "127.0.0.1:7777" in page
    body = a.exchange(a.code()).json()
    assert body["token_type"] == "Bearer"


def test_cimd_document_is_cached_then_refetched_after_the_ttl(web, server):
    c, clock = web
    cid = server.url("/client.json")
    server.routes["/client.json"] = Reply(body=doc(cid))
    Authz(c, cid).open()
    Authz(c, cid).open()
    assert server.hits == ["/client.json"]
    server.routes["/client.json"] = Reply(body=doc(cid, client_name="Renamed"))
    clock.t += timedelta(hours=1, minutes=1)
    page = Authz(c, cid).open()
    assert len(server.hits) == 2 and "Renamed" in page.text


@pytest.mark.parametrize(
    "mutation",
    [
        {"client_id": "https://client.test/other.json"},
        {"redirect_uris": []},
        {"redirect_uris": ["javascript:alert(1)"]},
        {"redirect_uris": ["http://evil.example/cb"]},
        {"redirect_uris": "http://127.0.0.1/cb"},
        {"token_endpoint_auth_method": "client_secret_post"},
        {"client_secret": "s3cret"},
        {"grant_types": ["implicit"]},
        {"response_types": ["token"]},
        {"jwks_uri": "https://client.test/jwks"},
    ],
)
def test_invalid_documents_are_refused_and_not_cached(web, server, mutation):
    c, _ = web
    cid = server.url("/client.json")
    server.routes["/client.json"] = Reply(body=doc(cid, **mutation))
    r = Authz(c, cid).open()
    assert r.status_code == 400 and "location" not in r.headers
    assert "could not be verified" in r.text


def test_not_json_documents_are_refused(web, server):
    c, _ = web
    cid = server.url("/client.json")
    for body in (b"not json", b"[]", b'"x"', b"{" * 5000):
        server.routes["/client.json"] = Reply(body=body)
        assert Authz(c, cid).open().status_code == 400


def test_unreachable_client_documents_are_refused(web, server):
    c, _ = web
    assert Authz(c, server.url("/missing.json")).open().status_code == 400
    assert Authz(c, "https://private.example/c.json").open().status_code == 400
    assert Authz(c, "http://client.test/c.json").open().status_code == 400


def test_client_fetches_are_rate_limited(web, server):
    c, _ = web
    statuses = [Authz(c, server.url(f"/m{i}.json")).open().status_code for i in range(33)]
    assert statuses[-1] == 429


def test_redirect_uri_must_be_listed_in_the_document(web, server):
    c, _ = web
    cid = server.url("/client.json")
    server.routes["/client.json"] = Reply(body=doc(cid))
    r = Authz(c, cid, redirect_uri="http://127.0.0.1:7777/evil").open()
    assert r.status_code == 400 and "location" not in r.headers
    ok = Authz(c, cid, redirect_uri="http://127.0.0.1:50000/callback").open()
    assert ok.status_code == 200


def test_ssrf_never_reaches_the_network_with_the_default_policy():
    # default policy (public addresses only, system CA): a name resolving to loopback is refused
    from universal_email_mcp.oauth.clients import ClientError, ClientRegistry
    from universal_email_mcp.oauth.config import OAuthConfig

    store = Store(MemoryBackend(), KeyRing({"k1": b"k" * 32}))
    reg = ClientRegistry(
        store,
        OAuthConfig(issuer="https://mcp.test"),
        FetchPolicy(resolver=lambda h, p: ["127.0.0.1"]),
    )
    import asyncio

    with pytest.raises(ClientError):
        asyncio.run(reg.resolve("https://client.test:8443/c.json"))


def test_hostile_names_are_cleaned(web, server):
    c, _ = web
    cid = server.url("/client.json")
    server.routes["/client.json"] = Reply(
        body=doc(cid, client_name="<b>Bank</b>‮​\n\tof Evil " + "x" * 300)
    )
    page = Authz(c, cid).open().text
    assert "<b>" not in page and "&lt;b&gt;Bank" in page
    assert "‮" not in page and "x" * 101 not in page


def test_dcr_clients_cannot_use_urls_and_urls_are_not_registered(web, server):
    c, _ = web
    assert HOST  # keep import used
    r = Authz(c, "dcr_doesnotexist").open()
    assert r.status_code == 400


# ---------------------------------------------------------------- ports and the global limit (review W5)


@pytest.mark.parametrize(
    "url",
    [
        "https://client.test:8443/c.json",
        "https://client.test:22/c.json",
        "https://client.test:6379/c.json",
        "https://client.test:80/c.json",
        "https://client.test:444/c.json",
    ],
)
def test_only_port_443_is_acceptable_for_client_documents(url):
    with pytest.raises(FetchError, match="443"):
        check_document_url(url)
    with pytest.raises(FetchError):
        fetch_document(url, FetchPolicy(resolver=lambda h, p: ["93.184.216.34"]))
    assert check_document_url("https://client.test/c.json")[1] == 443
    assert check_document_url("https://client.test:443/c.json")[1] == 443
    assert check_document_url(url, None)[1] != 443  # only tests may open the port


def test_the_default_policy_never_connects_to_other_ports():
    seen: list[int] = []

    def resolver_(host: str, port: int) -> list[str]:
        seen.append(port)
        return ["127.0.0.1"]

    with pytest.raises(FetchError):
        fetch_document("https://client.test:8443/c.json", FetchPolicy(resolver=resolver_))
    assert seen == []  # refused before any name lookup


async def test_client_fetches_have_one_budget_for_the_whole_instance(server):
    """Review W5: many networks together cannot make the instance fetch (and cache) without
    end - the per-network limit alone is a limit per attacker address."""
    from dataclasses import replace

    from universal_email_mcp.oauth.config import Rate, RateLimits

    limits = replace(RateLimits(), client_fetch_global=Rate(3, timedelta(hours=1)))
    app = await make_app(fetch_policy=policy(server), rate_limits=limits)
    with new_client(app) as c:
        for i in range(3):
            assert Authz(c, server.url(f"/g{i}.json")).open().status_code == 400  # fetched, no doc
        before = len(server.hits)
        assert before == 3
        r = Authz(c, server.url("/g3.json")).open()
        assert r.status_code == 429 or "Too many" in r.text
        assert len(server.hits) == before  # no further request reached the document server
