"""Download links: tokens, incremental transfer decoders, headers, request checks."""

from __future__ import annotations

import base64
import quopri
import random
from collections.abc import MutableMapping
from typing import Any

import pytest

from universal_email_mcp.config import Config
from universal_email_mcp.mail.mime import decode_transfer, safe_mime_type
from universal_email_mcp.mail.transfer import make_decoder
from universal_email_mcp.models import MessageRef
from universal_email_mcp.server.downloads import DownloadApp, content_disposition
from universal_email_mcp.service.downloads import (
    DownloadTokens,
    LinkExpired,
    LinkInvalid,
    token_fingerprint,
)
from universal_email_mcp.service.router import AccountRouter

REF = MessageRef("Work", "INBOX/Ümläut", 77, 1234)


# ---------------------------------------------------------------- tokens


def test_token_roundtrip():
    t = DownloadTokens()
    token = t.issue(REF, "2.1")
    assert token.startswith("d1.") and all(c.isalnum() or c in "-_." for c in token)
    assert t.verify(token) == (REF, "2.1")


def test_token_tampering_is_rejected():
    t = DownloadTokens()
    token = t.issue(REF, "2")
    body, mac = token.split(".", 2)[1:]
    # (the last base64 character may carry unused bits, so flip an inner one)
    flipped = body[:5] + ("A" if body[5] != "A" else "B") + body[6:]
    bad_mac = ("A" if mac[3] != "A" else "B").join((mac[:3], mac[4:]))
    for bad in (
        f"d1.{flipped}.{mac}",
        f"d1.{body}.{bad_mac}",
        f"d1.{body}.",
        f"d1.{body}",
        "d1.",
        "",
        "x" * 10_000,
        "d2." + token[3:],
    ):
        with pytest.raises(LinkInvalid):
            t.verify(bad)


def test_token_from_another_run_is_invalid():
    token = DownloadTokens().issue(REF, "1")
    with pytest.raises(LinkInvalid):
        DownloadTokens().verify(token)


def test_token_expiry():
    now = [1000.0]
    t = DownloadTokens(ttl=60, clock=lambda: now[0])
    token = t.issue(REF, "1")
    now[0] = 1059.0
    assert t.verify(token)[1] == "1"
    now[0] = 1060.0
    with pytest.raises(LinkExpired):
        t.verify(token)


def test_signed_garbage_payload_is_invalid():
    t = DownloadTokens(key=b"k" * 32)
    for payload in (b"not json", b'["a","b",1]', b'["a","b","x",1,"1",9999999999999]', b"[]"):
        mac = t._mac(payload)  # pyright: ignore[reportPrivateUsage]
        enc = base64.urlsafe_b64encode
        token = "d1." + enc(payload).decode().rstrip("=") + "." + enc(mac).decode().rstrip("=")
        with pytest.raises(LinkInvalid):
            t.verify(token)


def test_fingerprint_is_short_and_not_the_token():
    token = DownloadTokens().issue(REF, "1")
    fp = token_fingerprint(token)
    assert len(fp) == 8 and fp not in token


# ---------------------------------------------------------------- decoders


def _stream(data: bytes, encoding: str, sizes: list[int]) -> bytes:
    dec = make_decoder(encoding)
    out = b""
    i = 0
    n = 0
    while i < len(data):
        size = sizes[n % len(sizes)]
        out += dec.feed(data[i : i + size])
        i += size
        n += 1
    return out + dec.finish()


def _noisy_base64(rng: random.Random, n: int) -> bytes:
    raw = base64.encodebytes(rng.randbytes(n)).replace(b"\n", b"\r\n")
    if rng.random() < 0.5:
        raw = raw.replace(b"=", b"")  # missing padding
    junk = list(raw)
    for _ in range(rng.randrange(0, 5)):
        junk.insert(rng.randrange(0, len(junk) + 1), rng.choice(b"!* \x01=\x80"))
    return bytes(junk)


@pytest.mark.parametrize("seed", range(40))
def test_base64_matches_decode_transfer(seed: int):
    rng = random.Random(seed)
    data = _noisy_base64(rng, rng.randrange(0, 600))
    sizes = [1] if seed % 5 == 0 else [rng.randrange(1, 90) for _ in range(5)]
    assert _stream(data, "base64", sizes) == decode_transfer(data, "base64")


def _qp_sample(rng: random.Random) -> bytes:
    pieces: list[bytes] = []
    for _ in range(rng.randrange(0, 40)):
        pieces.append(
            rng.choice(
                [
                    b"hello world",
                    b"caf=C3=A9",
                    b"soft=\r\n",
                    b"soft=\n",
                    b"trailing  \r\n",
                    b"\t\n",
                    b"=3D",
                    b"=",
                    b"=4",
                    b"=zz",
                    b"\r\n",
                    b"\n",
                    b" ",
                    b"\r",
                    b"x" * rng.randrange(1, 100),
                ]
            )
        )
    return b"".join(pieces)


@pytest.mark.parametrize("seed", range(60))
def test_quoted_printable_matches_decode_transfer(seed: int):
    rng = random.Random(seed)
    data = _qp_sample(rng)
    sizes = [1] if seed % 5 == 0 else [rng.randrange(1, 40) for _ in range(5)]
    assert _stream(data, "quoted-printable", sizes) == decode_transfer(data, "quoted-printable")


def test_quoted_printable_hostile_endless_line_is_bounded():
    dec = make_decoder("quoted-printable")
    held = 0
    out = b""
    for _ in range(50):
        out += dec.feed(b"a" * 40_000)
        held = max(held, len(dec._carry))  # pyright: ignore[reportAttributeAccessIssue]
    out += dec.feed(b"  =3")
    out += dec.finish()
    assert held < 70_000
    assert out == quopri.decodestring(b"a" * 2_000_000 + b"  =3")


def test_quoted_printable_endless_line_split_inside_escape():
    data = b"a" * 70_000 + b"=C3=A9" + b"b" * 70_000
    for size in (1, 7, 65_537, 70_001):
        assert _stream(data, "quoted-printable", [size]) == quopri.decodestring(data)


@pytest.mark.parametrize("enc", ["7bit", "8bit", "binary", "x-weird", ""])
def test_identity_encodings_pass_through(enc: str):
    data = random.Random(1).randbytes(1000)
    assert _stream(data, enc, [7]) == data


# ---------------------------------------------------------------- headers


@pytest.mark.parametrize(
    "name",
    [
        'evil"; filename="x.exe',
        "a\r\nSet-Cookie: x=1",
        "back\\slash%41.txt",
        "Müller Übersicht (€).pdf",
        "..",
        "",
        None,
        "日本語.pdf",
        "x" * 5000,
        "a;b,c.txt",
    ],
)
def test_content_disposition_is_one_safe_line(name: str | None):
    value = content_disposition(name).decode("ascii")
    assert "\r" not in value and "\n" not in value
    assert value.startswith('attachment; filename="')
    fallback = value.split('filename="', 1)[1].split('"', 1)[0]
    assert fallback and all(c.isalnum() or c in "._ -" for c in fallback)
    assert len(value) < 700


def test_content_disposition_utf8_form():
    value = content_disposition("Müller (1).pdf").decode()
    assert "filename*=UTF-8''M%C3%BCller%20%281%29.pdf" in value


def test_safe_mime_type_allowlist():
    assert safe_mime_type("application/pdf") == "application/pdf"
    for bad in ("text/html", "image/svg+xml", "application/xhtml+xml", "x/y\r\nz", "text/plain"):
        assert safe_mime_type(bad) == "application/octet-stream"


# ---------------------------------------------------------------- request checks


class _Asgi:
    def __init__(self, app: DownloadApp) -> None:
        self.app = app

    async def request(
        self,
        path: str,
        *,
        method: str = "GET",
        host: str | list[str] | None = "127.0.0.1:5555",
        query: bytes = b"",
    ) -> tuple[int, dict[bytes, bytes], bytes]:
        hosts = [] if host is None else [host] if isinstance(host, str) else host
        scope: dict[str, Any] = {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": query,
            "headers": [(b"host", h.encode()) for h in hosts],
        }
        sent: list[MutableMapping[str, Any]] = []

        async def receive() -> MutableMapping[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(msg: MutableMapping[str, Any]) -> None:
            sent.append(msg)

        await self.app(scope, receive, send)
        start = sent[0]
        body = b"".join(m.get("body", b"") for m in sent[1:])
        return start["status"], dict(start["headers"]), body


@pytest.fixture
def asgi() -> tuple[_Asgi, DownloadTokens]:
    tokens = DownloadTokens()
    router = AccountRouter(Config())
    return _Asgi(DownloadApp(router, tokens, port=5555, max_bytes=1000)), tokens


@pytest.mark.parametrize(
    "host",
    [
        None,
        "evil.example",
        "127.0.0.1",
        "127.0.0.1:5556",
        "127.0.0.1:5555.evil.example",
        "[::1]:5555",
    ],
)
async def test_bad_host_is_refused_before_anything_else(host: str | None, asgi: Any):
    app, tokens = asgi
    token = tokens.issue(REF, "1")
    status, headers, body = await app.request(f"/a/{token}", host=host)
    assert status == 403
    assert body == b"Forbidden.\n"
    assert headers[b"x-content-type-options"] == b"nosniff"


async def test_two_host_headers_are_refused(asgi: Any):
    app, _ = asgi
    status, _, _ = await app.request("/a/x", host=["127.0.0.1:5555", "evil.example"])
    assert status == 403


@pytest.mark.parametrize("host", ["127.0.0.1:5555", "localhost:5555", "LOCALHOST:5555"])
async def test_loopback_hosts_pass_the_check(host: str, asgi: Any):
    app, _ = asgi
    status, _, _ = await app.request("/a/nonsense", host=host)
    assert status == 404


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
async def test_other_methods_are_refused(method: str, asgi: Any):
    app, tokens = asgi
    status, headers, _ = await app.request(f"/a/{tokens.issue(REF, '1')}", method=method)
    assert status == 405
    assert headers[b"allow"] == b"GET, HEAD"


@pytest.mark.parametrize(
    "path", ["/", "/a", "/a/", "/m/x", "/../a/x", "/a/x/y", "/a/%2e%2e", "/static"]
)
async def test_no_other_routes(path: str, asgi: Any):
    app, _ = asgi
    status, _, body = await app.request(path)
    assert status == 404 and b"Not found" in body


async def test_query_string_is_refused(asgi: Any):
    app, tokens = asgi
    status, _, _ = await app.request(f"/a/{tokens.issue(REF, '1')}", query=b"x=1")
    assert status == 404


async def test_tampered_and_expired_tokens(asgi: Any):
    app, tokens = asgi
    token = tokens.issue(REF, "1")
    assert (await app.request(f"/a/{token[:-2]}AA"))[0] == 404
    now = [0.0]
    old = DownloadTokens(key=b"k" * 32, ttl=10, clock=lambda: now[0])
    app2 = _Asgi(DownloadApp(AccountRouter(Config()), old, port=5555, max_bytes=10))
    t = old.issue(REF, "1")
    now[0] = 11.0
    status, _, body = await app2.request(f"/a/{t}")
    assert status == 403 and b"expired" in body


async def test_failure_after_response_start_aborts_instead_of_second_response():
    from universal_email_mcp.server.downloads import DownloadAborted

    class Boom(DownloadApp):
        async def _handle(self, scope: Any, receive: Any, send: Any) -> None:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            raise RuntimeError("boom")

    app = Boom(AccountRouter(Config()), DownloadTokens(), port=1, max_bytes=1)
    sent: list[Any] = []

    async def send(msg: Any) -> None:
        sent.append(msg)

    async def receive() -> Any:
        return {"type": "http.request"}

    with pytest.raises(DownloadAborted):
        await app({"type": "http", "headers": []}, receive, send)
    assert [m["type"] for m in sent] == ["http.response.start"]


async def test_message_tokens_only_on_m_route_and_attachment_tokens_only_on_a(asgi: Any):
    app, tokens = asgi
    assert (await app.request(f"/m/{tokens.issue(REF, '2')}"))[0] == 404
    assert (await app.request(f"/a/{tokens.issue(REF, '')}"))[0] == 404
