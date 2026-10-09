"""Local download links against Dovecot: the loopback listener streams attachments.

Real HTTP (httpx2) against the real listener; the bytes come out of a real IMAP
server in small ranged reads. Reading never sets ``\\Seen``.
"""

from __future__ import annotations

import os
import random
import re
import sys
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx2
import pytest
from mcp import Client, StdioServerParameters
from mcp.types import TextContent

from tests.integration.conftest import ImapServer, Mailbox
from universal_email_mcp.config import Config, Downloads, parse_config
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.models import MessageRef
from universal_email_mcp.server.app import build_server
from universal_email_mcp.server.downloads import LocalDownloads
from universal_email_mcp.service import downloads as dl_service
from universal_email_mcp.service.downloads import DownloadTokens
from universal_email_mcp.service.mail import MailService
from universal_email_mcp.service.router import AccountRouter

pytestmark = pytest.mark.integration

BIG = random.Random(11).randbytes(600_000)
# 8bit data without NUL, CR or LF: plain IMAP BODY[] fetches cannot carry those unchanged.
BINARY = bytes(random.Random(12).choices([b for b in range(1, 256) if b not in (10, 13)], k=50_000))
QP_TEXT = ("Grüße aus Wien — schöne Zeile mit Umlauten ÄÖÜ äöü ß und =Zeichen\n" * 3000).encode()


def _base(subject: str) -> EmailMessage:
    m = EmailMessage()
    m["From"] = "Sender <sender@example.net>"
    m["To"] = "me@example.org"
    m["Subject"] = subject
    m["Message-ID"] = f"<{uuid.uuid4().hex}@example.net>"
    return m


def _messages() -> dict[str, bytes]:
    big = _base("big")
    big.set_content("big file")
    big.add_attachment(
        BIG, maintype="application", subtype="pdf", filename='Großer "Bericht"\r\nX: y.pdf'
    )
    binary = (
        b"From: Sender <sender@example.net>\r\nTo: me@example.org\r\nSubject: binary\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=bnd\r\n\r\n"
        b"--bnd\r\nContent-Type: text/plain\r\n\r\nbinary file\r\n"
        b"--bnd\r\nContent-Type: application/zip; name=b.zip\r\n"
        b"Content-Transfer-Encoding: 8bit\r\nContent-Disposition: attachment; filename=b.zip"
        b"\r\n\r\n" + BINARY + b"\r\n--bnd--\r\n"
    )
    qp = _base("qp")
    qp.set_content("quoted-printable file")
    qp.add_attachment(
        QP_TEXT.decode(),
        subtype="html",
        filename="notiz.html",
        cte="quoted-printable",
        charset="utf-8",
    )
    return {"big": big.as_bytes(), "binary": binary, "qp": qp.as_bytes()}


@dataclass(frozen=True)
class Box:
    server: ImapServer
    mb: Mailbox
    uidvalidity: int
    uids: dict[str, int]

    def ref(self, name: str, *, uidvalidity: int | None = None, uid: int | None = None):
        return MessageRef("Work", "INBOX", uidvalidity or self.uidvalidity, uid or self.uids[name])

    def config(self, **downloads: Any) -> Config:
        base = parse_config(
            {
                "accounts": [
                    {
                        "name": "Work",
                        "username": self.mb.user,
                        "password_env": "UEM_IT_PASSWORD",
                        "tls_verify": False,
                        "imap": {"host": self.server.host, "port": self.server.imaps_port},
                    }
                ],
                "limits": {"account_timeout": 20, "max_attachment_bytes": 100_000},
            }
        )
        return Config(
            accounts=base.accounts,
            limits=base.limits,
            downloads=Downloads(**downloads),
        )

    def flags(self, name: str) -> tuple[Any, ...]:
        c = self.mb.admin()
        try:
            c.select_folder("INBOX", readonly=True)
            return tuple(c.fetch([self.uids[name]], ["FLAGS"])[self.uids[name]][b"FLAGS"])  # pyright: ignore[reportArgumentType]
        finally:
            c.logout()


@pytest.fixture(scope="module")
def box(imap_server: ImapServer) -> Iterator[Box]:
    mb = Mailbox(imap_server, f"dl{uuid.uuid4().hex[:10]}@example.org")
    c = mb.admin()
    try:
        for raw in _messages().values():
            c.append("INBOX", raw)
        uidvalidity = int(c.select_folder("INBOX")[b"UIDVALIDITY"])
        found = sorted(c.search("ALL"))
    finally:
        c.logout()
    uids = dict(zip(_messages(), found, strict=True))
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("UEM_IT_PASSWORD", imap_server.password)
        yield Box(imap_server, mb, uidvalidity, uids)


@asynccontextmanager
async def listener(
    box: Box, tokens: DownloadTokens | None = None, **downloads: Any
) -> AsyncIterator[tuple[LocalDownloads, httpx2.AsyncClient]]:
    config = box.config(**downloads)
    router = AccountRouter(config)
    dl = LocalDownloads(router, config.downloads, tokens)
    assert await dl.start()
    try:
        async with httpx2.AsyncClient(timeout=30) as http:
            yield dl, http
    finally:
        await dl.stop()
        await router.aclose()


def url_for(dl: LocalDownloads, ref: MessageRef, section: str) -> str:
    url = dl.attachment_url(ref, section)
    assert url is not None
    return url


async def test_multi_chunk_base64_download_matches_and_leaves_unseen(
    box: Box, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(dl_service, "CHUNK_BYTES", 50_000)  # many ranged reads, odd sizes
    calls = 0
    real = ImapSession.read_part_chunk

    def counting(self: ImapSession, *a: Any, **kw: Any) -> bytes:
        nonlocal calls
        calls += 1
        return real(self, *a, **kw)

    monkeypatch.setattr(ImapSession, "read_part_chunk", counting)
    before = box.flags("big")
    async with listener(box) as (dl, http):
        url = url_for(dl, box.ref("big"), "2")
        assert re.fullmatch(rf"http://127\.0\.0\.1:{dl.port}/a/[A-Za-z0-9_.-]+", url)
        r = await http.get(url)
    assert r.status_code == 200
    assert r.content == BIG
    assert calls >= 16  # 800 kB of base64 in 50 kB reads
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["transfer-encoding"] == "chunked"
    assert "content-length" not in r.headers
    disp = r.headers["content-disposition"]
    assert disp.startswith('attachment; filename="')
    assert "\r" not in disp and "\n" not in disp and '"Bericht"' not in disp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["content-security-policy"] == "sandbox; default-src 'none'"
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cross-origin-resource-policy"] == "same-origin"
    assert box.flags("big") == before
    assert b"\\Seen" not in box.flags("big")


async def test_binary_download_has_content_length_and_head_matches(box: Box):
    async with listener(box) as (dl, http):
        url = url_for(dl, box.ref("binary"), "2")
        r = await http.get(url)
        h = await http.head(url)
    assert r.status_code == 200 and r.content == BINARY
    assert r.headers["content-length"] == str(len(BINARY))
    assert r.headers["content-type"] == "application/zip"
    assert h.status_code == 200 and h.content == b""
    for name in ("content-type", "content-disposition", "x-content-type-options"):
        assert h.headers[name] == r.headers[name]
    assert h.headers.get("content-length") == r.headers["content-length"]


async def test_quoted_printable_download_is_decoded_and_never_html(
    box: Box, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(dl_service, "CHUNK_BYTES", 7_001)
    async with listener(box) as (dl, http):
        r = await http.get(url_for(dl, box.ref("qp"), "2"))
    assert r.status_code == 200
    assert r.content == QP_TEXT.replace(b"\n", b"\r\n")  # stored with CRLF
    assert r.headers["content-type"] == "application/octet-stream"  # text/html is not passive


async def test_head_of_chunked_download_has_no_length(box: Box):
    async with listener(box) as (dl, http):
        h = await http.head(url_for(dl, box.ref("big"), "2"))
    assert h.status_code == 200 and "content-length" not in h.headers


async def test_bad_tokens(box: Box):
    now = [1000.0]
    tokens = DownloadTokens(ttl=60, clock=lambda: now[0])
    async with listener(box, tokens) as (dl, http):
        good = url_for(dl, box.ref("binary"), "2")
        base, token = good.rsplit("/", 1)
        assert (await http.get(f"{base}/{token[:-3]}AAA")).status_code == 404
        assert (
            await http.get(f"{base}/{DownloadTokens().issue(box.ref('binary'), '2')}")
        ).status_code == 404
        assert (await http.get(f"{base}/garbage")).status_code == 404
        now[0] = 2000.0
        r = await http.get(good)
        assert r.status_code == 403 and "expired" in r.text
        assert "binary" not in r.text and "INBOX" not in r.text


async def test_stale_uidvalidity_message_gone_and_unknown_part(box: Box):
    async with listener(box) as (dl, http):
        assert (
            await http.get(url_for(dl, box.ref("binary", uidvalidity=box.uidvalidity + 1), "2"))
        ).status_code == 410
        assert (await http.get(url_for(dl, box.ref("binary", uid=99_999), "2"))).status_code == 410
        assert (await http.get(url_for(dl, box.ref("binary"), "7"))).status_code == 404
        assert (await http.get(url_for(dl, box.ref("binary"), "../1"))).status_code == 404
        unknown = MessageRef("Nobody", "INBOX", box.uidvalidity, 1)
        assert (await http.get(url_for(dl, unknown, "1"))).status_code == 403


async def test_request_hardening(box: Box):
    async with listener(box) as (dl, http):
        url = url_for(dl, box.ref("binary"), "2")
        r = await http.get(url, headers={"Host": "evil.example"})
        assert r.status_code == 403 and r.text == "Forbidden.\n"
        r = await http.get(url, headers={"Host": f"localhost:{dl.port}"})
        assert r.status_code == 200
        assert (await http.post(url)).status_code == 405
        assert (await http.put(url)).status_code == 405
        assert (await http.get(f"http://127.0.0.1:{dl.port}/")).status_code == 404
        assert (await http.get(f"http://127.0.0.1:{dl.port}/a/")).status_code == 404
        assert (await http.get(f"{url}?x=1")).status_code == 404


async def test_download_limit(box: Box):
    async with listener(box, max_download_bytes=10_000) as (dl, http):
        r = await http.get(url_for(dl, box.ref("binary"), "2"))
    assert r.status_code == 413


async def test_message_vanishing_mid_download_cuts_the_connection(
    box: Box, imap_server: ImapServer, monkeypatch: pytest.MonkeyPatch
):
    # A message of its own, so the shared ones stay intact.
    c = box.mb.admin()
    try:
        m = _base("doomed")
        m.set_content("x")
        m.add_attachment(BIG, maintype="application", subtype="pdf", filename="doomed.pdf")
        c.append("INBOX", m.as_bytes())
        c.select_folder("INBOX")
        uid = max(c.search("ALL"))
    finally:
        c.logout()
    monkeypatch.setattr(dl_service, "CHUNK_BYTES", 40_000)
    real = ImapSession.read_part_chunk
    calls = 0

    def expunging(self: ImapSession, ref: MessageRef, *a: Any) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 3:
            admin = box.mb.admin()
            try:
                admin.select_folder("INBOX")
                admin.delete_messages([uid])
                admin.expunge()
            finally:
                admin.logout()
        return real(self, ref, *a)

    monkeypatch.setattr(ImapSession, "read_part_chunk", expunging)
    async with listener(box) as (dl, http):
        url = url_for(dl, box.ref("big", uid=uid), "2")
        got = 0
        with pytest.raises(httpx2.HTTPError):
            async with http.stream("GET", url) as r:
                assert r.status_code == 200
                async for chunk in r.aiter_raw():
                    got += len(chunk)
    assert 0 < got < len(BIG)


async def test_listener_binds_loopback_only_and_stops(box: Box):
    async with listener(box) as (dl, http):
        assert (await http.get(f"http://127.0.0.1:{dl.port}/x")).status_code == 404
        port = dl.port
    with pytest.raises(httpx2.TransportError):
        async with httpx2.AsyncClient() as http2:
            await http2.get(f"http://127.0.0.1:{port}/x")


async def test_port_in_use_disables_links_without_failing(box: Box):
    async with listener(box) as (first, _):
        config = box.config(port=first.port)
        dl = LocalDownloads(AccountRouter(config), config.downloads)
        assert not await dl.start()
        assert dl.attachment_url(box.ref("big"), "2") is None


async def test_tools_hand_out_working_links(box: Box):
    config = box.config()
    router = AccountRouter(config)
    dl = LocalDownloads(router, config.downloads)
    assert await dl.start()
    service = MailService(config, router=router, download_links=dl)
    try:
        async with Client(build_server(service)) as c:
            msg = await c.call_tool("get_message", {"id": box.ref("big").encode()})
            assert msg.structured_content is not None
            att = msg.structured_content["attachments"][0]
            assert att["download_url"].startswith(f"http://127.0.0.1:{dl.port}/a/")
            res = await c.call_tool(
                "get_attachment", {"id": box.ref("big").encode(), "attachment": att["part_id"]}
            )
            assert res.structured_content is not None
            assert res.structured_content["kind"] == "link"  # over max_attachment_bytes
            link = res.structured_content["download_url"]
            block = res.content[0]
            assert isinstance(block, TextContent) and link in block.text
        async with httpx2.AsyncClient(timeout=30) as http:
            r = await http.get(link)
        assert r.status_code == 200 and r.content == BIG
    finally:
        await dl.stop()
        await service.aclose()


@pytest.mark.parametrize("enabled", [True, False])
async def test_local_command_serves_links_over_stdio(box: Box, tmp_path: Path, enabled: bool):
    cfg = tmp_path / "c.toml"
    cfg.write_text(
        f"""
[downloads]
enabled = {str(enabled).lower()}
[limits]
max_attachment_bytes = 100000
[[accounts]]
name = "Work"
username = "{box.mb.user}"
password_env = "UEM_IT_PASSWORD"
tls_verify = false
[accounts.imap]
host = "{box.server.host}"
port = {box.server.imaps_port}
"""
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "universal_email_mcp", "local", "--config", str(cfg)],
        env=dict(os.environ),
    )
    async with Client(params) as c:
        r = await c.call_tool("get_attachment", {"id": box.ref("big").encode(), "attachment": "2"})
        if not enabled:
            assert r.is_error  # too large to return and no link to hand out
            return
        assert not r.is_error and r.structured_content is not None
        link = r.structured_content["download_url"]
        async with httpx2.AsyncClient(timeout=30) as http:
            got = await http.get(link)
        assert got.status_code == 200 and got.content == BIG
    with pytest.raises(httpx2.TransportError):  # the listener stops with the server
        async with httpx2.AsyncClient() as http:
            await http.get(link)


async def test_eml_download_is_the_whole_raw_message(box: Box, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(dl_service, "CHUNK_BYTES", 60_000)
    c = box.mb.admin()
    try:
        c.select_folder("INBOX", readonly=True)
        raw: bytes = c.fetch([box.uids["big"]], ["BODY.PEEK[]"])[box.uids["big"]][b"BODY[]"]  # pyright: ignore[reportAssignmentType]
    finally:
        c.logout()
    async with listener(box) as (dl, http):
        url = dl.message_url(box.ref("big"))
        assert url is not None and "/m/" in url
        r = await http.get(url)
        h = await http.head(url)
        # an attachment token is not accepted on the message route and vice versa
        wrong = url_for(dl, box.ref("big"), "2").replace("/a/", "/m/")
        assert (await http.get(wrong)).status_code == 404
    assert r.status_code == 200 and r.content == raw
    assert r.headers["content-length"] == str(len(raw)) == h.headers["content-length"]
    assert 'filename="message.eml"' in r.headers["content-disposition"]
    assert b"\\Seen" not in box.flags("big")


async def test_account_info_reports_download_status(box: Box):
    config = box.config()
    router = AccountRouter(config)
    dl = LocalDownloads(router, config.downloads)
    assert await dl.start()
    service = MailService(config, router=router, download_links=dl, download_status=dl.status())
    try:
        async with Client(build_server(service)) as c:
            r = await c.call_tool("account_info", {"overview": False})
            assert r.structured_content is not None
            status = r.structured_content["policy"]["download_links"]
            assert status.startswith(f"on (127.0.0.1:{dl.port}")
            block = r.content[0]
            assert isinstance(block, TextContent) and "download links: on" in block.text
            msg = await c.call_tool("get_message", {"id": box.ref("big").encode()})
            assert msg.structured_content is not None
            assert "/m/" in msg.structured_content["eml_url"]
    finally:
        await dl.stop()
        await service.aclose()
