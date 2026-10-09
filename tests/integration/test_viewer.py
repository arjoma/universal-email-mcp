"""The portal message viewer against a real Dovecot (WP 3g): ``/m/<id>`` and friends.

Users sign in through the real sign-in page (a real IMAP login against Dovecot creates the
"Main" account), mail is appended with a plain IMAP client, ids are built from what the server
reports. Nothing here sets a flag: viewing must leave ``\\Seen`` alone.
"""

from __future__ import annotations

import base64
import re
import uuid
from dataclasses import dataclass
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate
from pathlib import Path
from typing import Any, cast

import pytest
from starlette.applications import Starlette

from tests.oauth_util import ISSUER, operator
from tests.portal_util import Browser
from universal_email_mcp.config import Settings
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.mail.pop3 import Pop3Session
from universal_email_mcp.models import Endpoint, MessageRef, ServerProfile, TlsSettings
from universal_email_mcp.oauth.app import build_oauth_app
from universal_email_mcp.oauth.identity import ImapLoginVerifier, Pseudonyms
from universal_email_mcp.portal.connect import LiveTester
from universal_email_mcp.store import KeyRing, MailAccount, MemoryBackend, Store

from .conftest import ImapServer, Mailbox

pytestmark = pytest.mark.integration

DATA = Path(__file__).parent.parent / "data" / "sandbox"
# 1x1 transparent PNG
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)
BLOB = bytes(range(256)) * 2500  # 640 KB: several download chunks, every byte value
CONTENT_HOST = "content.test"


@dataclass
class Env:
    server: ImapServer
    store: Store
    app: Starlette
    tag: str

    def address(self, name: str) -> str:
        return f"{name}{self.tag}@example.org"

    def uid(self, address: str) -> str:
        return Pseudonyms(b"p" * 32).user_id(address)

    def mailbox(self, address: str) -> Mailbox:
        return Mailbox(self.server, address)

    def put(self, address: str, raw: bytes, flags: tuple[bytes, ...] = ()) -> MessageRef:
        """Append to INBOX; the reference as the viewer names it (account "Main")."""
        mb = self.mailbox(address)
        c = mb.admin()
        try:
            c.append("INBOX", raw, flags=flags)
        finally:
            c.logout()
        s = mb.session()
        try:
            res = s.search("INBOX")
            return MessageRef("Main", res.folder, res.uidvalidity, max(res.uids))
        finally:
            s.close()

    def seen(self, address: str, ref: MessageRef) -> bool:
        c = self.mailbox(address).admin()
        try:
            c.select_folder("INBOX", readonly=True)
            got = c.fetch([ref.uid], ["FLAGS"])
            return b"\\Seen" in cast(Any, got[ref.uid])[b"FLAGS"]
        finally:
            c.logout()

    def browser(self, address: str) -> Browser:
        b = Browser(self.app, address)
        assert b.sign_in(self.server.password).status_code == 303
        return b


def rich_message(tag: str) -> bytes:
    """text + HTML (cid image, remote image, link) + PDF-ish attachment + hostile name."""
    msg = EmailMessage()
    msg["From"] = "Anna Example <anna@example.com>"
    msg["To"] = f"Bob <bob{tag}@example.org>, carl@example.org"
    msg["Cc"] = "Dora <dora@example.net>"
    msg["Subject"] = f"Quarterly report {tag}"
    msg["Date"] = formatdate(1_790_000_000)
    msg["Message-ID"] = f"<rich-{tag}@example.com>"
    msg["Received"] = "from mx.example.com by mail.example.org with ESMTPS; Mon, 1 Jan 2026"
    msg["Authentication-Results"] = "mail.example.org; dkim=pass header.d=example.com; spf=pass"
    msg.set_content(f"Plain version of the report {tag}.\n")
    msg.add_alternative(
        "<html><body><h1>Report</h1><p style='color:red;background:url(https://t.example/x)'>"
        "Formatted <b>text</b> <a href='https://example.com/page'>a link</a></p>"
        "<img src='cid:logo@example.com' alt='logo'>"
        "<img src='https://tracker.example/pixel.gif' width=1 height=1></body></html>",
        subtype="html",
    )
    html_part = msg.get_body(("html",))
    assert html_part is not None
    html_part.add_related(PNG, "image", "png", cid="<logo@example.com>", disposition="inline")
    msg.add_attachment(
        BLOB, maintype="application", subtype="pdf", filename='report"; X-Injected=1.pdf'
    )
    msg.add_attachment(
        b"<script>alert(1)</script>",
        maintype="text",
        subtype="html",
        filename="page.html",
    )
    return msg.as_bytes(policy=SMTP)


@pytest.fixture
async def env(imap_server: ImapServer) -> Env:
    tag = uuid.uuid4().hex[:8]
    prof = ServerProfile(
        name="dovecot",
        label="Dovecot",
        imap=Endpoint(imap_server.host, imap_server.imaps_port, "tls"),
        pop3=Endpoint(imap_server.host, imap_server.pop3s_port, "tls"),
    )
    op = operator(
        mail_servers=(prof,),
        login_domains={"example.org": prof},
        settings=Settings(allow_private_networks=True),
        allowed_hosts=("mcp.test", CONTENT_HOST),
    )
    login = ImapLoginVerifier(
        NetPolicy(allow_private=True, connect_timeout=5, read_timeout=10), TlsSettings(verify=False)
    )
    store = Store(MemoryBackend(), KeyRing({"k1": b"k" * 32}))
    app = await build_oauth_app(
        op,
        store=store,
        login=login,
        tester=LiveTester(tls=TlsSettings(verify=False)),
        mail_tls=TlsSettings(verify=False),
    )
    return Env(imap_server, store, app, tag)


# ------------------------------------------------------------------------------- the page


async def test_message_page_shows_headers_text_attachments_and_leaves_seen_alone(env: Env):
    addr = env.address("alice")
    with env.browser(addr) as b:
        ref = env.put(addr, rich_message(env.tag))
        assert not env.seen(addr, ref)
        page = b.page(f"/m/{ref.encode()}")
        assert f"Quarterly report {env.tag}" in page
        assert "Anna Example" in page and "anna@example.com" in page
        assert "carl@example.org" in page and "dora@example.net" in page
        assert f"Plain version of the report {env.tag}" in page
        assert "Formatted" not in page  # the HTML version is opt-in
        assert "/m/" + ref.encode() + "/thread" in page
        assert "/m/" + ref.encode() + "/headers" in page
        assert "/m/" + ref.encode() + "/eml" in page
        assert re.search(r'/m/[^"]+/a/2"', page) or "/a/" in page
        assert "page.html" in page
        # no frame without view=html: the page CSP does not even allow one
        r = b.get(f"/m/{ref.encode()}")
        assert "frame-src" not in r.headers["content-security-policy"]
        assert r.headers["cache-control"] == "no-store"
        assert not env.seen(addr, ref)  # BODY.PEEK: nothing was marked as read


async def test_html_view_is_sandboxed_sanitised_and_images_need_a_click(env: Env):
    addr = env.address("alice")
    with env.browser(addr) as b:
        ref = env.put(addr, rich_message(env.tag))
        mid = ref.encode()
        page = b.get(f"/m/{mid}?view=html")
        assert page.status_code == 200
        iframe = re.search(r"<iframe[^>]*>", page.text)
        assert iframe is not None
        tag = iframe.group(0)
        assert 'sandbox="allow-popups allow-popups-to-escape-sandbox"' in tag
        assert "allow-scripts" not in tag and "allow-same-origin" not in tag
        assert f'src="/m/{mid}/html"' in tag
        assert "frame-src 'self'" in page.headers["content-security-policy"]
        assert "1 remote image is not loaded" in page.text
        assert f"/m/{mid}?view=html&amp;images=1" in page.text
        assert "hxxps[:]//example[.]com/page" in page.text  # the link list is defanged
        assert "https://example.com/page" not in page.text

        doc = b.get(f"/m/{mid}/html")
        assert doc.status_code == 200
        csp = doc.headers["content-security-policy"]
        assert "default-src 'none'" in csp and "img-src data:;" in csp
        assert "script-src" not in csp and "'unsafe-eval'" not in csp
        assert "sandbox allow-popups allow-popups-to-escape-sandbox" in csp
        assert "frame-ancestors 'self'" in csp
        assert doc.headers["x-content-type-options"] == "nosniff"
        assert doc.headers["referrer-policy"] == "no-referrer"
        body = doc.text
        assert "Formatted" in body and "<b>text</b>" in body
        assert 'rel="noopener noreferrer"' in body and 'target="_blank"' in body
        assert "data:image/png;base64," in body  # the cid image, served from the message
        assert "cid:" not in body
        assert "tracker.example" not in body and "url(" not in body  # blocked, no CSS fetch
        assert "color:red" in body  # harmless presentation stays

        # the explicit click: remote images allowed for this view only
        page2 = b.get(f"/m/{mid}?view=html&images=1")
        assert "Remote images are loaded" in page2.text
        assert f'src="/m/{mid}/html?images=1"' in page2.text
        doc2 = b.get(f"/m/{mid}/html?images=1")
        assert "img-src data: https:;" in doc2.headers["content-security-policy"]
        assert "https://tracker.example/pixel.gif" in doc2.text
        # ... and the next plain view blocks them again
        assert "img-src data:;" in b.get(f"/m/{mid}/html").headers["content-security-policy"]
        assert not env.seen(addr, ref)


async def test_hostile_html_from_the_corpus_is_neutralised(env: Env):
    addr = env.address("alice")
    with env.browser(addr) as b:
        raw = (DATA / "hostile-html.eml").read_bytes()
        ref = env.put(addr, raw)
        doc = b.get(f"/m/{ref.encode()}/html")
        assert doc.status_code == 200
        body = doc.text.lower()
        for bad in (
            "<script",
            "fetch(",
            "javascript:",
            "<base",
            "http-equiv",
            "<meta http",
            "<form",
            "<input",
            "<iframe",
            "onerror",
            "onclick",
            "<style>.x",
        ):
            assert bad not in body, bad
        # the lookalike link stays a plain link to its real target, new tab, no opener
        assert 'href="https://attacker.test/login"' in body
        assert 'rel="noopener noreferrer"' in body
        # the page around it names the sender's real target, not the text of the link
        page = b.page(f"/m/{ref.encode()}?view=html")
        assert "hxxps[:]//attacker[.]test/login" in page
        assert "<script" not in page.lower()


async def test_raw_headers_and_source(env: Env):
    addr = env.address("alice")
    with env.browser(addr) as b:
        raw = rich_message(env.tag)
        ref = env.put(addr, raw)
        mid = ref.encode()
        page = b.page(f"/m/{mid}/headers")
        assert "Received" in page and re.search(r"from mx\.example\.com\s+by mail", page)
        assert "Authentication-Results" in page and "dkim=pass" in page
        assert "Message-ID" in page
        eml = b.get(f"/m/{mid}/eml")
        assert eml.status_code == 200
        assert eml.content == raw
        assert eml.headers["content-type"] == "message/rfc822"
        assert eml.headers["content-disposition"].startswith("attachment;")
        assert eml.headers["x-content-type-options"] == "nosniff"
        assert "sandbox" in eml.headers["content-security-policy"]
        assert not env.seen(addr, ref)


async def test_attachment_download_streams_exact_bytes_with_safe_headers(env: Env):
    addr = env.address("alice")
    with env.browser(addr) as b:
        ref = env.put(addr, rich_message(env.tag))
        mid = ref.encode()
        page = b.page(f"/m/{mid}")
        sections = re.findall(rf"/m/{re.escape(mid)}/a/([0-9.]+)", page)
        assert len(sections) >= 2
        got: dict[str, tuple[bytes, dict[str, str]]] = {}
        for sec in dict.fromkeys(sections):
            r = b.get(f"/m/{mid}/a/{sec}")
            assert r.status_code == 200, sec
            got[sec] = (r.content, dict(r.headers))
        pdf = next(v for v in got.values() if v[0] == BLOB)
        headers = pdf[1]
        assert headers["content-type"] == "application/pdf"
        assert headers.get("content-length") in (None, str(len(BLOB)))  # base64: not known
        disp = headers["content-disposition"]
        assert disp.startswith("attachment;") and "\r" not in disp and "\n" not in disp
        assert "X-Injected" not in headers and 'report"' not in disp.split(";")[1]
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["content-security-policy"].startswith("sandbox;")
        assert headers["cache-control"] == "no-store"
        # an HTML attachment is never served as HTML
        html = next(v for v in got.values() if v[0] == b"<script>alert(1)</script>")
        assert html[1]["content-type"] == "application/octet-stream"
        assert html[1]["content-disposition"].startswith("attachment;")
        # the inline cid image is a part too, with a passive raster type
        assert not env.seen(addr, ref)
        # unknown or malformed sections
        assert b.get(f"/m/{mid}/a/99").status_code == 404
        assert b.get(f"/m/{mid}/a/1.MIME").status_code == 404
        assert b.get(f"/m/{mid}/a/..%2f..").status_code == 404


async def test_hostile_file_names_never_reach_a_header_raw(env: Env):
    addr = env.address("alice")
    with env.browser(addr) as b:
        ref = env.put(addr, (DATA / "attachment-names.eml").read_bytes())
        mid = ref.encode()
        page = b.page(f"/m/{mid}")
        for sec in dict.fromkeys(re.findall(rf"/m/{re.escape(mid)}/a/([0-9.]+)", page)):
            r = b.get(f"/m/{mid}/a/{sec}")
            assert r.status_code == 200
            disp = r.headers["content-disposition"]
            assert (
                "\r" not in disp
                and "\n" not in disp
                and "/" not in disp.split("filename=")[1].split(";")[0]
            )
            assert r.headers["content-type"] in ("application/octet-stream", "application/pdf")


async def test_thread_page(env: Env):
    addr = env.address("alice")
    with env.browser(addr) as b:
        first = EmailMessage()
        first["From"] = "Anna <anna@example.com>"
        first["To"] = addr
        first["Subject"] = f"Plan {env.tag}"
        first["Message-ID"] = f"<t1-{env.tag}@example.com>"
        first["Date"] = formatdate(1_790_000_000)
        first.set_content("First message of the conversation.\n")
        reply = EmailMessage()
        reply["From"] = f"Alice <{addr}>"
        reply["To"] = "anna@example.com"
        reply["Subject"] = f"Re: Plan {env.tag}"
        reply["Message-ID"] = f"<t2-{env.tag}@example.com>"
        reply["In-Reply-To"] = f"<t1-{env.tag}@example.com>"
        reply["References"] = f"<t1-{env.tag}@example.com>"
        reply["Date"] = formatdate(1_790_000_500)
        reply.set_content("The reply with more details.\n")
        ref1 = env.put(addr, first.as_bytes())
        env.put(addr, reply.as_bytes())
        page = b.page(f"/m/{ref1.encode()}/thread")
        assert "First message of the conversation." in page
        assert "The reply with more details." in page
        assert page.count("<details") == 2
        assert not env.seen(addr, ref1)


# ------------------------------------------------------------------------------- access


async def test_signed_out_is_sent_to_sign_in_and_back(env: Env):
    addr = env.address("alice")
    ref = env.put(addr, rich_message(env.tag))
    # nothing signed in yet: build the account by signing in, then look as a stranger
    env.browser(addr).client.close()
    mid = ref.encode()
    with Browser(env.app, addr) as b:
        for path in (
            f"/m/{mid}",
            f"/m/{mid}/thread",
            f"/m/{mid}/headers",
            f"/m/{mid}/eml",
            f"/m/{mid}/a/2",
        ):
            r = b.get(path)
            assert r.status_code == 303, path
            assert r.headers["location"].startswith("/portal/signin?next=")
        # the iframe document answers a plain 404 (no redirect inside a frame)
        assert b.get(f"/m/{mid}/html").status_code == 404
        # sign in with the target: back to the message
        r = b.sign_in(env.server.password, next_=f"/m/{mid}")
        assert r.status_code == 303 and r.headers["location"] == f"/m/{mid}"
        assert f"Quarterly report {env.tag}" in b.page(f"/m/{mid}")


async def test_another_users_message_id_is_a_404_everywhere(env: Env):
    alice, mallory = env.address("alice"), env.address("mallory")
    ref = env.put(alice, rich_message(env.tag))
    secret = f"Quarterly report {env.tag}"
    with env.browser(alice) as a, env.browser(mallory) as m:
        assert secret in a.page(f"/m/{ref.encode()}")
        # a forged id: mallory also has an account called "Main" (her own mailbox), so
        # the id resolves inside *her* context - never to alice's mail
        env.put(mallory, b"From: x@example.com\r\nSubject: Mallory note\r\n\r\nhers\r\n")
        mid = ref.encode()
        for path in (
            f"/m/{mid}",
            f"/m/{mid}?view=html",
            f"/m/{mid}/html",
            f"/m/{mid}/thread",
            f"/m/{mid}/headers",
            f"/m/{mid}/eml",
            f"/m/{mid}/a/2",
            f"/m/{mid}/a/3",
        ):
            r = m.get(path)
            # normally a 404 (UIDVALIDITY differs); if two mailboxes happen to share it the id
            # resolves to mallory's *own* mail - never to alice's
            assert r.status_code in (200, 404, 410), (path, r.status_code)
            assert secret not in r.text and r.content != BLOB
        # an id naming an account mallory does not have
        other = MessageRef("Alices Private", "INBOX", ref.uidvalidity, ref.uid).encode()
        for path in (f"/m/{other}", f"/m/{other}/eml", f"/m/{other}/a/2"):
            r = m.get(path)
            assert r.status_code == 404 and secret not in r.text
        # garbage
        assert m.get("/m/not-an-id").status_code == 404
        assert m.get("/m/m1.%00%00").status_code == 404
        assert m.get("/m/" + "A" * 5000).status_code == 404


async def test_an_account_without_read_is_not_viewable(env: Env):
    addr = env.address("alice")
    with env.browser(addr) as b:
        ref = env.put(addr, rich_message(env.tag))
        assert b.get(f"/m/{ref.encode()}").status_code == 200
        (main,) = await env.store.list_for_user(MailAccount, env.uid(addr))
        from dataclasses import replace

        await env.store.update(replace(main, permissions=("organize",)))
        r = b.get(f"/m/{ref.encode()}")
        assert r.status_code == 404
        await env.store.update(
            replace(await env.store.get(MailAccount, main.id) or main, permissions=("read",))
        )
        assert b.get(f"/m/{ref.encode()}").status_code == 200


async def test_removing_the_account_ends_access(env: Env):
    addr = env.address("alice")
    with env.browser(addr) as b:
        ref = env.put(addr, rich_message(env.tag))
        (main,) = await env.store.list_for_user(MailAccount, env.uid(addr))
        assert b.get(f"/m/{ref.encode()}/eml").status_code == 200
        await env.store.delete(MailAccount, main.id)
        assert b.get(f"/m/{ref.encode()}/eml").status_code == 404


# ------------------------------------------------------------------------------- content origin


async def test_content_origin_serves_the_html_from_another_host(imap_server: ImapServer):
    tag = uuid.uuid4().hex[:8]
    prof = ServerProfile(
        name="dovecot",
        label="Dovecot",
        imap=Endpoint(imap_server.host, imap_server.imaps_port, "tls"),
    )
    op = operator(
        mail_servers=(prof,),
        login_domains={"example.org": prof},
        settings=Settings(allow_private_networks=True),
        allowed_hosts=("mcp.test", CONTENT_HOST),
        content_origin=f"https://{CONTENT_HOST}",
    )
    login = ImapLoginVerifier(
        NetPolicy(allow_private=True, connect_timeout=5, read_timeout=10), TlsSettings(verify=False)
    )
    store = Store(MemoryBackend(), KeyRing({"k1": b"k" * 32}))
    app = await build_oauth_app(
        op,
        store=store,
        login=login,
        tester=LiveTester(tls=TlsSettings(verify=False)),
        mail_tls=TlsSettings(verify=False),
    )
    env = Env(imap_server, store, app, tag)
    addr = env.address("alice")
    with env.browser(addr) as b:
        ref = env.put(addr, rich_message(tag))
        mid = ref.encode()
        page = b.get(f"/m/{mid}?view=html")
        src = re.search(r'<iframe[^>]* src="([^"]+)"', page.text)
        assert src is not None
        url = src.group(1)
        assert url.startswith(f"https://{CONTENT_HOST}/c/")
        assert f"frame-src https://{CONTENT_HOST}" in page.headers["content-security-policy"]
        # the same-origin route is closed when a content origin exists
        assert b.get(f"/m/{mid}/html").status_code == 404
        token_path = url.removeprefix(f"https://{CONTENT_HOST}")
        # no cookie needed (and none is sent: other host)
        with Browser(app, addr) as stranger:
            r = stranger.get(token_path, headers={"host": CONTENT_HOST})
            assert r.status_code == 200
            assert "Formatted" in r.text
            csp = r.headers["content-security-policy"]
            assert f"frame-ancestors {ISSUER}" in csp
            # wrong host, tampered or foreign token
            assert stranger.get(token_path).status_code == 404
            assert stranger.get(token_path + "x", headers={"host": CONTENT_HOST}).status_code == 404
            assert stranger.get("/c/abc.def", headers={"host": CONTENT_HOST}).status_code == 404


# ------------------------------------------------------------------------------- POP3


async def test_pop3_accounts_can_be_viewed_too(env: Env):
    addr = env.address("alice")
    with env.browser(addr) as b:
        env.put(addr, rich_message(env.tag))
        r = b.post(
            "/portal/accounts/new",
            {"name": "Pop", "protocol": "pop3", "username": addr, "password": env.server.password},
        )
        assert r.status_code == 303
        s = Pop3Session.connect(
            Endpoint(env.server.host, env.server.pop3s_port, "tls"),
            addr,
            env.server.password,
            account_name="Pop",
            net=NetPolicy(allow_private=True, connect_timeout=10, read_timeout=30),
            tls=TlsSettings(verify=False),
        )
        try:
            res = s.search("INBOX")
            (summary,) = s.fetch_summaries("INBOX", list(res.uids[:1]))
        finally:
            s.close()
        mid = summary.ref.encode()
        assert f"Quarterly report {env.tag}" in b.page(f"/m/{mid}")
        assert "Authentication-Results" in b.page(f"/m/{mid}/headers")
        eml = b.get(f"/m/{mid}/eml")
        assert eml.status_code == 200 and eml.content.startswith(b"From:")
        doc = b.get(f"/m/{mid}/html")
        assert doc.status_code == 200 and "Formatted" in doc.text
        att = b.get(f"/m/{mid}/a/3")
        assert att.status_code == 200
        assert att.content in (BLOB, b"<script>alert(1)</script>", PNG)


async def test_raw_headers_label_forged_authentication_and_survive_8bit(env: Env):
    # security review L7: only auth lines above the first Received are the own server's;
    # raw 8-bit header bytes must not make the page unavailable
    addr = env.address("hdr")
    raw = (
        b"Authentication-Results: mail.example.org; dkim=pass header.d=own.example\r\n"
        b"Received: from relay.example by mail.example.org; Mon, 1 Jan 2026\r\n"
        b"Authentication-Results: forged.example; dkim=pass header.d=bank.example\r\n"
        b"X-Spam-Status: No, score=-99\r\n"
        b"From: x@example.com\r\nTo: y@example.org\r\nSubject: Gr\xfc\xdfe\r\n"
        b"X-Mailer: \xe4\r\nMessage-ID: <hdr@example.com>\r\n\r\nbody\r\n"
    )
    with env.browser(addr) as b:
        ref = env.put(addr, raw)
        r = b.get(f"/m/{ref.encode()}/headers")
        assert r.status_code == 200
        page = r.text
        auth_section = page.split("All headers")[0]
        assert "own.example" in auth_section
        assert "bank.example" not in auth_section and "score=-99" not in auth_section
        assert page.count("from the sender, not checked") == 2
        assert "Gr\u00fc\u00dfe" in page
