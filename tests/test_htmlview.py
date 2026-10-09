"""The viewer's HTML sanitizer: allow-list, CSS filter, images, links, limits."""

from __future__ import annotations

import base64
import time
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

import pytest

from universal_email_mcp.mail.htmlview import (
    MAX_NESTING,
    TooComplex,
    build_html_view,
    clean_style,
    csp,
)
from universal_email_mcp.mail.mime import html_view_parts, normalize_cid

DATA = Path(__file__).parent / "data" / "sandbox"
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


def mail(html: str, *, images: dict[str, bytes] | None = None) -> bytes:
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg["Subject"] = "x"
    msg.set_content("plain")
    msg.add_alternative(html, subtype="html")
    for cid, data in (images or {}).items():
        part = msg.get_body(("html",))
        assert part is not None
        part.add_related(data, "image", "png", cid=f"<{cid}>")
    return msg.as_bytes(policy=SMTP)


def render(html: str, **kw: bool) -> str:
    view = build_html_view(mail(html), **kw)
    assert view.document is not None
    return view.document


def test_no_html_part_means_no_document():
    raw = b"From: a@b.c\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
    assert build_html_view(raw).document is None


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<a href='javascript:alert(1)'>x</a>",
        "<a href=' jav&#x09;ascript:alert(1)'>x</a>",
        "<a href='data:text/html,<script>alert(1)</script>'>x</a>",
        "<a href='vbscript:x'>x</a>",
        "<svg onload=alert(1)><script>1</script></svg>",
        "<math><mi xlink:href='javascript:alert(1)'>x</mi></math>",
        "<iframe src='https://evil.example'></iframe>",
        "<object data='https://evil.example'></object><embed src='https://evil.example'>",
        "<form action='https://evil.example'><input name=p><button>go</button></form>",
        "<base href='https://evil.example/'>",
        "<meta http-equiv='refresh' content='0;url=https://evil.example'>",
        "<link rel=stylesheet href='https://evil.example/x.css'>",
        "<style>@import url(https://evil.example/x.css); p{background:url(https://evil.example/a)}</style>",
        "<p style='background:url(https://evil.example/a)'>x</p>",
        "<p style='background-image:image-set(\"https://evil.example/a\" 1x)'>x</p>",
        "<p style='width:expression(alert(1))'>x</p>",
        "<p style='behavior:url(x.htc)'>x</p>",
        "<p style='color:r\\65 d;background:u\\72l(https://evil.example)'>x</p>",
        "<p style='position:fixed;top:0;left:0;width:100%;height:100%'>x</p>",
        "<table background='https://evil.example/a'><tr><td>x</td></tr></table>",
        "<img src='https://evil.example/a' srcset='https://evil.example/b 2x'>",
        "<video src=x onerror=alert(1)></video><audio src=x></audio>",
        "<!--[if gte mso 9]><script>alert(1)</script><![endif]-->",
        "<textarea><script>alert(1)</script></textarea>",
        "<noscript><p title='</noscript><script>alert(1)</script>'>x</p></noscript>",
        "<a href='//evil.example/x'>x</a>",
        "<a href='/relative'>x</a>",
    ],
)
def test_hostile_markup_is_removed(payload: str):
    doc = render(f"<html><body><p>keep</p>{payload}</body></html>").lower()
    body = doc.split("</style>", 1)[1]  # skip our own page style
    assert "keep" in body
    for bad in (
        "<script",
        "onerror",
        "onload",
        "javascript:",
        "vbscript:",
        "evil.example",
        "<iframe",
        "<object",
        "<embed",
        "<form",
        "<input",
        "<base",
        "<meta http",
        "<link",
        "<svg",
        "<math",
        "<video",
        "<audio",
        "url(",
        "image-set",
        "expression",
        "@import",
        "position",
        "srcset",
        "background=",
        "//evil",
        'href="/relative',
    ):
        assert bad not in body, (bad, body)
    assert "<style" not in body


def test_style_filter_keeps_presentation_only():
    assert clean_style("color: red; FONT-SIZE:12px") == "color:red;font-size:12px"
    assert clean_style("font-family:'Segoe UI', Arial") == "font-family:'Segoe UI', Arial"
    assert (
        clean_style("color:rgb(1,2,3);width:calc(100% - 4px)")
        == "color:rgb(1,2,3);width:calc(100% - 4px)"
    )
    assert clean_style("background:url(x)") is None
    assert clean_style("background:linear-gradient(red,blue)") is None
    assert clean_style("color:red;position:absolute;z-index:9") == "color:red"
    assert clean_style("content:'x';cursor:pointer") is None
    assert clean_style("color:red /* hi */") is None
    assert clean_style("color:\\72ed") is None
    assert clean_style("width:" + "9" * 300) is None
    assert clean_style("") is None


def test_images_cid_data_and_remote():
    html = (
        "<img src='cid:Logo%40Example.com'>"
        "<img src='cid:missing'>"
        "<img src='data:image/png;base64,AAAA'>"
        "<img src='data:image/svg+xml;base64,AAAA'>"
        "<img src='data:text/html;base64,AAAA'>"
        "<img src='https://tracker.example/p.gif'>"
        "<img src='http://tracker.example/q.gif'>"
    )
    raw = mail(html, images={"logo@example.com": PNG})
    blocked = build_html_view(raw)
    assert blocked.document is not None
    assert blocked.remote_images == 1 and not blocked.images_loaded
    assert "tracker.example" not in blocked.document
    assert blocked.document.count("data:image/png;base64,") == 2  # cid + the inline one
    assert "svg" not in blocked.document and "text/html" not in blocked.document
    assert "cid:" not in blocked.document
    allowed = build_html_view(raw, remote_images=True)
    assert allowed.document is not None and allowed.images_loaded
    assert "https://tracker.example/p.gif" in allowed.document
    assert "http://tracker.example" not in allowed.document  # never plain http


def test_links_open_in_a_new_tab_without_opener_and_are_listed():
    view = build_html_view(
        mail(
            "<a href='https://a.example/x?y=1&z=2'>one</a><a href='mailto:me@example.org'>m</a>"
            "<a href='https://a.example/x?y=1&z=2'>dup</a><a href='ftp://f.example/'>ftp</a>"
            "<a href='tel:+43123'>t</a><a href='javascript:x'>j</a>"
        )
    )
    assert view.document is not None
    assert view.links == ("https://a.example/x?y=1&z=2", "mailto:me@example.org", "tel:+43123")
    assert view.document.count('rel="noopener noreferrer"') == view.document.count("<a ")
    assert view.document.count('target="_blank"') == view.document.count("<a ")
    assert "ftp:" not in view.document


def test_invisible_and_bidi_characters_are_removed_from_the_html():
    doc = render("<p>pay‮ moc.example​</p>")
    assert "‮" not in doc and "​" not in doc


def test_deep_nesting_is_refused_fast():
    start = time.monotonic()
    with pytest.raises(TooComplex):
        build_html_view(mail("<div>" * (MAX_NESTING + 50) + "x"))
    assert time.monotonic() - start < 2
    # ordinary nesting and void-element runs are fine
    assert "x" in render("<div>" * 50 + "x" + "</div>" * 50)
    assert "x" in render("<br>" * 2000 + "x")


def test_csp_has_no_script_frame_or_remote_sources():
    base = csp(remote_images=False, ancestor="'self'")
    assert "default-src 'none'" in base and "img-src data:;" in base
    assert "script-src" not in base and "frame-src" not in base and "connect-src" not in base
    assert "form-action 'none'" in base and "base-uri 'none'" in base
    assert "sandbox allow-popups allow-popups-to-escape-sandbox" in base
    assert "allow-scripts" not in base and "allow-same-origin" not in base
    remote = csp(remote_images=True, ancestor="https://p.example")
    assert "img-src data: https:;" in remote and "frame-ancestors https://p.example" in remote


def test_corpus_hostile_mail_renders_without_active_content():
    raw = (DATA / "hostile-html.eml").read_bytes()
    view = build_html_view(raw)
    assert view.document is not None
    low = view.document.lower()
    assert "<script" not in low and "<form" not in low and "<base" not in low
    assert "attacker.test/frame" not in low and "http-equiv" not in low
    assert view.links == ("https://attacker.test/login",)


def test_html_view_parts_collect_html_and_raster_images_only():
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg.set_content("t")
    msg.add_alternative("<p>h</p>", subtype="html")
    related = msg.get_body(("html",))
    assert related is not None
    related.add_related(PNG, "image", "png", cid="<A@x>")
    related.add_related(b"<svg/>", "image", "svg+xml", cid="<s@x>")
    raw = msg.as_bytes(policy=SMTP)
    parts = html_view_parts(raw, max_image_bytes=1000, max_total_bytes=1000)
    assert parts.html[0].strip() == "<p>h</p>"
    assert list(parts.images) == ["a@x"]
    assert html_view_parts(raw, max_image_bytes=10, max_total_bytes=1000).images == {}
    assert normalize_cid("cid:%3CAbC@X%3E") == "abc@x"
