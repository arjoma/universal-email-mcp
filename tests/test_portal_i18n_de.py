"""The German catalog: complete, consistent, and actually used by every page.

If ``test_german_catalog_is_complete`` fails after a UI change, add the listed ids to
``src/universal_email_mcp/portal/locales/de.json`` (formal "Sie", see docs/portal.md).
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import pytest

from tests.oauth_util import Authz, make_app, new_client, operator, register
from tests.portal_util import Browser, FakeTester
from universal_email_mcp.oauth.clients import ClientInfo
from universal_email_mcp.portal import i18n
from universal_email_mcp.portal.dynamic import DYNAMIC_MESSAGES, translate_dynamic
from universal_email_mcp.portal.i18n import Translator, extract_messages, load_catalogs

HOSTILE = '</script><script>alert("x")</script>'
PLACEHOLDER = re.compile(r"%\((\w+)\)s")
TAG = re.compile(r"</?\w+[^>]*>")


def german() -> dict[str, str]:
    return json.loads((i18n.LOCALE_DIR / "de.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------------ the catalog itself


def test_german_catalog_is_complete():
    de = german()
    ids = set(extract_messages())
    missing = sorted(ids - set(de))
    stale = sorted(set(de) - ids)
    assert not missing, (
        f"{len(missing)} message id(s) without a German translation - add them to "
        "portal/locales/de.json:\n" + "\n".join(f"  {m!r}" for m in missing)
    )
    assert not stale, (
        f"{len(stale)} catalog entr(ies) no longer used by any template - remove or rename "
        "them in portal/locales/de.json:\n" + "\n".join(f"  {m!r}" for m in stale)
    )
    assert all(isinstance(v, str) and v.strip() for v in de.values()), "empty translation"


def test_translations_keep_placeholders_and_markup():
    for msgid, text in german().items():
        assert sorted(PLACEHOLDER.findall(text)) == sorted(PLACEHOLDER.findall(msgid)), msgid
        assert sorted(TAG.findall(text)) == sorted(TAG.findall(msgid)), msgid
        if msgid == i18n.TIME_FORMAT:  # a strftime format, not a %-format
            datetime(2026, 10, 9, 14, 30).strftime(text)
            continue
        # must survive the %-formatting the template layer applies
        values = {name: "x" for name in PLACEHOLDER.findall(msgid)}
        _ = text % values


def test_plural_pairs_map_to_two_german_forms():
    cat = load_catalogs()["de"]
    assert cat.ngettext("%(n)s day", "%(n)s days", 1) == "%(n)s Tag"
    assert cat.ngettext("%(n)s day", "%(n)s days", 2) == "%(n)s Tage"
    assert cat.ngettext("%(n)s day", "%(n)s days", 0) == "%(n)s Tage"


def test_german_is_formal():
    # "du" forms would be a style break (the catalog speaks to the user as "Sie")
    informal = re.compile(r"\b(du|dein|deine|deinen|deinem|deiner|dir|dich)\b", re.I)
    assert not [m for m, t in german().items() if informal.search(t)]


def test_times_follow_the_language():
    de = Translator().env("de").from_string("{{ x|when }}").render(x="2026-10-09 14:30 UTC")
    en = Translator().env("en").from_string("{{ x|when }}").render(x="2026-10-09 14:30 UTC")
    assert de == "09.10.2026 14:30 UTC" and en == "2026-10-09 14:30 UTC"
    odd = Translator().env("de").from_string("{{ x|when }}").render(x="<b>soon</b>")
    assert odd == "&lt;b&gt;soon&lt;/b&gt;"  # unparseable text is left alone (and escaped)


# ------------------------------------------------------------------ server-generated text


def test_dynamic_sentences_are_translated_and_the_rest_left_alone():
    cat = load_catalogs()["de"]
    tr = lambda s: translate_dynamic(cat.gettext, s)  # noqa: E731
    assert tr("NEW - never written to") == "NEU - noch nie geschrieben"
    assert tr("the draft has no subject") == "Der Entwurf hat keinen Betreff"
    assert tr("copy into 'Sent' failed: quota exceeded") == (
        "Kopie in 'Sent' fehlgeschlagen: quota exceeded"
    )
    assert tr("... 12 more characters (3 lines) of the text NOT shown").startswith("... 12 weitere")
    # several lines: each is translated on its own
    two = tr("... 5 more characters of this part NOT shown\nsomething new")
    assert two.endswith("\nsomething new") and "NICHT" in two
    assert tr("something the pattern table does not know") == (
        "something the pattern table does not know"
    )


def test_every_text_the_send_service_produces_has_a_pattern():
    """The approval page shows these strings; they come from the service that also talks to
    the AI client in English, so the portal matches them - this keeps the two in step."""
    from universal_email_mcp.service import send

    out = SimpleNamespace(
        preview_cut=7, html_cut=0, has_text_body=True, remote_images=2, extra_parts=(), extra_more=3
    )
    cat = load_catalogs()["de"]
    produced = [
        send.preview_cut_note(out),  # type: ignore[arg-type]
        send.html_heading(out),  # type: ignore[arg-type]
        send.remote_images_warning(out),  # type: ignore[arg-type]
        send.extra_sections(out)[0][0],  # type: ignore[arg-type]
        *send.confirmation_reasons("confirm", []),
        *send.confirmation_reasons("confirm-external", [SimpleNamespace(klass="new")]),  # type: ignore[list-item]
        *send.confirmation_reasons("confirm", [SimpleNamespace(klass="lookalike")]),  # type: ignore[list-item]
        send.class_tag(SimpleNamespace(klass="internal", history_unknown=False)),  # type: ignore[arg-type]
        send.class_tag(SimpleNamespace(klass="known", history_unknown=False)),  # type: ignore[arg-type]
        send.class_tag(SimpleNamespace(klass="new", history_unknown=False)),  # type: ignore[arg-type]
        send.class_tag(SimpleNamespace(klass="new", history_unknown=True)),  # type: ignore[arg-type]
        send.class_tag(SimpleNamespace(klass="lookalike", history_unknown=False)),  # type: ignore[arg-type]
        send.text_excerpt("x " * 20000)[1],
    ]
    for text in produced:
        assert translate_dynamic(cat.gettext, text) != text, f"no pattern for: {text!r}"
    assert len(set(DYNAMIC_MESSAGES)) == len(DYNAMIC_MESSAGES)


# ------------------------------------------------------------------ every page, in German


def _client() -> ClientInfo:
    return ClientInfo("c", HOSTILE, ("http://127.0.0.1/cb",), "dcr")


def _result(kind: str = "imap", status: str = "ok") -> dict[str, Any]:
    return {"kind": kind, "outcome": {"status": status, "features": ["MOVE"]}}


def _account() -> dict[str, Any]:
    return {
        "id": "a1",
        "name": HOSTILE,
        "protocol": "imap",
        "host": "imap.example.org",
        "username": HOSTILE,
        "permissions": ["read", "organize", "delete", "drafts"],
    }


def _view() -> dict[str, Any]:
    return {
        "sender": "A <a@example.org>",
        "identity": "Main",
        "recipients": [
            {
                "field": f,
                "address": HOSTILE,
                "tag": "NEW - never written to",
                "flagged": True,
                "notes": ["could not check whether you have written to this address before"],
            }
            for f in ("to", "cc", "bcc")
        ],  # fmt: skip
        "has_bcc": True,
        "subject": HOSTILE,
        "attachments": ["a.pdf (1.0 KB)"],
        "more_attachments": 2,
        "text": ["Hello"],
        "text_note": "... 5 more characters (1 lines) of the text NOT shown",
        "has_text": True,
        "preview_note": "... 7 more characters beyond the first 9 NOT shown",
        "html": ["<b>x</b>"],
        "html_note": "... 3 more characters of the HTML version NOT shown",
        "html_heading": "HTML version (the message has no plain text part - recipients read this):",
        "extra_parts": [{"heading": "Additional text part 1 (x):", "lines": ["y"], "note": ""}],
        "images_warning": "! The HTML version loads 2 remote image(s): they can tell the "
        "sender when and where the mail is read (tracking).",
        "quoted": ["> q"],
        "quoted_note": "",
        "reasons": ["the policy asks for confirmation of every message"],
        "warnings": ["the draft has no subject"],
    }


def _activity() -> list[dict[str, Any]]:
    events = [
        ("auth.sign_in", ""), ("auth.consent", ""), ("portal.account_add", ""),
        ("tool.call", "find_messages"), ("tool.call", "mark_messages"), ("tool.call", "other"),
        ("send", ""), ("approval.approved", ""), ("viewer.open", ""), ("nothing.known", ""),
    ]  # fmt: skip
    return [
        {"when": "2026-10-09 14:30 UTC", "event": e, "tool": t, "client": HOSTILE,
         "account": HOSTILE, "counts": {"succeeded": 2}, "calls": 3, "failed": i % 2 == 0}
        for i, (e, t) in enumerate(events)
    ]  # fmt: skip


def _msg() -> dict[str, Any]:
    return {
        "id": "m1.x", "subject": HOSTILE, "account": HOSTILE, "date": "2026-10-09 14:30 UTC",
        "sender": [{"name": HOSTILE, "email": "a@example.org"}], "to": [], "cc": [],
        "reply_to": [], "has_html": True, "text": HOSTILE, "more": True, "notes": [
            "HTML part 1.2 is too long; only its beginning is shown"],
        "attachments": [{"name": HOSTILE, "inline": True, "type": "image/png", "size": "1.0 KB",
                         "section": "2"}],
    }  # fmt: skip


BASE: dict[str, Any] = {
    "csrf_token": "t", "signed_in": True, "section": "", "here": "/portal", "next": "/portal",
    "languages": [("en", "English"), ("de", "Deutsch")], "current_lang": "de",
    "notice": "account_added", "error": "", "address": HOSTILE, "hidden": {"a": HOSTILE},
    "client": _client(), "redirect_host": HOSTILE,
}  # fmt: skip

CONTEXTS: dict[str, dict[str, Any]] = {
    "account.html": {
        "account": _account(),
        "allowed": ["read", "organize", "delete", "drafts"],
        "results": [_result("smtp"), _result("pop3", "test_x"), _result("imap", "auth")],
        "error": "test_auth",
    },
    "account_new.html": {
        "values": {
            "name": HOSTILE,
            "server": "",
            "host": HOSTILE,
            "protocol": "imap",
            "username": HOSTILE,
            "perms": ["read"],
            "identity": True,
        },
        "fixed_server": "",
        "servers": [("k", HOSTILE)],
        "permissions": ["read", "organize", "delete", "drafts"],
        "error": "host",
    },  # fmt: skip
    "account_password.html": {"account": _account(), "error": "bad_credentials"},
    "account_remove.html": {"account": _account(), "clients": 2, "identities": 1},
    "accounts.html": {"accounts": [_account()]},
    "activity.html": {"days": 30, "rows": _activity()},
    "approval.html": {
        "approval": {
            "id": "a_1",
            "state": "pending",
            "client": HOSTILE,
            "created": "2026-10-09 14:30 UTC",
            "expires": "2026-10-09 15:30 UTC",
        },
        "problem": "",
        "view": _view(),
    },  # fmt: skip
    "approval_result.html": {
        "outcome": "failed",
        "code": "X",
        "detail": HOSTILE,
        "steps": ["the draft was removed", HOSTILE],
    },  # fmt: skip
    "approvals.html": {
        "approvals": [
            {
                "id": "a_1",
                "state": s,
                "client": HOSTILE,
                "created": "2026-10-09 14:30 UTC",
                "expires": "2026-10-09 15:30 UTC",
            }
            for s in ("pending", "expired", "rejected", "approved", "void")
        ],
    },  # fmt: skip
    "client.html": {
        "grant": {"id": "g1", "name": HOSTILE},
        "error": "keep_one",
        "rows": [{"id": "a1", "name": HOSTILE, "perms": ["read", "drafts"]}],
        "idents": [("i1", HOSTILE)],
    },  # fmt: skip
    "clients.html": {
        "grants": [
            {
                "id": "g1",
                "name": HOSTILE,
                "host": "",
                "registered": True,
                "created": "2026-10-09 14:30 UTC",
                "last_used": "",
                "expires": "",
                "accounts": [{"name": HOSTILE, "permissions": ["read", "delete"]}],
                "identities": [HOSTILE],
            }
        ],
    },  # fmt: skip
    "consent.html": {
        "error": "nothing",
        "rows": [
            {"id": "a1", "name": HOSTILE, "available": ["mail.read"], "checked": ["mail.read"]}
        ],
        "account_scopes": ["mail.read", "mail.delete"],
        "send_asked": True,
        "identities": [{"id": "i1", "label": HOSTILE, "checked": True}],
    },  # fmt: skip
    "consent_reauth.html": {"error": "bad_credentials", "carried": [("grant", HOSTILE)]},
    "error.html": {"reason": "notfound"},
    "headers.html": {"mid": "m1.x", "lines": [{"name": "X", "value": HOSTILE, "auth": True}]},
    "identities.html": {
        "identities": [
            {
                "id": "i1",
                "display_name": HOSTILE,
                "address": "a@example.org",
                "default": True,
                "smtp_account": HOSTILE,
                "smtp_host": "",
                "store_account": HOSTILE,
                "send": True,
            }
        ],
        "can_add": True,
    },  # fmt: skip
    "identity_form.html": {
        "identity_id": "i1",
        "results": [_result("smtp")],
        "error": "address",
        "values": {
            "address": HOSTILE,
            "display_name": HOSTILE,
            "signature": HOSTILE,
            "smtp_account": "",
            "store_account": "",
            "default": True,
            "send": True,
        },
        "smtp_choices": [("k", HOSTILE)],
        "store_choices": [("k", HOSTILE)],
        "send_possible": True,
    },  # fmt: skip
    "identity_remove.html": {"identity": {"id": "i1", "address": HOSTILE}},
    "message.html": {
        "msg": _msg(),
        "want_html": False,
        "eml_url": "/m/x.eml",
        "frame_url": "",
        "remote_images": 0,
        "images_loaded": False,
        "links": [],
        "html_failed": True,
    },  # fmt: skip
    "portal_signin.html": {"error": "rate_limited"},
    "privacy.html": {
        "counts": SimpleNamespace(accounts=1, identities=2, grants=3, activity=4, approvals=5),
        "retention": SimpleNamespace(
            access={"unit": "minute", "n": 15},
            refresh={"unit": "day", "n": 1},
            absolute={"unit": "day", "n": 90},
            activity={"unit": "day", "n": 30},
            approval={"unit": "hour", "n": 1},
            session_max={"unit": "hour", "n": 12},
            session_idle={"unit": "none", "n": 0},
        ),
    },  # fmt: skip
    "privacy_delete.html": {"error": "confirm"},
    "privacy_deleted.html": {},
    "reauth.html": {"error": "bad_credentials"},
    "signin.html": {"error": "bad_credentials"},
    "thread.html": {
        "mid": "m1.x",
        "partial": True,
        "notes": ["the message has no Message-ID; showing it alone"],
        "root_subject": HOSTILE,
        "items": [
            {
                "id": "m1",
                "date": "2026-10-09 14:30 UTC",
                "sender": [],
                "subject": HOSTILE,
                "current": True,
                "text": HOSTILE,
            }
        ],
    },  # fmt: skip
}
PARTIALS = {"_macros.html", "_client.html", "base.html", "portal_base.html"}


def test_every_page_template_has_a_rendering_context():
    pages = {p.name for p in i18n.TEMPLATE_DIR.glob("*.html")} - PARTIALS
    assert pages == set(CONTEXTS), (
        "add a representative context for new templates to CONTEXTS in this test "
        f"(missing: {sorted(pages - set(CONTEXTS))}, obsolete: {sorted(set(CONTEXTS) - pages)})"
    )


def _untranslated_english() -> list[str]:
    """Message ids (no placeholders, long enough to be unmistakable) whose German text differs."""
    de = german()
    return [m for m, t in de.items() if len(m) >= 14 and "%(" not in m and m != t]


@pytest.mark.parametrize("template", sorted(CONTEXTS))
def test_page_renders_in_german_without_english_leftovers(template: str):
    t = Translator()
    ctx = {**BASE, **CONTEXTS[template]}
    page = t.render(template, "de", **ctx)
    english = t.render(template, "en", **ctx)
    assert page != english and 'lang="de"' in page
    leftovers = [m for m in _untranslated_english() if m in page]
    assert not leftovers, f"{template} shows English text in German: {leftovers}"
    # hostile values stay escaped in both languages
    for text in (page, english):
        assert "<script>" not in text and "</script><script" not in text


def test_error_pages_and_notices_and_error_boxes_in_german():
    t = Translator()
    reasons = ("client", "redirect", "csrf", "notfound", "messagegone", "toolarge",
               "unavailable", "reauth", "ratelimited", "busy", "other")  # fmt: skip
    for reason in reasons:
        page = t.render("error.html", "de", **BASE, reason=reason)
        assert not [m for m in _untranslated_english() if m in page], reason
    # macros: every notice and error code renders (and none stays English)
    src = (i18n.TEMPLATE_DIR / "_macros.html").read_text(encoding="utf-8")
    notices = re.findall(r'code == "(\w+)"', src.split("macro error_box")[0])
    errors = re.findall(r'code == "(\w+)"', src.split("macro error_box")[1].split("endmacro")[0])
    assert len(notices) >= 10 and len(errors) >= 25
    env = t.env("de")
    for macro, codes in (("notice_box", notices), ("error_box", errors)):
        for code in codes:
            tpl = env.from_string(f'{{% import "_macros.html" as m %}}{{{{ m.{macro}(code) }}}}')
            out = tpl.render(code=code, csrf_token="")
            assert not [m for m in _untranslated_english() if m in out], (macro, code)
            assert re.search(r"[A-Za-zäöü]{3}", out)


# ------------------------------------------------------------------ choosing the language


async def test_language_selection_with_the_shipped_catalog():
    app = await make_app()
    with new_client(app) as c:
        a = Authz(c, register(c))
        assert "E-mail address" in a.open().text  # no signal: English
        c.cookies.set("uem_lang", "de")
        page = a.open()
        assert "E-Mail-Adresse" in page.text and page.headers["content-language"] == "de"
        c.cookies.delete("uem_lang")
        r = c.get("/authorize", params=a.params(), headers={"accept-language": "de-AT,de;q=0.9"})
        assert "E-Mail-Adresse" in r.text and 'lang="de"' in r.text
        r = c.get("/authorize", params=a.params(), headers={"accept-language": "fr,en;q=0.5"})
        assert "E-mail address" in r.text
        # the cookie beats the browser
        c.cookies.set("uem_lang", "en")
        r = c.get("/authorize", params=a.params(), headers={"accept-language": "de"})
        assert "E-mail address" in r.text


async def test_operator_default_language_de():
    op = operator()
    op = replace(op, oauth=replace(op.oauth, default_language="de"))
    with new_client(await make_app(op)) as c:
        assert "E-Mail-Adresse" in Authz(c, register(c)).open().text
        # an explicit browser preference for English still wins over the operator default
        a = Authz(c, register(c))
        r = c.get("/authorize", params=a.params(), headers={"accept-language": "en"})
        assert "E-mail address" in r.text


async def test_switcher_and_portal_pages_in_german():
    app = await make_app(tester=FakeTester())
    with Browser(app) as b:
        page = b.page("/portal/signin")
        assert 'name="lang"' in page and "Deutsch" in page and "Anmelden" not in page
        r = b.post("/portal/language", {"lang": "de", "next": "/portal/signin"})
        assert r.status_code == 303 and "uem_lang=de" in r.headers["set-cookie"]
        assert "Anmelden" in b.page("/portal/signin")
        b.signed_in()
        for path, expected in (
            ("/portal/accounts", "E-Mail-Konten"),
            ("/portal/identities", "Absenderidentitäten"),
            ("/portal/clients", "Verbundene Anwendungen"),
            ("/portal/approvals", "Offene Freigaben"),
            ("/portal/activity", "Aktivität"),
            ("/portal/privacy", "Datenschutz"),
        ):
            assert expected in b.page(path), path


async def test_hostile_account_name_is_escaped_in_german_pages():
    app = await make_app(tester=FakeTester())
    with Browser(app) as b:
        b.post("/portal/language", {"lang": "de"})
        b.signed_in()
        r = b.post(
            "/portal/accounts/new",
            {
                "name": "<b>x</b>",
                "server": "",
                "host": "imap.example.org",
                "protocol": "imap",
                "username": "u",
                "password": "pw",
                "perm": "read",
            },
        )
        page = b.page("/portal/accounts")
        assert "<b>x</b>" not in page and "E-Mail-Konten" in page, r.status_code
