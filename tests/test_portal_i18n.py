"""The translation layer of the end-user UI."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.oauth_util import Authz, make_app, new_client, operator, register
from universal_email_mcp.portal import i18n
from universal_email_mcp.portal.i18n import (
    Catalog,
    Translator,
    extract_messages,
    load_catalogs,
    parse_accept_language,
    resolve_locale,
)

GERMAN = {"Sign in": "Anmelden", "E-mail address": "E-Mail-Adresse", "Password": "Passwort"}


def test_english_is_the_identity_and_needs_no_catalog():
    cats = load_catalogs(Path("/nonexistent"))
    assert set(cats) == {"en"} and cats["en"].gettext("Sign in") == "Sign in"
    assert Catalog(GERMAN).gettext("not translated") == "not translated"


def test_catalogs_are_json_files_named_by_language(tmp_path: Path):
    (tmp_path / "de.json").write_text(json.dumps(GERMAN))
    (tmp_path / "pt-BR.json").write_text("{}")
    (tmp_path / "../bad name.json".replace("../", "")).write_text("{}")
    (tmp_path / "x.txt").write_text("")
    cats = load_catalogs(tmp_path)
    assert set(cats) == {"en", "de", "pt-br"}
    assert cats["de"].gettext("Sign in") == "Anmelden"


def test_accept_language_parsing():
    assert parse_accept_language("de-AT,de;q=0.9,en;q=0.8") == ["de-at", "de", "en"]
    assert parse_accept_language("en;q=0.5, de;q=0.9, *;q=0.1, xx_bad;q=1, fr;q=0") == ["de", "en"]
    assert parse_accept_language("") == []
    assert parse_accept_language("a" * 5000) == []


def test_locale_resolution_order():
    have = ["en", "de"]
    assert resolve_locale(have, cookie="de", accept_language="en") == "de"
    assert resolve_locale(have, cookie="fr", accept_language="de-AT") == "de"  # falls through
    assert resolve_locale(have, accept_language="fr, de;q=0.5", default="en") == "de"
    assert resolve_locale(have, default="de") == "de"  # operator default
    assert resolve_locale(have, default="fr") == "en"  # unknown default
    assert resolve_locale(have, cookie="../../etc") == "en"


def test_translator_renders_with_the_catalog():
    t = Translator({"en": Catalog(), "de": Catalog(GERMAN)})
    de = t.render("signin.html", "de", client=_client(), redirect_host="h", hidden={},
                  csrf_token="t", error="", address="")  # fmt: skip
    en = t.render("signin.html", "en", client=_client(), redirect_host="h", hidden={},
                  csrf_token="t", error="", address="")  # fmt: skip
    assert "Anmelden" in de and "E-Mail-Adresse" in de and 'lang="de"' in de
    assert "Sign in" in en and "E-mail address" in en and "Anmelden" not in en
    assert "Anmelden" not in t.render("signin.html", "xx", client=_client(), redirect_host="h",
                                      hidden={}, csrf_token="t", error="", address="")  # fmt: skip


def _client():
    from universal_email_mcp.oauth.clients import ClientInfo

    return ClientInfo("c", "Name", ("http://127.0.0.1/cb",), "dcr")


def test_templates_have_no_literal_visible_text():
    """Every visible string is behind ``_()`` / ``{% trans %}``; nothing is hard-coded."""
    offenders: list[str] = []
    for path in sorted(i18n.TEMPLATE_DIR.glob("*.html")):
        src = path.read_text(encoding="utf-8")
        src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
        src = re.sub(r"\{%\s*trans\b.*?\{%\s*endtrans\s*%\}", "", src, flags=re.S)
        src = re.sub(r"\{%.*?%\}", "", src, flags=re.S)
        src = re.sub(r"\{\{.*?\}\}", "", src, flags=re.S)
        src = re.sub(r"<(script|style)\b.*?</\1>", "", src, flags=re.S)
        src = re.sub(r"<[^>]*>", "", src, flags=re.S)
        if re.search(r"[^\W\d_]", src):  # letters; bare punctuation such as ' - ' is fine
            offenders.append(f"{path.name}: {src.strip()[:60]!r}")
    assert not offenders, offenders


def test_attributes_are_translated_too():
    # aria-label / title / placeholder texts must go through _() as well
    for path in i18n.TEMPLATE_DIR.glob("*.html"):
        src = path.read_text(encoding="utf-8")
        for m in re.finditer(r'\b(?:aria-label|title|placeholder|alt)="([^"]*)"', src):
            assert "{{" in m.group(1), (path.name, m.group(1))


def test_message_extraction_lists_the_worklist():
    messages = extract_messages()
    for expected in ("Sign in", "E-mail address", "Allow", "Deny", "Read mail",
                     "Select at least one permission, or choose Deny."):  # fmt: skip
        assert expected in messages
    assert messages == sorted(set(messages))


@pytest.fixture
async def app():
    return await make_app()


async def test_web_pages_use_cookie_then_browser_then_operator_language(app):
    svc = app.state.oauth_service
    svc.portal.translator.catalogs["de"] = Catalog(GERMAN)
    with new_client(app) as c:
        a = Authz(c, register(c))
        assert "E-mail address" in a.open().text
        c.cookies.set("uem_lang", "de")
        page = a.open()
        assert "E-Mail-Adresse" in page.text and page.headers["content-language"] == "de"
        c.cookies.delete("uem_lang")
        assert "Passwort" in c.get("/authorize", params=a.params(),
                                   headers={"accept-language": "de-AT,de;q=0.9"}).text  # fmt: skip
        assert "Password" in c.get("/authorize", params=a.params(),
                                   headers={"accept-language": "fr"}).text  # fmt: skip


async def test_operator_default_language():
    from dataclasses import replace

    op = operator()
    op = replace(op, oauth=replace(op.oauth, default_language="de"))
    app = await make_app(op)
    app.state.oauth_service.portal.translator.catalogs["de"] = Catalog(GERMAN)
    with new_client(app) as c:
        assert "Anmelden" in Authz(c, register(c)).open().text
        # a language without a catalog falls back to English
    op2 = replace(op, oauth=replace(op.oauth, default_language="fr"))
    with new_client(await make_app(op2)) as c:
        assert "E-mail address" in Authz(c, register(c)).open().text
