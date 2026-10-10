"""Viewer building blocks that need no mail server: content tokens, operator settings,
the signed-in redirect target and error pages."""

from __future__ import annotations

import pytest

from tests.oauth_util import operator
from universal_email_mcp.errors import ConfigError
from universal_email_mcp.operator import load_operator_config
from universal_email_mcp.portal.pages import safe_next


def test_safe_next_allows_the_viewer_but_nothing_foreign():
    assert safe_next("/m/m1.abc/thread") == "/m/m1.abc/thread"
    assert safe_next("/portal/accounts/a_1") == "/portal/accounts/a_1"
    assert safe_next("/m/" + "A" * 2100) == "/portal/accounts"
    for bad in ("//evil.example/m/x", "/mx", "https://evil.example/m/", "/m/\\evil", "/m/a\nb", ""):
        assert safe_next(bad) == "/portal/accounts"


ENV = {
    "STORE_BACKEND": "memory",
    "PUBLIC_URL": "https://mcp.example.com",
    "LOGIN_DOMAINS": "example.org=imap.example.org",
}


def test_content_origin_setting():
    op = load_operator_config({**ENV, "CONTENT_ORIGIN": "https://mcp-content.example.com"})
    assert op.content_origin == "https://mcp-content.example.com"
    assert op.allowed_hosts == ("mcp.example.com", "mcp-content.example.com")
    assert load_operator_config(ENV).content_origin is None
    for bad, why in (
        ("https://mcp.example.com", "different origin"),
        ("http://content.localhost", "http is only allowed"),
        ("https://x.example.com/path", "path"),
        ("not a url", "http"),
    ):
        with pytest.raises(ConfigError, match=why) as e:
            load_operator_config({**ENV, "CONTENT_ORIGIN": bad})
        assert "CONTENT_ORIGIN" in str(e.value)


def test_download_limit_setting():
    assert load_operator_config(ENV).max_download_bytes == 100 * 1024 * 1024
    assert (
        load_operator_config({**ENV, "UEM_MAX_DOWNLOAD_BYTES": "5000"}).max_download_bytes == 5000
    )
    with pytest.raises(ConfigError, match="UEM_MAX_DOWNLOAD_BYTES"):
        load_operator_config({**ENV, "UEM_MAX_DOWNLOAD_BYTES": "0"})


def test_test_operator_defaults():
    assert operator().content_origin is None
