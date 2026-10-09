"""Operator environment parsing: defaults, overlay on the TOML config, clear errors."""

from __future__ import annotations

import pytest

from universal_email_mcp.config import Limits, parse_config
from universal_email_mcp.errors import ConfigError
from universal_email_mcp.operator import OperatorConfig, load_operator_config

TOKEN = "t" * 40
BASE = {"UEM_DEV_TOKEN": TOKEN, "PUBLIC_URL": "https://mcp.example.com"}


def load(extra: dict[str, str] | None = None, **kw: object) -> OperatorConfig:
    return load_operator_config({**BASE, **(extra or {})}, **kw)  # pyright: ignore[reportArgumentType]


def test_defaults_and_derived_hosts():
    op = load()
    assert (op.host, op.port) == ("0.0.0.0", 8080)
    assert op.allowed_hosts == ("mcp.example.com",)
    assert op.allowed_origins == ("https://mcp.example.com",)
    assert op.hsts and not op.settings.allow_private_networks
    assert TOKEN not in repr(op)


def test_port_from_env_and_flag():
    assert load({"PORT": "9000"}).port == 9000
    assert load({"PORT": "9000"}, port=1234).port == 1234
    with pytest.raises(ConfigError, match="PORT"):
        load({"PORT": "abc"})
    with pytest.raises(ConfigError, match="out of range"):
        load(port=70000)


def test_token_required_unless_insecure_local():
    with pytest.raises(ConfigError, match="STORE_BACKEND") as e:
        load_operator_config({"PUBLIC_URL": "https://mcp.example.com"})
    assert "--insecure-local" in e.value.hint
    op = load_operator_config({}, insecure_local=True)
    assert op.dev_token is None and op.host == "127.0.0.1"
    assert "[::1]" in op.allowed_hosts


def test_insecure_local_refuses_public_bind():
    with pytest.raises(ConfigError, match="loopback"):
        load_operator_config({}, insecure_local=True, host="0.0.0.0")


def test_short_token_rejected():
    with pytest.raises(ConfigError, match="too short"):
        load_operator_config({**BASE, "UEM_DEV_TOKEN": "short"})


@pytest.mark.parametrize(
    "extra, match",
    [
        ({"PUBLIC_URL": "mcp.example.com"}, "PUBLIC_URL"),
        ({"PUBLIC_URL": "http://mcp.example.com"}, "http is only allowed"),
        ({"PUBLIC_URL": "https://mcp.example.com/path"}, "path"),
        ({"PUBLIC_URL": "https://u:p@mcp.example.com"}, "credentials"),
        ({"ALLOWED_HOSTS": "https://x.example.com"}, "ALLOWED_HOSTS"),
        ({"ALLOWED_HOSTS": "x.example.com:8080"}, "port"),
        ({"ALLOWED_ORIGINS": "ftp://x"}, "ALLOWED_ORIGINS"),
        ({"UEM_LOG_LEVEL": "LOUD"}, "UEM_LOG_LEVEL"),
        ({"UEM_SEND_POLICY": "always"}, "UEM_SEND_POLICY"),
        ({"UEM_MAX_RESULTS": "-3"}, "positive"),
        ({"UEM_MAX_RESULTS": "1.5"}, "UEM_MAX_RESULTS"),
        ({"UEM_ACCOUNT_TIMEOUT": "nan"}, "positive"),
        ({"UEM_READ_ONLY": "maybe"}, "true/false"),
        ({"MAIL_SERVERS": "bad host name"}, "MAIL_SERVERS"),
        ({"LOGIN_DOMAINS": "example.com"}, "LOGIN_DOMAINS"),
    ],
)
def test_invalid_values_name_the_variable(extra: dict[str, str], match: str):
    with pytest.raises(ConfigError, match=match):
        load(extra)


def test_hosts_required():
    with pytest.raises(ConfigError, match="PUBLIC_URL"):
        load_operator_config({"UEM_DEV_TOKEN": TOKEN})
    op = load_operator_config(
        {"UEM_DEV_TOKEN": TOKEN, "ALLOWED_HOSTS": "A.example.com, b.example.com"}
    )
    assert op.allowed_hosts == ("a.example.com", "b.example.com")


def test_servers_and_domains():
    op = load({"MAIL_SERVERS": "united-domains", "LOGIN_DOMAINS": "company.example"})
    assert [s.name for s in op.mail_servers] == ["united-domains"]
    assert set(op.login_domains) == {"company.example"}


def test_limits_and_policy_overlay_the_base_config():
    base = parse_config({"limits": {"max_results": 7, "max_body_chars": 999}})
    op = load(
        {
            "UEM_MAX_RESULTS": "20",
            "UEM_SEND_POLICY": "draft",
            "UEM_READ_ONLY": "true",
            "UEM_INTERNAL_DOMAINS": "Company.Example",
            "UEM_ALLOW_PRIVATE_NETWORKS": "1",
            "UEM_MAX_REQUEST_BYTES": "1000",
        },
        base=base,
    )
    assert op.limits.max_results == 20 and op.limits.max_body_chars == 999
    assert op.policy.send == "draft" and op.policy.read_only
    assert op.policy.internal_domains == ("company.example",)
    assert op.settings.allow_private_networks and op.max_request_bytes == 1000
    assert load().limits == Limits()


# ---------------------------------------------------------------- OAuth mode

OAUTH = {
    "PUBLIC_URL": "https://mcp.example.com",
    "STORE_BACKEND": "memory",
    "LOGIN_DOMAINS": "example.org=imap.example.org",
}
KEY = "A" * 43 + "="  # 32 bytes of base64


def oauth(extra: dict[str, str] | None = None) -> OperatorConfig:
    return load_operator_config({**OAUTH, **(extra or {})})


def test_oauth_mode_defaults():
    op = oauth()
    assert op.oauth_mode and op.dev_token is None and op.store is not None
    assert op.store.backend == "memory" and op.store.ephemeral_keys
    assert len(op.pseudonym_key) == 32
    assert op.oauth.access_ttl.total_seconds() == 3600
    assert op.oauth.refresh_ttl.days == 30 and op.oauth.absolute_max.days == 90
    assert op.oauth.dcr_enabled and op.oauth.trusted_proxy_hops == 0
    assert not load().oauth_mode  # dev mode has no store


def test_oauth_mode_needs_url_and_login_domains():
    with pytest.raises(ConfigError, match="LOGIN_DOMAINS"):
        load_operator_config({k: v for k, v in OAUTH.items() if k != "LOGIN_DOMAINS"})
    with pytest.raises(ConfigError, match="PUBLIC_URL"):
        load_operator_config(
            {
                "STORE_BACKEND": "memory",
                "ALLOWED_HOSTS": "x.example",
                "LOGIN_DOMAINS": OAUTH["LOGIN_DOMAINS"],
            }
        )


def test_oauth_and_dev_mode_are_exclusive():
    with pytest.raises(ConfigError, match="STORE_BACKEND"):
        load_operator_config({**OAUTH, "UEM_DEV_TOKEN": TOKEN})
    with pytest.raises(ConfigError, match="STORE_BACKEND"):
        load_operator_config(OAUTH, insecure_local=True)


def test_store_backend_and_keys():
    with pytest.raises(ConfigError, match="STORE_BACKEND"):
        oauth({"STORE_BACKEND": "sqlite"})
    with pytest.raises(ConfigError, match="STORE_KEYS"):
        oauth({"STORE_BACKEND": "firestore", "PSEUDONYM_KEY": KEY})
    with pytest.raises(ConfigError, match="PSEUDONYM_KEY"):
        oauth({"STORE_BACKEND": "firestore", "STORE_KEYS": f"k1={KEY}"})
    op = oauth(
        {
            "STORE_BACKEND": "firestore",
            "STORE_KEYS": f"k1={KEY},k2={KEY}",
            "STORE_ACTIVE_KEY": "k1",
            "PSEUDONYM_KEY": KEY,
            "FIRESTORE_PROJECT": "proj",
            "FIRESTORE_PREFIX": "uem1_",
        }
    )
    assert op.store is not None and not op.store.ephemeral_keys
    assert (op.store.firestore_project, op.store.prefix) == ("proj", "uem1_")
    assert op.store.keys.active == "k1"
    assert KEY not in repr(op) and "A" * 40 not in repr(op.store)


def test_secrets_from_files(tmp_path):
    f = tmp_path / "pseudo"
    f.write_text(KEY + "\n")
    assert oauth({"PSEUDONYM_KEY_FILE": str(f)}).pseudonym_key == b"\x00" * 32
    with pytest.raises(ConfigError, match="only one"):
        oauth({"PSEUDONYM_KEY_FILE": str(f), "PSEUDONYM_KEY": KEY})
    with pytest.raises(ConfigError, match="PSEUDONYM_KEY_FILE"):
        oauth({"PSEUDONYM_KEY_FILE": str(tmp_path / "missing")})
    with pytest.raises(ConfigError, match="base64"):
        oauth({"PSEUDONYM_KEY": "not base64!"})
    with pytest.raises(ConfigError, match="32 bytes"):
        oauth({"PSEUDONYM_KEY": "QUJD"})


def test_oauth_lifetimes_and_switches():
    op = oauth(
        {
            "UEM_ACCESS_TOKEN_TTL": "600",
            "UEM_REFRESH_TOKEN_TTL": "0",
            "UEM_SESSION_MAX_AGE": "86400",
            "UEM_PORTAL_IDLE_TIMEOUT": "300",
            "UEM_DCR": "false",
            "UEM_DCR_REDIRECT_HOSTS": "Claude.example, app.example",
            "UEM_TRUSTED_PROXY_HOPS": "1",
            "UEM_DEFAULT_LANGUAGE": "DE",
        }
    )
    o = op.oauth
    assert o.access_ttl.total_seconds() == 600 and o.refresh_ttl.total_seconds() == 0
    assert o.absolute_max.days == 1 and o.portal_idle.total_seconds() == 300
    assert not o.dcr_enabled and o.dcr_redirect_hosts == ("claude.example", "app.example")
    assert o.trusted_proxy_hops == 1 and o.default_language == "de"
    for var, value in (
        ("UEM_ACCESS_TOKEN_TTL", "0"),
        ("UEM_ACCESS_TOKEN_TTL", "soon"),
        ("UEM_REFRESH_TOKEN_TTL", "-1"),
        ("UEM_TRUSTED_PROXY_HOPS", "9"),
        ("UEM_TRUSTED_PROXY_HOPS", "x"),
        ("UEM_DCR", "maybe"),
    ):
        with pytest.raises(ConfigError, match=var):
            oauth({var: value})


def test_portal_settings():
    o = oauth().oauth
    assert (
        o.reauth_window.total_seconds() == 300 and o.max_accounts == 10 and o.max_identities == 10
    )
    o = oauth(
        {
            "UEM_REAUTH_WINDOW": "60",
            "UEM_MAX_ACCOUNTS_PER_USER": "3",
            "UEM_MAX_IDENTITIES_PER_USER": "4",
        }
    ).oauth
    assert o.reauth_window.total_seconds() == 60 and o.max_accounts == 3 and o.max_identities == 4
    for var, value in (
        ("UEM_REAUTH_WINDOW", "0"),
        ("UEM_REAUTH_WINDOW", "soon"),
        ("UEM_MAX_ACCOUNTS_PER_USER", "0"),
        ("UEM_MAX_IDENTITIES_PER_USER", "many"),
    ):
        with pytest.raises(ConfigError, match=var):
            oauth({var: value})


def test_default_ports_are_dropped_from_the_origin():
    op = load({"PUBLIC_URL": "https://mcp.example.com:443"})
    assert op.allowed_origins == ("https://mcp.example.com",)


def test_pool_settings():
    d = oauth({}).pool
    assert (d.max_connections, d.max_connections_per_user, d.max_concurrent_calls_per_user) == (
        200,
        8,
        8,
    )
    op = oauth(
        {
            "UEM_MAX_CONNECTIONS": "50",
            "UEM_MAX_CONNECTIONS_PER_USER": "3",
            "UEM_MAX_CONCURRENT_CALLS_PER_USER": "4",
            "UEM_CONNECTION_IDLE_TTL": "60",
            "UEM_USER_IDLE_TTL": "120",
            "UEM_MAX_CACHED_USERS": "10",
            "UEM_REAUTH_RETRY_AFTER": "30",
        }
    )
    p = op.pool
    assert (p.max_connections, p.max_connections_per_user, p.max_concurrent_calls_per_user) == (
        50,
        3,
        4,
    )
    assert (p.connection_idle_ttl, p.user_idle_ttl, p.max_cached_users) == (60, 120, 10)
    assert p.reauth_retry_after == 30
    for var in ("UEM_MAX_CONNECTIONS", "UEM_MAX_CONCURRENT_CALLS_PER_USER", "UEM_USER_IDLE_TTL"):
        for bad in ("0", "many"):
            with pytest.raises(ConfigError, match=var):
                oauth({var: bad})
