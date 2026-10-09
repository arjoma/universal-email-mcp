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
    with pytest.raises(ConfigError, match="UEM_DEV_TOKEN") as e:
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
