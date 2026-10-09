from pathlib import Path

import pytest

from universal_email_mcp.config import (
    CONFIG_ENV,
    KEYRING_SERVICE,
    Config,
    config_path,
    default_config_path,
    load_config,
    parse_config,
    resolve_password,
)
from universal_email_mcp.errors import ConfigError, CredentialMissing
from universal_email_mcp.models import Endpoint

EXAMPLE = Path(__file__).parent.parent / "docs" / "config.example.toml"


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_example_config_is_valid():
    cfg = load_config(EXAMPLE, env={})
    assert cfg.path == EXAMPLE
    names = [a.name for a in cfg.accounts]
    assert names == ["Work", "Archive", "Old POP"]
    work = cfg.account("work")
    assert work.endpoint == Endpoint("imaps.udag.de", 993, "tls")
    assert work.credential.kind == "env"
    assert work.permissions.read and work.permissions.organize and not work.permissions.delete
    archive = cfg.account("Archive")
    assert archive.endpoint == Endpoint("mail.example.net", 143, "starttls")
    assert archive.effective_folder_roles() == {"sent": "INBOX.Gesendet"}
    assert archive.credential.kind == "keyring" and archive.credential.name == "Archive"
    assert cfg.account("old pop").kind == "pop3"
    assert cfg.default_identity is not None
    assert cfg.default_identity.addresses == ("alice@example.com",)
    assert cfg.policy.send == "confirm"


def test_minimal_config_and_defaults(tmp_path: Path):
    cfg = load_config(
        write(
            tmp_path,
            '[[accounts]]\nname = "a"\nserver = "mail.example.com"\nusername = "u"\n',
        ),
        env={},
    )
    acc = cfg.accounts[0]
    assert acc.kind == "imap"
    assert acc.endpoint == Endpoint("mail.example.com", 993, "tls")
    assert acc.permissions.read and not acc.permissions.organize
    assert acc.tls.verify
    assert cfg.settings.allow_private_networks
    assert cfg.net_policy().allow_private
    assert cfg.identities == ()


def test_identity_default_is_first_when_unset():
    cfg = parse_config(
        {
            "accounts": [{"name": "a", "server": "united-domains", "username": "u"}],
            "identities": [
                {"address": "a@example.com", "account": "A"},
                {"addresses": ["b@example.com", "B@example.com"]},
            ],
        }
    )
    assert cfg.identities[0].default and not cfg.identities[1].default
    assert cfg.identities[0].smtp_account == "a" and cfg.identities[0].store_account == "a"
    assert cfg.identities[1].addresses == ("b@example.com",)


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        ({"acounts": []}, "unknown key 'acounts'"),
        (
            {"accounts": [{"name": "a", "server": "x.example", "username": "u", "password": "p"}]},
            "never stored",
        ),
        (
            {
                "accounts": [
                    {"name": "a", "server": "x.example", "username": "u", "pasword_env": "X"}
                ]
            },
            "Did you mean 'password_env'",
        ),
        ({"accounts": [{"server": "x.example", "username": "u"}]}, "'name' is required"),
        ({"accounts": [{"name": "a", "username": "u"}]}, "no imap server"),
        (
            {"accounts": [{"name": "a", "server": "nopreset", "username": "u"}]},
            "unknown mail server preset",
        ),
        ({"accounts": [{"name": "a", "server": "x.example"}]}, "'username' is required"),
        (
            {"accounts": [{"name": "a", "server": "x.example", "username": "u", "kind": "jmap"}]},
            "kind",
        ),
        (
            {
                "accounts": [
                    {"name": "a", "server": "x.example", "username": "u", "permissions": ["send"]}
                ]
            },
            "unknown permission",
        ),
        (
            {
                "accounts": [
                    {
                        "name": "a",
                        "kind": "pop3",
                        "server": "x.example",
                        "username": "u",
                        "permissions": ["read", "delete"],
                    }
                ]
            },
            "read-only",
        ),
        (
            {
                "accounts": [
                    {"name": "a", "server": "x.example", "username": "u", "password_env": "1BAD"}
                ]
            },
            "not a valid variable",
        ),
        (
            {
                "accounts": [
                    {
                        "name": "a",
                        "server": "x.example",
                        "username": "u",
                        "password_env": "X",
                        "keyring_key": "k",
                    }
                ]
            },
            "not both",
        ),
        (
            {
                "accounts": [
                    {
                        "name": "a",
                        "server": "x.example",
                        "username": "u",
                        "imap": {"host": "h.example", "tls": "none"},
                    }
                ]
            },
            "tls = 'none'",
        ),
        (
            {
                "accounts": [
                    {
                        "name": "a",
                        "server": "x.example",
                        "username": "u",
                        "imap": {"host": "h.example", "port": 70000},
                    }
                ]
            },
            "port",
        ),
        (
            {
                "accounts": [
                    {
                        "name": "a",
                        "server": "x.example",
                        "username": "u",
                        "folders": {"outbox": "X"},
                    }
                ]
            },
            "unknown key 'outbox'",
        ),
        (
            {
                "accounts": [
                    {"name": "a", "server": "x.example", "username": "u"},
                    {"name": "A", "server": "x.example", "username": "u"},
                ]
            },
            "duplicate account",
        ),
        (
            {"accounts": [{"name": "bad/name", "server": "x.example", "username": "u"}]},
            "invalid account name",
        ),
        ({"accounts": {"name": "a"}}, "[[accounts]]"),
        ({"identities": [{"address": "not-an-address"}]}, "invalid e-mail"),
        ({"identities": [{}]}, "'address'"),
        ({"identities": [{"address": "a@example.com", "account": "missing"}]}, "no such account"),
        (
            {
                "identities": [
                    {"address": "a@example.com", "default": True},
                    {"address": "b@example.com", "default": True},
                ]
            },
            "more than one",
        ),
        ({"policy": {"send": "sometimes"}}, "send = 'sometimes'"),
        ({"limits": {"max_results": 0}}, "positive"),
        ({"limits": {"max_results": 1.5}}, "whole number"),
        ({"limits": {"max_batch_messages": 0}}, "positive"),
        ({"settings": {"allow_private_networks": "yes"}}, "true or false"),
    ],
)
def test_validation_errors(doc: dict[str, object], message: str):
    with pytest.raises(ConfigError) as exc:
        parse_config(doc, source="test.toml")
    text = f"{exc.value.message} {exc.value.hint}"
    assert message in text
    assert exc.value.message.startswith("test.toml: ")


def test_pop3_identity_store_must_be_imap():
    doc = {
        "accounts": [{"name": "p", "kind": "pop3", "server": "x.example", "username": "u"}],
        "identities": [{"address": "a@example.com", "store_account": "p"}],
    }
    with pytest.raises(ConfigError, match="must be an IMAP account"):
        parse_config(doc)


def test_load_config_errors(tmp_path: Path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.toml", env={})
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(write(tmp_path, "accounts = [\n"), env={})


def test_config_path_precedence(tmp_path: Path):
    assert config_path("x.toml", {CONFIG_ENV: "y.toml"}) == Path("x.toml")
    assert config_path(None, {CONFIG_ENV: "y.toml"}) == Path("y.toml")
    assert config_path(None, {}) == default_config_path()
    assert default_config_path().name == "config.toml"


def test_unknown_account_lookup():
    with pytest.raises(ConfigError, match="unknown account"):
        Config().account("nope")


def _acc(**kw: object):
    doc = {"accounts": [{"name": "Work", "server": "x.example", "username": "u", **kw}]}
    return parse_config(doc).accounts[0]


def test_resolve_password_env():
    acc = _acc(password_env="WORK_PW")
    assert resolve_password(acc, env={"WORK_PW": "s3cret"}) == "s3cret"
    with pytest.raises(CredentialMissing, match="WORK_PW"):
        resolve_password(acc, env={})


def test_resolve_password_keyring():
    acc = _acc(keyring_key="work-key")
    calls: list[tuple[str, str]] = []

    def getter(service: str, key: str) -> str | None:
        calls.append((service, key))
        return "from-keyring" if key == "work-key" else None

    assert resolve_password(acc, keyring_get=getter) == "from-keyring"
    assert calls == [(KEYRING_SERVICE, "work-key")]
    with pytest.raises(CredentialMissing, match="keyring"):
        resolve_password(_acc(), keyring_get=lambda s, k: None)


def test_batch_limit_default_and_override():
    assert parse_config({"accounts": []}).limits.max_batch_messages == 50
    cfg = parse_config({"accounts": [], "limits": {"max_batch_messages": 7}})
    assert cfg.limits.max_batch_messages == 7

def test_downloads_defaults_and_overrides():
    from universal_email_mcp.config import Downloads, parse_config

    assert parse_config({}).downloads == Downloads()
    assert Downloads().enabled and Downloads().port == 0
    d = parse_config(
        {"downloads": {"enabled": False, "port": 8765, "link_ttl": 600, "max_download_bytes": 5}}
    ).downloads
    assert (d.enabled, d.port, d.link_ttl, d.max_download_bytes) == (False, 8765, 600, 5)


@pytest.mark.parametrize(
    "bad",
    [{"port": -1}, {"port": 70000}, {"port": "80"}, {"port": True}, {"link_ttl": 0}, {"bogus": 1}],
)
def test_downloads_rejects_bad_values(bad: dict[str, object]):
    from universal_email_mcp.config import parse_config

    with pytest.raises(ConfigError):
        parse_config({"downloads": bad})
