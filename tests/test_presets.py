import pytest

from universal_email_mcp.errors import ConfigError
from universal_email_mcp.models import Endpoint
from universal_email_mcp.presets import (
    PRESETS,
    normalize_hostname,
    parse_login_domains,
    parse_mail_servers,
    resolve_server_entry,
)


def test_united_domains_preset():
    p = PRESETS["united-domains"]
    assert p.imap == Endpoint("imaps.udag.de", 993, "tls")
    assert p.pop3 == Endpoint("pops.udag.de", 995, "tls")
    assert p.smtp == Endpoint("smtps.udag.de", 465, "tls")


def test_hostname_entry_uses_standard_ports():
    p = resolve_server_entry(" Mail.Example.COM ")
    assert p.name == "mail.example.com"
    assert p.imap == Endpoint("mail.example.com", 993, "tls")
    assert p.pop3 == Endpoint("mail.example.com", 995, "tls")
    assert p.smtp == Endpoint("mail.example.com", 465, "tls")


def test_preset_lookup_is_case_insensitive():
    assert resolve_server_entry("United-Domains") is PRESETS["united-domains"]


@pytest.mark.parametrize("bad", ["", "unknown-preset", "bad_host.example.com", "-x.example.com"])
def test_bad_entries(bad: str):
    with pytest.raises(ConfigError):
        resolve_server_entry(bad)


def test_idn_and_ip_hosts():
    assert normalize_hostname("mäil.example.com.") == "xn--mil-qla.example.com"
    assert normalize_hostname("[::1]") == "::1"
    assert normalize_hostname("127.0.0.1") == "127.0.0.1"
    with pytest.raises(ConfigError):
        normalize_hostname("  ")
    with pytest.raises(ConfigError):
        normalize_hostname("a" * 64 + ".example.com")


def test_parse_mail_servers():
    assert parse_mail_servers(None) == []
    assert parse_mail_servers("  ") == []
    servers = parse_mail_servers("united-domains, mail.example.com,,united-domains")
    assert [s.name for s in servers] == ["united-domains", "mail.example.com"]


def test_parse_login_domains():
    servers = parse_mail_servers("united-domains")
    result = parse_login_domains("company.example, other.example=mail.other.example", servers)
    assert result["company.example"].name == "united-domains"
    assert result["other.example"].name == "mail.other.example"
    assert parse_login_domains("", servers) == {}


def test_parse_login_domains_errors():
    with pytest.raises(ConfigError):
        parse_login_domains("company.example", [])
    with pytest.raises(ConfigError):
        parse_login_domains("a.example=united-domains,A.example=united-domains")
