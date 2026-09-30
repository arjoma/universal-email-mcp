"""Built-in server presets and parsing of the operator lists ``MAIL_SERVERS`` and
``LOGIN_DOMAINS`` (design §5).

An *entry* is either a preset name (``united-domains``) or a hostname
(``mail.example.com``: same host for IMAP/POP3/SMTP on the standard implicit-TLS
ports 993/995/465).
"""

from __future__ import annotations

import ipaddress
import re

from universal_email_mcp.errors import ConfigError
from universal_email_mcp.models import Endpoint, ServerProfile

# Presets are validated with `universal-email-mcp probe --server <name>`.
# ``folder_roles`` stays empty unless a provider's folder names defeat the
# generic role detection (SPECIAL-USE flags + EN/DE name heuristics).
PRESETS: dict[str, ServerProfile] = {
    "united-domains": ServerProfile(
        name="united-domains",
        label="united-domains",
        imap=Endpoint("imaps.udag.de", 993, "tls"),
        pop3=Endpoint("pops.udag.de", 995, "tls"),
        smtp=Endpoint("smtps.udag.de", 465, "tls"),
    ),
}

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_hostname(host: str) -> str:
    """Validate a DNS hostname and return its lower-case ASCII (IDNA) form.

    IP literals are accepted too (useful for local/test setups).
    """
    h = host.strip().rstrip(".").lower()
    if not h:
        raise ConfigError("empty host name")
    if _is_ip_literal(h):
        return h.strip("[]")
    try:
        ascii_host = h.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ConfigError(f"invalid host name {host!r}") from e
    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or not all(_LABEL.match(label) for label in labels):
        raise ConfigError(f"invalid host name {host!r}")
    return ascii_host


def _is_ip_literal(h: str) -> bool:
    try:
        ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        return False
    return True


def profile_for_host(host: str) -> ServerProfile:
    """Generic profile: one host, implicit TLS on 993 (IMAP), 995 (POP3), 465 (SMTP)."""
    h = normalize_hostname(host)
    return ServerProfile(
        name=h,
        label=h,
        imap=Endpoint(h, 993, "tls"),
        pop3=Endpoint(h, 995, "tls"),
        smtp=Endpoint(h, 465, "tls"),
    )


def resolve_server_entry(entry: str) -> ServerProfile:
    """A preset name or a hostname → :class:`ServerProfile`."""
    key = entry.strip().lower()
    if not key:
        raise ConfigError("empty mail server entry")
    if key in PRESETS:
        return PRESETS[key]
    if "." not in key and not _is_ip_literal(key) and key != "localhost":
        known = ", ".join(sorted(PRESETS))
        raise ConfigError(
            f"unknown mail server preset {entry!r}",
            hint=f"Use a preset ({known}) or a fully qualified host name.",
        )
    return profile_for_host(key)


def parse_mail_servers(value: str | None) -> list[ServerProfile]:
    """Parse ``MAIL_SERVERS``. Empty/unset → ``[]`` (= free entry with SSRF guards)."""
    if not value or not value.strip():
        return []
    seen: dict[str, ServerProfile] = {}
    for part in value.split(","):
        if not part.strip():
            continue
        profile = resolve_server_entry(part)
        seen.setdefault(profile.name, profile)
    return list(seen.values())


def parse_login_domains(
    value: str | None, mail_servers: list[ServerProfile] | None = None
) -> dict[str, ServerProfile]:
    """Parse ``LOGIN_DOMAINS`` (``domain=entry,…``) into ``{domain: profile}``.

    A bare ``domain`` without ``=entry`` uses the single ``MAIL_SERVERS`` entry if
    there is exactly one; otherwise that is an error.
    """
    result: dict[str, ServerProfile] = {}
    if not value or not value.strip():
        return result
    default = mail_servers[0] if mail_servers and len(mail_servers) == 1 else None
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        domain, sep, entry = part.partition("=")
        domain = normalize_hostname(domain)
        if sep:
            profile = resolve_server_entry(entry)
        elif default is not None:
            profile = default
        else:
            raise ConfigError(
                f"LOGIN_DOMAINS entry {part!r} names no server",
                hint="Write domain=server, or set MAIL_SERVERS to exactly one entry.",
            )
        if domain in result:
            raise ConfigError(f"LOGIN_DOMAINS lists domain {domain!r} twice")
        result[domain] = profile
    return result
