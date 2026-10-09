"""Operator configuration of the remote server (design section 11), read from the
environment.

The local TOML config (``config.py``) describes one user's accounts; this module
describes the *deployment*: which mail servers users may use, where the service
lives, which limits and policy apply to everybody. Secrets come from the
environment (or files mounted by a secret manager into it) and are never logged:
``OperatorConfig.dev_token`` is excluded from ``repr``.

Every problem is a ``ConfigError`` naming the variable, so a bad deployment fails
at startup with a clear message instead of misbehaving later.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, cast
from urllib.parse import urlsplit

from universal_email_mcp.config import (
    SEND_POLICIES,
    Config,
    Limits,
    Policy,
    SendPolicy,
    Settings,
)
from universal_email_mcp.errors import ConfigError
from universal_email_mcp.models import ServerProfile
from universal_email_mcp.presets import (
    normalize_hostname,
    parse_login_domains,
    parse_mail_servers,
)

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")
MIN_DEV_TOKEN_LENGTH = 32
DEFAULT_PORT = 8080
DEFAULT_MAX_REQUEST_BYTES = 4 * 1024 * 1024
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

# env name -> Limits field (all positive whole numbers except the float ones)
_LIMIT_INTS = {
    "UEM_MAX_RESULTS": "max_results",
    "UEM_MAX_BODY_CHARS": "max_body_chars",
    "UEM_MAX_MESSAGE_BYTES": "max_message_bytes",
    "UEM_MAX_ATTACHMENT_BYTES": "max_attachment_bytes",
    "UEM_MAX_ACCOUNTS_PER_CALL": "max_accounts_per_call",
    "UEM_MAX_HEADERS_SCANNED": "max_headers_scanned",
    "UEM_MAX_BATCH_MESSAGES": "max_batch_messages",
    "UEM_MAX_SEND_BYTES": "max_send_bytes",
}
_LIMIT_FLOATS = {"UEM_ACCOUNT_TIMEOUT": "account_timeout"}


@dataclass(frozen=True, slots=True)
class OperatorConfig:
    host: str
    port: int
    insecure_local: bool
    """Temporary dev mode without a token; only valid on loopback."""
    dev_token: str | None = field(default=None, repr=False)
    """Static bearer token of the dev/test mode (until OAuth, WP 3c). Secret."""
    public_url: str | None = None
    """Externally visible origin, e.g. ``https://mail-mcp.example.com`` (no path)."""
    allowed_hosts: tuple[str, ...] = ()
    """Host names (no port) the server answers to; anything else is refused."""
    allowed_origins: tuple[str, ...] = ()
    """Origins that may send an ``Origin`` header (browser clients)."""
    mail_servers: tuple[ServerProfile, ...] = ()
    login_domains: Mapping[str, ServerProfile] = field(default_factory=dict[str, ServerProfile])
    limits: Limits = Limits()
    policy: Policy = Policy()
    settings: Settings = Settings(allow_private_networks=False)
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    log_level: str = "INFO"

    @property
    def hsts(self) -> bool:
        return bool(self.public_url and self.public_url.startswith("https://"))


# ---------------------------------------------------------------- parsing helpers


def _fail(var: str, msg: str, hint: str | None = None) -> ConfigError:
    return ConfigError(f"{var}: {msg}", hint=hint or "")


def _text(env: Mapping[str, str], var: str) -> str | None:
    v = env.get(var)
    return v.strip() if v and v.strip() else None


def _number[T: (int, float)](
    env: Mapping[str, str], var: str, default: T, cast_to: Callable[[str], T]
) -> T:
    raw = _text(env, var)
    if raw is None:
        return default
    try:
        value = cast_to(raw)
    except ValueError:
        kind = "whole number" if cast_to is int else "number"
        raise _fail(var, f"{raw!r} is not a {kind}") from None
    if not value > 0 or value != value or value in (float("inf"),):
        raise _fail(var, "must be positive")
    return value


def _flag(env: Mapping[str, str], var: str, default: bool) -> bool:
    raw = _text(env, var)
    if raw is None:
        return default
    low = raw.lower()
    if low in ("1", "true", "yes", "on"):
        return True
    if low in ("0", "false", "no", "off"):
        return False
    raise _fail(var, f"{raw!r} is not true/false")


def _names(env: Mapping[str, str], var: str) -> tuple[str, ...]:
    raw = _text(env, var)
    if raw is None:
        return ()
    return tuple(normalize_hostname(p) for p in raw.split(",") if p.strip())


def _host_name(var: str, value: str) -> str:
    """A bare host name or IP literal (no scheme, port or path), lower-cased."""
    v = value.strip().lower()
    if not v or any(c in v for c in "/?#@ ") or "://" in v:
        raise _fail(var, f"{value!r} is not a host name", hint="Write names only, no scheme.")
    if v.startswith("["):  # [::1] literal
        if not v.endswith("]"):
            raise _fail(var, f"{value!r} is not a host name")
        try:
            ipaddress.IPv6Address(v[1:-1])
        except ValueError:
            raise _fail(var, f"{value!r} is not a valid IPv6 literal") from None
        return v
    if ":" in v:
        raise _fail(var, f"{value!r} must not contain a port", hint="Ports are ignored.")
    return v


def _origin(var: str, value: str) -> tuple[str, str]:
    """Validate an origin ``scheme://host[:port]``; returns (origin, host)."""
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise _fail(
            var, f"{value!r} is not an http(s) URL", hint="Example: https://mcp.example.com"
        )
    if parts.username or parts.password or parts.query or parts.fragment:
        raise _fail(var, "must not contain credentials, query or fragment")
    if parts.path not in ("", "/"):
        raise _fail(var, f"{value!r} must not have a path")
    try:
        port = parts.port
    except ValueError:
        raise _fail(var, f"{value!r} has an invalid port") from None
    host = parts.hostname.lower()
    bracket = f"[{host}]" if ":" in host else host
    if parts.scheme == "http" and bracket not in LOOPBACK_HOSTS:
        raise _fail(var, "http is only allowed for localhost", hint="Use https://…")
    origin = f"{parts.scheme}://{bracket}" + (f":{port}" if port else "")
    return origin, bracket


def _limits(env: Mapping[str, str], base: Limits) -> Limits:
    changes: dict[str, Any] = {}
    for var, name in _LIMIT_INTS.items():
        if _text(env, var) is not None:
            changes[name] = _number(env, var, getattr(base, name), int)
    for var, name in _LIMIT_FLOATS.items():
        if _text(env, var) is not None:
            changes[name] = _number(env, var, getattr(base, name), float)
    return replace(base, **changes)


def _policy(env: Mapping[str, str], base: Policy) -> Policy:
    changes: dict[str, Any] = {}
    if _text(env, "UEM_READ_ONLY") is not None:
        changes["read_only"] = _flag(env, "UEM_READ_ONLY", base.read_only)
    send = _text(env, "UEM_SEND_POLICY")
    if send is not None:
        if send not in SEND_POLICIES:
            raise _fail(
                "UEM_SEND_POLICY",
                f"{send!r} is invalid",
                f"Use one of: {', '.join(SEND_POLICIES)}.",
            )
        changes["send"] = cast(SendPolicy, send)
    for var, name in (
        ("UEM_ALLOWED_RECIPIENT_DOMAINS", "allowed_recipient_domains"),
        ("UEM_INTERNAL_DOMAINS", "internal_domains"),
    ):
        if _text(env, var) is not None:
            changes[name] = _names(env, var)
    for var, name in (
        ("UEM_MAX_RECIPIENTS", "max_recipients"),
        ("UEM_MAX_SENDS_PER_HOUR", "max_sends_per_hour"),
        ("UEM_MAX_SENDS_PER_DAY", "max_sends_per_day"),
    ):
        if _text(env, var) is not None:
            changes[name] = _number(env, var, getattr(base, name), int)
    return replace(base, **changes)


# ---------------------------------------------------------------- entry point


def load_operator_config(
    env: Mapping[str, str] | None = None,
    *,
    base: Config | None = None,
    host: str | None = None,
    port: int | None = None,
    insecure_local: bool = False,
) -> OperatorConfig:
    """Read and validate the operator environment.

    ``base`` (dev mode: the local TOML config) supplies the defaults of limits,
    policy and network settings; variables that are set override them. ``host`` and
    ``port`` are the command-line values and win over ``PORT``.
    """
    env = os.environ if env is None else env

    token = env.get("UEM_DEV_TOKEN") or None
    if token is not None and len(token) < MIN_DEV_TOKEN_LENGTH:
        raise _fail(
            "UEM_DEV_TOKEN",
            f"too short (at least {MIN_DEV_TOKEN_LENGTH} characters)",
            hint='Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"',
        )
    if token is None and not insecure_local:
        raise _fail(
            "UEM_DEV_TOKEN",
            "is required: /mcp must not be open",
            hint="Set a bearer token, or pass --insecure-local (binds 127.0.0.1 only; "
            "temporary dev mode until OAuth exists).",
        )

    bind = host or ("127.0.0.1" if insecure_local else "0.0.0.0")  # noqa: S104 - container default
    if insecure_local and bind not in ("127.0.0.1", "localhost", "::1"):
        raise ConfigError(
            f"--insecure-local only binds to loopback, not {bind!r}",
            hint="Drop --insecure-local and set UEM_DEV_TOKEN to listen on other addresses.",
        )

    if port is None:
        port = _number(env, "PORT", DEFAULT_PORT, int)
    if not 1 <= port <= 65535:
        raise _fail("PORT", f"{port} is out of range")

    public_url: str | None = None
    hosts: list[str] = []
    origins: list[str] = []
    raw_url = _text(env, "PUBLIC_URL")
    if raw_url is not None:
        origin, url_host = _origin("PUBLIC_URL", raw_url)
        public_url = origin
        hosts.append(url_host)
        origins.append(origin)
    for h in (p for p in (_text(env, "ALLOWED_HOSTS") or "").split(",") if p.strip()):
        hosts.append(_host_name("ALLOWED_HOSTS", h))
    for o in (p for p in (_text(env, "ALLOWED_ORIGINS") or "").split(",") if p.strip()):
        origins.append(_origin("ALLOWED_ORIGINS", o)[0])
    if insecure_local:
        hosts.extend(LOOPBACK_HOSTS)
    if not hosts:
        raise _fail(
            "PUBLIC_URL",
            "or ALLOWED_HOSTS is required (Host header checks, DNS rebinding protection)",
            hint="Example: PUBLIC_URL=https://mcp.example.com",
        )

    try:
        mail_servers = parse_mail_servers(_text(env, "MAIL_SERVERS"))
    except ConfigError as e:
        raise _fail("MAIL_SERVERS", e.message, e.hint) from None
    try:
        login_domains = parse_login_domains(_text(env, "LOGIN_DOMAINS"), mail_servers)
    except ConfigError as e:
        raise _fail("LOGIN_DOMAINS", e.message, e.hint) from None

    level = (_text(env, "UEM_LOG_LEVEL") or "INFO").upper()
    if level not in LOG_LEVELS:
        raise _fail(
            "UEM_LOG_LEVEL", f"{level!r} is invalid", f"Use one of: {', '.join(LOG_LEVELS)}."
        )

    settings = base.settings if base else Settings(allow_private_networks=False)
    if _text(env, "UEM_ALLOW_PRIVATE_NETWORKS") is not None:
        settings = replace(
            settings,
            allow_private_networks=_flag(
                env, "UEM_ALLOW_PRIVATE_NETWORKS", settings.allow_private_networks
            ),
        )

    return OperatorConfig(
        host=bind,
        port=port,
        insecure_local=insecure_local,
        dev_token=token,
        public_url=public_url,
        allowed_hosts=tuple(dict.fromkeys(hosts)),
        allowed_origins=tuple(dict.fromkeys(origins)),
        mail_servers=tuple(mail_servers),
        login_domains=login_domains,
        limits=_limits(env, base.limits if base else Limits()),
        policy=_policy(env, base.policy if base else Policy()),
        settings=settings,
        max_request_bytes=_number(env, "UEM_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES, int),
        log_level=level,
    )
