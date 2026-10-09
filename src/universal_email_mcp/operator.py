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

import base64
import binascii
import ipaddress
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from universal_email_mcp.config import (
    SEND_FALLBACKS,
    SEND_POLICIES,
    Config,
    Limits,
    Policy,
    SendFallback,
    SendPolicy,
    Settings,
)
from universal_email_mcp.errors import ConfigError
from universal_email_mcp.models import ServerProfile
from universal_email_mcp.oauth.config import RATE_PREFIX, RATE_VARIABLES, Rate, RateLimits
from universal_email_mcp.presets import (
    normalize_hostname,
    parse_login_domains,
    parse_mail_servers,
)
from universal_email_mcp.store.crypto import KeyRing

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")
MIN_DEV_TOKEN_LENGTH = 32
DEFAULT_PORT = 8080
DEFAULT_MAX_REQUEST_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
STORE_BACKENDS = ("memory", "firestore")
MIN_PSEUDONYM_KEY_BYTES = 32

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
class StoreSettings:
    """Where remote mode keeps its state (design section 10) and the keys that seal it."""

    backend: str
    """``memory`` (lost on restart; development) or ``firestore``."""
    keys: KeyRing
    firestore_project: str | None = None
    firestore_database: str | None = None
    prefix: str = ""
    ephemeral_keys: bool = False
    """Keys were generated for this run (memory backend without ``STORE_KEYS``)."""


@dataclass(frozen=True, slots=True)
class OAuthSettings:
    """Lifetimes and switches of the authorization server; ``0`` = unlimited where noted."""

    access_ttl: timedelta = timedelta(hours=1)
    refresh_ttl: timedelta = timedelta(days=30)
    """Sliding; 0 = a refresh token never expires on its own (weaker, documented)."""
    absolute_max: timedelta = timedelta(days=90)
    portal_idle: timedelta = timedelta(minutes=30)
    portal_max: timedelta = timedelta(hours=12)
    approval_ttl: timedelta = timedelta(minutes=10)
    """How long a send waits in the portal for the user's approval."""
    reauth_window: timedelta = timedelta(minutes=5)
    """How long after typing the password again a sensitive portal action may be done."""
    max_accounts: int = 10
    max_identities: int = 10
    default_language: str = "en"
    dcr_enabled: bool = True
    dcr_redirect_hosts: tuple[str, ...] = ()
    trusted_proxy_hops: int = 0


@dataclass(frozen=True, slots=True)
class PoolSettings:
    """Per-instance resource caps of the per-user service (WP 3e)."""

    max_connections: int = 200
    """Open mail-server connections in this process (all users)."""
    max_connections_per_user: int = 8
    max_concurrent_calls_per_user: int = 8
    """Tool calls of one user running at once; more are answered with a ``BUSY`` error."""
    connection_idle_ttl: float = 120.0
    """Seconds an unused mail connection stays open (hosters cap connections per mailbox)."""
    user_idle_ttl: float = 900.0
    """Seconds an unused per-user service (decrypted accounts, header caches) stays in memory."""
    max_cached_users: int = 500
    """Per-user services kept in memory; the least recently used idle ones go first."""
    reauth_retry_after: float = 600.0
    """After a rejected login the account is not tried again for this long (unless the
    password changed)."""


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
    audit_log_client_ip: bool = False
    """``AUDIT_LOG_CLIENT_IP``: sign-in and rate-limit audit events carry the keyed pseudonym of
    the client's network (IPv4 /24, IPv6 /48). Off by default; addresses are never logged."""
    store: StoreSettings | None = None
    """Set in OAuth mode (``STORE_BACKEND``), ``None`` in the temporary dev mode."""
    pseudonym_key: bytes = field(default=b"", repr=False)
    oauth: OAuthSettings = OAuthSettings()
    pool: PoolSettings = PoolSettings()
    rate_limits: RateLimits = RateLimits()
    """``UEM_RATE_*``: every in-memory rate limit (per instance), see ``docs/operator-env.md``."""
    max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES
    """Largest decoded attachment or ``.eml`` the portal viewer streams."""
    content_origin: str | None = None
    """Optional separate origin (own host name) that serves mail HTML (``CONTENT_ORIGIN``)."""

    @property
    def oauth_mode(self) -> bool:
        return self.store is not None

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
    if (parts.scheme, port) in (("https", 443), ("http", 80)):
        port = None  # browsers omit default ports in Origin
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
    fallback = _text(env, "SEND_FALLBACK")
    if fallback is not None:
        if fallback not in SEND_FALLBACKS:
            raise _fail(
                "SEND_FALLBACK",
                f"{fallback!r} is invalid",
                f"Use one of: {', '.join(SEND_FALLBACKS)}.",
            )
        changes["send_fallback"] = cast(SendFallback, fallback)
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


MAX_SECONDS = 10 * 365 * 24 * 3600
"""Upper bound of a duration setting (10 years). Larger values overflow the calendar when
added to "now" (the server would fail on the first token), and no deployment wants them."""


def _seconds(env: Mapping[str, str], var: str, default: timedelta, *, zero_ok: bool) -> timedelta:
    raw = _text(env, var)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise _fail(var, f"{raw!r} is not a whole number of seconds") from None
    if value < 0 or (value == 0 and not zero_ok):
        raise _fail(var, "must be positive" + (" (0 = unlimited)" if zero_ok else ""))
    if value > MAX_SECONDS:
        raise _fail(var, f"too large (at most {MAX_SECONDS} seconds, 10 years)")
    return timedelta(seconds=value)


def read_key_material(env: Mapping[str, str], var: str) -> bytes | None:
    """A base64 secret from ``VAR`` or the file named by ``VAR_FILE``."""
    inline, path = _text(env, var), _text(env, var + "_FILE")
    if inline and path:
        raise _fail(var, f"set only one of {var} and {var}_FILE")
    if path:
        try:
            inline = Path(path).read_text().strip()
        except OSError as e:
            raise _fail(var + "_FILE", f"cannot read the file: {e.strerror}") from None
    if not inline:
        return None
    try:
        return base64.b64decode(inline, validate=True)
    except (binascii.Error, ValueError):
        raise _fail(var, "is not valid base64") from None


def _store(env: Mapping[str, str]) -> tuple[StoreSettings, bytes]:
    backend = (_text(env, "STORE_BACKEND") or "").lower()
    if backend not in STORE_BACKENDS:
        raise _fail(
            "STORE_BACKEND", f"{backend!r} is invalid", f"Use one of: {', '.join(STORE_BACKENDS)}."
        )
    has_keys = bool(_text(env, "STORE_KEYS") or _text(env, "STORE_KEYS_FILE"))
    ephemeral = False
    if has_keys:
        try:
            keys = KeyRing.from_env(env)
        except ConfigError as e:
            raise _fail("STORE_KEYS", e.message, e.hint) from None
    elif backend == "memory":
        keys = KeyRing({"k1": os.urandom(32)})
        ephemeral = True
    else:
        raise _fail(
            "STORE_KEYS",
            "or STORE_KEYS_FILE is required with the firestore backend",
            hint='Generate a key: python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"',
        )
    pseudo = read_key_material(env, "PSEUDONYM_KEY")
    if pseudo is None:
        if backend != "memory":
            raise _fail(
                "PSEUDONYM_KEY",
                "is required (base64, at least 32 bytes): it keys the user ids",
                hint="Generate it like a store key; losing or changing it orphans all users.",
            )
        pseudo = os.urandom(32)
    if len(pseudo) < MIN_PSEUDONYM_KEY_BYTES:
        raise _fail("PSEUDONYM_KEY", f"needs at least {MIN_PSEUDONYM_KEY_BYTES} bytes")
    return (
        StoreSettings(
            backend=backend,
            keys=keys,
            firestore_project=_text(env, "FIRESTORE_PROJECT"),
            firestore_database=_text(env, "FIRESTORE_DATABASE"),
            prefix=_text(env, "FIRESTORE_PREFIX") or "",
            ephemeral_keys=ephemeral,
        ),
        pseudo,
    )


def _oauth(env: Mapping[str, str]) -> OAuthSettings:
    base = OAuthSettings()
    lang = (_text(env, "UEM_DEFAULT_LANGUAGE") or base.default_language).lower()
    hosts = tuple(
        normalize_hostname(p)
        for p in (_text(env, "UEM_DCR_REDIRECT_HOSTS") or "").split(",")
        if p.strip()
    )
    hops = _text(env, "UEM_TRUSTED_PROXY_HOPS")
    try:
        hop_count = int(hops) if hops else 0
    except ValueError:
        raise _fail("UEM_TRUSTED_PROXY_HOPS", f"{hops!r} is not a whole number") from None
    if not 0 <= hop_count <= 5:
        raise _fail("UEM_TRUSTED_PROXY_HOPS", "must be between 0 and 5")
    return OAuthSettings(
        access_ttl=_seconds(env, "UEM_ACCESS_TOKEN_TTL", base.access_ttl, zero_ok=False),
        refresh_ttl=_seconds(env, "UEM_REFRESH_TOKEN_TTL", base.refresh_ttl, zero_ok=True),
        absolute_max=_seconds(env, "UEM_SESSION_MAX_AGE", base.absolute_max, zero_ok=True),
        portal_idle=_seconds(env, "UEM_PORTAL_IDLE_TIMEOUT", base.portal_idle, zero_ok=False),
        portal_max=_seconds(env, "UEM_PORTAL_SESSION_MAX", base.portal_max, zero_ok=False),
        reauth_window=_seconds(env, "UEM_REAUTH_WINDOW", base.reauth_window, zero_ok=False),
        approval_ttl=_seconds(env, "UEM_APPROVAL_TTL", base.approval_ttl, zero_ok=False),
        max_accounts=_number(env, "UEM_MAX_ACCOUNTS_PER_USER", base.max_accounts, int),
        max_identities=_number(env, "UEM_MAX_IDENTITIES_PER_USER", base.max_identities, int),
        default_language=lang,
        dcr_enabled=_flag(env, "UEM_DCR", base.dcr_enabled),
        dcr_redirect_hosts=hosts,
        trusted_proxy_hops=hop_count,
    )


def _pool(env: Mapping[str, str]) -> PoolSettings:
    d = PoolSettings()
    return PoolSettings(
        max_connections=_number(env, "UEM_MAX_CONNECTIONS", d.max_connections, int),
        max_connections_per_user=_number(
            env, "UEM_MAX_CONNECTIONS_PER_USER", d.max_connections_per_user, int
        ),
        max_concurrent_calls_per_user=_number(
            env, "UEM_MAX_CONCURRENT_CALLS_PER_USER", d.max_concurrent_calls_per_user, int
        ),
        connection_idle_ttl=_number(env, "UEM_CONNECTION_IDLE_TTL", d.connection_idle_ttl, float),
        user_idle_ttl=_number(env, "UEM_USER_IDLE_TTL", d.user_idle_ttl, float),
        max_cached_users=_number(env, "UEM_MAX_CACHED_USERS", d.max_cached_users, int),
        reauth_retry_after=_number(env, "UEM_REAUTH_RETRY_AFTER", d.reauth_retry_after, float),
    )


_RATE_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
MAX_RATE_COUNT = 100_000
MAX_RATE_WINDOW = timedelta(days=7)


def parse_rate(var: str, raw: str) -> Rate:
    """``COUNT/WINDOW`` - ``5/15m``, ``300/1m``, ``30/10s`` (units s, m, h, d; bare = seconds)."""
    count_text, sep, window_text = raw.strip().partition("/")
    window_text = window_text.strip().lower()
    unit = 1
    if window_text[-1:] in _RATE_UNITS:
        unit, window_text = _RATE_UNITS[window_text[-1]], window_text[:-1]
    if (
        not sep
        or not count_text.strip().isdecimal()
        or not count_text.isascii()
        or not window_text.isdecimal()
        or not window_text.isascii()
    ):
        raise _fail(
            var, f"{raw!r} is not COUNT/WINDOW", hint="Example: 20/15m (20 per 15 minutes)."
        )
    try:
        count, window = int(count_text), int(window_text) * unit
    except ValueError:
        raise _fail(
            var, f"{raw!r} is not COUNT/WINDOW", hint="Example: 20/15m (20 per 15 minutes)."
        ) from None
    if not 1 <= count <= MAX_RATE_COUNT:
        raise _fail(var, f"the count must be between 1 and {MAX_RATE_COUNT}")
    if not 1 <= window <= MAX_RATE_WINDOW.total_seconds():
        raise _fail(var, "the window must be between 1 second and 7 days")
    return Rate(count, timedelta(seconds=window))


def _rate_limits(env: Mapping[str, str]) -> RateLimits:
    changes = {
        field_name: parse_rate(var, raw)
        for var, field_name in RATE_VARIABLES.items()
        if (raw := _text(env, var)) is not None
    }
    unknown = sorted(
        k for k in env if k.startswith(RATE_PREFIX) and k not in RATE_VARIABLES and env[k].strip()
    )
    if unknown:
        raise _fail(unknown[0], "is not a rate limit", hint="See docs/operator-env.md.")
    return replace(RateLimits(), **changes)


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
    dev_mode = token is not None or insecure_local
    if dev_mode and _text(env, "STORE_BACKEND") is not None:
        raise _fail(
            "STORE_BACKEND",
            "cannot be combined with UEM_DEV_TOKEN / --insecure-local",
            hint="Dev mode (static token, TOML accounts) and OAuth mode are exclusive.",
        )
    if not dev_mode and _text(env, "STORE_BACKEND") is None:
        raise _fail(
            "STORE_BACKEND",
            "is required (OAuth mode: memory or firestore)",
            hint="For the temporary dev mode set UEM_DEV_TOKEN or pass --insecure-local.",
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
    content_origin: str | None = None
    raw_content = _text(env, "CONTENT_ORIGIN")
    if raw_content is not None:
        content_origin, content_host = _origin("CONTENT_ORIGIN", raw_content)
        if public_url is None or content_origin == public_url or content_host in hosts:
            raise _fail(
                "CONTENT_ORIGIN",
                "must be a different origin than PUBLIC_URL (its own host name)",
                hint="Example: PUBLIC_URL=https://mcp.example.com CONTENT_ORIGIN=https://mcp-content.example.com",
            )
        if (public_url.startswith("https://")) != content_origin.startswith("https://"):
            raise _fail("CONTENT_ORIGIN", "must use the same scheme as PUBLIC_URL")
        hosts.append(content_host)
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

    store_settings, pseudonym_key = _store(env) if not dev_mode else (None, b"")
    if store_settings is not None and not login_domains:
        raise _fail(
            "LOGIN_DOMAINS",
            "is required in OAuth mode (users sign in with their mailbox login)",
            hint="Example: LOGIN_DOMAINS=company.example=united-domains",
        )
    if store_settings is not None and public_url is None:
        raise _fail(
            "PUBLIC_URL",
            "is required in OAuth mode (it is the issuer and the resource URL)",
            hint="Example: PUBLIC_URL=https://mcp.example.com",
        )

    policy = _policy(env, base.policy if base else Policy())
    if store_settings is None and policy.send_fallback != "draft":
        raise _fail(
            "SEND_FALLBACK",
            f"{policy.send_fallback!r} needs the portal (OAuth mode)",
            hint="The dev mode keeps unconfirmed sends as drafts: unset SEND_FALLBACK.",
        )
    if store_settings is not None and _text(env, "SEND_FALLBACK") is None:
        # Remote mode: an unconfirmed send waits for the user in the portal, never goes out.
        policy = replace(policy, send_fallback="portal")

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
        policy=policy,
        settings=settings,
        max_request_bytes=_number(env, "UEM_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES, int),
        log_level=level,
        audit_log_client_ip=_flag(env, "AUDIT_LOG_CLIENT_IP", False),
        store=store_settings,
        pseudonym_key=pseudonym_key,
        oauth=_oauth(env),
        pool=_pool(env),
        rate_limits=_rate_limits(env),
        max_download_bytes=_number(env, "UEM_MAX_DOWNLOAD_BYTES", DEFAULT_MAX_DOWNLOAD_BYTES, int),
        content_origin=content_origin,
    )
