"""Local-mode configuration file (TOML).

Location, first match wins: ``--config`` on the command line, the environment
variable ``UEM_CONFIG``, then the platform config dir
(``~/.config/universal-email-mcp/config.toml`` on Linux). See
``docs/config.example.toml`` for a commented example.

Passwords are never read from the file: each account names an environment
variable (``password_env``) or uses the OS keyring (service
``universal-email-mcp``, key = ``keyring_key`` or the account name).
"""

from __future__ import annotations

import difflib
import os
import re
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast, get_args

from universal_email_mcp.errors import ConfigError, CredentialMissing
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import (
    ACCOUNT_KINDS,
    FOLDER_ROLES,
    TLS_MODES,
    Account,
    AccountKind,
    CredentialRef,
    Endpoint,
    FolderRole,
    Identity,
    Permissions,
    ServerProfile,
    TlsMode,
    TlsSettings,
)
from universal_email_mcp.presets import normalize_hostname, resolve_server_entry

APP_NAME = "universal-email-mcp"
KEYRING_SERVICE = APP_NAME
CONFIG_ENV = "UEM_CONFIG"

SendPolicy = Literal["off", "confirm", "confirm-external", "on"]
SEND_POLICIES: tuple[SendPolicy, ...] = get_args(SendPolicy)
PERMISSION_NAMES = ("read", "organize", "delete", "drafts")

_NAME_RE = re.compile(r"^[\w][\w .@+-]{0,63}$", re.UNICODE)


@dataclass(frozen=True, slots=True)
class Settings:
    allow_private_networks: bool = True
    """Local mode may reach servers on private networks (LAN, containers)."""
    connect_timeout: float = 15.0
    read_timeout: float = 60.0


@dataclass(frozen=True, slots=True)
class Policy:
    read_only: bool = False
    send: SendPolicy = "confirm"
    allowed_recipient_domains: tuple[str, ...] = ()
    max_recipients: int = 20


@dataclass(frozen=True, slots=True)
class Limits:
    max_results: int = 50
    max_body_chars: int = 20_000
    max_message_bytes: int = 10 * 1024 * 1024
    max_attachment_bytes: int = 2 * 1024 * 1024
    """Largest attachment ``get_attachment`` returns (decoded); bigger ones are
    refused or, with a download link provider, handed out as a link."""
    max_accounts_per_call: int = 10
    account_timeout: float = 30.0
    max_headers_scanned: int = 2_000
    """Headers read per account and call for fuzzy search and contact lookup."""


@dataclass(frozen=True, slots=True)
class Config:
    accounts: tuple[Account, ...] = ()
    identities: tuple[Identity, ...] = ()
    policy: Policy = Policy()
    limits: Limits = Limits()
    settings: Settings = Settings()
    path: Path | None = field(default=None, compare=False)

    def account(self, name: str) -> Account:
        """Look up an account by name (case-insensitive)."""
        for acc in self.accounts:
            if acc.name.casefold() == name.casefold():
                return acc
        names = ", ".join(a.name for a in self.accounts) or "none configured"
        raise ConfigError(f"unknown account {name!r}", hint=f"Known accounts: {names}.")

    @property
    def default_identity(self) -> Identity | None:
        for ident in self.identities:
            if ident.default:
                return ident
        return None

    def net_policy(self) -> NetPolicy:
        return NetPolicy(
            allow_private=self.settings.allow_private_networks,
            connect_timeout=self.settings.connect_timeout,
            read_timeout=self.settings.read_timeout,
        )


# --------------------------------------------------------------------------- paths


def default_config_path() -> Path:
    from platformdirs import user_config_path

    return user_config_path(APP_NAME, appauthor=False) / "config.toml"


def config_path(
    explicit: str | os.PathLike[str] | None = None, env: Mapping[str, str] | None = None
) -> Path:
    env = os.environ if env is None else env
    if explicit:
        return Path(explicit).expanduser()
    if env.get(CONFIG_ENV):
        return Path(env[CONFIG_ENV]).expanduser()
    return default_config_path()


def load_config(
    path: str | os.PathLike[str] | None = None, env: Mapping[str, str] | None = None
) -> Config:
    p = config_path(path, env)
    try:
        raw = p.read_bytes()
    except FileNotFoundError as e:
        raise ConfigError(
            f"config file not found: {p}",
            hint=f"Create it (see docs/config.example.toml) or point {CONFIG_ENV} / --config to it.",
        ) from e
    except OSError as e:
        raise ConfigError(f"cannot read config file {p}: {e.strerror}") from e
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ConfigError(f"{p}: invalid TOML: {e}") from e
    cfg = parse_config(data, source=str(p))
    return Config(
        accounts=cfg.accounts,
        identities=cfg.identities,
        policy=cfg.policy,
        limits=cfg.limits,
        settings=cfg.settings,
        path=p,
    )


# --------------------------------------------------------------------------- parsing


class _Ctx:
    def __init__(self, source: str) -> None:
        self.source = source

    def err(self, where: str, msg: str, hint: str | None = None) -> ConfigError:
        return ConfigError(f"{self.source}: {where}: {msg}", hint=hint)

    def table(self, value: object, where: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise self.err(where, "expected a table")
        return cast(dict[str, Any], value)

    def check_keys(self, table: Mapping[str, Any], allowed: tuple[str, ...], where: str) -> None:
        for key in table:
            if key in allowed:
                continue
            if key in ("password", "pass", "passwd", "secret"):
                raise self.err(
                    where,
                    f"'{key}' is not allowed: passwords are never stored in the config file",
                    hint='Use password_env = "VARNAME" or the OS keyring '
                    f"(service '{KEYRING_SERVICE}').",
                )
            close = difflib.get_close_matches(key, allowed, n=1)
            hint = f"Did you mean '{close[0]}'?" if close else f"Allowed: {', '.join(allowed)}."
            raise self.err(where, f"unknown key '{key}'", hint=hint)

    def str_(
        self, table: Mapping[str, Any], key: str, where: str, default: str | None = None
    ) -> str | None:
        v = table.get(key, default)
        if v is None:
            return None
        if not isinstance(v, str):
            raise self.err(where, f"'{key}' must be a string")
        return v

    def req_str(self, table: Mapping[str, Any], key: str, where: str) -> str:
        v = self.str_(table, key, where)
        if not v or not v.strip():
            raise self.err(where, f"'{key}' is required")
        return v.strip()

    def bool_(self, table: Mapping[str, Any], key: str, where: str, default: bool) -> bool:
        v = table.get(key, default)
        if not isinstance(v, bool):
            raise self.err(where, f"'{key}' must be true or false")
        return v

    def num(
        self,
        table: Mapping[str, Any],
        key: str,
        where: str,
        default: float,
        *,
        integer: bool = False,
    ) -> float:
        v = table.get(key, default)
        if (
            isinstance(v, bool)
            or not isinstance(v, (int, float))
            or (integer and not isinstance(v, int))
        ):
            raise self.err(where, f"'{key}' must be a {'whole ' if integer else ''}number")
        if v <= 0:
            raise self.err(where, f"'{key}' must be positive")
        return v

    def str_list(self, table: Mapping[str, Any], key: str, where: str) -> list[str]:
        v = table.get(key, [])
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in cast(list[object], v)):
            raise self.err(where, f"'{key}' must be a list of strings")
        return [x.strip() for x in cast(list[str], v) if x.strip()]


def parse_config(data: Mapping[str, Any], *, source: str = "config") -> Config:
    """Validate a parsed TOML document and build a :class:`Config`."""
    c = _Ctx(source)
    c.check_keys(data, ("settings", "policy", "limits", "accounts", "identities"), "top level")
    settings = _parse_settings(c, c.table(data.get("settings", {}), "[settings]"))
    policy = _parse_policy(c, c.table(data.get("policy", {}), "[policy]"))
    limits = _parse_limits(c, c.table(data.get("limits", {}), "[limits]"))

    raw_accounts = data.get("accounts", [])
    if not isinstance(raw_accounts, list):
        raise c.err("accounts", "use [[accounts]] tables")
    accounts: list[Account] = []
    seen: set[str] = set()
    for i, raw in enumerate(cast(list[object], raw_accounts)):
        acc = _parse_account(c, c.table(raw, f"accounts[{i}]"), i)
        key = acc.name.casefold()
        if key in seen:
            raise c.err(f"accounts[{i}]", f"duplicate account name {acc.name!r}")
        seen.add(key)
        accounts.append(acc)

    raw_idents = data.get("identities", [])
    if not isinstance(raw_idents, list):
        raise c.err("identities", "use [[identities]] tables")
    by_name = {a.name.casefold(): a for a in accounts}
    identities = [
        _parse_identity(c, c.table(raw, f"identities[{i}]"), i, by_name)
        for i, raw in enumerate(cast(list[object], raw_idents))
    ]
    identities = _settle_default_identity(c, identities)
    return Config(
        accounts=tuple(accounts),
        identities=tuple(identities),
        policy=policy,
        limits=limits,
        settings=settings,
    )


def _parse_settings(c: _Ctx, t: dict[str, Any]) -> Settings:
    c.check_keys(t, ("allow_private_networks", "connect_timeout", "read_timeout"), "[settings]")
    return Settings(
        allow_private_networks=c.bool_(t, "allow_private_networks", "[settings]", True),
        connect_timeout=c.num(t, "connect_timeout", "[settings]", 15.0),
        read_timeout=c.num(t, "read_timeout", "[settings]", 60.0),
    )


def _parse_policy(c: _Ctx, t: dict[str, Any]) -> Policy:
    w = "[policy]"
    c.check_keys(t, ("read_only", "send", "allowed_recipient_domains", "max_recipients"), w)
    send = c.str_(t, "send", w, "confirm") or "confirm"
    if send not in SEND_POLICIES:
        raise c.err(
            w, f"send = {send!r} is invalid", hint=f"Use one of: {', '.join(SEND_POLICIES)}."
        )
    domains = tuple(normalize_hostname(d) for d in c.str_list(t, "allowed_recipient_domains", w))
    return Policy(
        read_only=c.bool_(t, "read_only", w, False),
        send=cast(SendPolicy, send),
        allowed_recipient_domains=domains,
        max_recipients=int(c.num(t, "max_recipients", w, 20, integer=True)),
    )


def _parse_limits(c: _Ctx, t: dict[str, Any]) -> Limits:
    w = "[limits]"
    keys = (
        "max_results",
        "max_body_chars",
        "max_message_bytes",
        "max_attachment_bytes",
        "max_accounts_per_call",
        "account_timeout",
        "max_headers_scanned",
    )
    c.check_keys(t, keys, w)
    d = Limits()
    return Limits(
        max_results=int(c.num(t, "max_results", w, d.max_results, integer=True)),
        max_body_chars=int(c.num(t, "max_body_chars", w, d.max_body_chars, integer=True)),
        max_message_bytes=int(c.num(t, "max_message_bytes", w, d.max_message_bytes, integer=True)),
        max_attachment_bytes=int(
            c.num(t, "max_attachment_bytes", w, d.max_attachment_bytes, integer=True)
        ),
        max_accounts_per_call=int(
            c.num(t, "max_accounts_per_call", w, d.max_accounts_per_call, integer=True)
        ),
        account_timeout=c.num(t, "account_timeout", w, d.account_timeout),
        max_headers_scanned=int(
            c.num(t, "max_headers_scanned", w, d.max_headers_scanned, integer=True)
        ),
    )


_ACCOUNT_KEYS = (
    "name",
    "kind",
    "server",
    "imap",
    "pop3",
    "smtp",
    "username",
    "password_env",
    "keyring_key",
    "permissions",
    "tls_verify",
    "tls_ca_file",
    "folders",
)
_DEFAULT_PORTS: dict[tuple[str, TlsMode], int] = {
    ("imap", "tls"): 993,
    ("imap", "starttls"): 143,
    ("pop3", "tls"): 995,
    ("pop3", "starttls"): 110,
    ("smtp", "tls"): 465,
    ("smtp", "starttls"): 587,
}


def _parse_endpoint(c: _Ctx, t: dict[str, Any], proto: str, where: str) -> Endpoint:
    c.check_keys(t, ("host", "port", "tls"), where)
    host = normalize_hostname(c.req_str(t, "host", where))
    tls = c.str_(t, "tls", where, "tls") or "tls"
    if tls not in TLS_MODES:
        raise c.err(where, f"tls = {tls!r} is invalid", hint='Use "tls" or "starttls".')
    mode = cast(TlsMode, tls)
    port = t.get("port", _DEFAULT_PORTS[(proto, mode)])
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise c.err(where, "'port' must be a number between 1 and 65535")
    return Endpoint(host, port, mode)


def _parse_account(c: _Ctx, t: dict[str, Any], i: int) -> Account:
    w = f"accounts[{i}]"
    c.check_keys(t, _ACCOUNT_KEYS, w)
    name = c.req_str(t, "name", w)
    if not _NAME_RE.match(name):
        raise c.err(
            w, f"invalid account name {name!r}", hint="Use letters, digits, space, . _ - @ +."
        )
    w = f"account {name!r}"
    kind = c.str_(t, "kind", w, "imap") or "imap"
    if kind not in ACCOUNT_KINDS:
        raise c.err(w, f"kind = {kind!r} is invalid", hint='Use "imap" or "pop3".')

    server_entry = c.str_(t, "server", w)
    try:
        base = resolve_server_entry(server_entry) if server_entry else ServerProfile(name=name)
    except ConfigError as e:
        raise c.err(w, e.message, hint=e.hint) from e
    endpoints: dict[str, Endpoint | None] = {
        "imap": base.imap,
        "pop3": base.pop3,
        "smtp": base.smtp,
    }
    for proto in ("imap", "pop3", "smtp"):
        if proto in t:
            endpoints[proto] = _parse_endpoint(
                c, c.table(t[proto], f"{w}.{proto}"), proto, f"{w}.{proto}"
            )
    if endpoints[kind] is None:
        raise c.err(
            w,
            f"no {kind} server configured",
            hint=f'Set server = "<preset or host name>" or add a [accounts.{kind}] table.',
        )

    folder_table = c.table(t.get("folders", {}), f"{w}.folders")
    c.check_keys(folder_table, FOLDER_ROLES, f"{w}.folders")
    folder_roles: dict[FolderRole, str] = {}
    for role, value in folder_table.items():
        if not isinstance(value, str) or not value.strip():
            raise c.err(f"{w}.folders", f"'{role}' must be a folder name")
        folder_roles[cast(FolderRole, role)] = value

    perms_list = c.str_list(t, "permissions", w) if "permissions" in t else ["read"]
    for p in perms_list:
        if p not in PERMISSION_NAMES:
            raise c.err(w, f"unknown permission {p!r}", hint=f"Use: {', '.join(PERMISSION_NAMES)}.")
    perms = Permissions(**{p: p in perms_list for p in PERMISSION_NAMES})
    if kind == "pop3" and (perms.organize or perms.delete or perms.drafts):
        raise c.err(w, "POP3 accounts are read-only", hint='Use permissions = ["read"].')

    password_env = c.str_(t, "password_env", w)
    if password_env is not None:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", password_env):
            raise c.err(w, f"password_env = {password_env!r} is not a valid variable name")
        if "keyring_key" in t:
            raise c.err(w, "use either password_env or keyring_key, not both")
        credential = CredentialRef("env", password_env)
    else:
        credential = CredentialRef("keyring", c.str_(t, "keyring_key", w) or name)

    ca_file = c.str_(t, "tls_ca_file", w)
    server = ServerProfile(
        name=base.name,
        label=base.label,
        imap=endpoints["imap"],
        pop3=endpoints["pop3"],
        smtp=endpoints["smtp"],
        folder_roles=dict(base.folder_roles),
    )
    return Account(
        name=name,
        kind=cast(AccountKind, kind),
        username=c.req_str(t, "username", w),
        server=server,
        credential=credential,
        permissions=perms,
        tls=TlsSettings(
            verify=c.bool_(t, "tls_verify", w, True),
            ca_file=str(Path(ca_file).expanduser()) if ca_file else None,
        ),
        folder_roles=folder_roles,
    )


_EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")


def _parse_identity(
    c: _Ctx, t: dict[str, Any], i: int, accounts: Mapping[str, Account]
) -> Identity:
    w = f"identities[{i}]"
    keys = (
        "name",
        "address",
        "addresses",
        "display_name",
        "account",
        "smtp_account",
        "store_account",
        "default",
        "send",
        "signature",
    )
    c.check_keys(t, keys, w)
    addresses = c.str_list(t, "addresses", w)
    single = c.str_(t, "address", w)
    if single:
        addresses.insert(0, single.strip())
    if not addresses:
        raise c.err(w, "'address' (or 'addresses') is required")
    for a in addresses:
        if not _EMAIL_RE.match(a):
            raise c.err(w, f"invalid e-mail address {a!r}")
    addresses = list(dict.fromkeys(a.lower() for a in addresses))

    def account_ref(key: str, fallback: str | None) -> str | None:
        v = c.str_(t, key, w) or fallback
        if v is None:
            return None
        acc = accounts.get(v.casefold())
        if acc is None:
            raise c.err(w, f"{key} = {v!r}: no such account")
        return acc.name

    base = c.str_(t, "account", w)
    smtp_account = account_ref("smtp_account", base)
    store_account = account_ref("store_account", base)
    if smtp_account and accounts[smtp_account.casefold()].server.smtp is None:
        raise c.err(w, f"account {smtp_account!r} has no SMTP server")
    if store_account and accounts[store_account.casefold()].kind != "imap":
        raise c.err(w, f"store_account {store_account!r} must be an IMAP account")
    return Identity(
        name=c.str_(t, "name", w) or addresses[0],
        addresses=tuple(addresses),
        display_name=(c.str_(t, "display_name", w) or "").strip(),
        smtp_account=smtp_account,
        store_account=store_account,
        default=c.bool_(t, "default", w, False),
        send=c.bool_(t, "send", w, False),
        signature=c.str_(t, "signature", w) or "",
    )


def _settle_default_identity(c: _Ctx, identities: list[Identity]) -> list[Identity]:
    defaults = [i for i in identities if i.default]
    if len(defaults) > 1:
        raise c.err("identities", "more than one identity has default = true")
    if identities and not defaults:
        first = identities[0]
        identities[0] = Identity(
            name=first.name,
            addresses=first.addresses,
            display_name=first.display_name,
            smtp_account=first.smtp_account,
            store_account=first.store_account,
            default=True,
            send=first.send,
            signature=first.signature,
        )
    return identities


# --------------------------------------------------------------------------- secrets

KeyringGetter = Callable[[str, str], str | None]


def _keyring_get(service: str, key: str) -> str | None:
    import keyring
    from keyring.errors import KeyringError

    try:
        return keyring.get_password(service, key)
    except KeyringError as e:
        raise CredentialMissing(f"OS keyring unavailable: {e}") from e


def resolve_password(
    account: Account,
    *,
    env: Mapping[str, str] | None = None,
    keyring_get: KeyringGetter | None = None,
) -> str:
    """Fetch the account's password from the environment or the OS keyring."""
    ref = account.credential
    if ref.kind == "env":
        value = (os.environ if env is None else env).get(ref.name)
        if not value:
            raise CredentialMissing(
                f"environment variable {ref.name} (password of account {account.name!r}) is not set"
            )
        return value
    value = (keyring_get or _keyring_get)(KEYRING_SERVICE, ref.name)
    if not value:
        raise CredentialMissing(
            f"no password for account {account.name!r} in the OS keyring",
            hint=f"Store it with: keyring set {KEYRING_SERVICE} {ref.name}  "
            "(or set password_env in the config).",
        )
    return value
