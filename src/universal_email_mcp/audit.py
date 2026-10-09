"""Audit events (design section 9): the one pipeline for "what happened".

Every event is a single JSON line with a fixed shape::

    {"event":"tool.call","message":"tool.call","severity":"INFO","ts":1760000000.123,
     "instance":"rev-7","request_id":"...","user":"u_3f9a1c2e7b4d","client":"c_...",
     "account":"a_...","outcome":"ok","tool":"find_messages","dur":"<1s",...}

* Written to **stdout** in ``serve`` mode (Cloud Run / Cloud Logging reads ``severity``),
  to **stderr** in local stdio mode (stdout carries the MCP protocol there).
* Events describe *what happened*, never *what was in it*. A per-event **allow-list**
  (:data:`EVENTS`) names the fields an event may carry; every field has a *kind*
  (:data:`FIELDS`) that validates the value. A value that does not fit is replaced by
  ``"invalid"`` (strict mode, used by the tests: an error), a field that is not allowed
  is dropped. So even a call site that passes mail text by mistake cannot leak it:
  tokens cannot contain ``@``, spaces, ``/`` or ``:`` and are at most 24-character words.
* Identifiers are **pseudonyms**: ``user`` is the short form of the (already keyed)
  user id; ``client``, ``account``, ``grant``, ``identity`` and ``approval`` become
  ``<letter>_<12 hex>`` of an HMAC-SHA256 under the pseudonym key (``PSEUDONYM_KEY`` in
  remote mode, a per-install key in local mode). Callers pass the raw ids; they never
  reach the log. Names the user chose (accounts, clients) are not logged at all.
* IP addresses are never logged in clear. Only with ``AUDIT_LOG_CLIENT_IP`` an ``ip``
  field (sign-in and rate-limit events) carries the keyed pseudonym of the *network*
  (IPv4 /24, IPv6 /48), enough to see "many failures from one place".

``record()`` is ``event()`` plus the user's own-activity feed (see :func:`configure_feed`):
the same facts, with ids instead of pseudonyms, stored per user for the portal's
"Activity" page. ``event()`` alone is for contexts without a user (or without a loop).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sys
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TextIO

LOGGER_NAME = "universal_email_mcp.audit"
log = logging.getLogger(LOGGER_NAME)
_internal = logging.getLogger("universal_email_mcp.audit_internal")

FEED_TIMEOUT = 3.0
"""Seconds a feed write may take before the request goes on without it."""

INVALID = "invalid"

_TOKEN = re.compile(r"[A-Za-z0-9_<>=+-]{1,24}(\.[A-Za-z0-9_<>=+-]{1,24}){0,2}")
_INSTANCE = re.compile(r"[A-Za-z0-9_-]{1,63}")
_USER = re.compile(r"u_[0-9a-f]{8,64}")


class AuditSchemaError(ValueError):
    """An event, field or value outside the allow-list (strict mode only)."""


# --------------------------------------------------------------------- field kinds

# kind -> how the value is checked / transformed
#   user   a user id (already a keyed pseudonym); logged as its first 14 characters
#   ref:X  a raw id (client id, account id ...), logged as X_<hmac>
#   tok    short token: up to three dot-separated words of letters, digits and _<>=+-
#          (no spaces, '@', '/', ':'; an IP address or a URL is not a token)
#   words  up to 12 tokens separated by single spaces (scopes, permissions)
#   int    non-negative integer
#   bool   boolean
#   counts mapping token -> non-negative integer
#   ip     IP address, logged as the pseudonym of its network (only if enabled)
FIELDS: dict[str, str] = {
    "user": "user",
    "client": "ref:c",
    "account": "ref:a",
    "grant": "ref:g",
    "identity": "ref:i",
    "approval": "ref:p",
    "ip": "ip",
    "outcome": "tok",
    "reason": "tok",
    "code": "tok",
    "tool": "tok",
    "area": "tok",
    "scope": "words",
    "permissions": "words",
    "grant_type": "tok",
    "token_type": "tok",
    "kind": "tok",
    "family": "tok",
    "protocol": "tok",
    "mode": "tok",
    "size": "tok",
    "dur": "tok",
    "error": "tok",
    "recipients": "counts",
    "deleted": "counts",
    "accounts": "int",
    "grants": "int",
    "identities": "int",
    "attachments": "int",
    "messages": "int",
    "lines": "int",
    "succeeded": "int",
    "unchanged": "int",
    "failed": "int",
    "planned": "int",
    "html": "bool",
    "complete": "bool",
    "done": "bool",
    "can_send": "bool",
    "with_identity": "bool",
}

COMMON = frozenset({"user", "client", "account", "outcome", "code"})


@dataclass(frozen=True, slots=True)
class Spec:
    fields: frozenset[str] = frozenset()
    severity: str = "INFO"
    """Default severity. ``"outcome"`` means: INFO for ``outcome`` in :data:`GOOD`, else WARNING."""
    feed: bool = False
    """Does the event reach the user's own-activity feed (when it has a user)?"""
    feed_if: tuple[str, str] | None = None
    """Feed only when ``outcome`` equals this value (``("outcome", "ok")``)."""


GOOD = frozenset({"ok", "approved", "accepted"})


def _s(*names: str, severity: str = "INFO", feed: bool = False, feed_if: str | None = None) -> Spec:
    return Spec(
        frozenset(names),
        severity,
        feed,
        ("outcome", feed_if) if feed_if is not None else None,
    )


SEND_FIELDS = ("recipients", "attachments", "size", "mode", "grant")

EVENTS: dict[str, Spec] = {
    # --- authentication (OAuth server and portal sign-in)
    "auth.sign_in": _s("ip", severity="outcome", feed=True, feed_if="ok"),
    "auth.csrf_failed": _s("area", severity="WARNING"),
    "auth.consent": _s(
        "scope", "accounts", "grant", severity="outcome", feed=True, feed_if="approved"
    ),
    "auth.client_refused": _s(severity="WARNING"),
    "auth.redirect_refused": _s(severity="WARNING"),
    "auth.register": _s(),
    "auth.token": _s("grant_type", "grant", severity="outcome"),
    "auth.code_replay": _s(severity="WARNING"),
    "auth.revoke": _s("token_type", "grant", feed=True),
    "portal.reauth": _s("reason", "ip", severity="outcome"),
    "ratelimit.hit": _s("scope", "ip", "grant", severity="WARNING"),
    # --- portal changes
    "portal.account_add": _s("protocol", "with_identity", feed=True),
    "portal.account_test": _s(severity="outcome", feed=True),
    "portal.account_permissions": _s("permissions", feed=True),
    "portal.account_password": _s(feed=True),
    "portal.account_remove": _s("grants", "identities", feed=True),
    "portal.identity_add": _s("identity", "can_send", feed=True),
    "portal.identity_edit": _s("identity", "can_send", feed=True),
    "portal.identity_remove": _s("identity", "grants", feed=True),
    "portal.identity_test": _s("identity", severity="outcome", feed=True),
    "portal.grant_edit": _s("grant", "scope", feed=True),
    "portal.grant_revoke": _s("grant", feed=True),
    "portal.export": _s("accounts", "identities", "grants", feed=True),
    "portal.delete_all": _s("deleted"),  # no feed: the user's feed is deleted with them
    # --- tool calls (OAuth mode)
    "tool.call": _s(
        "tool",
        "dur",
        "grant",
        "accounts",
        "succeeded",
        "unchanged",
        "failed",
        "planned",
        severity="outcome",
        feed=True,
    ),  # fmt: skip
    # --- sends
    "send.requested": _s(*SEND_FIELDS),
    "send.confirmed": _s(*SEND_FIELDS),
    "send.declined": _s(*SEND_FIELDS, severity="WARNING", feed=True),
    "send.draft_kept": _s(*SEND_FIELDS, "reason", feed=True),
    "send.fallback_send": _s(*SEND_FIELDS),
    "send.approval_requested": _s(*SEND_FIELDS, "approval", feed=True),
    "send.replay_refused": _s(*SEND_FIELDS, severity="WARNING"),
    "send.failed": _s(*SEND_FIELDS, severity="ERROR", feed=True),
    "send.sent": _s(*SEND_FIELDS),  # the feed entry "send" is written with the rate limit
    "approval.rejected": _s("approval", "grant", "done", feed=True),
    "approval.refused": _s("approval", "grant", "reason", severity="WARNING", feed=True),
    "approval.approved": _s("approval", "grant", feed=True),
    "approval.send_failed": _s("approval", "grant", severity="ERROR"),  # feed: send.failed
    "approval.expired_use": _s("approval", severity="WARNING"),
    # --- viewer
    "viewer.open": _s("kind", "html", "attachments", "messages", "size", feed=True),
    "viewer.raw": _s("kind", "lines", "size", "family", "complete", feed=True),
    "attachment.download": _s("kind", "size", "family", "complete", feed=True),
    # --- the pipeline itself
    "audit.invalid": _s("reason", severity="ERROR"),
}
TOOL_FEED_SKIP = frozenset({"send_message"})
"""Tools whose use is already in the feed through their own entries (``send``)."""

READ_TOOLS = frozenset(
    {
        "account_info",
        "list_folders",
        "find_messages",
        "get_message",
        "get_attachment",
        "find_contacts",
    }  # fmt: skip
)
"""Read-only tools: their feed entries are merged per hour (one entry, a call counter)."""

WRITE_TOOLS = frozenset(
    {
        "mark_messages",
        "move_messages",
        "create_folder",
        "delete_messages",
        "save_draft",
        "send_message",
    }  # fmt: skip
)


# --------------------------------------------------------------------- configuration


@dataclass(slots=True)
class _State:
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)
    instance: str = ""
    log_ip: bool = False
    strict: bool = False
    feed: Callable[..., Awaitable[Any]] | None = None


_state = _State()


def configure(
    *,
    key: bytes | None = None,
    instance: str | None = None,
    log_ip: bool | None = None,
    strict: bool | None = None,
) -> None:
    """Set the pseudonym key (at least 16 bytes) and options. Without a key an ephemeral
    random one is used: pseudonyms are then stable only within the process."""
    if key is not None:
        if len(key) < 16:
            raise ValueError("the audit key needs at least 16 bytes")
        _state.key = key
    if instance is not None:
        _state.instance = instance if _INSTANCE.fullmatch(instance) else INVALID
    if log_ip is not None:
        _state.log_ip = log_ip
    if strict is not None:
        _state.strict = strict


def configure_feed(sink: Callable[..., Awaitable[Any]] | None) -> None:
    """Attach (or with ``None`` detach) the own-activity feed writer."""
    _state.feed = sink


def is_strict() -> bool:
    return _state.strict


def reset() -> None:
    """Back to the defaults (tests)."""
    global _state
    _state = _State()


def local_key(directory: str | os.PathLike[str] | None = None) -> bytes:
    """The per-install key of local mode: created once (mode 0600) in the user's state
    directory. If that fails (read-only home ...), a throw-away key for this process."""
    try:
        if directory is None:
            from platformdirs import user_state_dir

            directory = user_state_dir("universal-email-mcp")
        path = os.path.join(directory, "audit.key")
        os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            with open(path, "rb") as f:
                data = f.read()
            if len(data) >= 16:
                return data
        except FileNotFoundError:
            pass
        # Write a complete private file first, then publish it atomically: a concurrent
        # process sees either no key or the whole key, never half of it. A damaged file
        # (too short) is replaced.
        key = secrets.token_bytes(32)
        tmp = f"{path}.{secrets.token_hex(4)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        try:
            os.link(tmp, path)
        except FileExistsError:
            with open(path, "rb") as f:
                data = f.read()
            if len(data) >= 16:
                return data
            os.replace(tmp, path)
            return key
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return key
    except OSError:
        return secrets.token_bytes(32)


def setup(stream: TextIO | None = None) -> None:
    """Send audit events to ``stream`` (default stderr), independent of ``-v``.

    ``serve`` passes stdout (Cloud Logging); local stdio mode must keep the default,
    because stdout is the MCP protocol there. Idempotent; a second call re-targets."""
    for h in list(log.handlers):
        if getattr(h, "_uem_audit", False):
            log.removeHandler(h)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler._uem_audit = True  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False


# --------------------------------------------------------------------- building events


def size_bucket(n: int) -> str:
    for limit, label in (
        (10_000, "<10k"),
        (100_000, "<100k"),
        (1_000_000, "<1M"),
        (10_000_000, "<10M"),
    ):
        if n < limit:
            return label
    return ">=10M"


def duration_bucket(seconds: float) -> str:
    for limit, label in ((0.1, "<100ms"), (1.0, "<1s"), (5.0, "<5s"), (30.0, "<30s")):
        if seconds < limit:
            return label
    return ">=30s"


def pseudonym(prefix: str, raw: str, key: bytes | None = None) -> str:
    """The logged pseudonym of ``raw`` in namespace ``prefix`` (``c``, ``a``, ``g``, ``i``,
    ``p``, ``n``); ``key`` defaults to the configured one. Used by the ``audit`` CLI."""
    mac = hmac.new(
        _state.key if key is None else key,
        f"uem-audit-v1\0{prefix}\0{raw}".encode(),
        hashlib.sha256,
    )
    return f"{prefix}_{mac.hexdigest()[:12]}"


def network_of(raw: str) -> str | None:
    """The network (IPv4 /24, IPv6 /48) whose pseudonym is logged for ``raw``."""
    try:
        addr = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    net = ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 48}", strict=False)
    return str(net)


def _bad(strict: bool, what: str) -> None:
    if strict:
        raise AuditSchemaError(what)


def _convert(name: str, kind: str, value: Any, strict: bool) -> Any:
    """The logged form of ``value``; ``None`` = leave the field out."""
    if kind == "user":
        if isinstance(value, str) and _USER.fullmatch(value):
            return value[:14]
        if isinstance(value, str) and value:
            _bad(strict, f"field {name}: not a user id")
            return pseudonym("u", value)
        return None
    if kind.startswith("ref:"):
        if isinstance(value, str) and value:
            return pseudonym(kind[4:], value)
        return None
    if kind == "ip":
        if not _state.log_ip:
            return None
        net = network_of(value) if isinstance(value, str) else None
        return pseudonym("n", net) if net else None
    if kind == "tok":
        if isinstance(value, str) and _TOKEN.fullmatch(value):
            return value
        _bad(strict, f"field {name}: not a short token")
        return INVALID
    if kind == "words":
        if isinstance(value, str) and value == "":
            return ""
        parts = value.split(" ") if isinstance(value, str) else []
        if 0 < len(parts) <= 12 and all(_TOKEN.fullmatch(p) for p in parts):
            return value
        _bad(strict, f"field {name}: not a list of tokens")
        return INVALID
    if kind == "int":
        if type(value) is int and value >= 0:
            return value
        _bad(strict, f"field {name}: not a count")
        return None
    if kind == "bool":
        if type(value) is bool:
            return value
        _bad(strict, f"field {name}: not a flag")
        return None
    if kind == "counts":
        if isinstance(value, Mapping) and all(
            isinstance(k, str) and _TOKEN.fullmatch(k) and type(v) is int and v >= 0
            for k, v in value.items()  # pyright: ignore[reportUnknownVariableType]
        ):
            return dict(value)  # pyright: ignore[reportUnknownArgumentType]
        _bad(strict, f"field {name}: not a mapping of counts")
        return None
    raise AssertionError(kind)  # pragma: no cover


def _build(name: str, fields: Mapping[str, Any]) -> tuple[dict[str, Any], Spec | None]:
    strict = _state.strict
    spec = EVENTS.get(name)
    if spec is None:
        _bad(strict, f"unknown audit event {name!r}")
        payload: dict[str, Any] = {"event": "audit.invalid", "reason": "unknown_event"}
        spec = EVENTS["audit.invalid"]
        fields = {}
        feed_spec = None
    else:
        payload = {"event": name}
        feed_spec = spec
    allowed = spec.fields | COMMON
    for key, raw in fields.items():
        if raw is None:
            continue
        if key not in allowed or key not in FIELDS:
            _bad(strict, f"event {name}: field {key!r} is not allowed")
            continue
        out = _convert(key, FIELDS[key], raw, strict)
        if out is not None:
            payload[key] = out
    sev = spec.severity
    if sev == "outcome":
        sev = "INFO" if payload.get("outcome", "ok") in GOOD else "WARNING"
    # imported lazily: jsonlog is the HTTP server's module
    from universal_email_mcp.jsonlog import request_id_var

    payload["message"] = payload["event"]
    payload["severity"] = sev
    payload["ts"] = round(time.time(), 3)
    if _state.instance:
        payload["instance"] = _state.instance
    rid = request_id_var.get()
    if rid:
        payload["request_id"] = rid
    return payload, feed_spec


def _emit(payload: Mapping[str, Any]) -> None:
    line = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    level = {"WARNING": logging.WARNING, "ERROR": logging.ERROR}.get(
        str(payload.get("severity")), logging.INFO
    )
    log.log(level, line)


def event(name: str, **fields: Any) -> None:
    """Log one event. Callers pass raw ids (user id, client id, account id ...), counts,
    buckets and outcome codes - see :data:`EVENTS` for what each event may carry."""
    payload, _ = _build(name, fields)
    _emit(payload)


async def record(name: str, /, *, coalesce: bool = False, **fields: Any) -> None:
    """:func:`event` plus the own-activity feed entry of the user (when the event is a
    feed event, a feed is attached and the event names a user). Never raises because of
    the feed: the audit trail must not break the action it describes."""
    payload, spec = _build(name, fields)
    _emit(payload)
    sink = _state.feed
    raw_user = fields.get("user")
    if sink is None or spec is None or not spec.feed or not isinstance(raw_user, str):
        return
    if spec.feed_if is not None and fields.get(spec.feed_if[0]) != spec.feed_if[1]:
        return
    if not raw_user or payload["event"] != name:
        return
    tool = payload.get("tool", "")
    if name == "tool.call" and tool in TOOL_FEED_SKIP:
        return
    counts: dict[str, int] = {}
    for k, v in payload.items():
        if type(v) is int and k not in ("ts",) and FIELDS.get(k) == "int":
            counts[k] = v
    rec = payload.get("recipients")
    if isinstance(rec, dict):
        counts.update({f"to_{k}": v for k, v in rec.items()})  # pyright: ignore[reportUnknownVariableType]
    client = fields.get("grant") if isinstance(fields.get("grant"), str) else ""
    account = fields.get("account") if isinstance(fields.get("account"), str) else ""
    try:
        await asyncio.wait_for(
            sink(
                raw_user,
                name,
                client=_clip(client),
                tool=str(tool),
                account=_clip(account),
                outcome=str(payload.get("outcome", "")),
                counts=counts,
                coalesce=coalesce,
            ),
            FEED_TIMEOUT,
        )
    except Exception as e:  # incl. timeout and store errors
        if _state.strict and not isinstance(e, TimeoutError):
            raise
        _internal.warning("activity entry not stored: %s", type(e).__name__)


def _clip(text: Any) -> str:
    return text[:64] if isinstance(text, str) and "@" not in text else ""
