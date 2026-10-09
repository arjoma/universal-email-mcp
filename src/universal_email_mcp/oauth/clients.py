"""OAuth clients: Client ID Metadata Documents (CIMD) and Dynamic Client Registration.

* **CIMD** - the ``client_id`` is an https URL; the JSON document behind it names the
  client and its redirect URIs. It is fetched SSRF-safe (:mod:`.fetch`), must repeat its own
  URL as ``client_id``, may not use a client secret, and is cached in the store for
  ``cimd_cache_ttl`` (default one hour), so a changed document takes effect after that.
* **DCR** (RFC 7591) - fallback for clients without a metadata document. Public clients
  only, minimal metadata (name, redirect URIs), no secret is ever issued. Registration is
  open but rate limited, and the operator may restrict the redirect hosts. Registered
  clients expire when unused (store policy).

Everything in a client's metadata is attacker-controlled. Only the name is ever shown (cleaned
and escaped by the template); logos, client URIs and the like are ignored and never fetched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import unicodedata
from dataclasses import dataclass, replace
from typing import Any

from universal_email_mcp.jsonlog import log_event
from universal_email_mcp.oauth.config import OAuthConfig
from universal_email_mcp.oauth.fetch import (
    FetchError,
    FetchPolicy,
    check_document_url,
    fetch_document,
)
from universal_email_mcp.oauth.ratelimit import RateLimiter, ip_group
from universal_email_mcp.oauth.redirects import RedirectError, host_allowed, validate_redirect_uri
from universal_email_mcp.store import AlreadyExists, OAuthClient, Store, StoreConflict

log = logging.getLogger(__name__)

MAX_NAME = 100
MAX_REDIRECT_URIS = 10
MAX_CONCURRENT_FETCHES = 8
ALLOWED_GRANT_TYPES = frozenset({"authorization_code", "refresh_token"})
_BIDI_AND_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁩﻿]")


class ClientError(Exception):
    """The client cannot be used. ``detail`` is for the log, ``str(self)`` may be shown."""

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail or message


class RegistrationError(Exception):
    def __init__(self, error: str, description: str) -> None:
        super().__init__(description)
        self.error = error
        self.description = description


@dataclass(frozen=True, slots=True)
class ClientInfo:
    id: str
    name: str
    redirect_uris: tuple[str, ...]
    registration: str
    """``cimd`` or ``dcr``."""


def clean_text(value: object, limit: int = MAX_NAME) -> str:
    """A short single-line label: control, bidi and zero-width characters removed."""
    if not isinstance(value, str):
        return ""
    text = _BIDI_AND_INVISIBLE.sub("", value)
    text = "".join(" " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else c for c in text)
    return " ".join(text.split())[:limit]


def _redirect_list(raw: object, *, strict_hosts: tuple[str, ...] = ()) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("redirect_uris must be a non-empty list")
    items: list[object] = list(raw)  # pyright: ignore[reportUnknownArgumentType]
    if len(items) > MAX_REDIRECT_URIS:
        raise ValueError(f"at most {MAX_REDIRECT_URIS} redirect URIs")
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError("redirect URIs must be strings")
        try:
            uri = validate_redirect_uri(item)
        except RedirectError as e:
            raise ValueError(str(e)) from None
        if not host_allowed(uri, strict_hosts):
            raise ValueError("this redirect host is not allowed for registered clients")
        if uri not in out:
            out.append(uri)
    return tuple(out)


def _check_common(meta: dict[str, Any]) -> None:
    """Public clients only; no secrets; the authorization-code flow must be wanted."""
    method = meta.get("token_endpoint_auth_method", "none")
    if method != "none":
        raise ValueError("only public clients (token_endpoint_auth_method none) are supported")
    for secret in ("client_secret", "client_secret_expires_at", "jwks", "jwks_uri"):
        if secret in meta:
            raise ValueError(f"{secret} is not supported")
    grants = meta.get("grant_types")
    if grants is not None:
        if not isinstance(grants, list) or not all(isinstance(g, str) for g in grants):  # pyright: ignore[reportUnknownVariableType]
            raise ValueError("grant_types must be a list of strings")
        names = set(grants)  # pyright: ignore[reportUnknownArgumentType]
        if "authorization_code" not in names or not names <= ALLOWED_GRANT_TYPES:
            raise ValueError("grant_types must be authorization_code (and refresh_token)")
    types = meta.get("response_types")
    if types is not None and types != ["code"]:
        raise ValueError("response_types must be [code]")


def parse_client_document(client_id: str, body: bytes) -> tuple[str, tuple[str, ...]]:
    """Validate a CIMD document; returns ``(name, redirect_uris)``."""
    try:
        meta = json.loads(body)
    except (ValueError, RecursionError):
        raise ClientError("The client's metadata document is not valid JSON.") from None
    if not isinstance(meta, dict):
        raise ClientError("The client's metadata document is not a JSON object.")
    doc: dict[str, Any] = meta  # pyright: ignore[reportUnknownVariableType]
    try:
        if doc.get("client_id") != client_id:
            raise ValueError("client_id does not match the document URL")
        _check_common(doc)
        redirects = _redirect_list(doc.get("redirect_uris"))
    except ValueError as e:
        raise ClientError("The client's metadata document is not acceptable.", str(e)) from None
    return clean_text(doc.get("client_name")), redirects


def parse_registration(body: object, cfg: OAuthConfig) -> tuple[str, tuple[str, ...]]:
    """Validate an RFC 7591 request body; returns ``(name, redirect_uris)``."""
    if not isinstance(body, dict):
        raise RegistrationError("invalid_client_metadata", "the body must be a JSON object")
    meta: dict[str, Any] = body  # pyright: ignore[reportUnknownVariableType]
    try:
        redirects = _redirect_list(meta.get("redirect_uris"), strict_hosts=cfg.dcr_redirect_hosts)
    except ValueError as e:
        raise RegistrationError("invalid_redirect_uri", str(e)) from None
    try:
        _check_common(meta)
    except ValueError as e:
        raise RegistrationError("invalid_client_metadata", str(e)) from None
    return clean_text(meta.get("client_name")), redirects


class ClientRegistry:
    def __init__(
        self,
        store: Store,
        cfg: OAuthConfig,
        fetch_policy: FetchPolicy | None = None,
        *,
        fetch_limiter: RateLimiter | None = None,
    ) -> None:
        self._store = store
        self._cfg = cfg
        self._fetch_policy = fetch_policy or FetchPolicy()
        self._fetch_limiter = fetch_limiter
        self._sem = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    @staticmethod
    def is_document_id(client_id: str) -> bool:
        return client_id.startswith("https://")

    async def resolve(self, client_id: str, *, ip: str = "") -> ClientInfo:
        """The client for an authorization request. Raises :class:`ClientError`."""
        if self.is_document_id(client_id):
            return await self._resolve_document(client_id, ip)
        rec = await self._store.get(OAuthClient, client_id) if len(client_id) <= 128 else None
        if rec is None or rec.registration != "dcr":
            raise ClientError("This client is not registered.")
        rec = await self._store.touch_client(rec)
        return ClientInfo(rec.id, rec.name, rec.redirect_uris, "dcr")

    async def _resolve_document(self, client_id: str, ip: str) -> ClientInfo:
        try:
            check_document_url(client_id)
        except FetchError as e:
            raise ClientError("The client identifier is not acceptable.", str(e)) from None
        cached = await self._store.get(OAuthClient, client_id)
        if cached is not None and cached.registration == "cimd":
            return ClientInfo(cached.id, cached.name, cached.redirect_uris, "cimd")
        if self._fetch_limiter is not None and not self._fetch_limiter.allow(ip_group(ip)):
            raise ClientError(
                "Too many requests. Please try again in a minute.", "fetch rate limit"
            )
        try:
            async with self._sem:
                body = await asyncio.to_thread(fetch_document, client_id, self._fetch_policy)
        except FetchError as e:
            raise ClientError(
                "The client's metadata document could not be fetched.", str(e)
            ) from None
        name, redirects = parse_client_document(client_id, body)
        now = self._store.now()
        rec = OAuthClient(
            id=client_id,
            name=name,
            redirect_uris=redirects,
            registration="cimd",
            created_at=now,
            last_used=now,
            expires_at=now + self._cfg.cimd_cache_ttl,
        )
        await self._save(rec)
        return ClientInfo(client_id, name, redirects, "cimd")

    async def _save(self, rec: OAuthClient) -> None:
        for _ in range(3):
            try:
                await self._store.create(rec)
                return
            except AlreadyExists:
                # an expired copy still occupies the id (or another request won the race)
                live = await self._store.get(OAuthClient, rec.id)
                if live is not None and live.registration == "cimd":
                    return
                try:
                    await self._store.delete(OAuthClient, rec.id)
                except StoreConflict:  # pragma: no cover - delete is unconditional
                    pass
        log_event(log, logging.WARNING, "could not cache client document", event="cimd_cache")

    async def register(self, name: str, redirect_uris: tuple[str, ...]) -> ClientInfo:
        client_id = "dcr_" + secrets.token_urlsafe(18)
        rec = await self._store.register_client(
            client_id, name=name, redirect_uris=redirect_uris, registration="dcr"
        )
        return ClientInfo(rec.id, rec.name, rec.redirect_uris, "dcr")


__all__ = [
    "ClientError",
    "ClientInfo",
    "ClientRegistry",
    "RegistrationError",
    "clean_text",
    "parse_client_document",
    "parse_registration",
    "replace",
]
