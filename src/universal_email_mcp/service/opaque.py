"""Opaque, URL-safe identifiers: authenticated encryption under keys derived from the store ring.

Request logs of the platform in front of the service (load balancer, Cloud Run) record full
URLs. A message address such as ``/m/<id>`` must therefore not carry the mailbox name, folder
name or UID in a form anybody with access to the logs can read, and the short-lived address of
the HTML view on the content origin must not carry the user id. :class:`SealBox` turns such
a payload into a short token that reveals nothing and cannot be forged.

Construction: AES-256-GCM with a *synthetic* nonce (``HMAC-SHA256(iv key, aad || payload)``
truncated to 96 bits), so the same payload always yields the same token (stable links; the
nonce repeats only for identical payloads, where it leaks nothing but equality). Encryption and
nonce keys are derived from the key given by the caller with distinct labels. Several keys are
accepted for opening (key rotation), the first is used for sealing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from collections.abc import Callable, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from universal_email_mcp.b64 import b64u, unb64u

_NONCE = 12
_TAG = 16
MAX_TOKEN_LEN = 8192


def _sub(key: bytes, label: bytes) -> bytes:
    return hmac.new(key, b"uem-sealbox\0" + label, hashlib.sha256).digest()


class SealBox:
    """Seal and open short payloads. ``keys`` are 32-byte secrets (already domain-separated
    by the caller, e.g. ``KeyRing.derive("viewer-id-v1")``); the first one seals."""

    def __init__(self, keys: Sequence[bytes]) -> None:
        if not keys:
            raise ValueError("a SealBox needs at least one key")
        self._keys = [(AESGCM(_sub(k, b"enc")), _sub(k, b"iv")) for k in keys]

    def seal(self, payload: bytes, aad: bytes = b"") -> str:
        aead, iv_key = self._keys[0]
        framed = len(aad).to_bytes(2, "big") + aad + payload
        nonce = hmac.new(iv_key, framed, hashlib.sha256).digest()[:_NONCE]
        return b64u(nonce + aead.encrypt(nonce, payload, aad))

    def open(self, token: str, aad: bytes = b"") -> bytes | None:
        """The payload, or ``None`` for anything that does not authenticate under ``aad``."""
        if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN_LEN:  # pyright: ignore[reportUnnecessaryIsInstance]
            return None
        try:
            raw = unb64u(token)
        except ValueError:
            return None
        if len(raw) < _NONCE + _TAG or b64u(raw) != token:  # one spelling per token
            return None
        for aead, _ in self._keys:
            try:
                return aead.decrypt(raw[:_NONCE], raw[_NONCE:], aad)
            except InvalidTag:
                continue
        return None


class ViewerIds:
    """The id in a viewer URL (``/m/<id>``): the message id, sealed and bound to the user
    whose portal session opens it (another user's link opens nothing)."""

    def __init__(self, keys: Sequence[bytes]) -> None:
        self._box = SealBox(keys)

    def seal(self, user_id: str, message_id: str) -> str:
        return self._box.seal(message_id.encode("utf-8"), user_id.encode("utf-8"))

    def open(self, user_id: str, sealed: str) -> str | None:
        raw = self._box.open(sealed, user_id.encode("utf-8"))
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None


LinkId = Callable[[str], str]
"""Turns a message id into the id used in links (see :class:`ViewerIds`)."""

CONTENT_TOKEN_TTL = 120.0
"""Seconds an address on the content origin lives, and the most a token may say it lives."""


class ContentTokens:
    """Short-lived addresses of the HTML view on the content origin (which never receives the
    portal cookie): user, message id, remote-images choice, expiry - all inside the sealed
    token, so the URL shows nothing. The expiry is also capped on the server: a token whose
    ``exp`` lies further ahead than ``ttl`` is refused, whoever made it."""

    def __init__(
        self,
        keys: Sequence[bytes] | None = None,
        *,
        ttl: float = CONTENT_TOKEN_TTL,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._box = SealBox(keys or [os.urandom(32)])
        self._ttl = ttl
        self._clock = clock

    def issue(self, user_id: str, message_id: str, remote_images: bool) -> str:
        data = [user_id, message_id, int(remote_images), int(self._clock() + self._ttl)]
        return self._box.seal(json.dumps(data, separators=(",", ":")).encode("utf-8"), b"content")

    def verify(self, token: str) -> tuple[str, str, bool] | None:
        raw = self._box.open(token, b"content")
        if raw is None:
            return None
        try:
            user_id, message_id, images, exp = json.loads(raw)
            now = self._clock()
            if not (isinstance(user_id, str) and isinstance(message_id, str)):
                return None
            if isinstance(exp, bool) or not isinstance(exp, int | float):
                return None
            if not (now < exp <= now + self._ttl + 1):  # also rejects NaN
                return None
            return user_id, message_id, bool(images)
        except (ValueError, TypeError):
            return None
