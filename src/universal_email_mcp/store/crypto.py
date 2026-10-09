"""Encryption of stored secrets and hashing of bearer tokens.

**Blobs.** ``seal()`` produces a text blob ``e1.<key id>.<base64url(nonce || ciphertext+tag)>``:
``e1`` is the format version, the key id names the ring key that sealed it, the payload is
AES-256-GCM with a fresh random 96-bit nonce. The *associated data* (AAD) binds the blob to
its place: format version, key id, owner user id, record kind, record id and field name.
A blob copied to another record, user or field therefore fails authentication, as does any
change of the ciphertext, the nonce, the key id or the format version.

**Key ring.** Versioned 32-byte keys (``k1``, ``k2`` ...); exactly one is *active* (used to
encrypt), all of them decrypt. Rotation: add ``k2``, make it active, deploy; old blobs still
open with ``k1`` and are re-sealed with ``k2`` whenever their record is written. ``rotate_keys()``
in :mod:`universal_email_mcp.store.rotation` rewrites every record eagerly so that ``k1`` can be
removed afterwards. Key material comes from the environment or secret mounts
(see :meth:`KeyRing.from_env`) and never appears in ``repr`` or error messages.

**Tokens.** Bearer tokens are 256-bit random strings (``secrets``); the store keeps only their
SHA-256 digest, which is sufficient because the input is high-entropy (no salt or slow hash
needed). Comparisons use ``hmac.compare_digest``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from universal_email_mcp.errors import ConfigError, MailError

FORMAT = "e1"
KEY_BYTES = 32
_NONCE_BYTES = 12
_KEY_ID_RE = re.compile(r"^k[1-9][0-9]{0,5}$")


class CryptoError(MailError):
    """A blob cannot be opened (tampered, wrong place, unknown key). Never carries key material."""

    code = "STORE_CRYPTO"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _key_number(key_id: str) -> int:
    return int(key_id[1:])


@dataclass(frozen=True, slots=True)
class Aad:
    """Where a blob lives: owner, record kind, record id, field."""

    user_id: str
    kind: str
    record_id: str
    field: str

    def encode(self, key_id: str) -> bytes:
        return json.dumps(
            [FORMAT, key_id, self.user_id, self.kind, self.record_id, self.field],
            separators=(",", ":"),
        ).encode()


class KeyRing:
    """Versioned AES-256 keys; one active for sealing, all for opening."""

    def __init__(self, keys: Mapping[str, bytes], active: str | None = None) -> None:
        if not keys:
            raise ConfigError("the store key ring is empty", hint="Set STORE_KEYS.")
        for key_id, key in keys.items():
            if not _KEY_ID_RE.match(key_id):
                raise ConfigError(
                    f"invalid store key id {key_id!r} (expected k1, k2, ...; no leading zeros)"
                )
            if len(key) != KEY_BYTES:
                raise ConfigError(f"store key {key_id} must be exactly {KEY_BYTES} bytes")
        self._aead = {k: AESGCM(v) for k, v in keys.items()}
        self.active = active or max(keys, key=_key_number)
        if self.active not in keys:
            raise ConfigError(f"active store key {self.active!r} is not in the key ring")

    def __repr__(self) -> str:
        return f"KeyRing(keys={list(self.key_ids)}, active={self.active!r})"

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._aead, key=_key_number))

    @classmethod
    def generate_key(cls) -> str:
        """A fresh key as base64 text (for ``STORE_KEYS``)."""
        return base64.b64encode(os.urandom(KEY_BYTES)).decode("ascii")

    @classmethod
    def parse(cls, text: str, active: str | None = None) -> KeyRing:
        """Parse ``k1=<base64>,k2=<base64>`` (commas or newlines; ``#`` comment lines)."""
        keys: dict[str, bytes] = {}
        for raw in re.split(r"[,\n]", text):
            item = raw.strip()
            if not item or item.startswith("#"):
                continue
            name, sep, b64 = item.partition("=")
            key_id = name.strip()
            if not sep:
                raise ConfigError("store keys must look like k1=<base64 of 32 bytes>")
            try:
                key = base64.b64decode(b64.strip(), validate=True)
            except (binascii.Error, ValueError):
                raise ConfigError(f"store key {key_id[:12]} is not valid base64") from None
            if key_id in keys:
                raise ConfigError(f"duplicate store key id {key_id[:12]}")
            keys[key_id] = key
        return cls(keys, active)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> KeyRing:
        """``STORE_KEYS`` (inline) or ``STORE_KEYS_FILE`` (secret mount), ``STORE_ACTIVE_KEY``.

        The active key defaults to the highest-numbered one.
        """
        env = os.environ if env is None else env
        inline = env.get("STORE_KEYS", "").strip()
        path = env.get("STORE_KEYS_FILE", "").strip()
        if bool(inline) == bool(path):
            raise ConfigError(
                "set exactly one of STORE_KEYS and STORE_KEYS_FILE",
                hint="Format: k1=<base64 of 32 random bytes>[,k2=...]",
            )
        if path:
            try:
                inline = Path(path).read_text()
            except OSError as e:
                raise ConfigError(f"cannot read STORE_KEYS_FILE: {e.strerror}") from None
        return cls.parse(inline, env.get("STORE_ACTIVE_KEY", "").strip() or None)

    def seal(self, plaintext: bytes, aad: Aad) -> str:
        nonce = os.urandom(_NONCE_BYTES)
        ct = self._aead[self.active].encrypt(nonce, plaintext, aad.encode(self.active))
        return f"{FORMAT}.{self.active}.{_b64u(nonce + ct)}"

    def key_id_of(self, blob: str) -> str:
        parts = blob.split(".")
        if len(parts) != 3 or parts[0] != FORMAT:
            raise CryptoError("unsupported blob format")
        return parts[1]

    def open(self, blob: str, aad: Aad) -> bytes:
        key_id = self.key_id_of(blob)
        aead = self._aead.get(key_id)
        if aead is None:
            raise CryptoError(f"blob was sealed with unknown key {key_id[:12]!r}")
        try:
            raw = _unb64u(blob.split(".")[2])
        except (binascii.Error, ValueError):
            raise CryptoError("blob is not valid base64") from None
        if len(raw) < _NONCE_BYTES + 16:
            raise CryptoError("blob is too short")
        try:
            return aead.decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], aad.encode(key_id))
        except InvalidTag:
            raise CryptoError(
                "blob failed authentication (tampered or in the wrong place)"
            ) from None

    def seal_json(self, value: Any, aad: Aad) -> str:
        return self.seal(json.dumps(value, separators=(",", ":"), sort_keys=True).encode(), aad)

    def open_json(self, blob: str, aad: Aad) -> Any:
        return json.loads(self.open(blob, aad))

    def needs_rotation(self, blob: str) -> bool:
        return self.key_id_of(blob) != self.active


# --- bearer tokens -----------------------------------------------------------------------


def new_token(prefix: str) -> str:
    """A fresh 256-bit token, e.g. ``uem_at_<43 url-safe chars>``."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_token(token: str) -> str:
    """The SHA-256 hex digest that identifies a token in the store."""
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
