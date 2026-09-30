"""Opaque, tamper-evident paging cursors.

A cursor carries the paging position of a multi-account, multi-folder listing:
per source ``(account, folder)`` its UIDVALIDITY, how many messages were already
returned, the last UID returned (the next page resumes right after it in a fresh
SEARCH, so expunged messages cannot shift the position), and the highest UID seen
on the first page (newer arrivals are left out of later pages). It is bound to the tool and a hash of
the query arguments, and signed with HMAC-SHA256.

The key is per process in local mode (cursors die with the process — fine for a
paging session); remote mode passes a shared key so any instance can continue.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

from universal_email_mcp.errors import InvalidCursor

_PREFIX = "c1."
_MAX_LEN = 16_384
_MAC_LEN = 16


@dataclass(frozen=True, slots=True)
class SourcePos:
    """Position within one ``(account, folder)`` source."""

    uidvalidity: int
    offset: int
    max_uid: int
    """Highest UID of the first page's snapshot (0 = no limit)."""
    last_uid: int = 0
    """Last UID passed in this source (0 = none yet): the next page starts after it."""


@dataclass(frozen=True, slots=True)
class Cursor:
    tool: str
    query: str
    """Hash of the query arguments the cursor belongs to."""
    sources: dict[tuple[str, str], SourcePos] = field(
        default_factory=dict[tuple[str, str], SourcePos]
    )
    offset: int = 0
    """Offset into a ranked (fuzzy / contact) result list."""
    retries: int = 0
    """Consecutive pages issued only to retry failed accounts (capped)."""


def query_hash(args: Mapping[str, Any]) -> str:
    """Stable short hash of tool arguments (cursor excluded by the caller)."""
    blob = json.dumps(args, sort_keys=True, default=str, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class CursorCodec:
    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or secrets.token_bytes(32)

    def _mac(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()[:_MAC_LEN]

    def encode(self, cursor: Cursor) -> str:
        data = {
            "t": cursor.tool,
            "q": cursor.query,
            "o": cursor.offset,
            "r": cursor.retries,
            "s": [
                [acc, folder, p.uidvalidity, p.offset, p.max_uid, p.last_uid]
                for (acc, folder), p in sorted(cursor.sources.items())
            ],
        }
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return _PREFIX + _b64(payload) + "." + _b64(self._mac(payload))

    def decode(self, text: str, *, tool: str, query: str) -> Cursor:
        """Verify and decode; raises :class:`InvalidCursor` for anything wrong,
        including a cursor from another tool or other arguments."""
        if not isinstance(text, str) or not text.startswith(_PREFIX) or len(text) > _MAX_LEN:
            raise InvalidCursor("not a cursor from this server")
        try:
            body, mac = text[len(_PREFIX) :].split(".", 1)
            payload, mac_bytes = _unb64(body), _unb64(mac)
        except (ValueError, binascii.Error) as e:
            raise InvalidCursor("cursor is corrupted") from e
        if not hmac.compare_digest(mac_bytes, self._mac(payload)):
            raise InvalidCursor(
                "cursor signature is invalid (tampered, or issued before a server restart)"
            )
        try:
            data = cast(dict[str, Any], json.loads(payload.decode("utf-8")))
            sources: dict[tuple[str, str], SourcePos] = {}
            for acc, folder, uv, off, mx, last in cast(list[list[Any]], data["s"]):
                sources[(str(acc), str(folder))] = SourcePos(int(uv), int(off), int(mx), int(last))
            cur = Cursor(
                tool=str(data["t"]),
                query=str(data["q"]),
                sources=sources,
                offset=int(data["o"]),
                retries=int(data.get("r", 0)),
            )
        except (ValueError, KeyError, TypeError) as e:
            raise InvalidCursor("cursor is corrupted") from e
        if cur.tool != tool:
            raise InvalidCursor(f"cursor belongs to {cur.tool}, not {tool}")
        if cur.query != query:
            raise InvalidCursor("cursor belongs to a call with different arguments")
        return cur
