"""Attachment downloads: signed link tokens and the chunked, decoding stream.

Tokens are self-contained and tamper-evident (HMAC-SHA256 over a compact JSON
payload: account, folder, UIDVALIDITY, UID, section, expiry), like the paging
cursors. The key is per process in local mode, so a link dies with the server.
Whoever holds a link can download that one part until it expires — the link is
the credential, so it is only ever handed to the user's own AI client.

:func:`open_part` runs the same verified lookup as ``get_attachment``
(:meth:`ImapSession.locate_part`) and :func:`iter_part` then streams the part:
every chunk is a separate router call (the account's session lock is free between
chunks), so a download never blocks other tool calls for long, and every chunk
re-checks account, UIDVALIDITY and that the message still exists.
"""

from __future__ import annotations

import asyncio
import binascii
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass
from typing import Any, cast

from universal_email_mcp.b64 import b64u, unb64u
from universal_email_mcp.errors import AttachmentNotFound, InvalidRef, TooLarge
from universal_email_mcp.mail.bodystructure import BodyLeaf, decoded_size
from universal_email_mcp.mail.transfer import make_decoder
from universal_email_mcp.models import Account, MessageRef
from universal_email_mcp.service.router import AccountRouter

CHUNK_BYTES = 256 * 1024
"""Encoded bytes read from the server per request."""

_PREFIX = "d1."
_MAX_LEN = 4096
_MAC_LEN = 16


class LinkInvalid(Exception):
    """Not a token this process issued (garbled, tampered, or from an earlier run)."""


class LinkExpired(Exception):
    """A genuine token whose lifetime is over."""


class DownloadTokens:
    def __init__(
        self,
        key: bytes | None = None,
        *,
        ttl: float = 24 * 3600.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._key = key or secrets.token_bytes(32)
        self._ttl = ttl
        self._clock = clock

    def _mac(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()[:_MAC_LEN]

    def issue(self, ref: MessageRef, section: str) -> str:
        exp = int(self._clock() + self._ttl)
        data = [ref.account, ref.folder, ref.uidvalidity, ref.uid, section, exp]
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return _PREFIX + b64u(payload) + "." + b64u(self._mac(payload))

    def verify(self, token: str) -> tuple[MessageRef, str]:
        """The reference and section of a valid token. The signature is checked
        before anything else is looked at; expiry is reported only for genuine
        tokens."""
        if not token.startswith(_PREFIX) or len(token) > _MAX_LEN:
            raise LinkInvalid
        try:
            body, mac = token[len(_PREFIX) :].split(".", 1)
            payload, mac_bytes = unb64u(body), unb64u(mac)
        except (ValueError, binascii.Error) as e:
            raise LinkInvalid from e
        if not hmac.compare_digest(mac_bytes, self._mac(payload)):
            raise LinkInvalid
        try:
            account, folder, uidvalidity, uid, section, exp = cast(
                list[Any], json.loads(payload.decode("utf-8"))
            )
            ref = MessageRef(str(account), str(folder), int(uidvalidity), int(uid))
            if not isinstance(section, str):
                raise TypeError("section")
            expires = float(exp)
        except (ValueError, TypeError, UnicodeDecodeError, InvalidRef) as e:
            raise LinkInvalid from e
        if self._clock() >= expires:
            raise LinkExpired
        return ref, section


def token_fingerprint(token: str) -> str:
    """Short hash for logs: tokens themselves are never logged."""
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()[:8]


@dataclass(frozen=True, slots=True)
class PartInfo:
    account: Account
    ref: MessageRef
    leaf: BodyLeaf

    @property
    def length(self) -> int | None:
        """Exact decoded size when the encoding is the identity, else unknown."""
        enc = self.leaf.encoding.strip().lower()
        return None if enc in ("base64", "quoted-printable") else self.leaf.size


async def open_part(
    router: AccountRouter, ref: MessageRef, section: str, *, max_bytes: int
) -> PartInfo:
    """Permission check and the verified part lookup; raises :class:`MailError`
    (:class:`TooLarge` when the part would exceed ``max_bytes`` decoded)."""
    account = router.account(ref.account, "read")
    if section == "":  # the whole message as .eml
        size = await router.run_one(
            account, lambda a: router.call(a, lambda s: s.locate_message(ref))
        )
        if size > max_bytes:
            raise TooLarge("the message is larger than the download limit")
        leaf = BodyLeaf("", "message/rfc822", None, "message.eml", "attachment", None, "7bit", size)
        return PartInfo(account, ref, leaf)
    leaf = await router.run_one(
        account, lambda a: router.call(a, lambda s: s.locate_part(ref, section))
    )
    if decoded_size(leaf.encoding, leaf.size) > max_bytes or (
        leaf.encoding == "quoted-printable" and leaf.size > 3 * max_bytes
    ):
        raise TooLarge("the attachment is larger than the download limit")
    return PartInfo(account, ref, leaf)


async def iter_part(
    router: AccountRouter,
    info: PartInfo,
    *,
    max_bytes: int,
    chunk_bytes: int | None = None,
) -> AsyncGenerator[bytes]:
    """Decoded bytes of the part, read and decoded chunk by chunk. Raises a
    :class:`MailError` when the message vanishes or changes mid-stream, the
    server returns less than the part's size, or the output exceeds ``max_bytes``."""
    ref, section, size = info.ref, info.leaf.section, info.leaf.size
    decoder = make_decoder(info.leaf.encoding)
    identity = info.leaf.encoding.strip().lower() not in ("base64", "quoted-printable")
    chunk = chunk_bytes or CHUNK_BYTES
    offset = sent = 0
    while offset < size:
        want = min(chunk, size - offset)
        raw = await router.run_one(
            info.account,
            lambda a, o=offset, n=want: router.call(
                a, lambda s: s.read_part_chunk(ref, section, o, n)
            ),
        )
        if not raw:
            raise AttachmentNotFound("the server returned less data than the part's size")
        offset += len(raw)
        # Decoding is CPU work on hostile bytes: not on the event loop.
        out = raw if identity else await asyncio.to_thread(decoder.feed, raw)
        sent += len(out)
        if sent > max_bytes:
            raise TooLarge("the attachment is larger than the download limit")
        if out:
            yield out
    tail = await asyncio.to_thread(decoder.finish)
    if tail:
        yield tail
