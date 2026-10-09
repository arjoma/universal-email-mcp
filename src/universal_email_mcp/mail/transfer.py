"""Incremental Content-Transfer-Encoding decoders for streamed downloads.

``feed()`` takes encoded chunks of any size (down to one byte) and returns the
bytes decoded so far; ``finish()`` returns the rest. Together they produce exactly
what :func:`mime.decode_transfer` returns for the concatenated input, but memory
stays bounded by the chunk size: base64 carries over at most three characters,
quoted-printable the incomplete last line (capped, see ``_QP_MAX_CARRY``; so is a
run of trailing whitespace).
Unknown encodings and 7bit/8bit/binary pass through, as in ``decode_transfer``.
"""

from __future__ import annotations

import binascii
import quopri
from typing import Protocol

_B64_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
_B64_JUNK = bytes(b for b in range(256) if b not in _B64_ALPHABET)

_QP_MAX_CARRY = 64 * 1024
"""A quoted-printable line longer than this is cut anyway (hostile input must not
make the decoder buffer without bound)."""


class TransferDecoder(Protocol):
    def feed(self, data: bytes) -> bytes: ...

    def finish(self) -> bytes: ...


class _Identity:
    def feed(self, data: bytes) -> bytes:
        return data

    def finish(self) -> bytes:
        return b""


class _Base64:
    def __init__(self) -> None:
        self._carry = b""

    def feed(self, data: bytes) -> bytes:
        chars = self._carry + data.translate(None, _B64_JUNK)
        cut = len(chars) - len(chars) % 4
        self._carry = chars[cut:]
        return binascii.a2b_base64(chars[:cut]) if cut else b""

    def finish(self) -> bytes:
        chars, self._carry = self._carry, b""
        if len(chars) < 2:  # nothing, or a dangling character
            return b""
        return binascii.a2b_base64(chars + b"=" * (-len(chars) % 4))


class _QuotedPrintable:
    def __init__(self) -> None:
        self._carry = b""

    def feed(self, data: bytes) -> bytes:
        buf = self._carry + data
        cut = buf.rfind(b"\n") + 1
        if cut == 0 and len(buf) > _QP_MAX_CARRY:
            # No line end in sight: emit all but a possibly unfinished "=XX"
            # escape or whitespace/CR that a following line end would swallow.
            cut = len(buf.rstrip(b" \t\r"))
            if len(buf) - cut > _QP_MAX_CARRY:
                # Endless whitespace (hostile): emit it. Linear time, bounded
                # carry; a line end far later would not strip it any more.
                cut = len(buf)
            elif cut and b"=" in buf[max(0, cut - 2) : cut]:
                cut = buf.rfind(b"=", 0, cut)
        self._carry = buf[cut:]
        return quopri.decodestring(buf[:cut]) if cut else b""

    def finish(self) -> bytes:
        buf, self._carry = self._carry, b""
        return quopri.decodestring(buf) if buf else b""


def make_decoder(encoding: str) -> TransferDecoder:
    enc = encoding.strip().lower()
    if enc == "base64":
        return _Base64()
    if enc == "quoted-printable":
        return _QuotedPrintable()
    return _Identity()
