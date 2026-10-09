"""PKCE (RFC 7636), S256 only."""

from __future__ import annotations

import hashlib
import hmac
import re

from universal_email_mcp.b64 import b64u

_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_VERIFIER = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")


def valid_challenge(value: str) -> bool:
    """A base64url SHA-256 digest without padding is exactly 43 characters."""
    return bool(_CHALLENGE.fullmatch(value))


def valid_verifier(value: str) -> bool:
    return bool(_VERIFIER.fullmatch(value))


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return b64u(digest)


def verify(verifier: str, challenge: str) -> bool:
    """Constant-time check of a code verifier against the stored challenge."""
    if not valid_verifier(verifier):
        return False
    return hmac.compare_digest(s256(verifier).encode(), challenge.encode())
