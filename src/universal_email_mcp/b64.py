"""URL-safe base64 without padding, shared by ids, cursors, tokens and sealed records."""

from __future__ import annotations

import base64


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
