"""Redirect URI rules (OAuth 2.1 section 2.3.1, RFC 8252).

Accepted: ``https`` URIs, ``http`` only on a loopback host (the port is free when
matching, RFC 8252 section 7.3), and private-use schemes in reverse-domain style
(``com.example.app:/cb``, RFC 8252 section 7.1; the dot keeps ``javascript:``,
``data:`` and friends out). No fragments, no credentials, no control characters.
Matching is an exact string comparison, except for the loopback port.
"""

from __future__ import annotations

from urllib.parse import urlsplit

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "[::1]", "localhost"})
MAX_URI_LENGTH = 2000
_FORBIDDEN_SCHEMES = frozenset({"http", "https", "file", "ftp", "ws", "wss", "blob", "data"})


class RedirectError(ValueError):
    """The URI is not acceptable; the message is safe to show."""


def _host(netloc: str) -> str:
    hostport = netloc.rpartition("@")[2].lower()
    if hostport.startswith("["):
        return hostport[: hostport.find("]") + 1]
    return hostport.rsplit(":", 1)[0] if ":" in hostport else hostport


def validate_redirect_uri(uri: str) -> str:
    """Return ``uri`` if acceptable, else raise :class:`RedirectError`."""
    if not uri or len(uri) > MAX_URI_LENGTH:
        raise RedirectError("redirect URI is empty or too long")
    if any(not 0x21 <= ord(c) <= 0x7E for c in uri):
        raise RedirectError("redirect URI contains spaces, control or non-ASCII characters")
    try:
        parts = urlsplit(uri)
        _ = parts.port
    except ValueError:
        raise RedirectError("redirect URI is malformed") from None
    scheme = parts.scheme.lower()
    if not scheme:
        raise RedirectError("redirect URI must be absolute")
    if "#" in uri:
        raise RedirectError("redirect URI must not contain a fragment")
    if parts.username is not None or parts.password is not None:
        raise RedirectError("redirect URI must not contain credentials")
    if scheme == "https":
        if not parts.hostname:
            raise RedirectError("redirect URI has no host")
        return uri
    if scheme == "http":
        if _host(parts.netloc) not in LOOPBACK_HOSTS:
            raise RedirectError("http redirect URIs are only allowed for localhost")
        return uri
    if scheme in _FORBIDDEN_SCHEMES or "." not in scheme:
        raise RedirectError("custom URI schemes must use reverse-domain style (com.example.app)")
    return uri


def is_loopback(uri: str) -> bool:
    parts = urlsplit(uri)
    return parts.scheme.lower() == "http" and _host(parts.netloc) in LOOPBACK_HOSTS


def redirect_matches(registered: tuple[str, ...] | list[str], requested: str) -> bool:
    """Exact match; for a registered loopback URI any port is accepted."""
    if requested in registered:
        return True
    if not is_loopback(requested):
        return False
    want = urlsplit(requested)
    for reg in registered:
        if not is_loopback(reg):
            continue
        have = urlsplit(reg)
        if (
            _host(have.netloc) == _host(want.netloc)
            and have.path == want.path
            and have.query == want.query
        ):
            return True
    return False


def display_host(uri: str) -> str:
    """What the consent page shows as 'where the answer goes'."""
    parts = urlsplit(uri)
    if parts.scheme.lower() in ("http", "https"):
        return parts.netloc.rpartition("@")[2]
    return parts.scheme + ":"


def csp_form_target(uri: str) -> str:
    """CSP ``form-action`` source that lets the browser follow the final redirect."""
    parts = urlsplit(uri)
    scheme = parts.scheme.lower()
    if is_loopback(uri):
        return f"http://{_host(parts.netloc)}:*"
    if scheme == "https":
        return f"https://{parts.netloc.rpartition('@')[2]}"
    return f"{scheme}:"


def host_allowed(uri: str, allowed_hosts: tuple[str, ...]) -> bool:
    """Operator allowlist for dynamically registered clients (loopback always passes)."""
    if not allowed_hosts or is_loopback(uri):
        return True
    parts = urlsplit(uri)
    if parts.scheme.lower() != "https":
        return False
    return (parts.hostname or "").lower() in allowed_hosts
