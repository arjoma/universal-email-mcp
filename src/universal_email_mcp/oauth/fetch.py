"""SSRF-safe HTTPS GET for Client ID Metadata Documents.

The URL is chosen by whoever sends an authorization request, so it is hostile input. The
fetch therefore reuses the building blocks of the mail connections (``mail/net.py``):

1. https only, no credentials, no fragment, no IP literal host,
2. the host name is resolved **once** and every address must be public unicast,
3. the socket connects to the checked IP, TLS verifies the certificate for the *host name*,
4. **redirects are not followed** (a redirect is an error), no cookies, no compression,
5. the body is capped (``max_bytes``) and the whole exchange has a deadline that also
   covers a server that trickles bytes (a watchdog closes the socket).

Blocking code: call it through ``asyncio.to_thread``.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from universal_email_mcp.errors import MailError
from universal_email_mcp.mail.net import NetPolicy, Resolver, open_connection, tls_context, wrap_tls

USER_AGENT = "universal-email-mcp (client metadata fetch)"


class FetchError(Exception):
    """The document could not be fetched. The message is short and safe to log."""


@dataclass(frozen=True, slots=True)
class FetchPolicy:
    net: NetPolicy = field(
        default_factory=lambda: NetPolicy(allow_private=False, connect_timeout=5, read_timeout=5)
    )
    max_bytes: int = 16 * 1024
    total_timeout: float = 10.0
    ca_file: str | None = None
    """Extra trust anchor (tests with a self-signed CA); ``None`` = system store."""
    resolver: Resolver | None = None


def check_document_url(url: str) -> tuple[str, int, str]:
    """Return ``(host, port, path+query)`` of an acceptable https URL, else raise."""
    if not url or len(url) > 512 or any(not 0x21 <= ord(c) <= 0x7E for c in url):
        raise FetchError("the URL is empty, too long or contains unusual characters")
    try:
        parts = urlsplit(url)
        port = parts.port or 443
    except ValueError:
        raise FetchError("the URL is malformed") from None
    if parts.scheme != "https":
        raise FetchError("the URL must use https")
    if parts.username is not None or parts.password is not None or "#" in url:
        raise FetchError("the URL must not contain credentials or a fragment")
    host = (parts.hostname or "").lower()
    if not host:
        raise FetchError("the URL has no host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise FetchError("the URL must name a host, not an IP address")
    if not parts.path or parts.path == "/":
        raise FetchError("the URL must have a path")
    if parts.query:
        raise FetchError("the URL must not have a query string")
    if any(seg in (".", "..") for seg in parts.path.split("/")):
        raise FetchError("the URL must not contain dot segments")
    return host, port, parts.path


class _Connection(http.client.HTTPSConnection):
    """HTTPS connection whose socket comes from the checked ``open_connection``."""

    def __init__(self, host: str, port: int, policy: FetchPolicy) -> None:
        super().__init__(host, port, timeout=policy.net.read_timeout)
        self._policy = policy
        self._tls = tls_context(ca_file=policy.ca_file)
        self.watchdog: threading.Timer | None = None

    def connect(self) -> None:
        sock = open_connection(self.host, self.port, self._policy.net, self._policy.resolver)
        # Closing the socket is the only way to interrupt a blocked read in this thread.
        self.watchdog = threading.Timer(self._policy.total_timeout, _close_quietly, [sock])
        self.watchdog.daemon = True
        self.watchdog.start()
        self.sock = wrap_tls(sock, self._tls, self.host)


def _close_quietly(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def fetch_document(url: str, policy: FetchPolicy | None = None) -> bytes:
    """GET ``url`` and return the body (JSON content type, 200, at most ``max_bytes``)."""
    policy = policy or FetchPolicy()
    host, port, path = check_document_url(url)
    conn = _Connection(host, port, policy)
    deadline = time.monotonic() + policy.total_timeout
    try:
        try:
            conn.request(
                "GET",
                path,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "User-Agent": USER_AGENT,
                    "Connection": "close",
                },
            )
            resp = conn.getresponse()
            if 300 <= resp.status < 400:
                raise FetchError("the server answered with a redirect (not followed)")
            if resp.status != 200:
                raise FetchError(f"the server answered with status {resp.status}")
            ctype = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
            if ctype != "application/json" and not ctype.endswith("+json"):
                raise FetchError("the document is not served as JSON")
            if (resp.getheader("Content-Encoding") or "identity").lower() != "identity":
                raise FetchError("compressed responses are not accepted")
            declared = resp.getheader("Content-Length")
            if declared is not None and declared.isdigit() and int(declared) > policy.max_bytes:
                raise FetchError("the document is too large")
            chunks: list[bytes] = []
            size = 0
            while True:
                if time.monotonic() > deadline:
                    raise FetchError("the server is too slow")
                chunk = resp.read(4096)
                if not chunk:
                    break
                size += len(chunk)
                if size > policy.max_bytes:
                    raise FetchError("the document is too large")
                chunks.append(chunk)
            return b"".join(chunks)
        except FetchError:
            raise
        except MailError as e:  # unresolvable, private address, TLS failure, timeout
            raise FetchError(e.message) from None
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as e:
            raise FetchError(f"transfer failed ({type(e).__name__})") from None
    finally:
        if conn.watchdog is not None:
            conn.watchdog.cancel()
        conn.close()
