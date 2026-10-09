"""Local mode: loopback HTTP listener for attachment download links.

``http://127.0.0.1:<port>/a/<token>`` streams one attachment out of IMAP. The token
(see :class:`~universal_email_mcp.service.downloads.DownloadTokens`) is the only
credential; the listener binds 127.0.0.1 only, answers only ``GET``/``HEAD`` for
that one route, and rejects any ``Host`` header other than its own loopback name
and port (DNS rebinding). Everything that comes from the mail — file name, type —
is untrusted and sanitised before it reaches a header. Error pages are fixed texts
without mail data, and tokens are never logged (only a short hash).

The server runs on the event loop of the stdio MCP server and stops with it.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import socket
from collections.abc import Awaitable, Callable, Iterator, MutableMapping
from typing import Any
from urllib.parse import quote

import uvicorn

from universal_email_mcp.config import Downloads
from universal_email_mcp.errors import (
    AccountTimeout,
    AttachmentNotFound,
    ConfigError,
    MailError,
    MessageNotFound,
    NotPermitted,
    TooLarge,
    UidValidityChanged,
)
from universal_email_mcp.mail.mime import safe_mime_type
from universal_email_mcp.models import MessageRef
from universal_email_mcp.service.downloads import (
    DownloadTokens,
    LinkExpired,
    LinkInvalid,
    PartInfo,
    iter_part,
    open_part,
    token_fingerprint,
)
from universal_email_mcp.service.router import AccountRouter

log = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

_ROUTE = re.compile(r"^/([am])/([A-Za-z0-9_.-]{1,4096})$")

SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"content-security-policy", b"sandbox; default-src 'none'"),
    (b"cache-control", b"no-store"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-resource-policy", b"same-origin"),
]

_ASCII_SAFE = re.compile(r"[^A-Za-z0-9._ -]")


def content_disposition(name: str | None) -> bytes:
    """``attachment`` header for an untrusted file name: a plain ASCII fallback
    (no quotes, backslashes, percent signs or control characters) plus the RFC 5987
    UTF-8 form. Never contains CR/LF, whatever ``name`` holds."""
    name = (name or "").strip()
    fallback = _ASCII_SAFE.sub("_", name).strip(" .")[:100] or "attachment"
    value = f'attachment; filename="{fallback}"'
    if name:
        value += f"; filename*=UTF-8''{quote(name[:200], safe='')}"
    return value.encode("ascii")


def _status_for(err: MailError) -> tuple[int, str]:
    if isinstance(err, (ConfigError, NotPermitted)):
        return 403, "This link is not allowed to read that mailbox."
    if isinstance(err, (MessageNotFound, UidValidityChanged)):
        return 410, "The message is gone or the mailbox changed; ask for a fresh link."
    if isinstance(err, AttachmentNotFound):
        return 404, "No such attachment."
    if isinstance(err, TooLarge):
        return 413, "The attachment is larger than the download limit."
    if isinstance(err, AccountTimeout):
        return 504, "The mail server did not answer in time."
    return 502, "The mail server could not deliver the attachment."


class DownloadAborted(RuntimeError):
    """Raised after the response started to cut the connection short (an
    incomplete body must not look complete)."""


class DownloadApp:
    """The ASGI application (plain ASGI: exact control over headers and framing)."""

    def __init__(
        self,
        router: AccountRouter,
        tokens: DownloadTokens,
        *,
        port: int,
        max_bytes: int,
    ) -> None:
        self._router = router
        self._tokens = tokens
        self._max_bytes = max_bytes
        self._hosts = frozenset({f"127.0.0.1:{port}", f"localhost:{port}"})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self._handle(scope, receive, tracking_send)
        except DownloadAborted:
            raise
        except Exception:
            log.exception("download: unexpected error")
            if started:  # cannot send a second response: cut the connection
                raise DownloadAborted("download aborted") from None
            await _plain(send, 500, "Internal error.")

    async def _handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        hosts = [v for k, v in scope["headers"] if k == b"host"]
        if len(hosts) != 1 or hosts[0].decode("latin-1").lower() not in self._hosts:
            await _plain(send, 403, "Forbidden.")
            return
        method = scope["method"]
        if method not in ("GET", "HEAD"):
            await _plain(send, 405, "Method not allowed.", [(b"allow", b"GET, HEAD")])
            return
        m = _ROUTE.match(scope["path"])
        if m is None or scope.get("query_string"):
            await _plain(send, 404, "Not found.")
            return
        kind, token = m.group(1), m.group(2)
        try:
            ref, section = self._tokens.verify(token)
            if (kind == "m") != (section == ""):  # /m/ carries message tokens only
                raise LinkInvalid
        except LinkExpired:
            await _plain(send, 403, "This download link has expired; ask for a fresh one.")
            return
        except LinkInvalid:
            await _plain(send, 404, "Not found.")
            return
        fp = token_fingerprint(token)
        try:
            info = await open_part(self._router, ref, section, max_bytes=self._max_bytes)
        except MailError as e:
            status, text = _status_for(e)
            log.info("download %s: refused (%s, %d)", fp, e.code, status)
            await _plain(send, status, text)
            return
        headers = self._headers(info)
        if method == "HEAD":
            await send({"type": "http.response.start", "status": 200, "headers": headers})
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return
        log.info("download %s: streaming", fp)
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await self._stream(info, receive, send, fp)

    def _headers(self, info: PartInfo) -> list[tuple[bytes, bytes]]:
        headers = [
            (b"content-type", safe_mime_type(info.leaf.content_type).encode("ascii")),
            (b"content-disposition", content_disposition(info.leaf.filename)),
            *SECURITY_HEADERS,
        ]
        if info.length is not None:
            headers.append((b"content-length", str(info.length).encode("ascii")))
        return headers

    async def _stream(self, info: PartInfo, receive: Receive, send: Send, fp: str) -> None:
        gone = asyncio.create_task(_wait_disconnect(receive))
        try:
            async with contextlib.aclosing(
                iter_part(self._router, info, max_bytes=self._max_bytes)
            ) as chunks:
                async for chunk in chunks:
                    if gone.done():
                        log.info("download %s: client went away", fp)
                        return
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
        except MailError as e:
            log.warning("download %s: aborted (%s)", fp, e.code)
            raise DownloadAborted("download aborted") from None
        finally:
            gone.cancel()
        await send({"type": "http.response.body", "body": b"", "more_body": False})


async def _wait_disconnect(receive: Receive) -> None:
    while (await receive())["type"] != "http.disconnect":
        pass


async def _plain(
    send: Send, status: int, text: str, extra: list[tuple[bytes, bytes]] | None = None
) -> None:
    body = (text + "\n").encode("ascii")
    headers = [
        (b"content-type", b"text/plain; charset=us-ascii"),
        (b"content-length", str(len(body)).encode("ascii")),
        *SECURITY_HEADERS,
        *(extra or []),
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


class _Server(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        # The stdio MCP server owns the process's signals; uvicorn must not hook them.
        yield


class LocalDownloads:
    """Loopback listener plus the :class:`DownloadLinks` provider that points at it."""

    def __init__(
        self, router: AccountRouter, settings: Downloads, tokens: DownloadTokens | None = None
    ) -> None:
        self._router = router
        self._settings = settings
        self._tokens = tokens or DownloadTokens(ttl=settings.link_ttl)
        self._server: _Server | None = None
        self._task: asyncio.Task[None] | None = None
        self.port = 0

    async def start(self) -> bool:
        """Bind 127.0.0.1 and serve in the background. ``False`` (with a warning,
        no links) when the port is unavailable."""
        try:
            sock = socket.create_server(("127.0.0.1", self._settings.port))
        except OSError as e:
            log.warning("download links disabled: cannot listen on 127.0.0.1: %s", e.strerror)
            return False
        self.port = sock.getsockname()[1]
        app = DownloadApp(
            self._router, self._tokens, port=self.port, max_bytes=self._settings.max_download_bytes
        )
        cfg = uvicorn.Config(
            app,
            lifespan="off",
            ws="none",
            log_config=None,
            access_log=False,
            server_header=False,
            log_level="warning",
        )
        server = self._server = _Server(cfg)
        task = self._task = asyncio.create_task(self._run(server, sock))
        while not server.started and not task.done():
            await asyncio.sleep(0.01)
        if not server.started:
            sock.close()
            self._server = self._task = None
            return False
        log.info("download links served on 127.0.0.1:%d", self.port)
        return True

    @staticmethod
    async def _run(server: _Server, sock: socket.socket) -> None:
        try:
            await server.serve(sockets=[sock])
        except SystemExit:  # uvicorn exits on startup failure
            log.warning("download listener failed to start")
        finally:
            sock.close()

    async def stop(self) -> None:
        server, task = self._server, self._task
        self._server = self._task = None
        if server is None or task is None:
            return
        server.should_exit = True
        try:
            await asyncio.wait_for(asyncio.shield(task), 2.0)
        except TimeoutError:
            server.force_exit = True
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    def status(self) -> str:
        """One line for ``account_info``."""
        if self._server is None:
            return f"off (could not listen on 127.0.0.1:{self._settings.port or 'any port'})"
        hours = self._settings.link_ttl / 3600
        return f"on (127.0.0.1:{self.port}, valid {hours:g} h or until the server stops)"

    def message_url(self, ref: MessageRef) -> str | None:
        if self._server is None:
            return None
        return f"http://127.0.0.1:{self.port}/m/{self._tokens.issue(ref, '')}"

    def attachment_url(self, ref: MessageRef, section: str) -> str | None:
        if self._server is None:
            return None
        return f"http://127.0.0.1:{self.port}/a/{self._tokens.issue(ref, section)}"
