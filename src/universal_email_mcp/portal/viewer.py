"""The message viewer: ``/m/<message id>`` and friends (design section 6.2).

Chat clients cannot receive large files and a text summary is not always enough, so every
message in a tool result carries a link into the portal. Opening it needs a portal session;
the link itself grants nothing:

* the message id names an account **by the name its owner gave it**; it is resolved inside the
  per-user viewer context (:meth:`~universal_email_mcp.service.userpool.UserPool.lease_viewer`),
  which holds only the signed-in user's own accounts that grant ``read``. An id naming anything
  else - another user's account, a removed account, a forged id - fails exactly like a message
  that is gone (404, same page), so ids cannot be probed.
* the mail's HTML is shown only in a sandboxed ``iframe`` (no scripts, no same-origin) whose
  document is served by a separate route with its own strict CSP; see
  :mod:`universal_email_mcp.mail.htmlview`. With ``CONTENT_ORIGIN`` the document comes from
  another origin through a short-lived signed address (that origin never sees the session).
* attachments and the ``.eml`` are served as ``Content-Disposition: attachment`` with
  ``nosniff``, a ``sandbox`` CSP and a type from the passive allow-list, streamed from IMAP in
  chunks (never buffered whole).

Everything is read-only (``BODY.PEEK``): viewing a message does not mark it read.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from typing import Any

from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response, StreamingResponse
from starlette.routing import Route

from universal_email_mcp.errors import (
    AccountTimeout,
    AttachmentNotFound,
    Busy,
    ConfigError,
    InvalidRef,
    MailError,
    MessageNotFound,
    NotPermitted,
    ReauthRequired,
    TooLarge,
    UidValidityChanged,
)
from universal_email_mcp.mail.htmlview import TooComplex, csp
from universal_email_mcp.models import Message
from universal_email_mcp.portal.pages import Auth, PortalEndpoints
from universal_email_mcp.portal.service import PortalService
from universal_email_mcp.server import render
from universal_email_mcp.server.downloads import content_disposition
from universal_email_mcp.server.http import RouteGroup
from universal_email_mcp.service.userpool import UserContext
from universal_email_mcp.service.viewer import Viewer

log = logging.getLogger(__name__)

_MESSAGE_ID = re.compile(r"^[mp]1\.[A-Za-z0-9_-]{1,3000}$")
_SECTION = re.compile(r"^[0-9.]{1,100}$")
CONTENT_TOKEN_TTL = 120.0
FILE_HEADERS = {
    "x-content-type-options": "nosniff",
    "content-security-policy": "sandbox; default-src 'none'; frame-ancestors 'none'",
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "cross-origin-resource-policy": "same-origin",
    "x-frame-options": "DENY",
}
"""Headers of every file the viewer hands out (attachments, ``.eml``): the browser never
renders it in our origin, whatever the mail claims it is."""
HTML_HEADERS = {
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "cross-origin-resource-policy": "same-site",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


# --------------------------------------------------------------------------- content tokens


class ContentTokens:
    """Short-lived, tamper-evident addresses of the HTML view on the content origin (which
    never receives the portal cookie): user, message id, remote-images choice, expiry."""

    def __init__(
        self,
        key: bytes | None = None,
        *,
        ttl: float = CONTENT_TOKEN_TTL,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._key = hmac.new(
            key or secrets.token_bytes(32), b"uem-content-v1", hashlib.sha256
        ).digest()
        self._ttl = ttl
        self._clock = clock

    def _mac(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()[:16]

    def issue(self, user_id: str, message_id: str, remote_images: bool) -> str:
        data = [user_id, message_id, int(remote_images), int(self._clock() + self._ttl)]
        payload = json.dumps(data, separators=(",", ":")).encode()
        return _b64(payload) + "." + _b64(self._mac(payload))

    def verify(self, token: str) -> tuple[str, str, bool] | None:
        try:
            body, mac = token.split(".", 1)
            payload = _unb64(body)
            if not hmac.compare_digest(_unb64(mac), self._mac(payload)):
                return None
            user_id, message_id, images, exp = json.loads(payload)
            if not (isinstance(user_id, str) and isinstance(message_id, str)):
                return None
            if self._clock() >= float(exp):
                return None
            return user_id, message_id, bool(images)
        except (ValueError, TypeError, binascii.Error):
            return None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- helpers


def _when(dt: datetime | None) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if dt else ""


def _family(content_type: str) -> str:
    return content_type.split("/", 1)[0][:20]


def _addresses(items: Any) -> list[dict[str, str]]:
    return [{"name": a.name, "email": a.email} for a in items]


def _entry(msg: Message, message_id: str) -> dict[str, Any]:
    s = msg.summary
    return {
        "id": message_id,
        "subject": s.subject,
        "sender": _addresses(s.from_),
        "to": _addresses(s.to),
        "cc": _addresses(s.cc),
        "reply_to": _addresses(s.reply_to),
        "date": _when(s.date or s.received),
        "account": s.ref.account,
        "size": render.fmt_size(s.size) if s.size else "",
        "text": msg.body.text,
        "more": msg.body.next_offset is not None,
        "notes": list(msg.body_notes),
        "attachments": [
            {
                "section": a.part_id,
                "name": a.filename or "",
                "type": a.content_type,
                "size": render.fmt_size(a.size),
                "inline": a.inline,
            }
            for a in msg.attachments
        ],
        "has_html": msg.has_html,
    }


class ViewerEndpoints(PortalEndpoints):
    """Portal pages are plain; this subclass adds the viewer's routes and error mapping."""

    def __init__(self, ps: PortalService) -> None:
        super().__init__(ps)
        self.pool = ps.pool
        self.tokens = ContentTokens(ps.content_key or None)
        self.public = ps.oauth.cfg.issuer

    # ------------------------------------------------------------------ plumbing

    def _error(self, request: Request, e: Exception | None, reason: str | None = None) -> Response:
        """One fixed page per kind of failure; nothing the server or the mail said is shown.
        Ids of other users' accounts end up as "gone" exactly like deleted messages."""
        status = 404
        if reason is None:
            reason = "messagegone"
            if isinstance(e, (InvalidRef, MessageNotFound, UidValidityChanged, AttachmentNotFound)):
                pass
            elif isinstance(e, (ConfigError, NotPermitted)):
                pass
            elif isinstance(e, TooLarge):
                reason, status = "toolarge", 413
            elif isinstance(e, ReauthRequired):
                reason, status = "reauth", 502
            elif isinstance(e, Busy):
                reason, status = "busy", 429
            else:
                reason, status = "unavailable", 504 if isinstance(e, AccountTimeout) else 502
                if not isinstance(e, MailError):
                    log.error("message viewer failed", exc_info=e)
        return self._page(request, "error.html", status=status, csrf=False, reason=reason)

    async def _open(self, auth: Auth, stack: AsyncExitStack) -> tuple[Viewer, UserContext]:
        """The viewer of this user's own accounts; lease and call slot are released when
        ``stack`` closes (a streaming response keeps it open until the body is sent)."""
        pool = self.pool
        assert pool is not None
        ctx = await pool.lease_viewer(auth.user.id)
        stack.callback(pool.release, ctx)
        await stack.enter_async_context(pool.call_slot(ctx))
        return Viewer(ctx.service, max_download_bytes=ctx.config.downloads.max_download_bytes), ctx

    async def _guard(
        self,
        request: Request,
        mid: str,
        handler: Callable[[Auth, Viewer, str], Any],
    ) -> Response:
        """Session check, id syntax, lease; every failure ends in the same fixed pages."""
        auth = await self._auth(request)
        if auth is None:
            return self._to_signin(request)
        if self.pool is None or not _MESSAGE_ID.match(mid):
            return self._error(request, None, "messagegone")
        async with AsyncExitStack() as stack:
            try:
                viewer, _ctx = await self._open(auth, stack)
                return await handler(auth, viewer, mid)
            except Exception as e:  # noqa: BLE001 - never a stack trace in the browser
                return self._error(request, e)

    # ------------------------------------------------------------------ pages

    async def message(self, request: Request) -> Response:
        mid = request.path_params["mid"]
        want_html = request.query_params.get("view") == "html"
        images = request.query_params.get("images") == "1"

        async def handler(auth: Auth, viewer: Viewer, mid: str) -> Response:
            viewer.resolve(mid)
            msg = await viewer.message(mid)
            view = None
            if want_html and msg.has_html:
                try:
                    view = await viewer.html(mid, remote_images=images)
                except TooComplex:
                    view = None
            frame = (
                self._frame_url(auth, mid, images and view is not None)
                if view and view.document
                else ""
            )
            await self.svc.audit(
                "viewer.open",
                user=auth.user.id,
                kind="message",
                html=bool(frame),
                attachments=len(msg.attachments),
                size=_bucket(msg.summary.size),
            )
            return self._page(
                request,
                "message.html",
                auth=auth,
                frame_src=self._frame_src() if frame else "",
                msg=_entry(msg, mid),
                want_html=want_html,
                html_failed=want_html and msg.has_html and not frame,
                frame_url=frame,
                images_loaded=bool(view and view.images_loaded),
                remote_images=view.remote_images if view else 0,
                links=[render.defang(link) for link in (view.links if view else ())],
                eml_url=f"/m/{mid}/eml",
            )

        return await self._guard(request, mid, handler)

    async def thread(self, request: Request) -> Response:
        mid = request.path_params["mid"]

        async def handler(auth: Auth, viewer: Viewer, mid: str) -> Response:
            viewer.resolve(mid)
            result, entries = await viewer.thread(mid)
            items: list[dict[str, Any]] = []
            for e in entries:
                hit = result.hits[e.hit_index]
                item = (
                    _entry(e.message, e.summary_id)
                    if e.message is not None
                    else {
                        "id": e.summary_id,
                        "subject": hit.summary.subject,
                        "sender": _addresses(hit.summary.from_),
                        "date": _when(hit.summary.date or hit.summary.received),
                        "text": "",
                        "account": hit.summary.ref.account,
                        "to": [],
                    }
                )
                item["current"] = e.summary_id == mid
                items.append(item)
            await self.svc.audit(
                "viewer.open", user=auth.user.id, kind="thread", messages=len(items)
            )
            return self._page(
                request,
                "thread.html",
                auth=auth,
                mid=mid,
                items=items,
                root_subject=result.root.subject,
                notes=result.notes,
                partial=bool(result.problems),
            )

        return await self._guard(request, mid, handler)

    async def headers(self, request: Request) -> Response:
        mid = request.path_params["mid"]

        async def handler(auth: Auth, viewer: Viewer, mid: str) -> Response:
            viewer.resolve(mid)
            lines = await viewer.headers(mid)
            await self.svc.audit("viewer.raw", user=auth.user.id, kind="headers", lines=len(lines))
            return self._page(
                request,
                "headers.html",
                auth=auth,
                mid=mid,
                lines=[{"name": h.name, "value": h.value, "auth": h.authentication} for h in lines],
            )

        return await self._guard(request, mid, handler)

    # ------------------------------------------------------------------ the HTML document

    def _frame_src(self) -> str:
        return self.ps.content_origin or "'self'"

    def _frame_url(self, auth: Auth, mid: str, images: bool) -> str:
        if self.ps.content_origin:
            return f"{self.ps.content_origin}/c/{self.tokens.issue(auth.user.id, mid, images)}"
        return f"/m/{mid}/html" + ("?images=1" if images else "")

    def _html_response(self, document: str, *, images: bool) -> Response:
        ancestor = self.public if self.ps.content_origin else "'self'"
        headers = {
            **HTML_HEADERS,
            "content-security-policy": csp(remote_images=images, ancestor=ancestor),
        }
        if not self.ps.content_origin:
            headers["x-frame-options"] = "SAMEORIGIN"
        return HTMLResponse(document, headers=headers)

    def _blank(self) -> Response:
        return self._html_response("<!doctype html><meta charset=utf-8>", images=False)

    async def html_frame(self, request: Request) -> Response:
        """The sanitised HTML document, same origin (no ``CONTENT_ORIGIN``)."""
        mid = request.path_params["mid"]
        images = request.query_params.get("images") == "1"
        if self.ps.content_origin:  # only the content origin serves mail HTML then
            return Response("Not found.\n", status_code=404, media_type="text/plain")
        auth = await self._auth(request)
        if auth is None or self.pool is None or not _MESSAGE_ID.match(mid):
            return Response("Not found.\n", status_code=404, media_type="text/plain")
        return await self._serve_html(auth.user.id, mid, images)

    async def content_frame(self, request: Request) -> Response:
        """The same document on the content origin, addressed by a signed short-lived token
        (that origin has no session)."""
        origin = self.ps.content_origin
        if origin is None or self.pool is None:
            return Response("Not found.\n", status_code=404, media_type="text/plain")
        host = request.headers.get("host", "").lower()
        if host != origin.split("://", 1)[1].lower():
            return Response("Not found.\n", status_code=404, media_type="text/plain")
        found = self.tokens.verify(request.path_params["token"])
        if found is None or not _MESSAGE_ID.match(found[1]):
            return Response("Not found.\n", status_code=404, media_type="text/plain")
        return await self._serve_html(found[0], found[1], found[2])

    async def _serve_html(self, user_id: str, mid: str, images: bool) -> Response:
        pool = self.pool
        assert pool is not None
        try:
            async with AsyncExitStack() as stack:
                ctx = await pool.lease_viewer(user_id)
                stack.callback(pool.release, ctx)
                await stack.enter_async_context(pool.call_slot(ctx))
                viewer = Viewer(ctx.service, max_download_bytes=1)
                view = await viewer.html(mid, remote_images=images)
        except TooComplex:
            return self._blank()
        except MailError:
            return Response("Not found.\n", status_code=404, media_type="text/plain")
        if view.document is None:
            return self._blank()
        return self._html_response(view.document, images=images)

    # ------------------------------------------------------------------ downloads

    async def eml(self, request: Request) -> Response:
        return await self._download(request, request.path_params["mid"], "")

    async def attachment(self, request: Request) -> Response:
        section = request.path_params["section"]
        if not _SECTION.match(section):
            return self._error(request, None, "messagegone")
        return await self._download(request, request.path_params["mid"], section)

    async def _download(self, request: Request, mid: str, section: str) -> Response:
        auth = await self._auth(request)
        if auth is None:
            return self._to_signin(request)
        if self.pool is None or not _MESSAGE_ID.match(mid):
            return self._error(request, None, "messagegone")
        stack = AsyncExitStack()
        try:
            viewer, _ctx = await self._open(auth, stack)
            dl = await viewer.download(mid, section)
        except BaseException as e:
            await stack.aclose()  # also on cancellation: give the lease and the slot back
            if not isinstance(e, Exception):
                raise
            return self._error(request, e)
        headers = {
            **FILE_HEADERS,
            "content-disposition": content_disposition(dl.filename).decode("ascii"),
        }
        if dl.length is not None:
            headers["content-length"] = str(dl.length)
        kind = "eml" if not section else "attachment"
        user = auth.user.id
        if request.method == "HEAD":
            await dl.chunks.aclose()
            await stack.aclose()
            return Response(status_code=200, headers=headers, media_type=dl.content_type)

        sent = 0

        async def body() -> AsyncIterator[bytes]:
            nonlocal sent
            complete = False
            try:
                async with contextlib.aclosing(dl.chunks) as chunks:
                    async for chunk in chunks:
                        sent += len(chunk)
                        yield chunk
                complete = True
            finally:
                await stack.aclose()
                await self.svc.audit(
                    "viewer.raw" if kind == "eml" else "attachment.download",
                    user=user,
                    kind=kind,
                    size=_bucket(sent),
                    family=_family(dl.content_type),
                    complete=complete,
                )

        return StreamingResponse(
            body(),
            headers=headers,
            media_type=dl.content_type,
            # the lease is also given back when the client left before the first chunk
            background=BackgroundTask(stack.aclose),
        )


def _bucket(n: int | None) -> str:
    from universal_email_mcp.audit import size_bucket

    return size_bucket(n or 0)


def viewer_group(ps: PortalService) -> RouteGroup:
    ep = ViewerEndpoints(ps)
    get = ["GET"]
    routes = [
        Route("/m/{mid}", ep.message, methods=get),
        Route("/m/{mid}/thread", ep.thread, methods=get),
        Route("/m/{mid}/headers", ep.headers, methods=get),
        Route("/m/{mid}/html", ep.html_frame, methods=get),
        Route("/m/{mid}/eml", ep.eml, methods=get),
        Route("/m/{mid}/a/{section}", ep.attachment, methods=get),
        Route("/c/{token}", ep.content_frame, methods=get),
    ]
    return RouteGroup(routes)


__all__ = ["ContentTokens", "ViewerEndpoints", "viewer_group"]
