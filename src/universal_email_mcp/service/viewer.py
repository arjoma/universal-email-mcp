"""The read side of the portal's message viewer (design section 6.2).

A :class:`Viewer` sits on one user's :class:`~universal_email_mcp.service.mail.MailService`
(see ``UserPool.lease_viewer``: only the signed-in user's own accounts that grant ``read``),
so a message id that names an account the user does not own cannot be resolved at all.
Everything is read-only: the folder is ``EXAMINE``d and bodies are fetched with ``BODY.PEEK``,
so viewing never sets ``\\Seen``.

Attachments and the ``.eml`` reuse the local download listener's building blocks
(:func:`~universal_email_mcp.service.downloads.open_part` for the verified part lookup and
size limit, :func:`~universal_email_mcp.service.downloads.iter_part` for the chunked,
incrementally decoded stream). POP3 has no server-side parts, so there the message or part is
read as a whole (bounded by ``limits.max_message_bytes``).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from email import policy
from email.parser import BytesHeaderParser

from universal_email_mcp.errors import AttachmentNotFound, TooLarge
from universal_email_mcp.mail.bodystructure import SECTION_RE
from universal_email_mcp.mail.htmlview import HtmlView, build_html_view
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.mail.mime import safe_mime_type, sanitize_line
from universal_email_mcp.models import Message, MessageRef
from universal_email_mcp.service.downloads import iter_part, open_part
from universal_email_mcp.service.mail import MailService, ThreadResult

HEADER_BYTES = 256 * 1024
MAX_HEADER_LINES = 400
MAX_HEADER_VALUE = 4000
THREAD_BODIES = 25
"""Messages of a conversation whose text is read for the thread page."""

_SPACES = re.compile(r"\s+")
_AUTH_HEADERS = frozenset(
    {
        "authentication-results",
        "received-spf",
        "arc-authentication-results",
        "dkim-signature",
        "dmarc-filter",
        "x-spam-status",
        "x-spam-flag",
    }
)


@dataclass(frozen=True, slots=True)
class HeaderLine:
    name: str
    value: str
    """Single line, control/invisible characters removed, not decoded (RFC 2047 words stay)."""

    @property
    def authentication(self) -> bool:
        return self.name.lower() in _AUTH_HEADERS


@dataclass(frozen=True, slots=True)
class ThreadEntry:
    summary_id: str
    message: Message | None
    """``None``: the text could not be read (the entry still links to the message page)."""
    hit_index: int


@dataclass(frozen=True, slots=True)
class Download:
    content_type: str
    """Already reduced to the passive allow-list (:func:`safe_mime_type`)."""
    filename: str | None
    length: int | None
    chunks: AsyncGenerator[bytes]
    """Decoded bytes; raises a :class:`MailError` mid-stream when the source changes."""


class Viewer:
    def __init__(self, service: MailService, *, max_download_bytes: int) -> None:
        self.service = service
        self._router = service.router
        self._max_download = max_download_bytes

    # ------------------------------------------------------------ message

    def resolve(self, message_id: str) -> MessageRef:
        ref, _account = self.service.resolve(message_id)
        return ref

    async def message(self, message_id: str) -> Message:
        return await self.service.get_message(
            message_id, offset=0, max_chars=self.service.limits.max_body_chars
        )

    async def headers(self, message_id: str) -> list[HeaderLine]:
        ref, account = self.service.resolve(message_id)

        def fn(session: ImapSession) -> bytes:
            return session.fetch_headers(ref, max_bytes=HEADER_BYTES)

        raw = await self._router.run_one(account, lambda a: self._router.call(a, fn))
        msg = BytesHeaderParser(policy=policy.compat32).parsebytes(raw)
        lines: list[HeaderLine] = []
        for name, value in msg.raw_items():
            if len(lines) >= MAX_HEADER_LINES:
                break
            clean = _SPACES.sub(" ", sanitize_line(str(value)))[:MAX_HEADER_VALUE]
            lines.append(HeaderLine(sanitize_line(str(name))[:80], clean))
        return lines

    async def html(self, message_id: str, *, remote_images: bool) -> HtmlView:
        """The sanitised HTML version (``document=None``: there is none). May raise
        :class:`~universal_email_mcp.mail.htmlview.TooComplex`."""
        ref, account = self.service.resolve(message_id)
        cap = self.service.limits.max_message_bytes

        def fn(session: ImapSession) -> bytes:
            return session.fetch_raw_message(ref, max_bytes=cap)[1]

        raw = await self._router.run_one(account, lambda a: self._router.call(a, fn))
        return await asyncio.to_thread(build_html_view, raw, remote_images=remote_images)

    # ------------------------------------------------------------ thread

    async def thread(self, message_id: str) -> tuple[ThreadResult, list[ThreadEntry]]:
        result = await self.service.get_thread(message_id, limit=None)

        async def read(i: int, mid: str) -> ThreadEntry:
            try:
                return ThreadEntry(mid, await self.message(mid), i)
            except Exception:  # noqa: BLE001 - one unreadable message must not break the page
                return ThreadEntry(mid, None, i)

        hits = result.hits
        entries = list(
            await asyncio.gather(
                *(read(i, h.summary.id) for i, h in enumerate(hits[:THREAD_BODIES]))
            )
        )
        entries += [
            ThreadEntry(h.summary.id, None, i) for i, h in enumerate(hits) if i >= THREAD_BODIES
        ]
        return result, entries

    # ------------------------------------------------------------ downloads

    async def download(self, message_id: str, section: str) -> Download:
        """``section=""``: the whole message as ``.eml``; else one attachment.

        :raises MailError: not found, not readable, or larger than the download limit."""
        ref, account = self.service.resolve(message_id)
        if section and not SECTION_RE.match(section):
            raise AttachmentNotFound("not an attachment id")
        if ref.is_pop3:
            return await self._pop3_download(ref, account.name, section)
        info = await open_part(self._router, ref, section, max_bytes=self._max_download)
        return Download(
            safe_mime_type(info.leaf.content_type),
            info.leaf.filename,
            info.length,
            iter_part(self._router, info, max_bytes=self._max_download),
        )

    async def _pop3_download(self, ref: MessageRef, account_name: str, section: str) -> Download:
        account = self._router.account(account_name, "read")
        cap = min(self._max_download, self.service.limits.max_message_bytes)

        def fn(session: ImapSession) -> tuple[str, str | None, bytes]:
            if not section:
                _flags, raw = session.fetch_raw_message(ref, max_bytes=cap)
                return "message/rfc822", "message.eml", raw
            got = session.fetch_attachment(ref, section, max_bytes=cap)
            if got.data is None:
                raise TooLarge("the attachment is larger than the download limit")
            return got.leaf.content_type, got.leaf.filename, got.data

        ctype, name, data = await self._router.run_one(account, lambda a: self._router.call(a, fn))

        async def one() -> AsyncGenerator[bytes]:
            yield data

        return Download(safe_mime_type(ctype), name, len(data), one())


__all__ = ["Download", "HeaderLine", "ThreadEntry", "Viewer"]
