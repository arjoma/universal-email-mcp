"""POP3 backend: a synchronous, read-only session that looks like an IMAP session.

The service layer talks to sessions through a small duck-typed surface
(``list_folders``, ``search``, ``fetch_summaries``, ``fetch_message`` ...);
:class:`Pop3Session` implements it for a POP3 account so that listing, search,
contacts, threads and reading work unchanged, in one fan-out with IMAP accounts.

What POP3 is, and what that means here:

- **One mailbox, no flags.** The only folder is the pseudo folder ``INBOX``; there is
  no read/unread or flagged state (summaries carry no flags and the tools report
  "unknown", not "unread").
- **Identity = UIDL.** Message numbers change between sessions, the server's unique
  id (UIDL, RFC 1939) does not. A :class:`~universal_email_mcp.models.MessageRef`
  of a POP3 message is ``(account, UIDL)``; the integer ``uid`` the rest of the
  system wants is only a number :class:`Pop3State` assigns to a UIDL in this process
  (ascending in mailbox order, so "newest" is the highest). Servers without UIDL are
  refused: without it no id would be stable.
- **Read-only, for real.** ``DELE`` and ``RSET`` are never sent and no code path
  can produce them; the session ends with ``QUIT``, which commits nothing without
  ``DELE``. Mail that should disappear from the server is the user's business in
  their mail client.
- **Headers by ``TOP n 0``**, newest first, pipelined and under a time budget. They
  are cached per account by UIDL (:class:`Pop3State`), so a later session only reads
  the UIDLs it has not seen. Search is evaluated locally on the cached headers of
  the newest ``max_headers`` messages; without header criteria all messages count.
- **Whole messages by ``RETR``**, with a byte cap enforced while reading: a message
  larger than the cap is read as far as ``TOP n <lines>`` gets, and a response that
  runs past the cap cuts the connection (POP3 cannot fetch partially); the session
  then reconnects on next use. Attachments are numbered by this server's own MIME
  parse (there is no server ``BODYSTRUCTURE`` in POP3); ``get_attachment`` re-reads
  the message and uses the same parse.
- **Fresh mail needs a new connection**: a POP3 maildrop is a snapshot for the
  length of a session. Operations that list mail reconnect when the snapshot is
  older than :data:`REFRESH_AFTER` seconds.
- TLS is mandatory (implicit on 995, or ``STLS`` that must be offered on 110);
  credentials never cross a plain connection. ``USER``/``PASS``, or ``AUTH PLAIN``
  when only SASL is offered.

Every byte from the server is untrusted: line and response sizes are capped, UIDLs
are validated, server text in errors is sanitised.
"""

from __future__ import annotations

import base64
import logging
import re
import socket
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from email import policy
from email.message import Message as PyMessage
from email.parser import BytesHeaderParser
from typing import Final

from universal_email_mcp.errors import (
    AttachmentNotFound,
    AuthFailed,
    FolderNotFound,
    InvalidRef,
    MailError,
    MessageNotFound,
    ProtocolError,
    ServerUnreachable,
    TlsError,
    TooLarge,
    UidValidityChanged,
    UnsupportedByServer,
)
from universal_email_mcp.mail.bodystructure import SECTION_RE, BodyLeaf
from universal_email_mcp.mail.imap import (
    AttachmentData,
    FolderStatus,
    IncrementalBatch,
    Namespace,
    QuotaInfo,
    SearchCriteria,
    SearchResult,
    ServerFeatures,
)
from universal_email_mcp.mail.mime import (
    HeaderFields,
    extract_part,
    header_fields_from_message,
    parse_date,
    parse_message,
    sanitize_line,
    slice_text,
)
from universal_email_mcp.mail.net import NetPolicy, Resolver, open_connection, tls_context, wrap_tls
from universal_email_mcp.models import (
    POP3_FOLDER,
    POP3_UIDVALIDITY,
    Account,
    Address,
    Endpoint,
    FolderInfo,
    FolderRole,
    Message,
    MessageRef,
    MessageSummary,
    TlsSettings,
)

log = logging.getLogger(__name__)

REFRESH_AFTER: Final = 20.0
"""Seconds after which a listing operation reconnects to see mail that arrived."""
PIPELINE: Final = 25
"""``TOP`` commands sent before their answers are read (when the server pipelines)."""
MAX_STATUS_LINE: Final = 4096
MAX_LISTING_BYTES: Final = 32 * 1024 * 1024
MAX_MESSAGES: Final = 1_000_000
"""Most messages of one mailbox the session handles (UIDL/LIST lines)."""
MAX_HEADER_BYTES: Final = 128 * 1024
"""Most bytes of one ``TOP n 0`` answer; more cuts the connection."""
RETR_SLACK: Final = 8 * 1024
"""A message whose LIST size fits the cap may still read slightly larger (dot-stuffing,
line ends); beyond this slack the response is cut."""
DEFAULT_HEADER_BUDGET: Final = 12.0
DEFAULT_MAX_HEADERS: Final = 2_000
DEFAULT_MAX_MESSAGE_BYTES: Final = 10 * 1024 * 1024
_UIDL_RE = re.compile(rb"\A[\x21-\x7e]{1,70}\Z")
_ATTACHMENT_MAIN_TYPES = frozenset({"application", "image", "audio", "video", "message"})
_PLAIN_MULTIPARTS = frozenset({"multipart/alternative", "multipart/related"})
_BODY_LINES_PER_BYTE = 100
"""``TOP n <lines>`` for an oversize message: lines = cap / this (assumes long lines;
the read is capped anyway)."""


# =========================================================================== state


@dataclass(slots=True)
class Pop3State:
    """What survives between the sessions of one POP3 account: the UIDL numbering and
    the header cache. Thread-safe; the router owns one per account."""

    max_headers: int = DEFAULT_MAX_HEADERS
    """Newest messages whose headers a search reads (``limits.max_headers_scanned``)."""
    header_budget: float = DEFAULT_HEADER_BUDGET
    """Seconds one operation may spend loading headers; a search then answers from
    what is cached and says so."""
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    uid_of: dict[str, int] = field(default_factory=dict[str, int])
    uidl_of: dict[int, str] = field(default_factory=dict[int, str])
    summaries: dict[str, MessageSummary] = field(default_factory=dict[str, MessageSummary])
    next_uid: int = 1
    lock: threading.Lock = field(default_factory=threading.Lock)

    def assign(self, uidl: str) -> int:
        with self.lock:
            uid = self.uid_of.get(uidl)
            if uid is None:
                uid = self.uid_of[uidl] = self.next_uid
                self.uidl_of[uid] = uidl
                self.next_uid += 1
            return uid

    @property
    def cache_limit(self) -> int:
        return max(2 * self.max_headers, 1_000)

    def store(self, uidl: str, summary: MessageSummary) -> None:
        with self.lock:
            self.summaries[uidl] = summary
            over = len(self.summaries) - self.cache_limit
            if over > 0:  # oldest (lowest number) first
                for u in sorted(self.summaries, key=lambda x: self.uid_of.get(x, 0))[:over]:
                    del self.summaries[u]


# =========================================================================== wire


def _server_text(raw: bytes) -> str:
    return sanitize_line(raw.decode("utf-8", "replace"))[:200]


class _Wire:
    """A socket with a read buffer and the POP3 response framing. Not thread-safe
    except :meth:`abort`."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = bytearray()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def abort(self) -> None:
        """Cut the connection from another thread; a blocked read then fails."""
        try:
            socket.socket.shutdown(self.sock, socket.SHUT_RDWR)
        except OSError:
            pass

    def send(self, data: bytes) -> None:
        try:
            self.sock.sendall(data)
        except TimeoutError as e:
            raise ServerUnreachable("sending to the POP3 server timed out") from e
        except OSError as e:
            raise ServerUnreachable(f"connection lost: {type(e).__name__}") from e

    def _fill(self) -> None:
        try:
            data = self.sock.recv(65536)
        except TimeoutError as e:
            raise ServerUnreachable("the POP3 server did not answer in time") from e
        except OSError as e:
            raise ServerUnreachable(f"connection lost: {type(e).__name__}") from e
        if not data:
            raise ServerUnreachable("the POP3 server closed the connection")
        self.buf += data

    def readline(self, limit: int) -> bytes:
        """Up to ``limit`` bytes, ending at the first newline (included) if there is one."""
        while True:
            i = self.buf.find(b"\n", 0, limit)
            if i >= 0:
                end = i + 1
            elif len(self.buf) >= limit:
                end = limit
            else:
                self._fill()
                continue
            out = bytes(self.buf[:end])
            del self.buf[:end]
            return out

    def status(self) -> tuple[bool, str]:
        """One status line: ``(True, text)`` for ``+OK``, ``(False, text)`` for ``-ERR``."""
        raw = self.readline(MAX_STATUS_LINE)
        if not raw.endswith(b"\n"):
            raise ProtocolError("the POP3 server sent an overlong response line")
        line = raw.rstrip(b"\r\n")
        if line.startswith(b"+OK"):
            return True, _server_text(line[3:].strip())
        if line.startswith(b"-ERR"):
            return False, _server_text(line[4:].strip())
        raise ProtocolError("unexpected response from the POP3 server")

    def multiline(self, cap: int) -> tuple[bytes, bool]:
        """The body of a multi-line response, dot-unstuffed, CRLF kept. Stops after
        ``cap`` bytes: ``(data, True)`` and the rest of the response is still on the
        wire, so the caller must drop the connection."""
        out = bytearray()
        at_start = True
        while True:
            chunk = self.readline(8192)
            if at_start and chunk in (b".\r\n", b".\n"):
                return bytes(out), False
            if at_start and chunk.startswith(b"."):
                chunk = chunk[1:]
            at_start = chunk.endswith(b"\n")
            out += chunk
            if len(out) > cap:
                return bytes(out[:cap]), True

    def command(self, line: str) -> tuple[bool, str]:
        self.send(line.encode("utf-8") + b"\r\n")
        return self.status()

    def listing(self, line: str) -> tuple[bool, str, list[bytes]]:
        """A command with a short multi-line answer (``CAPA``, ``UIDL``, ``LIST``)."""
        ok, text = self.command(line)
        if not ok:
            return False, text, []
        data, overflow = self.multiline(MAX_LISTING_BYTES)
        if overflow:
            raise ProtocolError(f"the answer to {line.split()[0]} is too long")
        return True, text, data.splitlines()


def _check_credentials(username: str, password: str) -> None:
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in username + password):
        raise AuthFailed("user name or password contains control characters")
    if not username:
        raise AuthFailed("no user name configured")


def _parse_caps(lines: Sequence[bytes]) -> tuple[str, ...]:
    return tuple(ln.decode("ascii", "replace").strip().upper() for ln in lines if ln.strip())


def _login(wire: _Wire, username: str, password: str) -> None:
    ok, text = wire.command(f"USER {username}")
    if not ok:
        raise AuthFailed(f"login rejected by the server: {text}")
    ok, text = wire.command(f"PASS {password}")
    if not ok:
        if "[IN-USE]" in text.upper() or "LOCK" in text.upper():
            raise ProtocolError(
                f"the mailbox is in use by another session: {text}",
                hint="Close other POP3 clients that hold the mailbox, then try again.",
            )
        raise AuthFailed(f"login rejected by the server: {text}")


def _login_plain(wire: _Wire, username: str, password: str) -> None:
    """``AUTH PLAIN`` with a continuation (RFC 5034)."""
    wire.send(b"AUTH PLAIN\r\n")
    raw = wire.readline(MAX_STATUS_LINE)
    if not raw.startswith(b"+"):
        raise AuthFailed("the server rejected AUTH PLAIN")
    blob = base64.b64encode(f"\0{username}\0{password}".encode()).decode("ascii")
    ok, text = wire.command(blob)
    if not ok:
        raise AuthFailed(f"login rejected by the server: {text}")


def _open(
    endpoint: Endpoint,
    username: str,
    password: str,
    net: NetPolicy,
    tls: TlsSettings,
    resolver: Resolver | None,
) -> tuple[_Wire, tuple[str, ...]]:
    """Connect, secure, authenticate. Returns the wire and the capabilities."""
    _check_credentials(username, password)
    ctx = tls_context(verify=tls.verify, ca_file=tls.ca_file)
    host = endpoint.host
    implicit = endpoint.tls == "tls"
    sock = open_connection(host, endpoint.port, net, resolver)
    if implicit:
        sock = wrap_tls(sock, ctx, host)
    wire = _Wire(sock)
    try:
        try:
            ok, text = wire.status()
        except MailError as e:
            raise ServerUnreachable(
                f"no POP3 greeting from {host}:{endpoint.port}: {e.message}",
                hint="Check host and port; 995 expects implicit TLS, 110 STLS.",
            ) from e
        if not ok:
            raise ServerUnreachable(f"the POP3 server refused the connection: {text}")
        if not implicit:
            ok, _t, lines = wire.listing("CAPA")
            caps = _parse_caps(lines) if ok else ()
            if "STLS" not in caps:
                raise TlsError(
                    f"{host}:{endpoint.port} does not offer STLS",
                    hint="Refusing to log in without TLS. Use port 995 (implicit TLS).",
                )
            ok, text = wire.command("STLS")
            if not ok:
                raise TlsError(f"STLS refused by {host}: {text}")
            if wire.buf:  # plaintext injected before the handshake (STLS stripping/injection)
                raise TlsError("unexpected data before the TLS handshake")
            wire = _Wire(wrap_tls(wire.sock, ctx, host))
        ok, _t, lines = wire.listing("CAPA")
        caps = _parse_caps(lines) if ok else ()
        sasl_plain = any(c.startswith("SASL") and "PLAIN" in c.split() for c in caps)
        if caps and "USER" not in caps and sasl_plain:
            _login_plain(wire, username, password)
        else:
            _login(wire, username, password)
        ok, _t, lines = wire.listing("CAPA")
        if ok:
            caps = _parse_caps(lines)
    except BaseException:
        wire.close()
        raise
    return wire, caps


# =========================================================================== summaries


def _header_part(raw: bytes) -> bytes:
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = raw.find(sep)
        if i >= 0:
            return raw[: i + len(sep)]
    return raw


def _received_at(head: PyMessage, now: datetime) -> datetime | None:
    """Arrival time from the topmost ``Received`` header (written by the receiving
    server; POP3 has no INTERNALDATE). Not in the future."""
    for key, value in head.raw_items():
        if key.lower() == "received":
            text = str(value).rsplit(";", 1)[-1].strip()
            when = parse_date(text)
            if when is not None and when <= now + timedelta(hours=1):
                return when
            return None
    return None


def _may_have_attachments(head: PyMessage) -> bool:
    try:
        ctype = head.get_content_type()
    except Exception:  # noqa: BLE001 - malformed Content-Type
        return False
    if ctype.startswith("multipart/"):
        return ctype not in _PLAIN_MULTIPARTS
    return ctype.split("/", 1)[0] in _ATTACHMENT_MAIN_TYPES


def summary_from_headers(
    ref: MessageRef, raw: bytes, size: int | None, *, now: datetime | None = None
) -> MessageSummary:
    """Summary from a raw header block (``TOP n 0``). ``has_attachments`` is a guess
    from the top-level Content-Type; flags are unknown (empty)."""
    head = BytesHeaderParser(policy=policy.compat32).parsebytes(_header_part(raw))
    h: HeaderFields = header_fields_from_message(head)
    received = _received_at(head, now or datetime.now(UTC))
    return MessageSummary(
        ref=ref,
        date=h.date or received,
        received=received,
        from_=h.from_,
        to=h.to,
        cc=h.cc,
        reply_to=h.reply_to,
        subject=h.subject,
        flags=(),
        size=size,
        has_attachments=_may_have_attachments(head),
        message_id=h.message_id,
        in_reply_to=h.in_reply_to,
        references=h.references,
    )


def _addr_text(items: Sequence[Address]) -> str:
    return " ".join(f"{a.name} {a.email}" for a in items).casefold()


def matches(s: MessageSummary, c: SearchCriteria) -> bool:
    """Evaluate ``c`` on a cached header summary. ``body``/``text`` can only look at
    the headers (the caller says so); flags do not exist."""
    frm, to, cc = _addr_text(s.from_), _addr_text(s.to), _addr_text(s.cc)
    subject = s.subject.casefold()

    def has(needle: str | None, hay: str) -> bool:
        return needle is None or not needle.strip() or needle.strip().casefold() in hay

    if not (has(c.from_, frm) and has(c.to, to) and has(c.cc, cc) and has(c.subject, subject)):
        return False
    if not has(c.body, subject) or not has(c.text, f"{frm} {to} {cc} {subject}"):
        return False
    if c.since is not None or c.before is not None:
        when = s.received or s.date
        if when is None:
            return False
        day: date = when.date()
        if (c.since is not None and day < c.since) or (c.before is not None and day >= c.before):
            return False
    if c.has_attachment is not None and s.has_attachments != c.has_attachment:
        return False
    return True


# =========================================================================== session


class Pop3Session:
    """An authenticated, read-only POP3 connection for one account (see the module
    docstring). Create with :meth:`connect` or :meth:`for_account`."""

    kind: Final = "pop3"
    has_flags: Final = False

    def __init__(
        self,
        opener: Callable[[], tuple[_Wire, tuple[str, ...]]],
        *,
        account_name: str,
        state: Pop3State,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._opener = opener
        self.account_name = account_name
        self.state = state
        self._clock = clock
        self._wire: _Wire | None = None
        self.capabilities: tuple[str, ...] = ()
        self.role_warnings: list[str] = []
        self.notes: list[str] = []
        self._num: dict[str, int] = {}
        self._size: dict[str, int] = {}
        self._order: list[str] = []
        """UIDLs of the mailbox in mailbox order (oldest first)."""
        self._synced_at = 0.0

    # ------------------------------------------------------------ lifecycle

    @classmethod
    def connect(
        cls,
        endpoint: Endpoint,
        username: str,
        password: str,
        *,
        account_name: str = "",
        net: NetPolicy | None = None,
        tls: TlsSettings | None = None,
        state: Pop3State | None = None,
        resolver: Resolver | None = None,
    ) -> Pop3Session:
        """Connect and authenticate. Raises a :class:`MailError` subclass:
        ``ServerUnreachable``, ``TlsError``, ``AddressNotAllowed``, ``AuthFailed``,
        ``UnsupportedByServer`` (no UIDL or TOP), ``ProtocolError``."""
        net_ = net or NetPolicy()
        tls_ = tls or TlsSettings()

        def opener() -> tuple[_Wire, tuple[str, ...]]:
            return _open(endpoint, username, password, net_, tls_, resolver)

        session = cls(opener, account_name=account_name, state=state or Pop3State())
        session._reopen()
        return session

    @classmethod
    def for_account(
        cls,
        account: Account,
        password: str,
        *,
        net: NetPolicy | None = None,
        state: Pop3State | None = None,
        resolver: Resolver | None = None,
    ) -> Pop3Session:
        if account.kind != "pop3":
            raise ValueError(f"account {account.name!r} is not a POP3 account")
        return cls.connect(
            account.endpoint,
            account.username,
            password,
            account_name=account.name,
            net=net,
            tls=account.tls,
            state=state,
            resolver=resolver,
        )

    def close(self) -> None:
        self._drop(quit_=True)

    def abort(self) -> None:
        """Cut the connection from another thread (never blocks)."""
        wire = self._wire
        if wire is not None:
            wire.abort()

    def __enter__(self) -> Pop3Session:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _drop(self, *, quit_: bool) -> None:
        wire, self._wire = self._wire, None
        if wire is None:
            return
        try:
            if quit_:
                wire.sock.settimeout(3)
                wire.command("QUIT")  # commits nothing: no DELE was ever sent
        except (MailError, OSError):
            pass
        finally:
            wire.close()

    def _kill(self) -> None:
        self._drop(quit_=False)

    def _reopen(self) -> None:
        self._drop(quit_=True)
        wire, caps = self._opener()
        self._wire = wire
        self.capabilities = caps
        try:
            self._require_capabilities()
            self._sync()
        except BaseException:
            self._kill()
            raise

    def _require_capabilities(self) -> None:
        if not self.capabilities:
            return  # no CAPA: UIDL/TOP are probed by use
        for need in ("UIDL", "TOP"):
            if need not in self.capabilities:
                raise UnsupportedByServer(
                    f"the POP3 server does not support {need}",
                    hint="Stable message ids need UIDL and headers need TOP; "
                    "use IMAP for this mailbox if the provider offers it.",
                )

    # ------------------------------------------------------------ protocol helpers

    def _wire_or_fail(self) -> _Wire:
        if self._wire is None:
            raise ServerUnreachable("the POP3 connection is closed")
        return self._wire

    def _protect[T](self, fn: Callable[[_Wire], T]) -> T:
        """Run wire I/O; any failure leaves the stream in an unknown state, so the
        connection is dropped (the next operation reconnects)."""
        wire = self._wire_or_fail()
        try:
            return fn(wire)
        except MailError:
            self._kill()
            raise

    def _listing(self, line: str) -> list[bytes]:
        ok, text, lines = self._protect(lambda w: w.listing(line))
        if not ok:
            cmd = line.split()[0]
            if cmd == "UIDL":
                raise UnsupportedByServer(
                    f"the POP3 server does not support UIDL: {text}",
                    hint="Stable message ids need UIDL; use IMAP for this mailbox.",
                )
            raise ProtocolError(f"{cmd} failed: {text}")
        return lines

    def _sync(self) -> None:
        """Read the maildrop snapshot: UIDLs (message numbers) and sizes."""
        uidl_lines = self._listing("UIDL")
        size_lines = self._listing("LIST")
        if len(uidl_lines) > MAX_MESSAGES:
            raise ProtocolError(f"the mailbox has more than {MAX_MESSAGES} messages")
        num: dict[str, int] = {}
        order: list[tuple[int, str]] = []
        skipped = 0
        for ln in uidl_lines:
            parts = ln.split()
            if len(parts) != 2 or not parts[0].isdigit() or not _UIDL_RE.match(parts[1]):
                skipped += 1
                continue
            uidl = parts[1].decode("ascii")
            if uidl in num:
                skipped += 1  # a duplicate unique id would make two messages share an id
                continue
            num[uidl] = int(parts[0])
            order.append((int(parts[0]), uidl))
        order.sort()
        sizes: dict[str, int] = {}
        by_num = {n: u for u, n in num.items()}
        for ln in size_lines:
            parts = ln.split()
            if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                uidl = by_num.get(int(parts[0]))
                if uidl is not None:
                    sizes[uidl] = int(parts[1])
        for _n, uidl in order:  # assign in mailbox order: uid ascending = arrival
            self.state.assign(uidl)
        self._num, self._size = num, sizes
        self._order = [u for _n, u in order]
        self._synced_at = self._clock()
        self.notes = (
            [f"{skipped} message(s) skipped: invalid or duplicate unique id (UIDL)"]
            if skipped
            else []
        )

    def _ensure(self, *, fresh: bool) -> None:
        if self._wire is None:
            self._reopen()
        elif fresh and self._clock() - self._synced_at > REFRESH_AFTER:
            self._reopen()

    # ------------------------------------------------------------ capabilities

    @property
    def features(self) -> ServerFeatures:
        return ServerFeatures.from_capabilities(())

    def has(self, capability: str) -> bool:
        return capability.upper() in self.capabilities

    def namespace(self) -> Namespace | None:
        return None

    def quota(self) -> list[QuotaInfo] | None:
        return None

    def is_foreign(self, wire: str) -> bool:
        return False

    # ------------------------------------------------------------ folders

    def list_folders(self, *, with_counts: bool = False, refresh: bool = False) -> list[FolderInfo]:
        self._ensure(fresh=refresh)
        return [
            FolderInfo(
                name=POP3_FOLDER,
                display_name=POP3_FOLDER,
                delimiter=None,
                flags=(),
                role="inbox",
                selectable=True,
                messages=len(self._order),
                unseen=None,
            )
        ]

    def _check_folder(self, folder: str) -> None:
        if folder.casefold() not in (POP3_FOLDER.casefold(), "inbox"):
            raise FolderNotFound(
                f"no folder named {folder!r}", hint="POP3 accounts have the folder INBOX only."
            )

    def folder_status(self, folder: str) -> FolderStatus:
        self._check_folder(folder)
        self._ensure(fresh=True)
        return FolderStatus(POP3_FOLDER, len(self._order), 0, None, POP3_UIDVALIDITY)

    def folder_for_role(self, role: FolderRole) -> FolderInfo | None:
        return self.list_folders()[0] if role == "inbox" else None

    def resolve_folder(self, name: str) -> FolderInfo:
        self._check_folder(name)
        return self.list_folders()[0]

    # ------------------------------------------------------------ headers

    def _load_headers(self, uidls: Sequence[str]) -> bool:
        """``TOP n 0`` for the UIDLs not cached yet, pipelined, within the time
        budget. Returns whether all of them are cached afterwards."""
        pending = deque(u for u in uidls if u not in self.state.summaries)
        deadline = self._clock() + self.state.header_budget
        pipe = PIPELINE if "PIPELINING" in self.capabilities else 1
        while pending:
            if self._clock() > deadline:
                return False
            if self._wire is None:
                self._reopen()
            batch: list[str] = []
            while pending and len(batch) < pipe:
                u = pending.popleft()
                if u in self._num:
                    batch.append(u)
            if not batch:
                continue
            cmds = "".join(f"TOP {self._num[u]} 0\r\n" for u in batch).encode("ascii")
            self._protect(lambda w, c=cmds: w.send(c))
            for k, u in enumerate(batch):
                ok, _text = self._protect(lambda w: w.status())
                if not ok:
                    continue  # vanished meanwhile
                data, over = self._protect(lambda w: w.multiline(MAX_HEADER_BYTES))
                self._remember(u, data)
                if over:  # the rest of this answer is still on the wire
                    self._kill()
                    pending.extendleft(reversed(batch[k + 1 :]))
                    break
        return True

    def _remember(self, uidl: str, header_block: bytes) -> MessageSummary:
        ref = MessageRef(
            self.account_name or "-",
            POP3_FOLDER,
            POP3_UIDVALIDITY,
            self.state.uid_of[uidl],
            uidl,
        )
        summary = summary_from_headers(ref, header_block, self._size.get(uidl))
        self.state.store(uidl, summary)
        return summary

    # ------------------------------------------------------------ search

    def search(self, folder: str, criteria: SearchCriteria | None = None) -> SearchResult:
        """Matching UIDs newest first. Header criteria are evaluated locally on the
        cached headers of the newest ``max_headers`` messages (so the result can
        be approximate, which ``exact`` and ``notes`` say); with no header criteria
        every message counts and no header is read."""
        self._check_folder(folder)
        c = criteria or SearchCriteria()
        self._ensure(fresh=True)
        notes: list[str] = []
        exact = True
        newest = list(reversed(self._order))
        if c.larger is not None:
            newest = [u for u in newest if self._size.get(u, 0) > c.larger]
        if c.smaller is not None:
            newest = [u for u in newest if 0 < self._size.get(u, 0) < c.smaller]
        if c.unseen is not None or c.flagged is not None:
            exact = False
            notes.append(
                "POP3 has no read or flagged state: the unread/flagged criterion was ignored"
            )
        header_criteria = (
            c.from_,
            c.to,
            c.cc,
            c.subject,
            c.body,
            c.text,
            c.since,
            c.before,
            c.has_attachment,
        )
        if any(v is not None for v in header_criteria):
            window = newest[: self.state.max_headers]
            if len(newest) > len(window):
                exact = False
                notes.append(
                    f"POP3: matched against the headers of the newest {len(window)} "
                    f"of {len(newest)} messages"
                )
            complete = self._load_headers(window)
            have = [u for u in window if u in self.state.summaries]
            if not complete:
                exact = False
                notes.append(
                    f"POP3: headers of {len(window) - len(have)} of the newest {len(window)} "
                    "messages are not loaded yet (time budget); ask again to continue"
                )
            if c.body is not None or c.text is not None:
                exact = False
                notes.append(
                    "POP3 cannot search message bodies: body/text matched the headers only"
                )
            if c.has_attachment is not None:
                exact = False
                notes.append("POP3: attachments are guessed from the top-level Content-Type")
            newest = [u for u in have if matches(self.state.summaries[u], c)]
        uids = sorted((self.state.uid_of[u] for u in newest), reverse=True)
        return SearchResult(
            account=self.account_name,
            folder=POP3_FOLDER,
            uidvalidity=POP3_UIDVALIDITY,
            uids=tuple(uids),
            order="uid",
            exact=exact,
            notes=tuple(notes),
        )

    def search_related(self, folder: str, message_ids: Sequence[str]) -> SearchResult:
        """Messages whose Message-ID, In-Reply-To or References is one of
        ``message_ids``, among the newest ``max_headers`` messages."""
        self._check_folder(folder)
        self._ensure(fresh=True)
        wanted = {m.strip().casefold() for m in message_ids if m.strip()}
        uids: list[int] = []
        if wanted:
            window = list(reversed(self._order))[: self.state.max_headers]
            self._load_headers(window)
            for u in window:
                s = self.state.summaries.get(u)
                if s is None:
                    continue
                ids = {x.casefold() for x in (s.message_id, s.in_reply_to, *s.references) if x}
                if ids & wanted:
                    uids.append(self.state.uid_of[u])
        return SearchResult(
            self.account_name,
            POP3_FOLDER,
            POP3_UIDVALIDITY,
            tuple(sorted(uids, reverse=True)),
            "uid",
        )

    def search_recipients(
        self, folder: str, addresses: Sequence[str], *, since: date | None = None
    ) -> SearchResult:
        self._check_folder(folder)
        return SearchResult(self.account_name, POP3_FOLDER, POP3_UIDVALIDITY, (), "uid")

    def fetch_recipients(
        self, folder: str, uids: Sequence[int], *, uidvalidity: int | None = None
    ) -> dict[int, tuple[str, ...]]:
        out: dict[int, tuple[str, ...]] = {}
        for s in self.fetch_summaries(folder, uids, uidvalidity=uidvalidity):
            out[s.ref.uid] = tuple(
                e for a in (*s.to, *s.cc) if "@" in (e := a.email.strip().lower())
            )
        return out

    # ------------------------------------------------------------ fetch (headers)

    def _present(self, uids: Sequence[int]) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for u in uids:
            uidl = self.state.uidl_of.get(u)
            if uidl is not None and uidl in self._num:
                out.append((u, uidl))
        return out

    def _check_validity(self, uidvalidity: int | None) -> None:
        if uidvalidity is not None and uidvalidity != POP3_UIDVALIDITY:
            raise UidValidityChanged("the POP3 folder id does not match")

    def fetch_summaries(
        self, folder: str, uids: Sequence[int], *, uidvalidity: int | None = None
    ) -> list[MessageSummary]:
        self._check_folder(folder)
        self._check_validity(uidvalidity)
        self._ensure(fresh=False)
        present = self._present(uids)
        self._load_headers([u for _uid, u in present])
        return [s for _uid, u in present if (s := self.state.summaries.get(u)) is not None]

    def fetch_flags(
        self, folder: str, uids: Sequence[int], *, uidvalidity: int | None = None
    ) -> dict[int, tuple[str, ...]]:
        self._check_folder(folder)
        self._check_validity(uidvalidity)
        self._ensure(fresh=False)
        return {uid: () for uid, _u in self._present(uids)}

    def fetch_summaries_since_uid(
        self, folder: str, uidvalidity: int | None, last_uid: int, limit: int = 500
    ) -> IncrementalBatch:
        self._check_folder(folder)
        self._check_validity(uidvalidity)
        self._ensure(fresh=False)
        last_uid = max(0, int(last_uid))
        new = sorted(
            (self.state.uid_of[u], u) for u in self._order if self.state.uid_of[u] > last_uid
        )
        take = new[: max(1, limit)]
        self._load_headers([u for _uid, u in take])
        got: list[MessageSummary] = []
        highest = last_uid
        for uid, u in take:
            s = self.state.summaries.get(u)
            if s is None:
                break  # budget used up: resume from here next time
            got.append(s)
            highest = uid
        return IncrementalBatch(
            POP3_FOLDER, POP3_UIDVALIDITY, tuple(got), highest, len(new) > len(got)
        )

    # ------------------------------------------------------------ fetch (messages)

    def resolve_ref(self, ref: MessageRef) -> MessageRef:
        """``ref`` with the process-local ``uid`` filled in; the message must be in
        the mailbox (a snapshot that predates it is refreshed once)."""
        if self.account_name and ref.account != self.account_name:
            raise InvalidRef("message reference belongs to a different account")
        uidl = ref.uidl
        if uidl is None:
            raise InvalidRef("not a POP3 message id")
        self._ensure(fresh=False)
        if uidl not in self._num:
            self._reopen()
        if uidl not in self._num:
            raise MessageNotFound("message not found (deleted from the mailbox?)")
        return replace(ref, uid=self.state.uid_of[uidl])

    def _retrieve(self, uidl: str, cap: int, *, partial: bool) -> tuple[bytes, bool]:
        """``RETR`` (or ``TOP n <lines>`` when ``partial``), at most ``cap`` bytes.
        Returns ``(data, cut)``; a response beyond the cap drops the connection."""
        num = self._num[uidl]
        if partial:
            line = f"TOP {num} {max(1, cap // _BODY_LINES_PER_BYTE)}"
        else:
            line = f"RETR {num}"
        ok, text = self._protect(lambda w: w.command(line))
        if not ok:
            raise MessageNotFound(f"the server could not return the message: {text}")
        data, over = self._protect(lambda w: w.multiline(cap))
        if over:
            self._kill()
        return data, over

    def fetch_message(
        self,
        ref: MessageRef,
        *,
        max_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        max_body_chars: int = 20_000,
        body_offset: int = 0,
    ) -> Message:
        """Full message. Larger than ``max_bytes`` (by the server's size): the start
        of it (``TOP``), parsed as far as it goes (``source_truncated``)."""
        ref = self.resolve_ref(ref)
        assert ref.uidl is not None
        uidl = ref.uidl
        size = self._size.get(uidl, 0)
        partial = size > max_bytes
        raw, cut = self._retrieve(uidl, max_bytes + (0 if partial else RETR_SLACK), partial=partial)
        truncated = partial or cut
        parsed = parse_message(raw)
        summary = summary_from_headers(
            MessageRef(ref.account, POP3_FOLDER, POP3_UIDVALIDITY, ref.uid, uidl),
            raw,
            size or len(raw),
        )
        self.state.store(uidl, summary)
        notes = list(parsed.notes)
        atts = parsed.attachments
        if truncated:
            atts = tuple(replace(a, size_estimated=True) for a in atts)
            notes.append(
                "message larger than the size limit: only its beginning was read; "
                "attachments may be missing and sizes are partial"
            )
        summary = replace(summary, has_attachments=any(not a.inline for a in atts))
        return Message(
            summary=summary,
            body=slice_text(parsed.text, max(1, max_body_chars), body_offset),
            body_source=parsed.text_source,
            attachments=atts,
            source_truncated=truncated,
            body_notes=tuple(notes),
            has_html=any(ctype == "text/html" for _s, ctype in parsed.leaves),
        )

    def fetch_raw_message(
        self, ref: MessageRef, *, max_bytes: int
    ) -> tuple[tuple[str, ...], bytes]:
        """``((), raw bytes)`` of the whole message (``RETR``); larger than ``max_bytes``
        raises :class:`TooLarge` (POP3 has no flags)."""
        ref = self.resolve_ref(ref)
        assert ref.uidl is not None
        size = self._size.get(ref.uidl, 0)
        if size > max_bytes:
            raise TooLarge(f"the message is {size} bytes; the limit is {max_bytes}")
        raw, cut = self._retrieve(ref.uidl, max_bytes + RETR_SLACK, partial=False)
        if cut:
            raise TooLarge("the message is larger than the read limit")
        return (), raw

    def fetch_headers(self, ref: MessageRef, *, max_bytes: int) -> bytes:
        """The raw header block (``TOP n 0``), at most ``max_bytes``."""
        ref = self.resolve_ref(ref)
        assert ref.uidl is not None
        num = self._num.get(ref.uidl)
        if num is None:
            raise MessageNotFound("message not found (deleted from the mailbox?)")
        ok, text = self._protect(lambda w: w.command(f"TOP {num} 0"))
        if not ok:
            raise MessageNotFound(f"the server could not return the message: {text}")
        data, over = self._protect(lambda w: w.multiline(max_bytes))
        if over:
            self._kill()
        return data

    def fetch_attachment(self, ref: MessageRef, section: str, *, max_bytes: int) -> AttachmentData:
        """Decoded bytes of one part, numbered by this server's own MIME parse (POP3
        has no server-side structure). The whole message is read again (``RETR``,
        capped at ``max_message_bytes``)."""
        if not SECTION_RE.match(section):
            raise AttachmentNotFound(f"{section[:40]!r} is not an attachment id")
        ref = self.resolve_ref(ref)
        assert ref.uidl is not None
        cap = max(self.state.max_message_bytes, 2 * max_bytes)
        size = self._size.get(ref.uidl, 0)
        if size > cap:
            raise TooLarge(
                f"the message is {size} bytes; POP3 cannot fetch single parts and the "
                f"limit for reading a whole message is {cap} bytes",
                hint="Nothing was returned. Ask the user to open the attachment in their "
                "mail client.",
            )
        raw, cut = self._retrieve(ref.uidl, cap + RETR_SLACK, partial=False)
        if cut:
            raise TooLarge(
                "the message is larger than the read limit", hint="Nothing was returned."
            )
        part = extract_part(raw, section)
        if part is None:
            raise AttachmentNotFound(f"this message has no part {section}")
        leaf = BodyLeaf(
            section=section,
            content_type=part.content_type,
            charset=part.charset,
            filename=part.filename,
            disposition=part.disposition,
            content_id=part.content_id,
            encoding="7bit",
            size=len(part.data),
        )
        if len(part.data) > max_bytes:
            return AttachmentData(leaf, None, len(part.data), exact=True)
        return AttachmentData(leaf, part.data, len(part.data), exact=True)
