"""Read-only IMAP backend on top of ``imapclient``.

:class:`ImapSession` is **synchronous and not thread-safe**: one session per
worker thread; async callers use ``await asyncio.to_thread(...)``. It never
changes mailbox state: folders are opened with EXAMINE, bodies fetched with
``BODY.PEEK`` (``\\Seen`` is never set), and no STORE/COPY/MOVE/APPEND/EXPUNGE is
issued.

Connections go through :mod:`universal_email_mcp.mail.net`: ``imapclient`` builds
its ``imaplib`` object in ``IMAPClient._create_IMAP4``; we override that to return
an ``imaplib.IMAP4`` subclass whose ``_create_socket`` returns our checked (and,
for implicit TLS, already wrapped) socket. STARTTLS uses imaplib's own upgrade with
our verifying context; imaplib keeps the *host name* for SNI/verification.

Folder names are handled as **wire names** (modified UTF-7, exactly as listed by
the server) — ``FolderInfo.name`` — so references round-trip for any folder.
Methods also accept a non-ASCII display name and encode it.
"""

from __future__ import annotations

import imaplib
import re
import socket
import ssl
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Literal, cast

from imapclient import IMAPClient
from imapclient.exceptions import LoginError
from imapclient.imap4 import IMAP4WithTimeout
from imapclient.imap_utf7 import encode as _utf7_encode
from imapclient.imapclient import SocketTimeout
from imapclient.response_parser import parse_message_list

from universal_email_mcp.errors import (
    AuthFailed,
    FolderNotFound,
    InvalidRef,
    MailError,
    MessageNotFound,
    ProtocolError,
    ServerUnreachable,
    TlsError,
    UidValidityChanged,
)
from universal_email_mcp.mail.folders import RawFolder, assign_roles, decode_folder_name
from universal_email_mcp.mail.mime import (
    SUMMARY_HEADERS,
    HeaderFields,
    parse_header_block,
    parse_message,
    sanitize_line,
    slice_text,
)
from universal_email_mcp.mail.net import NetPolicy, Resolver, open_connection, tls_context, wrap_tls
from universal_email_mcp.models import (
    Account,
    Endpoint,
    FolderInfo,
    FolderRole,
    Message,
    MessageRef,
    MessageSummary,
    TlsSettings,
)

FETCH_BATCH = 200
DEFAULT_MAX_MESSAGE_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_BODY_CHARS = 20_000
MAX_CLIENT_FILTER = 2_000
"""Most candidates checked client-side (charset fallback, attachment filter)."""
MAX_RELATED_IDS = 30
"""Most Message-IDs per :meth:`ImapSession.search_related` call."""

_HEADER_FIELDS = "BODY.PEEK[HEADER.FIELDS (" + " ".join(h.upper() for h in SUMMARY_HEADERS) + ")]"
_SUMMARY_ITEMS = ["UID", "FLAGS", "INTERNALDATE", "RFC822.SIZE", "BODYSTRUCTURE", _HEADER_FIELDS]
_SUMMARY_ITEMS_NO_BS = [i for i in _SUMMARY_ITEMS if i != "BODYSTRUCTURE"]


# =========================================================================== results


@dataclass(frozen=True, slots=True)
class Namespace:
    """RFC 2342 namespaces as ``(prefix, delimiter)`` pairs (wire names)."""

    personal: tuple[tuple[str, str | None], ...] = ()
    other: tuple[tuple[str, str | None], ...] = ()
    shared: tuple[tuple[str, str | None], ...] = ()


@dataclass(frozen=True, slots=True)
class FolderStatus:
    folder: str
    messages: int
    unseen: int
    uidnext: int | None
    uidvalidity: int | None


@dataclass(frozen=True, slots=True)
class QuotaInfo:
    root: str
    resource: str
    usage: int
    limit: int


@dataclass(frozen=True, slots=True)
class ServerFeatures:
    """Capability flags the bridge cares about (post-authentication)."""

    sort: bool
    threads: tuple[str, ...]
    move: bool
    uidplus: bool
    condstore: bool
    qresync: bool
    special_use: bool
    namespace: bool
    quota: bool
    idle: bool
    esearch: bool
    utf8_accept: bool
    literal_plus: bool

    @classmethod
    def from_capabilities(cls, caps: Iterable[str]) -> ServerFeatures:
        c = {x.upper() for x in caps}
        return cls(
            sort="SORT" in c,
            threads=tuple(sorted(x.split("=", 1)[1] for x in c if x.startswith("THREAD="))),
            move="MOVE" in c,
            uidplus="UIDPLUS" in c,
            condstore="CONDSTORE" in c,
            qresync="QRESYNC" in c,
            special_use="SPECIAL-USE" in c,
            namespace="NAMESPACE" in c,
            quota="QUOTA" in c or any(x.startswith("QUOTA=") for x in c),
            idle="IDLE" in c,
            esearch="ESEARCH" in c,
            utf8_accept="UTF8=ACCEPT" in c or "UTF8=ONLY" in c,
            literal_plus="LITERAL+" in c or "LITERAL-" in c,
        )


@dataclass(frozen=True, slots=True)
class SearchCriteria:
    """Structured search. All given criteria must match (AND).

    Text criteria are case-insensitive substring matches done by the server.
    ``since``/``before`` compare the arrival date (INTERNALDATE, day precision;
    ``before`` is exclusive). ``unseen``/``flagged``: ``True`` = only those,
    ``False`` = only the opposite, ``None`` = don't care. ``has_attachment`` is
    best-effort (server pre-filter + BODYSTRUCTURE check of the newest candidates).
    """

    from_: str | None = None
    to: str | None = None
    cc: str | None = None
    subject: str | None = None
    body: str | None = None
    text: str | None = None
    since: date | None = None
    before: date | None = None
    unseen: bool | None = None
    flagged: bool | None = None
    has_attachment: bool | None = None
    larger: int | None = None
    smaller: int | None = None

    def text_items(self) -> list[tuple[str, str]]:
        """``(IMAP key, value)`` for the non-empty text criteria."""
        pairs = [
            ("FROM", self.from_),
            ("TO", self.to),
            ("CC", self.cc),
            ("SUBJECT", self.subject),
            ("BODY", self.body),
            ("TEXT", self.text),
        ]
        out: list[tuple[str, str]] = []
        for key, value in pairs:
            if value is not None:
                cleaned = _clean_search_value(value)
                if cleaned:
                    out.append((key, cleaned))
        return out


@dataclass(frozen=True, slots=True)
class SearchResult:
    """Matching UIDs of one folder, newest first. Page through ``uids`` and call
    :meth:`ImapSession.fetch_summaries`; keep ``uidvalidity`` in the cursor."""

    account: str
    folder: str
    uidvalidity: int
    uids: tuple[int, ...]
    order: Literal["arrival", "uid"]
    exact: bool = True
    notes: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return len(self.uids)

    def refs(self, start: int = 0, stop: int | None = None) -> list[MessageRef]:
        return [
            MessageRef(self.account, self.folder, self.uidvalidity, uid)
            for uid in self.uids[start:stop]
        ]


@dataclass(frozen=True, slots=True)
class IncrementalBatch:
    """Result of :meth:`ImapSession.fetch_summaries_since_uid` (ascending UIDs)."""

    folder: str
    uidvalidity: int
    summaries: tuple[MessageSummary, ...]
    last_uid: int
    """Highest UID covered; pass it back as ``last_uid`` next time."""
    more: bool
    """True if further new messages exist beyond ``limit``."""


@dataclass(frozen=True, slots=True)
class LoginInfo:
    """Facts gathered while connecting (for ``probe`` and diagnostics)."""

    greeting: str
    pre_auth_capabilities: tuple[str, ...]
    capabilities: tuple[str, ...]
    connect_seconds: float
    login_seconds: float
    tls: str
    auth_mechanism: str
    notes: tuple[str, ...] = field(default_factory=tuple)


# =========================================================================== plumbing


class _GuardedIMAP4(IMAP4WithTimeout):
    """imaplib.IMAP4 that takes its socket from our SSRF-safe connector."""

    def __init__(self, host: str, port: int, connector: Callable[[], socket.socket]) -> None:
        self._uem_connector = connector
        super().__init__(host, port, None)

    def _create_socket(self, timeout: float | None = None) -> socket.socket:  # noqa: ARG002
        return self._uem_connector()


class _GuardedIMAPClient(IMAPClient):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        implicit_tls: bool,
        ssl_context: ssl.SSLContext,
        connector: Callable[[], socket.socket],
        timeout: SocketTimeout,
    ) -> None:
        self._uem_connector = connector
        super().__init__(
            host,
            port,
            use_uid=True,
            ssl=implicit_tls,
            ssl_context=ssl_context,
            timeout=timeout,  # pyright: ignore[reportArgumentType]
        )
        self.folder_encode = False  # we handle modified UTF-7 ourselves
        self.normalise_times = False  # keep timezone-aware datetimes

    def _create_IMAP4(self) -> IMAP4WithTimeout:  # noqa: N802 - imapclient hook name
        return _GuardedIMAP4(self.host, self.port, self._uem_connector)


def _s(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return "" if value is None else str(value)


def _server_text(err: BaseException) -> str:
    text = sanitize_line(str(err))
    return text[:300]


_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _clean_search_value(value: str) -> str:
    return re.sub(r"\s+", " ", _CTRL.sub(" ", value)).strip()[:500]


def _astring(value: str) -> bytes:
    """Search argument: ASCII → quoted string; non-ASCII → raw UTF-8 (sent as literal)."""
    raw = value.encode("utf-8")
    if raw.isascii():
        return b'"' + raw.replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'
    return raw


def _imap_date(d: date) -> bytes:
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    return f"{d.day:02d}-{months[d.month - 1]}-{d.year:04d}".encode("ascii")


def _wire_name(folder: str) -> str:
    if not folder or _CTRL.search(folder) or len(folder) > 1000:
        raise FolderNotFound("invalid folder name")
    if folder.isascii():
        return folder
    return _utf7_encode(folder).decode("ascii")


# ---------------------------------------------------------------- BODYSTRUCTURE


def _lower(v: object) -> str:
    return _s(v).lower()


def _params_have_name(params: object) -> bool:
    if not isinstance(params, (tuple, list)):
        return False
    items = cast(Sequence[object], params)
    keys = [_lower(k) for k in items[0::2]]
    return any(k in ("name", "filename") or k.startswith(("name*", "filename*")) for k in keys)


def bodystructure_has_attachments(bs: Any, depth: int = 0) -> bool:
    """Best-effort: does a (parsed) BODYSTRUCTURE contain a real attachment?

    Inline images referenced by Content-ID (HTML newsletters) do not count.
    """
    if depth > 30 or not isinstance(bs, (tuple, list)) or not bs:
        return False
    parts = cast(Sequence[Any], bs)
    if isinstance(parts[0], list):  # multipart: ([parts...], subtype, ...)
        return any(bodystructure_has_attachments(p, depth + 1) for p in cast(list[Any], parts[0]))
    ctype, subtype = _lower(parts[0]), _lower(parts[1] if len(parts) > 1 else b"")
    params = parts[2] if len(parts) > 2 else None
    content_id = parts[3] if len(parts) > 3 else None
    disp_index = 9 if ctype == "text" else 11 if (ctype, subtype) == ("message", "rfc822") else 8
    disposition = parts[disp_index] if len(parts) > disp_index else None
    disp_type = ""
    disp_params: object = None
    if isinstance(disposition, (tuple, list)) and disposition:
        disp = cast(Sequence[object], disposition)
        disp_type = _lower(disp[0])
        disp_params = disp[1] if len(disp) > 1 else None
    if disp_type == "attachment":
        return True
    named = _params_have_name(params) or _params_have_name(disp_params)
    if ctype == "text":
        return named and disp_type != "inline"
    if ctype == "multipart":
        return False
    if ctype == "image" and (disp_type == "inline" or (not disp_type and content_id)):
        return False
    return True


# =========================================================================== session


class ImapSession:
    """An authenticated, read-only IMAP connection for one account.

    Create with :meth:`connect` (or :meth:`for_account`); use as a context manager
    or call :meth:`close`.
    """

    def __init__(
        self,
        client: IMAPClient,
        *,
        account_name: str,
        login_info: LoginInfo,
        folder_roles: Mapping[FolderRole, str] | None = None,
    ) -> None:
        self._client = client
        self.account_name = account_name
        self.login_info = login_info
        self._folder_role_overrides: dict[FolderRole, str] = dict(folder_roles or {})
        self._folders: list[FolderInfo] | None = None
        self.role_warnings: list[str] = []

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
        folder_roles: Mapping[FolderRole, str] | None = None,
        resolver: Resolver | None = None,
    ) -> ImapSession:
        """Connect, (STARTTLS,) authenticate. Raises a :class:`MailError` subclass:
        ``ServerUnreachable``, ``TlsError``, ``AddressNotAllowed``, ``AuthFailed``,
        ``ProtocolError``."""
        net = net or NetPolicy()
        tls = tls or TlsSettings()
        ctx = tls_context(verify=tls.verify, ca_file=tls.ca_file)
        implicit = endpoint.tls == "tls"
        host = endpoint.host
        notes: list[str] = []

        def connector() -> socket.socket:
            sock = open_connection(host, endpoint.port, net, resolver)
            return wrap_tls(sock, ctx, host) if implicit else sock

        t0 = time.monotonic()
        try:
            client = _GuardedIMAPClient(
                host,
                endpoint.port,
                implicit_tls=implicit,
                ssl_context=ctx,
                connector=connector,
                timeout=SocketTimeout(net.connect_timeout, net.read_timeout),
            )
        except MailError:
            raise
        except ssl.SSLError as e:
            raise TlsError(f"TLS error talking to {host}: {e.reason or e}") from e
        except (OSError, imaplib.IMAP4.error) as e:
            raise ServerUnreachable(
                f"no IMAP greeting from {host}:{endpoint.port}: {_server_text(e)}",
                hint="Check host and port; 993 expects implicit TLS, 143 STARTTLS.",
            ) from e

        try:
            greeting = _s(client.welcome)
            if not implicit:
                pre = {_s(c).upper() for c in client.capabilities()}
                if "STARTTLS" not in pre:
                    raise TlsError(
                        f"{host}:{endpoint.port} does not offer STARTTLS",
                        hint="Refusing to log in without TLS. Use port 993 (implicit TLS).",
                    )
                try:
                    client.starttls(ctx)
                except ssl.SSLCertVerificationError as e:
                    raise TlsError(
                        f"certificate verification failed for {host}: {e.verify_message}"
                    ) from e
                except (ssl.SSLError, imaplib.IMAP4.error) as e:
                    raise TlsError(f"STARTTLS with {host} failed: {_server_text(e)}") from e
            connect_seconds = time.monotonic() - t0
            pre_caps = tuple(_s(c).upper() for c in client.capabilities())

            t1 = time.monotonic()
            if "LOGINDISABLED" in pre_caps and "AUTH=PLAIN" not in pre_caps:
                raise AuthFailed("the server does not allow password login on this connection")
            mechanism = "AUTHENTICATE PLAIN" if "AUTH=PLAIN" in pre_caps else "LOGIN"
            try:
                if mechanism == "LOGIN":
                    client.login(username, password)
                else:
                    client.plain_login(username, password)
            except LoginError as e:
                raise AuthFailed(f"login rejected by the server: {_server_text(e)}") from e
            except UnicodeError as e:  # LOGIN cannot carry non-ASCII credentials
                raise AuthFailed(
                    "user name or password contains characters this server's LOGIN "
                    "command cannot transmit (no AUTH=PLAIN offered)"
                ) from e
            login_seconds = time.monotonic() - t1
            caps = tuple(_s(c).upper() for c in client.capabilities())
        except MailError:
            _quiet_shutdown(client)
            raise
        except (imaplib.IMAP4.abort, OSError) as e:
            _quiet_shutdown(client)
            raise ServerUnreachable(f"connection to {host} lost: {_server_text(e)}") from e
        except imaplib.IMAP4.error as e:
            _quiet_shutdown(client)
            raise ProtocolError(f"unexpected server response: {_server_text(e)}") from e

        info = LoginInfo(
            greeting=sanitize_line(greeting)[:200],
            pre_auth_capabilities=pre_caps,
            capabilities=caps,
            connect_seconds=connect_seconds,
            login_seconds=login_seconds,
            tls="implicit TLS" if implicit else "STARTTLS",
            auth_mechanism=mechanism,
            notes=tuple(notes),
        )
        return cls(client, account_name=account_name, login_info=info, folder_roles=folder_roles)

    @classmethod
    def for_account(
        cls,
        account: Account,
        password: str,
        *,
        net: NetPolicy | None = None,
        resolver: Resolver | None = None,
    ) -> ImapSession:
        if account.kind != "imap":
            raise ValueError(f"account {account.name!r} is not an IMAP account")
        return cls.connect(
            account.endpoint,
            account.username,
            password,
            account_name=account.name,
            net=net,
            tls=account.tls,
            folder_roles=account.effective_folder_roles(),
            resolver=resolver,
        )

    def close(self) -> None:
        try:
            self._client.logout()
        except Exception:  # noqa: BLE001 - connection may already be gone
            _quiet_shutdown(self._client)

    def abort(self) -> None:
        """Cut the connection without LOGOUT. Safe to call from another thread and
        never blocks: a call blocked in the owning thread then fails promptly.

        Only the socket is shut down here. ``imaplib``'s own ``shutdown()`` closes
        its buffered reader first, and that reader's lock is held by a thread
        blocked in ``readline()`` — closing would wait until the read timeout. The
        base-class ``socket.shutdown`` is used so an ``SSLSocket`` keeps its SSL
        object for the reader that is still inside it. Releasing file and socket
        is left to :meth:`close` once the owning thread has returned.
        """
        sock = getattr(getattr(self._client, "_imap", None), "sock", None)
        if isinstance(sock, socket.socket):
            try:
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass  # already closed or never connected

    def __enter__(self) -> ImapSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------ helpers

    def _call[T](self, what: str, fn: Callable[[], T]) -> T:
        try:
            return fn()
        except MailError:
            raise
        except (imaplib.IMAP4.abort, OSError) as e:
            raise ServerUnreachable(f"connection lost during {what}: {_server_text(e)}") from e
        except imaplib.IMAP4.error as e:
            raise ProtocolError(f"{what} failed: {_server_text(e)}") from e

    @property
    def capabilities(self) -> tuple[str, ...]:
        return self.login_info.capabilities

    @property
    def features(self) -> ServerFeatures:
        return ServerFeatures.from_capabilities(self.capabilities)

    def has(self, capability: str) -> bool:
        return capability.upper() in self.capabilities

    def _examine(self, folder: str) -> tuple[str, int, int]:
        """EXAMINE (read-only select). Returns ``(wire_name, uidvalidity, exists)``."""
        wire = _wire_name(folder)
        try:
            resp = self._client.select_folder(wire, readonly=True)
        except imaplib.IMAP4.abort as e:
            raise ServerUnreachable(f"connection lost: {_server_text(e)}") from e
        except OSError as e:
            raise ServerUnreachable(f"connection lost: {_server_text(e)}") from e
        except imaplib.IMAP4.error as e:
            raise FolderNotFound(
                f"cannot open folder {decode_folder_name(wire)!r}: {_server_text(e)}"
            ) from e
        uidvalidity = int(cast(int, resp.get(b"UIDVALIDITY", 0)) or 0)
        exists = int(cast(int, resp.get(b"EXISTS", 0)) or 0)
        if uidvalidity <= 0:
            raise ProtocolError(f"server sent no UIDVALIDITY for {decode_folder_name(wire)!r}")
        return wire, uidvalidity, exists

    # ------------------------------------------------------------ server info

    def namespace(self) -> Namespace | None:
        if not self.has("NAMESPACE"):
            return None
        ns = self._call("NAMESPACE", self._client.namespace)

        def conv(items: object) -> tuple[tuple[str, str | None], ...]:
            if not items:
                return ()
            pairs = cast(Iterable[tuple[object, object]], items)
            return tuple((_s(p), (_s(d) or None) if d is not None else None) for p, d in pairs)

        return Namespace(personal=conv(ns[0]), other=conv(ns[1]), shared=conv(ns[2]))

    def quota(self) -> list[QuotaInfo] | None:
        """Quota of the INBOX quota root(s), or ``None`` without the QUOTA extension."""
        if not self.features.quota:
            return None
        _roots, quotas = self._call("GETQUOTAROOT", lambda: self._client.get_quota_root("INBOX"))
        return [
            QuotaInfo(root=_s(q.quota_root), resource=_s(q.resource), usage=q.usage, limit=q.limit)
            for q in quotas
        ]

    # ------------------------------------------------------------ folders

    def list_folders(self, *, with_counts: bool = False, refresh: bool = False) -> list[FolderInfo]:
        """All folders with detected roles. ``with_counts`` adds STATUS counts
        (one round trip per selectable folder)."""
        if self._folders is None or refresh:
            raw = self._call("LIST", lambda: self._client.list_folders())
            items: list[RawFolder] = []
            for flags, delim, name in raw:
                wire = _s(name)
                items.append(
                    RawFolder(
                        name=wire,
                        display_name=decode_folder_name(wire),
                        delimiter=_s(delim) or None if delim is not None else None,
                        flags=tuple(_s(f) for f in flags),
                    )
                )
            roles, warnings = assign_roles(
                items,
                overrides=self._folder_role_overrides,
                use_special_use=True,
            )
            self.role_warnings = warnings
            folders: list[FolderInfo] = []
            for f in items:
                lowered = {x.lower() for x in f.flags}
                folders.append(
                    FolderInfo(
                        name=f.name,
                        display_name=f.display_name,
                        delimiter=f.delimiter,
                        flags=f.flags,
                        role=roles.get(f.name),
                        selectable="\\noselect" not in lowered and "\\nonexistent" not in lowered,
                    )
                )
            folders.sort(key=_folder_sort_key)
            self._folders = folders
        if not with_counts:
            return list(self._folders)
        out: list[FolderInfo] = []
        for f in self._folders:
            if not f.selectable:
                out.append(f)
                continue
            try:
                st = self.folder_status(f.name)
            except (FolderNotFound, ProtocolError):
                out.append(f)
                continue
            out.append(
                FolderInfo(
                    name=f.name,
                    display_name=f.display_name,
                    delimiter=f.delimiter,
                    flags=f.flags,
                    role=f.role,
                    selectable=True,
                    messages=st.messages,
                    unseen=st.unseen,
                )
            )
        return out

    def folder_status(self, folder: str) -> FolderStatus:
        wire = _wire_name(folder)
        what = [b"MESSAGES", b"UNSEEN", b"UIDNEXT", b"UIDVALIDITY"]
        try:
            st = self._client.folder_status(wire, what)
        except imaplib.IMAP4.abort as e:
            raise ServerUnreachable(f"connection lost: {_server_text(e)}") from e
        except imaplib.IMAP4.error as e:
            raise FolderNotFound(
                f"no status for folder {decode_folder_name(wire)!r}: {_server_text(e)}"
            ) from e

        def num(key: bytes) -> int | None:
            v = st.get(key)
            return int(v) if v is not None else None

        return FolderStatus(
            folder=wire,
            messages=num(b"MESSAGES") or 0,
            unseen=num(b"UNSEEN") or 0,
            uidnext=num(b"UIDNEXT"),
            uidvalidity=num(b"UIDVALIDITY"),
        )

    def folder_for_role(self, role: FolderRole) -> FolderInfo | None:
        for f in self.list_folders():
            if f.role == role:
                return f
        return None

    def resolve_folder(self, name: str) -> FolderInfo:
        """Find a folder by wire name, display name (exact, then case-insensitive)
        or role name (``inbox``, ``sent`` …). Raises :class:`FolderNotFound`."""
        folders = self.list_folders()
        for f in folders:
            if f.name == name:
                return f
        for f in folders:
            if f.display_name == name:
                return f
        target = name.casefold()
        for f in folders:
            if f.display_name.casefold() == target:
                return f
        for f in folders:
            if f.role is not None and f.role == target:
                return f
        raise FolderNotFound(f"no folder named {name!r}")

    # ------------------------------------------------------------ search

    def _criteria_bytes(
        self, criteria: SearchCriteria, *, include_text: Iterable[tuple[str, str]]
    ) -> list[bytes]:
        out: list[bytes] = [b"UNDELETED"]
        for key, value in include_text:
            out += [key.encode("ascii"), _astring(value)]
        if criteria.since:
            out += [b"SINCE", _imap_date(criteria.since)]
        if criteria.before:
            out += [b"BEFORE", _imap_date(criteria.before)]
        if criteria.unseen is True:
            out.append(b"UNSEEN")
        elif criteria.unseen is False:
            out.append(b"SEEN")
        if criteria.flagged is True:
            out.append(b"FLAGGED")
        elif criteria.flagged is False:
            out.append(b"UNFLAGGED")
        if criteria.larger is not None and criteria.larger >= 0:
            out += [b"LARGER", str(int(criteria.larger)).encode()]
        if criteria.smaller is not None and criteria.smaller > 0:
            out += [b"SMALLER", str(int(criteria.smaller)).encode()]
        if criteria.has_attachment is True:
            out += [
                b"OR",
                b"HEADER",
                b"Content-Type",
                b'"multipart/mixed"',
                b"HEADER",
                b"Content-Type",
                b'"application/"',
            ]
        return out

    def _run_search(self, args: list[bytes], charset: str | None) -> tuple[list[int], str]:
        client = cast(Any, self._client)
        if self.has("SORT"):
            data = client._raw_command_untagged(
                b"SORT",
                [b"(REVERSE ARRIVAL)", (charset or "US-ASCII").encode("ascii"), *args],
                unpack=True,
            )
            return [int(x) for x in _s(data).split()], "arrival"
        full = ([b"CHARSET", charset.encode("ascii")] if charset else []) + args
        data = client._raw_command_untagged(b"SEARCH", full)
        uids = sorted({int(x) for x in parse_message_list(data)}, reverse=True)
        return uids, "uid"

    def search(self, folder: str, criteria: SearchCriteria | None = None) -> SearchResult:
        """Search one folder; returns all matching UIDs newest first.

        Non-ASCII text is sent as UTF-8 (``CHARSET UTF-8``). If the server rejects
        that, the non-ASCII criteria are applied client-side to the headers of the
        newest candidates (bounded by ``MAX_CLIENT_FILTER``); body criteria then
        cannot be honoured and the result is marked ``exact=False`` with notes.
        """
        criteria = criteria or SearchCriteria()
        wire, uidvalidity, exists = self._examine(folder)
        notes: list[str] = []
        exact = True
        if exists == 0:
            return SearchResult(self.account_name, wire, uidvalidity, (), "uid")

        text_items = criteria.text_items()
        needs_utf8 = any(not v.isascii() for _k, v in text_items)
        args = self._criteria_bytes(criteria, include_text=text_items)
        try:
            uids, order = self._search_call(args, "UTF-8" if needs_utf8 else None)
        except ProtocolError:
            if not needs_utf8:
                raise
            ascii_items = [(k, v) for k, v in text_items if v.isascii()]
            local_items = [(k, v) for k, v in text_items if not v.isascii()]
            args = self._criteria_bytes(criteria, include_text=ascii_items)
            uids, order = self._search_call(args, None)
            uids, more_notes = self._filter_headers_locally(wire, uids, local_items)
            notes += ["server rejected UTF-8 search; non-ASCII terms matched locally", *more_notes]
            exact = False

        if criteria.has_attachment is not None:
            uids, att_notes = self._filter_attachments(uids, criteria.has_attachment)
            notes += att_notes
            if att_notes:
                exact = False

        return SearchResult(
            account=self.account_name,
            folder=wire,
            uidvalidity=uidvalidity,
            uids=tuple(uids),
            order=cast(Literal["arrival", "uid"], order),
            exact=exact,
            notes=tuple(notes),
        )

    def search_related(self, folder: str, message_ids: Sequence[str]) -> SearchResult:
        """Messages whose Message-ID, In-Reply-To or References header contains one
        of ``message_ids`` (for conversation lookup), newest first.

        At most ``MAX_RELATED_IDS`` ids are used per call; ids are sanitised like
        any other search value (they come from mail and are untrusted).
        """
        wire, uidvalidity, exists = self._examine(folder)
        ids = [c for c in (_clean_search_value(m) for m in message_ids) if c][:MAX_RELATED_IDS]
        if exists == 0 or not ids:
            return SearchResult(self.account_name, wire, uidvalidity, (), "uid")
        keys: list[list[bytes]] = []
        for mid in ids:
            for header in (b"Message-ID", b"In-Reply-To", b"References"):
                keys.append([b"HEADER", header, _astring(mid)])
        args: list[bytes] = [b"UNDELETED"] + [b"OR"] * (len(keys) - 1)
        for key in keys:
            args += key
        needs_utf8 = any(not m.isascii() for m in ids)
        uids, order = self._search_call(args, "UTF-8" if needs_utf8 else None)
        return SearchResult(
            account=self.account_name,
            folder=wire,
            uidvalidity=uidvalidity,
            uids=tuple(uids),
            order=cast(Literal["arrival", "uid"], order),
        )

    def _search_call(self, args: list[bytes], charset: str | None) -> tuple[list[int], str]:
        return self._call("SEARCH", lambda: self._run_search(args, charset))

    def _fetch_raw(self, uids: Sequence[int], items: list[str]) -> dict[int, dict[bytes, Any]]:
        wanted = set(uids)
        result: dict[int, dict[bytes, Any]] = {}
        for i in range(0, len(uids), FETCH_BATCH):
            batch = list(uids[i : i + FETCH_BATCH])
            data = self._call("FETCH", lambda b=batch: self._client.fetch(b, items))
            for uid, fields in cast(dict[int, dict[bytes, Any]], data).items():
                real_uid = fields.get(b"UID", uid)
                if real_uid in wanted:
                    result[int(real_uid)] = fields
        return result

    def _filter_headers_locally(
        self, wire: str, uids: list[int], items: list[tuple[str, str]]
    ) -> tuple[list[int], list[str]]:
        notes: list[str] = []
        if any(k in ("BODY", "TEXT") for k, _ in items):
            notes.append("non-ASCII body/text terms were matched against headers only")
        if len(uids) > MAX_CLIENT_FILTER:
            notes.append(f"only the newest {MAX_CLIENT_FILTER} candidates were checked")
            uids = uids[:MAX_CLIENT_FILTER]
        fetched = self._fetch_raw(uids, ["UID", _HEADER_FIELDS])
        keep: list[int] = []
        for uid in uids:
            fields = fetched.get(uid)
            if fields is None:
                continue
            h = parse_header_block(_header_bytes(fields))
            if all(_header_matches(h, k, v) for k, v in items):
                keep.append(uid)
        return keep, notes

    def _filter_attachments(self, uids: list[int], wanted: bool) -> tuple[list[int], list[str]]:
        notes: list[str] = []
        checked = uids
        if len(uids) > MAX_CLIENT_FILTER:
            checked = uids[:MAX_CLIENT_FILTER]
            notes.append(f"attachment filter checked only the newest {MAX_CLIENT_FILTER} matches")
        fetched = self._fetch_raw(checked, ["UID", "BODYSTRUCTURE"])
        keep = [
            uid
            for uid in checked
            if uid in fetched
            and bodystructure_has_attachments(fetched[uid].get(b"BODYSTRUCTURE")) == wanted
        ]
        return keep, notes

    # ------------------------------------------------------------ fetch

    def fetch_summaries(
        self, folder: str, uids: Sequence[int], *, uidvalidity: int | None = None
    ) -> list[MessageSummary]:
        """Header summaries for ``uids`` (in the given order; vanished UIDs are skipped).

        Pass the ``uidvalidity`` from a search/cursor to fail cleanly with
        :class:`UidValidityChanged` if the folder was rebuilt meanwhile.
        """
        wire, current, _exists = self._examine(folder)
        if uidvalidity is not None and uidvalidity != current:
            raise UidValidityChanged(f"UIDVALIDITY of {decode_folder_name(wire)!r} changed")
        if not uids:
            return []
        return self._summaries(wire, current, list(uids))

    def _summaries(self, wire: str, uidvalidity: int, uids: list[int]) -> list[MessageSummary]:
        try:
            fetched = self._fetch_raw(uids, _SUMMARY_ITEMS)
        except ProtocolError:
            # Some servers produce BODYSTRUCTUREs imapclient cannot parse.
            fetched = self._fetch_raw(uids, _SUMMARY_ITEMS_NO_BS)
        out: list[MessageSummary] = []
        for uid in uids:
            fields = fetched.get(uid)
            if fields is None:
                continue
            ref = MessageRef(self.account_name or "-", wire, uidvalidity, uid)
            headers = parse_header_block(_header_bytes(fields))
            out.append(_summary(ref, fields, headers))
        return out

    def fetch_summaries_since_uid(
        self, folder: str, uidvalidity: int | None, last_uid: int, limit: int = 500
    ) -> IncrementalBatch:
        """New messages with UID > ``last_uid`` (ascending, at most ``limit``).

        ``UID n:*`` always includes the highest message even if its UID < n, so
        UIDs ≤ ``last_uid`` are filtered out here. ``uidvalidity=None`` skips the
        check (first sync); otherwise a mismatch raises :class:`UidValidityChanged`
        and the caller must rebuild its index.
        """
        wire, current, exists = self._examine(folder)
        if uidvalidity is not None and uidvalidity != current:
            raise UidValidityChanged(f"UIDVALIDITY of {decode_folder_name(wire)!r} changed")
        last_uid = max(0, int(last_uid))
        if exists == 0:
            return IncrementalBatch(wire, current, (), last_uid, False)
        client = cast(Any, self._client)
        data = self._call(
            "SEARCH",
            lambda: client._raw_command_untagged(
                b"SEARCH", [b"UID", f"{last_uid + 1}:*".encode("ascii")]
            ),
        )
        new = sorted(u for u in {int(x) for x in parse_message_list(data)} if u > last_uid)
        limit = max(1, limit)
        take = new[:limit]
        summaries = self._summaries(wire, current, take) if take else []
        highest = take[-1] if take else last_uid
        return IncrementalBatch(wire, current, tuple(summaries), highest, len(new) > limit)

    def fetch_message(
        self,
        ref: MessageRef,
        *,
        max_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        max_body_chars: int = DEFAULT_MAX_BODY_CHARS,
        body_offset: int = 0,
    ) -> Message:
        """Full message (never sets ``\\Seen``). Messages larger than ``max_bytes``
        are fetched partially and parsed as far as possible (``source_truncated``)."""
        if self.account_name and ref.account != self.account_name:
            raise InvalidRef("message reference belongs to a different account")
        wire, current, _exists = self._examine(ref.folder)
        if ref.uidvalidity != current:
            raise UidValidityChanged(f"UIDVALIDITY of {decode_folder_name(wire)!r} changed")
        meta = self._fetch_raw([ref.uid], ["UID", "FLAGS", "INTERNALDATE", "RFC822.SIZE"])
        fields = meta.get(ref.uid)
        if fields is None:
            raise MessageNotFound(f"message {ref.uid} not found in {decode_folder_name(wire)!r}")
        size = int(fields.get(b"RFC822.SIZE") or 0)
        truncated = size > max_bytes
        item = f"BODY.PEEK[]<0.{max_bytes}>" if truncated else "BODY.PEEK[]"
        body = self._fetch_raw([ref.uid], ["UID", item]).get(ref.uid)
        if body is None:
            raise MessageNotFound(f"message {ref.uid} vanished from {decode_folder_name(wire)!r}")
        raw = b""
        for key, value in body.items():
            if key.startswith(b"BODY[]") and isinstance(value, bytes):
                raw = value
                break
        parsed = parse_message(raw)
        summary = _summary(
            MessageRef(ref.account, wire, current, ref.uid),
            fields,
            parsed.headers,
            has_attachments=any(not a.inline for a in parsed.attachments),
        )
        return Message(
            summary=summary,
            body=slice_text(parsed.text, max(1, max_body_chars), body_offset),
            body_source=parsed.text_source,
            attachments=parsed.attachments,
            source_truncated=truncated,
        )


# =========================================================================== helpers


def _quiet_shutdown(client: IMAPClient) -> None:
    try:
        client.shutdown()
    except Exception:  # noqa: BLE001
        pass


def _folder_sort_key(f: FolderInfo) -> tuple[int, str]:
    order: dict[str | None, int] = {
        "inbox": 0,
        "drafts": 1,
        "sent": 2,
        "archive": 3,
        "junk": 4,
        "trash": 5,
    }
    return (order.get(f.role, 10), f.display_name.casefold())


def _header_bytes(fields: Mapping[bytes, Any]) -> bytes:
    for key, value in fields.items():
        if key.startswith(b"BODY[HEADER.FIELDS") and isinstance(value, bytes):
            return value
    return b""


def _header_matches(h: HeaderFields, key: str, value: str) -> bool:
    needle = value.casefold()

    def addrs(items: Iterable[Any]) -> str:
        return " ".join(f"{a.name} {a.email}" for a in items)

    haystacks = {
        "FROM": addrs(h.from_),
        "TO": addrs(h.to),
        "CC": addrs(h.cc),
        "SUBJECT": h.subject,
        "BODY": h.subject,
        "TEXT": " ".join([addrs(h.from_), addrs(h.to), addrs(h.cc), h.subject]),
    }
    return needle in haystacks.get(key, "").casefold()


def _summary(
    ref: MessageRef,
    fields: Mapping[bytes, Any],
    headers: HeaderFields,
    *,
    has_attachments: bool | None = None,
) -> MessageSummary:
    received = fields.get(b"INTERNALDATE")
    received_dt = received if isinstance(received, datetime) else None
    if has_attachments is None:
        has_attachments = bodystructure_has_attachments(fields.get(b"BODYSTRUCTURE"))
    size = fields.get(b"RFC822.SIZE")
    return MessageSummary(
        ref=ref,
        date=headers.date or received_dt,
        received=received_dt,
        from_=headers.from_,
        to=headers.to,
        cc=headers.cc,
        reply_to=headers.reply_to,
        subject=headers.subject,
        flags=tuple(_s(f) for f in fields.get(b"FLAGS", ())),
        size=int(size) if size is not None else None,
        has_attachments=has_attachments,
        message_id=headers.message_id,
        in_reply_to=headers.in_reply_to,
        references=headers.references,
    )
