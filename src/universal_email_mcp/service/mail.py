"""Read-only mail operations behind the MCP tools.

:class:`MailService` combines the account router (sessions, fan-out, deadlines),
the header index and fuzzy matching. Each per-account unit of work is one
synchronous function run in the account's worker thread; results come back as
plain dataclasses that the tool layer renders (Markdown + structured content).

Nothing here trusts mail content: it is only matched, counted and passed on.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from universal_email_mcp.config import Config, Limits
from universal_email_mcp.errors import (
    AmbiguousFolder,
    FolderNotFound,
    InvalidArgument,
    InvalidRef,
    MailError,
    ProtocolError,
    StaleCursor,
    UidValidityChanged,
)
from universal_email_mcp.mail.folders import decode_folder_name
from universal_email_mcp.mail.imap import (
    ImapSession,
    Namespace,
    QuotaInfo,
    SearchCriteria,
    SearchResult,
    ServerFeatures,
)
from universal_email_mcp.models import (
    Account,
    Address,
    FolderInfo,
    FolderRole,
    Message,
    MessageRef,
    MessageSummary,
)
from universal_email_mcp.service import folder_list, fuzzy
from universal_email_mcp.service.cursor import Cursor, CursorCodec, Key, SourcePos, query_hash
from universal_email_mcp.service.index import HeaderIndex
from universal_email_mcp.service.paging import (
    MAX_CURSOR_RETRIES,
    STOPPED_RETRYING,
    TRANSIENT,
    keyset_page,
)
from universal_email_mcp.service.query import Query, score_message, similar
from universal_email_mcp.service.router import AccountProblem, AccountRouter, Fanout
from universal_email_mcp.service.trust import SentTo, SentToIndex

DEFAULT_PAGE = 20
MAX_THREAD_MESSAGES = 50
MAX_THREAD_FOLDERS = 25
THREAD_ROUNDS = 3
DEFAULT_CONTACT_DAYS = 180
"""How far back a contact search (with a query) looks by default."""
MAX_CONTACT_DAYS = 730
OVERVIEW_CONTACT_DAYS = 7
"""The contact overview (no query): recent correspondents only."""
OVERVIEW_HEADERS = 150
"""Headers per account the contact overview reads (newest first, INBOX + Sent)."""
OVERVIEW_CONTACTS = 20
_CONTACT_ROLES: tuple[FolderRole, ...] = ("sent", "inbox")
_THREAD_ROLES: tuple[FolderRole, ...] = ("inbox", "sent")
_SKIP_FOR_THREADS: frozenset[FolderRole | None] = frozenset({"trash", "junk", "drafts"})

THREAD_PARTICIPANT_THRESHOLD = 85.0
"""Folder-name score for a conversation participant (thread folder order)."""


# =========================================================================== results


@dataclass(frozen=True, slots=True)
class Hit:
    """A message in a result list."""

    summary: MessageSummary
    score: float | None = None
    """Fuzzy score (0–100); ``None`` for exact results."""

    @property
    def account(self) -> str:
        return self.summary.ref.account

    @property
    def folder_display(self) -> str:
        return decode_folder_name(self.summary.ref.folder)


@dataclass(slots=True)
class MessagePage:
    hits: list[Hit]
    total: int
    """Matches across all answering sources (after the first page's snapshot)."""
    offset: int
    """Results returned before this page."""
    cursor: str | None
    notes: list[str] = field(default_factory=list[str])
    problems: list[AccountProblem] = field(default_factory=list[AccountProblem])
    exact: bool = True
    answered: int = 0
    """Accounts that answered (0 with problems = the whole call failed)."""
    mode: Literal["exact", "wildcard", "fuzzy"] = "exact"
    exhausted: bool = False
    """A cursor was given but nothing was left (the list changed)."""


@dataclass(frozen=True, slots=True)
class AccountDetails:
    account: Account
    features: ServerFeatures | None
    capabilities: tuple[str, ...]
    quota: list[QuotaInfo] | None
    roles: dict[FolderRole, str]
    """Role → decoded folder name."""
    notes: tuple[str, ...] = ()


@dataclass(slots=True)
class FolderRow:
    account: str
    node: folder_list.Node
    level: int
    """1 = the level listed (top level, or the children of ``parent``)."""
    score: float | None = None
    messages: int | None = None
    unread: int | None = None


@dataclass(slots=True)
class FolderPage:
    rows: list[FolderRow]
    total: int
    offset: int
    cursor: str | None
    mode: Literal["top", "children", "wildcard", "fuzzy"]
    depth: int
    parent: list[str] = field(default_factory=list[str])
    """The resolved parent per account (full names), when ``parent`` was given."""
    similar: list[str] = field(default_factory=list[str])
    """Close folder names when a query matched nothing."""
    leaf: list[str] = field(default_factory=list[str])
    """Parents without subfolders (shown as the folder itself)."""
    counts_capped: bool = False
    exhausted: bool = False
    """A cursor was given but nothing was left (the list changed)."""
    notes: list[str] = field(default_factory=list[str])
    problems: list[AccountProblem] = field(default_factory=list[AccountProblem])
    answered: int = 0


@dataclass(slots=True)
class _AccountFolderRows:
    rows: list[tuple[Key, FolderRow]]
    parent: str | None = None
    leaf: bool = False
    """The parent has no subfolders: the row is the folder itself."""
    notes: list[str] = field(default_factory=list[str])
    similar: list[str] = field(default_factory=list[str])
    error: FolderNotFound | AmbiguousFolder | None = None


@dataclass(slots=True)
class Contact:
    email: str
    name: str
    received: int = 0
    """Messages from this address (in INBOX)."""
    sent: int = 0
    """Messages the user sent to this address (in Sent)."""
    last: datetime | None = None
    accounts: list[str] = field(default_factory=list[str])
    rank: float = 0.0
    score: float | None = None
    sent_to: bool | None = False
    """The user has written to this address (Sent, last two years — see
    :mod:`.trust`); ``None``: unknown (Sent unavailable or only partly read)."""


@dataclass(slots=True)
class ContactResult:
    contacts: list[Contact]
    total: int
    offset: int
    cursor: str | None
    mode: Literal["overview", "wildcard", "fuzzy"]
    days: int
    scanned: int
    """Message headers read (all accounts)."""
    notes: list[str]
    problems: list[AccountProblem]
    answered: int
    similar: list[str] = field(default_factory=list[str])
    exhausted: bool = False


@dataclass(slots=True)
class ThreadResult:
    root: MessageSummary
    hits: list[Hit]
    notes: list[str] = field(default_factory=list[str])
    problems: list[AccountProblem] = field(default_factory=list[AccountProblem])


# =========================================================================== helpers


def _sort_key(s: MessageSummary) -> float:
    """Arrival time for ordering (see :func:`_when`)."""
    d = _when(s, datetime.now(UTC))
    return d.timestamp() if d else 0.0


def _hit_key(h: Hit) -> Key:
    """Best score first, then newest arrival; unique per message."""
    r = h.summary.ref
    return (-round(h.score or 0.0), -_sort_key(h.summary), r.account, r.folder, r.uid)


def _personal_prefix(ns: Namespace | None) -> str:
    if ns and ns.personal:
        return ns.personal[0][0]
    return ""


def resolve_folder(
    session: ImapSession, name: str, personal_prefix: str = ""
) -> tuple[FolderInfo, str | None]:
    """A folder argument of the message tools (see :func:`folder_list.resolve`):
    selectable folders only. Returns the folder and a note when it was matched
    approximately."""
    roots = folder_list.build(session.list_folders(), personal_prefix)
    node, note = folder_list.resolve(
        roots, name, selectable_only=True, where=f" in account {session.account_name!r}"
    )
    assert node.info is not None  # selectable nodes are real folders
    return node.info, note


def _when(s: MessageSummary, now: datetime) -> datetime | None:
    """Arrival time for ordering and recency: INTERNALDATE (set by the server);
    the forgeable Date header only as a fallback, and never in the future."""
    if s.received is not None:
        return s.received
    if s.date is not None and s.date <= now + timedelta(hours=1):
        return s.date
    return None


# =========================================================================== service


class MailService:
    def __init__(
        self,
        config: Config,
        *,
        router: AccountRouter | None = None,
        index: HeaderIndex | None = None,
        cursors: CursorCodec | None = None,
        viewer_base: str | None = None,
    ) -> None:
        self.config = config
        self.router = router or AccountRouter(config)
        self.index = index or HeaderIndex()
        self.cursors = cursors or CursorCodec()
        self._viewer_base = viewer_base
        self._prefixes: dict[str, str] = {}
        self.sent_to = SentToIndex(self.index)
        """Per-account "written to" sets (contacts; the send-time check, WP 2d)."""

    @property
    def limits(self) -> Limits:
        return self.config.limits

    def viewer_url(self, ref: MessageRef) -> str | None:
        """Link to the portal message viewer (remote mode, M3); ``None`` locally."""
        if not self._viewer_base:
            return None
        return f"{self._viewer_base.rstrip('/')}/m/{ref.encode()}"

    async def aclose(self) -> None:
        await self.router.aclose()

    def clamp_limit(self, limit: int | None, default: int = DEFAULT_PAGE) -> int:
        return max(1, min(limit or default, self.limits.max_results))

    def _prefix(self, session: ImapSession) -> str:
        acc = session.account_name
        if acc not in self._prefixes:
            self._prefixes[acc] = _personal_prefix(session.namespace())
        return self._prefixes[acc]

    def _folders_for(
        self, session: ImapSession, names: Sequence[str] | None, notes: list[str]
    ) -> list[FolderInfo]:
        out: list[FolderInfo] = []
        for n in names or ["inbox"]:
            f, note = resolve_folder(session, n, self._prefix(session))
            if note:
                notes.append(f"{session.account_name}: {note}")
            if f.name not in {x.name for x in out}:
                out.append(f)
        return out

    # ------------------------------------------------------------ account_info

    async def account_info(
        self, accounts: Sequence[str] | None
    ) -> tuple[list[AccountDetails], list[AccountProblem]]:
        selected, problems = self.router.select(accounts)

        def work(session: ImapSession) -> AccountDetails:
            acc = self.config.account(session.account_name)
            folders = session.list_folders()
            quota: list[QuotaInfo] | None = None
            notes: list[str] = []
            try:
                quota = session.quota()
            except MailError as e:
                notes.append(f"quota unavailable: {e.message}")
            roles: dict[FolderRole, str] = {
                f.role: f.display_name for f in folders if f.role is not None
            }
            notes += session.role_warnings
            return AccountDetails(
                account=acc,
                features=session.features,
                capabilities=session.capabilities,
                quota=quota,
                roles=roles,
                notes=tuple(notes),
            )

        fan = await self._fan(selected, work)
        details = list(fan.results.values())
        # Accounts without a backend yet (POP3) are still described, unconnected.
        for p in problems:
            if p.code == "NOT_SUPPORTED_YET":
                acc = self.config.account(p.account)
                details.append(AccountDetails(acc, None, (), None, {}, (p.message,)))
        return details, [*problems, *fan.problems]

    async def _fan[T](
        self, accounts: Sequence[Account], fn: Callable[[ImapSession], T]
    ) -> Fanout[T]:
        async def work(acc: Account) -> T:
            return await self.router.call(acc, fn)

        return await self.router.fanout(accounts, work)

    # ------------------------------------------------------------ folders

    async def list_folders(
        self,
        *,
        args: dict[str, Any],
        accounts: Sequence[str] | None,
        parent: str | None = None,
        query: Query | None = None,
        depth: int = 1,
        counts: bool = True,
        limit: int | None = None,
        cursor: str | None = None,
        tool: str = "list_folders",
    ) -> FolderPage:
        """One level of the folder tree (top level, or the children of ``parent``)
        down to ``depth`` levels, or — with ``query`` — the matching folders at any
        depth below it. Keyset-paged per account; counts only for the page shown.
        The first page re-reads the folder list (folders created meanwhile)."""
        depth = max(1, min(depth, folder_list.MAX_DEPTH))
        limit = self.clamp_limit(limit, folder_list.DEFAULT_PAGE)
        qh = query_hash(args)
        cur = self.cursors.decode(cursor, tool=tool, query=qh) if cursor else None
        selected, problems = self.router.select(accounts)
        rank = {a.name: i for i, a in enumerate(selected)}

        def work(session: ImapSession) -> _AccountFolderRows:
            acc = session.account_name
            r = rank[acc]
            roots = folder_list.build(
                session.list_folders(refresh=cur is None), self._prefix(session)
            )
            out = _AccountFolderRows([])
            base = roots
            if parent is not None:
                try:
                    node, note = folder_list.resolve(roots, parent, prefer_groups=True)
                except (FolderNotFound, AmbiguousFolder) as e:
                    out.error = e
                    return out
                out.parent = node.full_name
                if note:
                    out.notes.append(f"{acc}: {note}")
                if not node.children and query is None:
                    out.leaf = True
                    out.rows = [((r, 0), FolderRow(acc, node, 1))]
                    return out
                base = node.children
            if query is None:
                out.rows = [
                    ((r, i), FolderRow(acc, n, lvl))
                    for i, (n, lvl) in enumerate(folder_list.levels(base, depth))
                ]
                return out
            matches = folder_list.search(base, query)
            out.rows = [
                ((-(m.score or 0.0), r, i), FolderRow(acc, m.node, 1, m.score))
                for i, m in enumerate(matches)
            ]
            if not matches:
                out.similar = folder_list.similar_names(list(folder_list.walk(base)), query)
            return out

        fan = await self._fan(selected, work)
        per_account = fan.results
        if (
            parent is not None
            and per_account
            and all(r.parent is None for r in per_account.values())
            and not fan.problems
        ):
            # Not found (or ambiguous) in every account: an error the model can
            # act on, instead of an empty list.
            errors = [r.error for r in per_account.values() if r.error]
            ambiguous = [e for e in errors if isinstance(e, AmbiguousFolder)]
            if ambiguous:
                choices = list(dict.fromkeys(c for a in ambiguous for c in a.choices))[:8]
                raise AmbiguousFolder(
                    f"{parent!r} matches several folders: " + "; ".join(choices),
                    choices,
                    hint=ambiguous[0].hint,
                )
            raise errors[0]
        notes: list[str] = []
        near: list[str] = []
        parents: list[str] = []
        leaves: list[str] = []
        for name, r in per_account.items():
            notes += r.notes
            if r.error is not None and (
                accounts is not None or isinstance(r.error, AmbiguousFolder)
            ):
                notes.append(f"{name}: {r.error.message}")
            if r.parent:
                parents.append(r.parent)
            if r.leaf and r.parent:
                leaves.append(r.parent)
            near += r.similar
        page = keyset_page(
            {name: r.rows for name, r in per_account.items()},
            limit=limit,
            cursor=cur,
            codec=self.cursors,
            tool=tool,
            query=qh,
            problems=fan.problems,
        )
        rows = [row for _acc, row in page.items]
        capped = False
        if counts and rows:
            capped = await self._folder_counts(selected, rows)
        mode: Literal["top", "children", "wildcard", "fuzzy"]
        if query is not None:
            mode = query.mode
        else:
            mode = "children" if parent is not None else "top"
        return FolderPage(
            rows=rows,
            total=page.total,
            offset=page.offset,
            cursor=page.cursor,
            mode=mode,
            depth=depth,
            parent=list(dict.fromkeys(parents)),
            leaf=list(dict.fromkeys(leaves)),
            similar=list(dict.fromkeys(near))[:5],
            counts_capped=capped,
            exhausted=page.exhausted,
            notes=notes + page.notes,
            problems=[*problems, *fan.problems],
            answered=len(fan.results),
        )

    async def _folder_counts(self, selected: Sequence[Account], rows: Sequence[FolderRow]) -> bool:
        """STATUS (messages, unread) for the selectable folders among ``rows``, at
        most ``MAX_STATUS``; fills the rows in place. Returns whether it capped."""
        wanted = [r for r in rows if r.node.selectable and r.node.info is not None]
        capped = len(wanted) > folder_list.MAX_STATUS
        wanted = wanted[: folder_list.MAX_STATUS]
        by_account: dict[str, list[FolderRow]] = {}
        for r in wanted:
            by_account.setdefault(r.account, []).append(r)

        def work(session: ImapSession) -> None:
            for r in by_account.get(session.account_name, []):
                info = r.node.info
                assert info is not None
                try:
                    st = session.folder_status(info.name)
                except (FolderNotFound, ProtocolError):
                    continue
                r.messages, r.unread = st.messages, st.unseen

        # Failures here only leave counts empty: the folder list itself stands.
        await self._fan([a for a in selected if a.name in by_account], work)
        return capped

    # ------------------------------------------------------------ list / search (exact)

    async def list_messages(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        accounts: Sequence[str] | None,
        folders: Sequence[str] | None,
        criteria: SearchCriteria,
        limit: int | None,
        cursor: str | None,
    ) -> MessagePage:
        """Newest-first paging over all (account, folder) sources matching
        ``criteria`` (server-side search, exact)."""
        limit = self.clamp_limit(limit)
        qh = query_hash(args)
        cur = self.cursors.decode(cursor, tool=tool, query=qh) if cursor else None
        selected, problems = self.router.select(accounts)

        def work(session: ImapSession) -> tuple[list[_Chunk], list[str], bool]:
            notes: list[str] = []
            exact = True
            chunks: list[_Chunk] = []
            for f in self._folders_for(session, folders, notes):
                res = session.search(f.name, criteria)
                notes += [f"{session.account_name}/{f.display_name}: {n}" for n in res.notes]
                exact = exact and res.exact
                chunks.append(self._chunk(session, res, cur, limit))
            return chunks, notes, exact

        fan = await self._fan(selected, work)
        chunks: list[_Chunk] = []
        notes: list[str] = []
        exact = True
        for c, n, e in fan.results.values():
            chunks += c
            notes += n
            exact = exact and e
        hits, next_sources = _merge(chunks, limit)
        total = sum(c.total for c in chunks)
        offset = sum(c.start for c in chunks)
        # Accounts that failed this time keep their old positions, and the cursor
        # stays available so a later page can retry them; a stale position is
        # dropped (that account starts over).
        stale = {p.account for p in fan.problems if p.code == StaleCursor.code}
        retry = any(p.code in TRANSIENT for p in fan.problems)
        more = any(next_sources[c.key].offset < c.total for c in chunks)
        retries = (cur.retries if cur else 0) + 1 if retry and not more else 0
        if retries > MAX_CURSOR_RETRIES:
            notes.append(STOPPED_RETRYING)
            retry = False
        next_cursor = None
        if retry or more:
            sources = {k: v for k, v in (cur.sources if cur else {}).items() if k[0] not in stale}
            sources.update(next_sources)
            next_cursor = self.cursors.encode(Cursor(tool, qh, sources, retries=retries))
        return MessagePage(
            hits=[Hit(h) for h in hits],
            total=total,
            offset=offset,
            cursor=next_cursor,
            notes=notes,
            problems=[*problems, *fan.problems],
            exact=exact,
            answered=len(fan.results),
            exhausted=cur is not None and not hits and not fan.problems,
        )

    def _chunk(
        self, session: ImapSession, res: SearchResult, cur: Cursor | None, limit: int
    ) -> _Chunk:
        key = (res.account, res.folder)
        pos = cur.sources.get(key) if cur else None
        uids = list(res.uids)
        if pos is not None:
            if pos.uidvalidity != res.uidvalidity:
                raise StaleCursor(
                    f"folder {decode_folder_name(res.folder)!r} was rebuilt on the server"
                )
            max_uid = pos.max_uid
        else:
            max_uid = max(uids, default=0)
        if max_uid:
            uids = [u for u in uids if u <= max_uid]
        last_uid = pos.last_uid if pos is not None else 0
        start = _resume_index(uids, last_uid)
        window = uids[start : start + limit]
        summaries = self.index.summaries(
            session, res.folder, res.uidvalidity, window, refresh_flags=True
        )
        return _Chunk(key, res.uidvalidity, max_uid, start, len(uids), window, summaries, last_uid)

    # ------------------------------------------------------------ query search

    async def query_search(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        accounts: Sequence[str] | None,
        folders: Sequence[str] | None,
        criteria: SearchCriteria,
        query: Query,
        threshold: float,
        limit: int | None,
        cursor: str | None,
    ) -> MessagePage:
        """``criteria`` select the candidates server-side; the newest of them (up to
        ``max_headers_scanned`` per account) are matched against ``query``.

        Fuzzy queries also run one exact server-side ``TEXT`` search (headers and
        body, substring): its hits score 100. Wildcard patterns match headers
        only (the server cannot evaluate them). Ranked best first, then by
        arrival (INTERNALDATE — the Date header is forgeable); keyset-paged per
        account.
        """
        limit = self.clamp_limit(limit)
        qh = query_hash(args)
        cur = self.cursors.decode(cursor, tool=tool, query=qh) if cursor else None
        selected, problems = self.router.select(accounts)
        budget = self.limits.max_headers_scanned
        fuzzy_mode = query.pattern is None
        exact_criteria = replace(criteria, text=query.text) if fuzzy_mode else None

        def work(session: ImapSession) -> tuple[list[Hit], list[str], bool]:
            acc = session.account_name
            notes: list[str] = []
            complete = True
            hits: dict[tuple[str, int], Hit] = {}
            remaining = budget
            targets = self._folders_for(session, folders, notes)
            for n, f in enumerate(targets):
                if remaining <= 0:
                    skipped = [x.display_name for x in targets[n:]]
                    complete = False
                    notes.append(
                        f"{acc}: header budget used up; not searched: "
                        + ", ".join(skipped[:5])
                        + (f" (+{len(skipped) - 5})" if len(skipped) > 5 else "")
                    )
                    break
                cand = session.search(f.name, criteria)
                notes += [f"{acc}/{f.display_name}: {x}" for x in cand.notes]
                complete = complete and cand.exact
                exact_uids: list[int] = []
                if exact_criteria is not None:
                    exact_res = session.search(f.name, exact_criteria)
                    if cand.uidvalidity != exact_res.uidvalidity:
                        raise UidValidityChanged("folder changed during the search; try again")
                    exact_uids = list(exact_res.uids[: limit * 4])
                scan = list(cand.uids[:remaining])
                if len(cand.uids) > remaining:
                    complete = False
                    notes.append(
                        f"{acc}/{f.display_name}: the query was matched "
                        f"against the newest {len(scan)} of {len(cand.uids)} messages"
                    )
                remaining -= len(scan)
                uids = list(dict.fromkeys([*exact_uids, *scan]))
                exact_set = set(exact_uids)
                sums = self.index.summaries(session, cand.folder, cand.uidvalidity, uids)
                for sm in sums:
                    sc = 100.0 if sm.ref.uid in exact_set else score_message(query, sm)
                    if sc >= threshold:
                        hits[(sm.ref.folder, sm.ref.uid)] = Hit(sm, round(sc, 1))
            return list(hits.values()), notes, complete

        fan = await self._fan(selected, work)
        rows: dict[str, list[tuple[Key, Hit]]] = {}
        notes: list[str] = []
        complete = True
        for acc, (hits, n, c) in fan.results.items():
            notes += n
            complete = complete and c
            keyed = [(_hit_key(h), h) for h in hits]
            keyed.sort(key=lambda kh: kh[0])
            rows[acc] = keyed
        page = keyset_page(
            rows,
            limit=limit,
            cursor=cur,
            codec=self.cursors,
            tool=tool,
            query=qh,
            problems=fan.problems,
        )
        return MessagePage(
            hits=[h for _acc, h in page.items],
            total=page.total,
            offset=page.offset,
            cursor=page.cursor,
            notes=notes + page.notes,
            problems=[*problems, *fan.problems],
            exact=complete and not fuzzy_mode,
            answered=len(fan.results),
            mode=query.mode,
            exhausted=page.exhausted,
        )

    # ------------------------------------------------------------ single message

    def _ref(self, message_id: str) -> tuple[MessageRef, Account]:
        ref = MessageRef.decode(message_id)
        try:
            acc = self.router.account(ref.account)
        except MailError as e:
            if e.code == "CONFIG_INVALID":
                raise InvalidRef("message id refers to an unknown account") from e
            raise
        return ref, acc

    async def get_message(self, message_id: str, *, offset: int, max_chars: int | None) -> Message:
        ref, acc = self._ref(message_id)
        if offset < 0:
            raise InvalidArgument("offset must be ≥ 0")
        chars = max(1, min(max_chars or self.limits.max_body_chars, self.limits.max_body_chars))

        def fn(session: ImapSession) -> Message:
            return session.fetch_message(
                ref,
                max_bytes=self.limits.max_message_bytes,
                max_body_chars=chars,
                body_offset=offset,
            )

        async def work(a: Account) -> Message:
            return await self.router.call(a, fn)

        return await self.router.run_one(acc, work)

    # ------------------------------------------------------------ threads

    async def get_thread(self, message_id: str, *, limit: int | None) -> ThreadResult:
        ref, acc = self._ref(message_id)
        cap = max(1, min(limit or MAX_THREAD_MESSAGES, MAX_THREAD_MESSAGES))

        def primary(
            session: ImapSession,
        ) -> tuple[MessageSummary, list[MessageSummary], list[str], list[str]]:
            notes: list[str] = []
            first = session.fetch_summaries(ref.folder, [ref.uid], uidvalidity=ref.uidvalidity)
            if not first:
                raise InvalidRef("message not found (moved or deleted?)")
            root = first[0]
            ids = _thread_ids(root)
            if not ids:
                notes.append("the message has no Message-ID; showing it alone")
                return root, [root], ids, notes
            candidates = [
                f
                for f in session.list_folders()
                if f.selectable and (f.role not in _SKIP_FOR_THREADS or f.name == ref.folder)
            ]
            scan = thread_folder_order(
                candidates, root, ref.folder, self._prefix(session), self._own_addresses()
            )
            if len(scan) > MAX_THREAD_FOLDERS:
                skipped = [f.display_name for f in scan[MAX_THREAD_FOLDERS:]]
                notes.append(
                    f"searched {MAX_THREAD_FOLDERS} of {len(scan)} folders (special folders, "
                    "archive and folders named like the participants first); not searched: "
                    + ", ".join(skipped[:5])
                    + (f" (+{len(skipped) - 5})" if len(skipped) > 5 else "")
                )
                scan = scan[:MAX_THREAD_FOLDERS]
            found = {(root.ref.folder, root.ref.uid): root}
            for _ in range(THREAD_ROUNDS):
                new_ids = False
                for f in scan:
                    res = session.search_related(f.name, ids)
                    fresh = [u for u in res.uids if (res.folder, u) not in found]
                    if not fresh:
                        continue
                    room = cap * 2 - len(found)
                    for s in self.index.summaries(
                        session,
                        res.folder,
                        res.uidvalidity,
                        fresh[: max(0, room)],
                        refresh_flags=True,
                    ):
                        found[(s.ref.folder, s.ref.uid)] = s
                        for i in _thread_ids(s):
                            if i not in ids:
                                ids.append(i)
                                new_ids = True
                if not new_ids or len(found) >= cap * 2:
                    break
            return root, list(found.values()), ids, notes

        async def work(
            a: Account,
        ) -> tuple[MessageSummary, list[MessageSummary], list[str], list[str]]:
            return await self.router.call(a, primary)

        root, messages, ids, notes = await self.router.run_one(acc, work)
        problems: list[AccountProblem] = []
        others, sel_problems = self.router.select(None)
        others = [a for a in others if a.name != acc.name]
        if ids and others:

            def secondary(session: ImapSession) -> list[MessageSummary]:
                out: list[MessageSummary] = []
                for role in _THREAD_ROLES:
                    f = session.folder_for_role(role)
                    if f is None:
                        continue
                    res = session.search_related(f.name, ids)
                    out += self.index.summaries(
                        session,
                        res.folder,
                        res.uidvalidity,
                        list(res.uids[:cap]),
                        refresh_flags=True,
                    )
                return out

            fan = await self._fan(others, secondary)
            for extra in fan.results.values():
                messages += extra
            problems += fan.problems
            problems += [p for p in sel_problems if p.code != "NOT_SUPPORTED_YET"]
        # Duplicates (same Message-ID) are merged only within one account and folder:
        # a forged copy elsewhere must not hide, say, the user's own Sent message.
        unique: dict[tuple[str, str, str], MessageSummary] = {}
        for m in messages:
            unique.setdefault((m.ref.account, m.ref.folder, m.message_id or m.ref.encode()), m)
        # Arrival order (INTERNALDATE, set by the server) — the Date header is forgeable.
        ordered = sorted(unique.values(), key=_sort_key)
        if len(ordered) > cap:
            notes.append(f"conversation has {len(ordered)} messages; showing the last {cap}")
            ordered = ordered[-cap:]
        return ThreadResult(root, [Hit(m) for m in ordered], notes, problems)

    # ------------------------------------------------------------ contacts

    async def find_contacts(
        self,
        *,
        query: Query | None,
        accounts: Sequence[str] | None,
        args: dict[str, Any],
        days: int | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        threshold: float = fuzzy.DEFAULT_THRESHOLD,
        now: datetime | None = None,
        tool: str = "find_contacts",
    ) -> ContactResult:
        """People from the From of INBOX and the To/Cc of Sent.

        Without ``query`` a cheap overview: the last ``OVERVIEW_CONTACT_DAYS`` days,
        at most ``OVERVIEW_HEADERS`` headers per account, most recent first. With a
        query a deeper window (``DEFAULT_CONTACT_DAYS``, up to ``MAX_CONTACT_DAYS``;
        ``max_headers_scanned`` headers per account, served incrementally by the
        header index), matched on name and address (wildcard or fuzzy). ``sent_to``
        comes from the per-account sent-to sets (:mod:`.trust`) in both modes.
        Recency is the arrival time (INTERNALDATE). Contacts merge all accounts, so
        the keyset cursor is one position in the merged ranking.
        """
        overview = query is None
        default_days = OVERVIEW_CONTACT_DAYS if overview else DEFAULT_CONTACT_DAYS
        days = max(1, min(days or default_days, MAX_CONTACT_DAYS))
        limit = self.clamp_limit(limit, OVERVIEW_CONTACTS if overview else DEFAULT_PAGE)
        qh = query_hash(args)
        cur = self.cursors.decode(cursor, tool=tool, query=qh) if cursor else None
        now = now or datetime.now(UTC)
        since = (now - timedelta(days=days)).date()
        selected, problems = self.router.select(accounts)
        budget = self.limits.max_headers_scanned
        if overview:
            budget = min(budget, OVERVIEW_HEADERS)
        own = self._own_addresses()

        def work(
            session: ImapSession,
        ) -> tuple[list[tuple[str, MessageSummary]], list[str], int, SentTo]:
            notes: list[str] = []
            out: list[tuple[str, MessageSummary]] = []
            read = 0
            for role in _CONTACT_ROLES:
                f = session.folder_for_role(role)
                if f is None:
                    notes.append(f"{session.account_name}: no {role} folder found")
                    continue
                res = session.search(f.name, SearchCriteria(since=since))
                share = budget // 2
                uids = list(res.uids[:share])
                if len(res.uids) > share and not overview:
                    notes.append(
                        f"{session.account_name}/{f.display_name}: read the newest "
                        f"{share} of {len(res.uids)} messages"
                    )
                read += len(uids)
                for sm in self.index.summaries(session, res.folder, res.uidvalidity, uids):
                    out.append((role, sm))
            sent_to = self.sent_to.get(session, now=now)
            if sent_to.note:
                notes.append(sent_to.note)
            return out, notes, read, sent_to

        fan = await self._fan(selected, work)
        notes: list[str] = []
        scanned = 0
        contacts: dict[str, Contact] = {}
        names: dict[str, dict[str, int]] = {}
        sent_sets = [r[3] for r in fan.results.values()]
        for acc_name, (items, n, read, _sent) in fan.results.items():
            notes += n
            scanned += read
            for role, sm in items:
                addrs: Iterable[Address] = (*sm.to, *sm.cc) if role == "sent" else sm.from_
                for a in addrs:
                    key = a.email.strip().lower()
                    if not key or "@" not in key or key in own:
                        continue
                    c = contacts.get(key)
                    if c is None:
                        c = contacts[key] = Contact(email=a.email.strip(), name="")
                    if role == "sent":
                        c.sent += 1
                    else:
                        c.received += 1
                    when = _when(sm, now)
                    if when and (c.last is None or when > c.last):
                        c.last = when
                    if acc_name not in c.accounts:
                        c.accounts.append(acc_name)
                    if a.name:
                        counts = names.setdefault(key, {})
                        counts[a.name] = counts.get(a.name, 0) + 1
        for key, c in contacts.items():
            if key in names:
                c.name = max(names[key].items(), key=lambda kv: kv[1])[0]
            age = (now - c.last).total_seconds() / 86400 if c.last else float(days)
            # frequency × recency; mail the user wrote counts double
            c.rank = round((c.received + 2 * c.sent) / (1 + max(0.0, age) / 30), 3)
            known = [st.has(key) for st in sent_sets]
            c.sent_to = True if True in known else (None if None in known else False)
        result = list(contacts.values())
        near: list[str] = []
        mode: Literal["overview", "wildcard", "fuzzy"] = "overview"
        keyed: list[tuple[Key, Contact]]
        if query is None:
            keyed = [((-c.last.timestamp() if c.last else 0.0, c.email.lower()), c) for c in result]
        else:
            mode = query.mode
            for c in result:
                c.score = round(query.score([c.name, c.email]), 1)
            matched = [c for c in result if (c.score or 0) >= threshold]
            keyed = [((-(c.score or 0.0), -c.rank, c.email.lower()), c) for c in matched]
            if not matched:
                near = similar(query, [x for c in result for x in (c.name, c.email)])
        keyed.sort(key=lambda kc: kc[0])
        page = keyset_page(
            {"*": keyed},
            limit=limit,
            cursor=cur,
            codec=self.cursors,
            tool=tool,
            query=qh,
            problems=fan.problems,
        )
        return ContactResult(
            contacts=[c for _k, c in page.items],
            total=page.total,
            offset=page.offset,
            cursor=page.cursor,
            mode=mode,
            days=days,
            scanned=scanned,
            notes=notes + page.notes,
            problems=[*problems, *fan.problems],
            answered=len(fan.results),
            similar=near,
            exhausted=page.exhausted,
        )

    def _own_addresses(self) -> set[str]:
        own = {a.lower() for i in self.config.identities for a in i.addresses}
        own |= {a.username.lower() for a in self.config.accounts if "@" in a.username}
        return own


# =========================================================================== paging


@dataclass(frozen=True, slots=True)
class _Chunk:
    key: tuple[str, str]
    uidvalidity: int
    max_uid: int
    start: int
    total: int
    window: list[int]
    """UIDs requested for this page (some may have vanished)."""
    summaries: list[MessageSummary]
    last_uid: int = 0
    """Where this page resumed (the previous page's last UID; 0 = from the top)."""


def _merge(
    chunks: Sequence[_Chunk], limit: int
) -> tuple[list[MessageSummary], dict[tuple[str, str], SourcePos]]:
    """k-way merge newest first; each source contributes a prefix of its chunk."""
    idx = [0] * len(chunks)
    out: list[MessageSummary] = []
    while len(out) < limit:
        best = -1
        for i, c in enumerate(chunks):
            if idx[i] < len(c.summaries) and (
                best < 0
                or _sort_key(c.summaries[idx[i]]) > _sort_key(chunks[best].summaries[idx[best]])
            ):
                best = i
        if best < 0:
            break
        out.append(chunks[best].summaries[idx[best]])
        idx[best] += 1
    positions: dict[tuple[str, str], SourcePos] = {}
    for i, c in enumerate(chunks):
        n = _consumed(c, idx[i])
        last = c.window[n - 1] if n else c.last_uid
        positions[c.key] = SourcePos(c.uidvalidity, c.start + n, c.max_uid, last)
    return out, positions


def _resume_index(uids: Sequence[int], last_uid: int) -> int:
    """Index after ``last_uid`` in a fresh (newest-first) SEARCH result.

    Resuming by UID instead of a stored offset means messages expunged meanwhile
    cannot make the next page skip anything. If ``last_uid`` itself is gone, the
    position falls back to UID order: everything with a higher UID was passed.
    """
    if not last_uid:
        return 0
    try:
        return uids.index(last_uid) + 1
    except ValueError:
        return sum(1 for u in uids if u > last_uid)


def _consumed(c: _Chunk, taken: int) -> int:
    """How far into ``c.window`` the source advanced; UIDs that vanished between
    SEARCH and FETCH are skipped rather than retried forever."""
    if taken >= len(c.summaries):
        return len(c.window)
    if taken == 0:
        return 0
    return c.window.index(c.summaries[taken - 1].ref.uid) + 1


_MAIL_PROVIDERS = frozenset(
    {
        "gmail",
        "googlemail",
        "gmx",
        "outlook",
        "hotmail",
        "live",
        "yahoo",
        "icloud",
        "web",
        "mail",
        "posteo",
        "aon",
        "a1",
        "t-online",
        "proton",
        "protonmail",
    }
)


def _participant_terms(s: MessageSummary, own: set[str]) -> list[str]:
    """Names, address local parts and domains of the other participants — what
    a client folder is typically named after (``Clients/Huber Bau``)."""
    terms: list[str] = []
    for a in (*s.from_, *s.reply_to, *s.to, *s.cc)[:20]:
        email = a.email.strip().lower()
        if email in own:
            continue
        local, _, domain = email.partition("@")
        labels = domain.split(".")[:-1]
        site = " ".join(x for x in labels if x not in _MAIL_PROVIDERS)
        for t in (a.name, local, site):
            t = " ".join(t.replace(".", " ").replace("-", " ").replace("_", " ").split())
            if len(t) >= 3 and t not in terms:
                terms.append(t)
    return terms


def thread_folder_order(
    folders: Sequence[FolderInfo],
    root: MessageSummary,
    anchor: str,
    personal_prefix: str,
    own: set[str],
) -> list[FolderInfo]:
    """Folders to search for a conversation, most promising first: the message's
    own folder, INBOX and Sent, the archive (and its subfolders), folders named
    like a participant (fuzzy: ``Clients/Huber Bau`` for ``anna@huber-bau.example``),
    then the rest alphabetically."""
    paths = [fuzzy.folder_path(f, personal_prefix) for f in folders]
    archives = [p for f, p in zip(folders, paths, strict=True) if f.role == "archive"]
    named: dict[int, float] = {}
    for term in _participant_terms(root, own):
        for m in fuzzy.match_paths(term, paths, threshold=THREAD_PARTICIPANT_THRESHOLD):
            named[m.index] = max(named.get(m.index, 0.0), m.score)

    def rank(i: int) -> tuple[int, float, str]:
        f, p = folders[i], paths[i]
        name = fuzzy.normalize(f.display_name)
        if f.name == anchor:
            return (0, 0.0, name)
        if f.role in _THREAD_ROLES:
            return (1, 0.0, name)
        if any(p[: len(a)] == a for a in archives):
            return (2, 0.0, name)
        if i in named:
            return (3, -named[i], name)
        return (4, 0.0, name)

    return [folders[i] for i in sorted(range(len(folders)), key=rank)]


def _thread_ids(s: MessageSummary) -> list[str]:
    """Conversation ids by relevance: Message-ID, In-Reply-To, then References from
    the last (the direct parent) backwards — searches use only the first ones."""
    ordered = [s.message_id, s.in_reply_to, *reversed(s.references)]
    return list(dict.fromkeys(i for i in ordered if i and 3 <= len(i) <= 998))
