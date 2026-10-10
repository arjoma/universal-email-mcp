"""Account router: per-account sessions, locking, timeouts and parallel fan-out.

Backends are synchronous and not thread-safe, so each account has one session and
one :class:`asyncio.Lock`; calls run in daemon worker threads (see :func:`_run_daemon`). A dropped connection is reconnected once; a call that exceeds the
deadline is cancelled and its connection torn down (the worker thread then fails
promptly instead of holding the session).

Fan-out runs one task per account in parallel, each under its own deadline.
Failures and time-outs of single accounts never fail the whole call: they are
collected as :class:`AccountProblem` entries and reported with the partial result.

Backends plug in per account kind (``connectors``): IMAP, and POP3 (read-only,
:mod:`universal_email_mcp.mail.pop3`; the router keeps one :class:`Pop3State` per
account so the UIDL numbering and the header cache outlive reconnects). A kind
without a connector is reported as not supported.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import sys
import threading
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from universal_email_mcp import audit
from universal_email_mcp.bounded import run_daemon
from universal_email_mcp.config import Config, resolve_password
from universal_email_mcp.errors import (
    WRONG_MAILBOX,
    AccountTimeout,
    ConfigError,
    InvalidRef,
    MailError,
    NotPermitted,
    NotSupportedYet,
    ProtocolError,
    ServerUnreachable,
)
from universal_email_mcp.jsonlog import safe_trace
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.mail.net import Deadline
from universal_email_mcp.mail.pop3 import Pop3Session, Pop3State
from universal_email_mcp.models import Account, AccountKind, MessageRef

log = logging.getLogger(__name__)

CLOSE_WAIT = 5.0
"""Longest :meth:`AccountRouter.aclose` waits for connections to be released."""

DEFAULT_IDLE_TTL = 120.0
"""Idle connections older than this are closed and reopened on next use."""

Permission = str  # "read" | "organize" | "delete" | "drafts"
Connector = Callable[[Account, Config], Any]
"""Opens an authenticated session for an account (blocking; runs in a thread)."""


class ConnectionHooks(Protocol):
    """Remote mode: the pool of the per-user service watches every new connection.

    All three run on the event loop and must not block.
    """

    def before_connect(self, router: AccountRouter, account: Account) -> None:
        """Called before a *new* connection attempt; raise a :class:`MailError` to refuse
        it (connection caps, an account known to need a new password)."""

    def connect_failed(self, account: Account, error: MailError) -> MailError:
        """A connection attempt failed; return the error to report (may be a replacement)."""
        ...

    def connect_succeeded(self, account: Account) -> None: ...


def connect_imap(account: Account, config: Config) -> ImapSession:
    password = resolve_password(account)
    net = config.net_policy(account)
    with Deadline(net.total_timeout):  # connect + login are bounded in absolute time
        return ImapSession.for_account(account, password, net=net)


DEFAULT_CONNECTORS: Mapping[AccountKind, Connector] = {"imap": connect_imap}


def ensure_ref_matches(ref: MessageRef, account: Account) -> None:
    """A POP3 id belongs to a POP3 account and an IMAP id to an IMAP account, and the id must
    have been issued for *this* mailbox: account names are chosen by the user and can be
    reused for another mailbox (remove and add again, positional names), so the key carried
    in the id has to be the account's own."""
    if ref.is_pop3 != (account.kind == "pop3"):
        raise InvalidRef("the message id does not match the kind of its account")
    if ref.key != account.key:
        raise InvalidRef(WRONG_MAILBOX)


@dataclass(frozen=True, slots=True)
class AccountProblem:
    """Why one account is missing from a (partial) result."""

    account: str
    code: str
    message: str
    hint: str = ""

    @classmethod
    def from_error(cls, account: str, err: MailError) -> AccountProblem:
        return cls(account, err.code, err.message, err.hint)

    def describe(self) -> str:
        return f"{self.account}: {self.message} [{self.code}]"


@dataclass(slots=True)
class Fanout[T]:
    results: dict[str, T] = field(default_factory=dict[str, T])
    """Per account name, in the order the accounts were given."""
    problems: list[AccountProblem] = field(default_factory=list[AccountProblem])


@dataclass(slots=True)
class _Slot:
    account: Account
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    session: Any = None
    last_used: float = 0.0
    connecting: asyncio.Future[Any] | None = None
    """The one in-flight connect attempt; a retry awaits it instead of starting
    another (a tarpitting server must not pile up connector threads)."""


def _close_quietly(session: Any) -> None:
    try:
        session.close()
    except Exception:  # noqa: BLE001 - best effort
        log.debug("closing session failed: %s", safe_trace(sys.exc_info()[1]))


def _abort_quietly(session: Any) -> None:
    try:
        (getattr(session, "abort", None) or session.close)()
    except Exception:  # noqa: BLE001
        log.debug("aborting session failed: %s", safe_trace(sys.exc_info()[1]))


def _discard(session: Any) -> None:
    """Abort, then release (after the owning thread is done with the session)."""
    _abort_quietly(session)
    _close_quietly(session)


def _in_thread(fn: Callable[[Any], None], session: Any) -> None:
    """Run cleanup on its own daemon thread: never on the event loop, and not
    queued behind worker threads that may all be blocked on dead servers."""
    threading.Thread(target=fn, args=(session,), name="uem-cleanup", daemon=True).start()


_run_daemon = run_daemon


def _release_after(session: Any, fut: asyncio.Future[Any]) -> None:
    if not fut.cancelled():
        fut.exception()  # retrieved: the caller is gone, the error was expected
    _in_thread(_discard, session)


class AccountRouter:
    def __init__(
        self,
        config: Config,
        *,
        connectors: Mapping[AccountKind, Connector] | None = None,
        idle_ttl: float = DEFAULT_IDLE_TTL,
        clock: Callable[[], float] = time.monotonic,
        hooks: ConnectionHooks | None = None,
        no_accounts_hint: str = "Add [[accounts]] to the config file.",
    ) -> None:
        self.config = config
        self._hooks = hooks
        self._no_accounts_hint = no_accounts_hint
        self._closed = False
        self._connectors = dict(DEFAULT_CONNECTORS if connectors is None else connectors)
        self._pop3_states: dict[str, Pop3State] = {}
        if connectors is None:
            self._connectors["pop3"] = self._connect_pop3
        self._slots: dict[str, _Slot] = {}
        self._idle_ttl = idle_ttl
        self._clock = clock

    def _connect_pop3(self, account: Account, config: Config) -> Pop3Session:
        state = self._pop3_states.get(account.name)
        if state is None:
            lim = config.limits
            state = self._pop3_states[account.name] = Pop3State(
                max_headers=lim.max_headers_scanned,
                header_budget=max(1.0, 0.4 * lim.account_timeout),
                max_message_bytes=lim.max_message_bytes,
            )
        net = config.net_policy(account)
        with Deadline(net.total_timeout):
            return Pop3Session.for_account(account, resolve_password(account), net=net, state=state)

    # ------------------------------------------------------------ selection

    def select(
        self, names: Sequence[str] | None, permission: Permission = "read"
    ) -> tuple[list[Account], list[AccountProblem]]:
        """Accounts for a call. ``None``/empty = all accounts with ``permission``.

        Unknown names raise :class:`ConfigError`; explicitly named accounts that
        lack the permission or whose kind has no backend yet become problems.
        Beyond ``max_accounts_per_call`` accounts are skipped (reported).
        """
        problems: list[AccountProblem] = []
        if names:
            wanted: list[Account] = []
            for n in names:
                acc = self.config.account(n)
                if acc not in wanted:
                    wanted.append(acc)
        else:
            wanted = list(self.config.accounts)
            if not wanted:
                raise ConfigError("no accounts configured", hint=self._no_accounts_hint)
        selected: list[Account] = []
        for acc in wanted:
            if not getattr(acc.permissions, permission, False) or (
                permission != "read" and self.config.policy.read_only
            ):
                if names:
                    why = (
                        "POP3 accounts are read-only"
                        if acc.kind == "pop3" and permission != "read"
                        else f"no {permission!r} permission"
                    )
                    problems.append(AccountProblem.from_error(acc.name, NotPermitted(why)))
                continue
            if acc.kind not in self._connectors:
                problems.append(
                    AccountProblem.from_error(
                        acc.name,
                        NotSupportedYet(
                            f"{acc.kind.upper()} accounts are not supported yet",
                        ),
                    )
                )
                continue
            selected.append(acc)
        cap = self.config.limits.max_accounts_per_call
        for acc in selected[cap:]:
            problems.append(
                AccountProblem(
                    acc.name,
                    "SKIPPED",
                    f"skipped: more than {cap} accounts in one call",
                    "Name the accounts to query with the 'accounts' argument.",
                )
            )
        return selected[:cap], problems

    def account(self, name: str, permission: Permission = "read") -> Account:
        """One account by name, checked for ``permission`` and backend support."""
        accounts, problems = self.select([name], permission)
        if problems:
            p = problems[0]
            err = (NotSupportedYet if p.code == NotSupportedYet.code else NotPermitted)(
                f"account {p.account!r}: {p.message}", hint=p.hint
            )
            raise err
        return accounts[0]

    # ------------------------------------------------------------ calls

    def _slot(self, account: Account) -> _Slot:
        slot = self._slots.get(account.name)
        if slot is None:
            slot = self._slots[account.name] = _Slot(account)
        return slot

    async def _connect(self, slot: _Slot) -> Any:
        """Session from the slot's in-flight connect, starting one if needed.

        A deadline cancels only the wait: the attempt keeps running, the next call
        for the account awaits the same future, and a session it produces after
        everybody gave up is adopted by the slot (or closed).
        """
        account = slot.account
        connector = self._connectors.get(account.kind)
        if connector is None:
            raise NotSupportedYet(f"{account.kind.upper()} accounts are not supported yet")
        fut = slot.connecting
        if fut is None:
            if self._closed:
                raise ServerUnreachable("the connection pool of this client was closed")
            if self._hooks is not None:
                self._hooks.before_connect(self, account)
            loop = asyncio.get_running_loop()
            fut = _run_daemon(loop, connector, account, self.config)
            slot.connecting = fut
            fut.add_done_callback(functools.partial(self._connected, slot))
        try:
            return await asyncio.shield(fut)
        except MailError as e:
            if self._hooks is None:
                raise
            replacement = self._hooks.connect_failed(account, e)
            if replacement is e:
                raise
            raise replacement from e

    def _connected(self, slot: _Slot, fut: asyncio.Future[Any]) -> None:
        if slot.connecting is fut:
            slot.connecting = None
        if fut.cancelled() or fut.exception() is not None:
            return
        session = fut.result()
        if self._closed:  # a connect that finished after aclose(): nobody will close it later
            _in_thread(_discard, session)
            return
        if self._hooks is not None:
            self._hooks.connect_succeeded(slot.account)
        if slot.session is None:
            slot.session = session
            slot.last_used = self._clock()
        elif slot.session is not session:  # pragma: no cover - defensive
            _in_thread(_discard, session)

    async def _ensure(self, slot: _Slot) -> tuple[Any, bool]:
        now = self._clock()
        if slot.session is not None and now - slot.last_used > self._idle_ttl:
            old, slot.session = slot.session, None
            _in_thread(_discard, old)
        if slot.session is not None:
            return slot.session, False
        session = await self._connect(slot)
        slot.session = session
        slot.last_used = self._clock()
        return session, True

    async def call[T](self, account: Account, fn: Callable[[Any], T]) -> T:
        """Run ``fn(session)`` in a worker thread with the account's session.

        Serialised per account. Reconnects once when a reused connection turns out
        to be dead. On cancellation (deadline) the connection is aborted.
        """
        slot = self._slot(account)
        async with slot.lock:
            for attempt in (1, 2):
                session, fresh = await self._ensure(slot)
                writes = getattr(session, "writes_started", 0)
                fut = _run_daemon(asyncio.get_running_loop(), fn, session)
                try:
                    result = await asyncio.shield(fut)
                except asyncio.CancelledError:
                    # Deadline: cut the connection so the worker fails promptly
                    # (never on the loop thread), release it once the worker is done.
                    slot.session = None
                    _in_thread(_abort_quietly, session)
                    fut.add_done_callback(functools.partial(_release_after, session))
                    raise
                except ServerUnreachable as e:
                    slot.session = None
                    _in_thread(_discard, session)
                    if getattr(session, "writes_started", 0) != writes:
                        # A write command may have reached the server: running it again
                        # could apply it twice (an APPEND would duplicate the message).
                        e.hint = (e.hint + " " if e.hint else "") + (
                            "The connection broke while the mailbox was being changed; "
                            "check the result before repeating it."
                        )
                        raise
                    if fresh or attempt == 2:
                        raise
                    log.info(
                        "account %s: connection lost (%s), reconnecting",
                        audit.pseudonym("a", account.name),
                        type(e).__name__,
                    )
                    continue
                except MailError:
                    slot.last_used = self._clock()
                    raise
                except Exception as e:
                    slot.session = None
                    _in_thread(_discard, session)
                    log.error(
                        "account %s: unexpected backend error: %s",
                        audit.pseudonym("a", account.name),
                        safe_trace(e),
                    )
                    raise ProtocolError(f"unexpected backend error: {type(e).__name__}") from e
                slot.last_used = self._clock()
                return result
        raise AssertionError("unreachable")  # pragma: no cover

    async def run_one[T](self, account: Account, work: Callable[[Account], Awaitable[T]]) -> T:
        """Run ``work`` for one account under the per-account deadline."""
        timeout = self.config.limits.account_timeout
        try:
            async with asyncio.timeout(timeout):
                return await work(account)
        except TimeoutError as e:
            raise AccountTimeout(
                f"account {account.name!r} did not answer within {timeout:g} s"
            ) from e

    async def fanout[T](
        self, accounts: Sequence[Account], work: Callable[[Account], Awaitable[T]]
    ) -> Fanout[T]:
        """Run ``work`` for all accounts in parallel, each under its own deadline."""

        async def one(acc: Account) -> T | AccountProblem:
            try:
                return await self.run_one(acc, work)
            except MailError as e:
                return AccountProblem.from_error(acc.name, e)

        outcomes = await asyncio.gather(*(one(a) for a in accounts))
        out: Fanout[T] = Fanout()
        for acc, res in zip(accounts, outcomes, strict=True):
            if isinstance(res, AccountProblem):
                out.problems.append(res)
            else:
                out.results[acc.name] = res
        return out

    # ------------------------------------------------------------ pool support

    def open_connections(self) -> int:
        """Connections open or being opened (what the pool's caps count)."""
        return sum(1 for s in self._slots.values() if s.session is not None or s.connecting)

    def idle_sessions(self) -> list[tuple[float, _Slot]]:
        """``(last_used, slot)`` of connections nobody is using right now."""
        return [
            (s.last_used, s)
            for s in self._slots.values()
            if s.session is not None and s.connecting is None and not s.lock.locked()
        ]

    def drop_idle(self, slot: _Slot) -> None:
        """Close an idle connection (on a cleanup thread; the slot reconnects on demand)."""
        if slot.session is None or slot.lock.locked():
            return
        session, slot.session = slot.session, None
        _in_thread(_discard, session)

    def close_idle(self, older_than: float) -> int:
        """Close connections idle for more than ``older_than`` seconds; returns how many."""
        now = self._clock()
        stale = [s for t, s in self.idle_sessions() if now - t > older_than]
        for s in stale:
            self.drop_idle(s)
        return len(stale)

    def last_activity(self) -> float:
        """Latest use of any connection (0 = none yet)."""
        return max((s.last_used for s in self._slots.values()), default=0.0)

    async def close_for_good(self) -> None:
        """Close and refuse any later connect (and close a connect still in flight when it
        completes): the router of a retired per-user service."""
        self._closed = True
        await self.aclose()

    async def aclose(self) -> None:
        sessions = [s.session for s in self._slots.values() if s.session is not None]
        for s in self._slots.values():
            s.session = None
        if not sessions:
            return
        loop = asyncio.get_running_loop()
        # Own daemon threads (a dead server must not occupy the default executor), and a
        # bounded wait: the sockets are aborted first, so this normally takes no time.
        pending = [_run_daemon(loop, _discard, s) for s in sessions]
        await asyncio.wait(pending, timeout=CLOSE_WAIT)
