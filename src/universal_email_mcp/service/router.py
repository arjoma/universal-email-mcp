"""Account router: per-account sessions, locking, timeouts and parallel fan-out.

Backends are synchronous and not thread-safe, so each account has one session and
one :class:`asyncio.Lock`; calls run in worker threads via the event loop's
executor. A dropped connection is reconnected once; a call that exceeds the
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
import threading
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from universal_email_mcp.config import Config, resolve_password
from universal_email_mcp.errors import (
    AccountTimeout,
    ConfigError,
    InvalidRef,
    MailError,
    NotPermitted,
    NotSupportedYet,
    ProtocolError,
    ServerUnreachable,
)
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.mail.pop3 import Pop3Session, Pop3State
from universal_email_mcp.models import Account, AccountKind, MessageRef

log = logging.getLogger(__name__)

DEFAULT_IDLE_TTL = 120.0
"""Idle connections older than this are closed and reopened on next use."""

Permission = str  # "read" | "organize" | "delete" | "drafts"
Connector = Callable[[Account, Config], Any]
"""Opens an authenticated session for an account (blocking; runs in a thread)."""


def connect_imap(account: Account, config: Config) -> ImapSession:
    password = resolve_password(account)
    return ImapSession.for_account(account, password, net=config.net_policy())


DEFAULT_CONNECTORS: Mapping[AccountKind, Connector] = {"imap": connect_imap}


def ensure_ref_matches(ref: MessageRef, account: Account) -> None:
    """A POP3 id belongs to a POP3 account and an IMAP id to an IMAP account."""
    if ref.is_pop3 != (account.kind == "pop3"):
        raise InvalidRef("the message id does not match the kind of its account")


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
        log.debug("closing session failed", exc_info=True)


def _abort_quietly(session: Any) -> None:
    try:
        (getattr(session, "abort", None) or session.close)()
    except Exception:  # noqa: BLE001
        log.debug("aborting session failed", exc_info=True)


def _discard(session: Any) -> None:
    """Abort, then release (after the owning thread is done with the session)."""
    _abort_quietly(session)
    _close_quietly(session)


def _in_thread(fn: Callable[[Any], None], session: Any) -> None:
    """Run cleanup on its own daemon thread: never on the event loop, and not
    queued behind worker threads that may all be blocked on dead servers."""
    threading.Thread(target=fn, args=(session,), name="uem-cleanup", daemon=True).start()


def _release_after(session: Any, fut: asyncio.Future[Any]) -> None:
    if not fut.cancelled():
        fut.exception()  # retrieved: the caller is gone, the error was expected
    _in_thread(_close_quietly, session)


class AccountRouter:
    def __init__(
        self,
        config: Config,
        *,
        connectors: Mapping[AccountKind, Connector] | None = None,
        idle_ttl: float = DEFAULT_IDLE_TTL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
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
        return Pop3Session.for_account(
            account, resolve_password(account), net=config.net_policy(), state=state
        )

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
                raise ConfigError(
                    "no accounts configured", hint="Add [[accounts]] to the config file."
                )
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
            loop = asyncio.get_running_loop()
            fut = loop.run_in_executor(None, connector, account, self.config)
            slot.connecting = fut
            fut.add_done_callback(functools.partial(self._connected, slot))
        return await asyncio.shield(fut)

    def _connected(self, slot: _Slot, fut: asyncio.Future[Any]) -> None:
        if slot.connecting is fut:
            slot.connecting = None
        if fut.cancelled() or fut.exception() is not None:
            return
        session = fut.result()
        if slot.session is None:
            slot.session = session
            slot.last_used = self._clock()
        elif slot.session is not session:  # pragma: no cover - defensive
            _in_thread(_close_quietly, session)

    async def _ensure(self, slot: _Slot) -> tuple[Any, bool]:
        now = self._clock()
        if slot.session is not None and now - slot.last_used > self._idle_ttl:
            old, slot.session = slot.session, None
            await asyncio.to_thread(_close_quietly, old)
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
                fut = asyncio.get_running_loop().run_in_executor(None, fn, session)
                try:
                    result = await asyncio.shield(fut)
                except asyncio.CancelledError:
                    # Deadline: cut the connection so the worker fails promptly
                    # (never on the loop thread), release it once the worker is done.
                    slot.session = None
                    _in_thread(_abort_quietly, session)
                    fut.add_done_callback(functools.partial(_release_after, session))
                    raise
                except ServerUnreachable:
                    slot.session = None
                    await asyncio.to_thread(_discard, session)
                    if fresh or attempt == 2:
                        raise
                    log.info("account %s: connection lost, reconnecting", account.name)
                    continue
                except MailError:
                    slot.last_used = self._clock()
                    raise
                except Exception as e:
                    slot.session = None
                    await asyncio.to_thread(_discard, session)
                    log.exception("account %s: unexpected backend error", account.name)
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

    async def aclose(self) -> None:
        sessions = [s.session for s in self._slots.values() if s.session is not None]
        for s in self._slots.values():
            s.session = None
        await asyncio.gather(*(asyncio.to_thread(_close_quietly, s) for s in sessions))
