"""The per-user service of remote mode (WP 3e): one :class:`MailService` per connected client.

A request to ``/mcp`` carries a :class:`~universal_email_mcp.oauth.bearer.Principal` (user,
grant, scopes, granted accounts and identities). :class:`UserPool` turns it into a
:class:`UserContext`: the local configuration model (:class:`~universal_email_mcp.config.Config`
with accounts, identities, permissions, limits) built **from the store** for exactly this
grant, a service running on it, and the MCP server whose tools that configuration allows.

Effective permission of a granted account (:func:`effective_permissions`)::

    account permissions  ∩  grant scope for that account  ∩  token scope  ∩  operator policy

(POP3 accounts stay read-only, ``UEM_READ_ONLY`` leaves only ``read``). An account without
``read`` is not part of the grant's view at all. Because the router checks the permission
of the *account object it was built with* on every call, a call for something the grant lacks
fails in the service layer even if a client calls a tool it was never shown.

Cross-user isolation is structural: a context only ever contains the accounts the store
returns for the principal's own ``user_id`` (and only those named in the grant); message ids
and cursors name accounts and are resolved inside that context, cursors are signed with a
per-user key. Contexts are cached per ``(user, grant)`` and rebuilt when the grant or one of
the user's account/identity records changed (record versions are part of the fingerprint),
which also closes the pooled mail connections of the old context: a changed password or a
removed account takes effect on the next request.

The pool also carries the per-instance resource caps (open mail connections in total and per
user with idle eviction, parallel calls per user) and the ``reauth_required`` handling: a
rejected login marks the account in the store and is not retried until the password changes
or ``reauth_retry_after`` has passed.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, replace
from typing import Any

from universal_email_mcp.config import PERMISSION_NAMES, Config, Downloads, Policy
from universal_email_mcp.errors import AuthFailed, Busy, MailError, ReauthRequired
from universal_email_mcp.jsonlog import log_event
from universal_email_mcp.models import (
    Account,
    CredentialRef,
    Endpoint,
    Identity,
    MessageRef,
    Permissions,
    ServerProfile,
    TlsSettings,
)
from universal_email_mcp.oauth.bearer import Principal
from universal_email_mcp.oauth.config import SCOPE_READ, SCOPE_SEND, permission_of
from universal_email_mcp.operator import OperatorConfig
from universal_email_mcp.presets import resolve_server_entry
from universal_email_mcp.service.cursor import CursorCodec
from universal_email_mcp.service.folder_map import STARTUP_TIMEOUT, FolderMap
from universal_email_mcp.service.mail import MailService
from universal_email_mcp.service.opaque import LinkId, ViewerIds
from universal_email_mcp.service.remote_send import StoreRemoteSend
from universal_email_mcp.service.router import AccountRouter
from universal_email_mcp.store import Identity as IdentityRecord
from universal_email_mcp.store import MailAccount, Store
from universal_email_mcp.store.backend import StoreConflict
from universal_email_mcp.store.records import login_mark

log = logging.getLogger(__name__)

DEFAULT_TLS = TlsSettings()
MAPS_TTL = 600.0
"""Seconds a folder map in the instructions is reused before ``initialize`` reads it again."""
SWEEP_INTERVAL = 30.0
MARK_DEBOUNCE = 5.0
"""A failure flag younger than this is not written again (parallel failing calls)."""
_NAME_OK = re.compile(r"^[\w][\w .@+-]{0,63}$", re.UNICODE)

VIEWER_GRANT = "portal-viewer"
"""Grant id of the pseudo grant behind the portal's message viewer: all of the user's own
accounts with ``read``, no identities, no MCP server."""

ServerFactory = Callable[[MailService, Mapping[str, FolderMap | None]], Any]
"""``build_server``: the MCP server (never run itself) whose tools a context offers."""


# ------------------------------------------------------------------ configuration


def effective_permissions(
    rec: MailAccount, granted: str, token_scopes: Sequence[str], policy: Policy
) -> Permissions | None:
    """What this grant may do with the account, or ``None`` when it may not even read."""
    names = set(granted.split()) & set(PERMISSION_NAMES)
    names &= {permission_of(s) for s in token_scopes}
    names &= set(rec.permissions)
    if rec.protocol != "imap" or policy.read_only:
        names &= {"read"}
    if "read" not in names:
        return None
    return Permissions(**{n: n in names for n in PERMISSION_NAMES})


class PortalLinks:
    """``DownloadLinks`` of remote mode: the portal's viewer routes (``/m/<id>/...``). The
    links carry no token: opening one needs the portal session of the mailbox's owner."""

    def __init__(self, base: str, link_id: LinkId) -> None:
        self._base = base.rstrip("/")
        self._id = link_id

    def attachment_url(self, ref: MessageRef, section: str) -> str | None:
        return f"{self._base}/m/{self._id(ref.encode())}/a/{section}"

    def message_url(self, ref: MessageRef) -> str | None:
        return f"{self._base}/m/{self._id(ref.encode())}/eml"


def _account_name(rec: MailAccount, taken: set[str], position: int) -> str:
    name = rec.name.strip()
    if not _NAME_OK.match(name):
        name = f"Account {position}"
    base, n = name, 2
    while name.casefold() in taken:
        name = f"{base} ({n})"
        n += 1
    taken.add(name.casefold())
    return name


def _account(rec: MailAccount, name: str, perms: Permissions, tls: TlsSettings) -> Account:
    try:
        base = resolve_server_entry(rec.preset) if rec.preset else ServerProfile(name=name)
    except MailError:
        base = ServerProfile(name=name)
    mode = "starttls" if rec.tls == "starttls" else "tls"
    endpoint = Endpoint(rec.host, rec.port, mode)
    kind = "pop3" if rec.protocol == "pop3" else "imap"
    server = replace(
        base,
        imap=endpoint if kind == "imap" else None,
        pop3=endpoint if kind == "pop3" else None,
        smtp=None,
    )
    return Account(
        name=name,
        kind=kind,
        username=rec.username,
        server=server,
        credential=CredentialRef("inline", name, rec.password),
        permissions=perms,
        tls=tls,
        public_only=not rec.preset,
    )


def build_user_config(
    op: OperatorConfig,
    principal: Principal,
    accounts: Sequence[MailAccount],
    identities: Sequence[IdentityRecord],
    tls: TlsSettings = DEFAULT_TLS,
) -> tuple[Config, dict[str, MailAccount]]:
    """The configuration of one grant, and the store record behind each account name.

    Only records of the principal's own user are used (checked again here, whatever the
    caller passed in), only accounts named in the grant, with the effective permissions.
    """
    by_id = {a.id: a for a in accounts if a.user_id == principal.user_id}
    taken: set[str] = set()
    built: list[Account] = []
    records: dict[str, MailAccount] = {}
    names: dict[str, str] = {}  # account id -> name in this configuration
    for position, account_id in enumerate(principal.account_scopes, start=1):
        rec = by_id.get(account_id)
        if rec is None:  # removed since the grant was made
            continue
        perms = effective_permissions(
            rec, principal.account_scopes[account_id], principal.scopes, op.policy
        )
        if perms is None:
            continue
        name = _account_name(rec, taken, position)
        built.append(_account(rec, name, perms, tls))
        records[name] = rec
        names[rec.id] = name

    drafts_accounts = {n for n, a in ((a.name, a) for a in built) if a.permissions.drafts}
    send_allowed = (
        SCOPE_SEND in principal.scopes and op.policy.send != "off" and not op.policy.read_only
    )
    all_accounts = {a.id: a for a in accounts if a.user_id == principal.user_id}
    smtp_built: list[Account] = []
    idents: list[Identity] = []
    for ident in identities:
        if ident.user_id != principal.user_id or not ident.addresses:
            continue
        granted = ident.id in principal.identity_ids
        store_account = names.get(ident.copies_account_id)
        # Drafts need an identity but not the right to send as it: identities whose copies
        # go to an account the grant may write drafts to are usable for drafts.
        if not granted and store_account not in drafts_accounts:
            continue
        store_name = store_account if store_account in drafts_accounts else None
        smtp = _smtp_account(ident, all_accounts, tls) if granted and send_allowed else None
        # Sending: the identity must be granted for it (grant), allow it itself (identity),
        # be permitted by the operator (policy) and have a drafts-capable copies account
        # (the draft is the safety net). All of it is rebuilt when any record changes.
        sends = smtp is not None and ident.send and store_name is not None
        if sends:
            assert smtp is not None
            smtp_built.append(smtp)
        idents.append(
            Identity(
                name=ident.addresses[0],
                addresses=tuple(a.lower() for a in ident.addresses),
                display_name=ident.display_name,
                smtp_account=smtp.name if sends and smtp else None,
                store_account=store_name,
                default=ident.is_default,
                send=sends,
                signature=ident.signature,
                ref=ident.id,
            )
        )
    if idents and not any(i.default for i in idents):
        idents[0] = replace(idents[0], default=True)
    seen_default = False
    for n, i in enumerate(idents):  # exactly one default
        if i.default and seen_default:
            idents[n] = replace(i, default=False)
        seen_default = seen_default or i.default

    config = Config(
        accounts=tuple(built),
        identities=tuple(idents),
        smtp_accounts=tuple(smtp_built),
        policy=op.policy,
        limits=op.limits,
        settings=op.settings,
        downloads=Downloads(enabled=False, max_download_bytes=op.max_download_bytes),
    )
    return config, records


def _smtp_account(
    ident: IdentityRecord, owned: Mapping[str, MailAccount], tls: TlsSettings
) -> Account | None:
    """The outgoing server of an identity as an :class:`Account` (never listed as a mailbox:
    it goes to ``Config.smtp_accounts``). ``None`` when the identity has no usable login."""
    if not (ident.smtp_host and ident.smtp_username and ident.smtp_password):
        return None
    source = owned.get(ident.smtp_account_id)
    try:
        base = resolve_server_entry(source.preset) if source and source.preset else None
    except MailError:
        base = None
    name = f"smtp:{ident.id}"
    mode = "starttls" if ident.smtp_tls == "starttls" else "tls"
    server = ServerProfile(
        name=name,
        smtp=Endpoint(ident.smtp_host, ident.smtp_port, mode),
        smtp_saves_sent=bool(base and base.smtp_saves_sent),
    )
    return Account(
        name=name,
        kind="imap",
        username=ident.smtp_username,
        server=server,
        credential=CredentialRef("inline", name, ident.smtp_password),
        permissions=Permissions(read=False),
        tls=tls,
        public_only=source is None or not source.preset,
    )


def fingerprint(
    principal: Principal,
    accounts: Sequence[MailAccount],
    identities: Sequence[IdentityRecord],
) -> tuple[Any, ...]:
    """Everything a context depends on. Record *versions* stand in for their content."""
    return (
        principal.user_id,
        principal.grant_id,
        principal.scopes,
        tuple(sorted(principal.account_scopes.items())),
        principal.identity_ids,
        tuple((a.id, a.version) for a in accounts if a.id in principal.account_scopes),
        tuple((i.id, i.version) for i in identities),
    )


# ------------------------------------------------------------------ contexts


@dataclass(slots=True, eq=False)
class UserContext:
    user_id: str
    grant_id: str
    fingerprint: tuple[Any, ...]
    config: Config
    records: dict[str, MailAccount] = field(repr=False)
    service: MailService
    router: AccountRouter
    server: Any
    """The MCP server with exactly the tools this grant allows (an ``MCPServer``)."""
    last_used: float = 0.0
    maps_at: float | None = None
    active: int = 0
    retired: bool = False
    reauth_until: dict[str, float] = field(default_factory=dict[str, float])
    """Account name -> monotonic time before which no login is tried (after a rejection)."""


class _Hooks:
    """Connection hooks of one context: reauth gate, caps, failure marking."""

    def __init__(self, pool: UserPool) -> None:
        self.pool = pool
        self.ctx: UserContext | None = None

    def before_connect(self, router: AccountRouter, account: Account) -> None:
        ctx = self.ctx
        assert ctx is not None
        self.pool.check_reauth_gate(ctx, account)
        self.pool.admit(ctx)

    def connect_failed(self, account: Account, error: MailError) -> MailError:
        ctx = self.ctx
        assert ctx is not None
        if isinstance(error, ReauthRequired) or not isinstance(error, AuthFailed):
            return error
        if not error.message.startswith("login rejected"):
            return error  # e.g. LOGINDISABLED: not a bad password, do not lock the account
        return self.pool.login_rejected(ctx, account)

    def connect_succeeded(self, account: Account) -> None:
        ctx = self.ctx
        assert ctx is not None
        self.pool.login_worked(ctx, account)


class UserPool:
    """Builds, caches and limits the per-user services of one process."""

    def __init__(
        self,
        store: Store,
        op: OperatorConfig,
        server_factory: ServerFactory,
        *,
        tls: TlsSettings = DEFAULT_TLS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.op = op
        self._factory = server_factory
        self._tls = tls
        self._clock = clock
        self._contexts: dict[tuple[str, str], UserContext] = {}
        self._retired: list[UserContext] = []
        self._calls: dict[str, int] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        # Keys of the store ring, never the pseudonym key (which an analyst of the logs may
        # hold): whoever can sign cursors or open viewer links must hold the store keys.
        self._cursor_secret = store.keys.derive("cursor-v1")[0]
        self.viewer_ids = ViewerIds(store.keys.derive("viewer-id-v1"))
        self._sweeper: asyncio.Task[None] | None = None

    # ------------------------------------------------------------ contexts

    def _cursor_key(self, user_id: str) -> bytes:
        return hmac.new(
            self._cursor_secret, b"uem-cursor-v1\0" + user_id.encode(), hashlib.sha256
        ).digest()

    def _build(
        self,
        principal: Principal,
        accounts: Sequence[MailAccount],
        identities: Sequence[IdentityRecord],
        fp: tuple[Any, ...],
        *,
        viewer: bool = False,
    ) -> UserContext:
        config, records = build_user_config(self.op, principal, accounts, identities, self._tls)
        hooks = _Hooks(self)
        router = AccountRouter(
            config,
            idle_ttl=self.op.pool.connection_idle_ttl,
            hooks=hooks,
            no_accounts_hint=(
                "This connection has no mailbox: the user adds one in the portal and "
                "authorizes the client for it."
            ),
        )
        base = self.op.public_url
        user_id = principal.user_id

        def link_id(message_id: str) -> str:
            return self.viewer_ids.seal(user_id, message_id)

        service = MailService(
            config,
            router=router,
            cursors=CursorCodec(self._cursor_key(principal.user_id)),
            viewer_base=base,
            link_id=link_id,
            download_links=PortalLinks(base, link_id) if base else None,
            download_status="on (portal viewer, sign-in required)" if base else "off",
            remote_send=StoreRemoteSend(
                self.store,
                config.policy,
                user_id=principal.user_id,
                grant_id=principal.grant_id,
                public_url=self.op.public_url,
                account_ids={name: rec.id for name, rec in records.items()},
            ),
        )
        ctx = UserContext(
            user_id=principal.user_id,
            grant_id=principal.grant_id,
            fingerprint=fp,
            config=config,
            records=records,
            service=service,
            router=router,
            server=None if viewer else self._factory(service, {}),
            last_used=self._clock(),
        )
        hooks.ctx = ctx
        return ctx

    async def acquire(self, principal: Principal) -> UserContext:
        """The context for this principal, built from the store if it is new or stale."""
        accounts = await self.store.list_for_user(MailAccount, principal.user_id)
        identities = await self.store.list_for_user(IdentityRecord, principal.user_id)
        return self._context(principal, accounts, identities)

    def _context(
        self,
        principal: Principal,
        accounts: Sequence[MailAccount],
        identities: Sequence[IdentityRecord],
        *,
        viewer: bool = False,
    ) -> UserContext:
        fp = fingerprint(principal, accounts, identities)
        key = (principal.user_id, principal.grant_id)
        ctx = self._contexts.get(key)
        if ctx is not None and ctx.fingerprint == fp:
            ctx.last_used = self._clock()
            return ctx
        fresh = self._build(principal, accounts, identities, fp, viewer=viewer)
        if ctx is not None:
            self._retire(ctx)
        self._contexts[key] = fresh
        self._trim(keep=fresh)
        return fresh

    async def lease(self, principal: Principal) -> UserContext:
        """The context for a request; pair with :meth:`release` (it is kept alive meanwhile)."""
        ctx = await self.acquire(principal)
        ctx.active += 1
        return ctx

    async def lease_viewer(self, user_id: str) -> UserContext:
        """The context behind the portal's message viewer: **only the signed-in user's own**
        accounts (from the store, by ``user_id``) that grant ``read``. Pair with :meth:`release`."""
        accounts = [
            a for a in await self.store.list_for_user(MailAccount, user_id) if a.user_id == user_id
        ]
        accounts.sort(key=lambda a: (a.created_at, a.id))
        principal = Principal(
            user_id=user_id,
            grant_id=VIEWER_GRANT,
            client_id="portal",
            client_name="portal",
            scopes=(SCOPE_READ,),
            account_scopes={a.id: "read" for a in accounts},
            identity_ids=(),
        )
        ctx = self._context(principal, accounts, (), viewer=True)
        ctx.active += 1
        return ctx

    def release(self, ctx: UserContext) -> None:
        ctx.active -= 1
        ctx.last_used = self._clock()
        if ctx.retired and ctx.active == 0:
            self._spawn(self._close(ctx))

    async def ensure_instructions(self, ctx: UserContext) -> None:
        """Put the user's folder maps into the instructions (``initialize``/discovery):
        read with the short timeout of local mode, failures never block."""
        now = self._clock()
        if ctx.maps_at is not None and now - ctx.maps_at < MAPS_TTL:
            return
        maps = await ctx.service.startup_folder_maps(STARTUP_TIMEOUT)
        ctx.server = self._factory(ctx.service, maps)
        ctx.maps_at = now

    # ------------------------------------------------------------ caps

    @asynccontextmanager
    async def call_slot(self, ctx: UserContext) -> AsyncIterator[None]:
        """At most ``max_concurrent_calls_per_user`` tool calls of one user at a time."""
        cap = self.op.pool.max_concurrent_calls_per_user
        running = self._calls.get(ctx.user_id, 0)
        if running >= cap:
            log_event(log, logging.INFO, "call refused: too many parallel calls", event="busy")
            raise Busy(
                f"{running} requests of this user are running already (limit {cap})",
                hint="Wait for the running requests, then try again.",
            )
        self._calls[ctx.user_id] = running + 1
        try:
            yield
        finally:
            left = self._calls.get(ctx.user_id, 1) - 1
            if left > 0:
                self._calls[ctx.user_id] = left
            else:
                self._calls.pop(ctx.user_id, None)

    def _all(self) -> list[UserContext]:
        return [*self._contexts.values(), *self._retired]

    def open_connections(self, user_id: str | None = None) -> int:
        return sum(c.router.open_connections() for c in self._all() if user_id in (None, c.user_id))

    def _evict_idle(self, user_id: str | None) -> bool:
        """Close the longest idle connection (of one user, or of anybody)."""
        best: tuple[float, UserContext, Any] | None = None
        for c in self._all():
            if user_id is not None and c.user_id != user_id:
                continue
            for used, slot in c.router.idle_sessions():
                if best is None or used < best[0]:
                    best = (used, c, slot)
        if best is None:
            return False
        best[1].router.drop_idle(best[2])
        return True

    def admit(self, ctx: UserContext) -> None:
        """Before a new mail connection: room for it per user and per instance, evicting
        idle connections first, else a ``BUSY`` error."""
        pool = self.op.pool
        if self.open_connections(ctx.user_id) >= pool.max_connections_per_user and not (
            self._evict_idle(ctx.user_id)
        ):
            raise Busy(
                f"this user has {pool.max_connections_per_user} mailbox connections open "
                "and all are in use",
                hint="Wait a moment and try again, or ask for fewer accounts per call.",
            )
        if self.open_connections() >= pool.max_connections and not self._evict_idle(None):
            log_event(log, logging.WARNING, "instance connection cap reached", event="busy")
            raise Busy("the server is at its limit of mailbox connections")

    # ------------------------------------------------------------ reauth

    def check_reauth_gate(self, ctx: UserContext, account: Account) -> None:
        """Refuse a login that is known to fail (no retry storm)."""
        rec = ctx.records.get(account.name)
        until = ctx.reauth_until.get(account.name, 0.0)
        if rec is not None and rec.needs_reauth and rec.auth_failed_at is not None:
            age = (self.store.now() - rec.auth_failed_at).total_seconds()
            until = max(until, self._clock() + self.op.pool.reauth_retry_after - age)
        if self._clock() < until:
            raise self._reauth_error(account)

    def _reauth_error(self, account: Account) -> ReauthRequired:
        where = f"{self.op.public_url}/portal/accounts" if self.op.public_url else "the portal"
        return ReauthRequired(
            f"the mail server rejected the stored password of account {account.name!r}",
            hint=f"Ask the user to enter the password for this account again in the portal "
            f"({where}). Other accounts keep working.",
        )

    def login_rejected(self, ctx: UserContext, account: Account) -> MailError:
        known = self._clock() < ctx.reauth_until.get(account.name, 0.0)
        ctx.reauth_until[account.name] = self._clock() + self.op.pool.reauth_retry_after
        rec = ctx.records.get(account.name)
        if rec is not None and not known:
            log_event(log, logging.INFO, "mail login rejected", event="reauth_required")
            self._spawn(self._mark_failed(ctx.user_id, rec))
        return self._reauth_error(account)

    def login_worked(self, ctx: UserContext, account: Account) -> None:
        ctx.reauth_until.pop(account.name, None)
        rec = ctx.records.get(account.name)
        if rec is not None and rec.auth_failed_at is not None:
            self._spawn(self._clear_failed(ctx.user_id, rec))

    async def _mark_failed(self, user_id: str, rec: MailAccount) -> None:
        mark = login_mark(rec.username, rec.password)
        for _ in range(3):
            fresh = await self.store.get(MailAccount, rec.id)
            if fresh is None or fresh.user_id != user_id:
                return
            if login_mark(fresh.username, fresh.password) != mark:
                return  # the login was changed meanwhile: the failure belongs to the old one
            now = self.store.now()
            if (
                fresh.needs_reauth
                and fresh.auth_failed_at is not None
                and (now - fresh.auth_failed_at).total_seconds() < MARK_DEBOUNCE
            ):
                return
            try:
                await self.store.update(replace(fresh, auth_failed_at=now, auth_failed_mark=mark))
                return
            except StoreConflict:
                continue

    async def _clear_failed(self, user_id: str, rec: MailAccount) -> None:
        for _ in range(3):
            fresh = await self.store.get(MailAccount, rec.id)
            if fresh is None or fresh.user_id != user_id or fresh.auth_failed_at is None:
                return
            try:
                await self.store.update(replace(fresh, auth_failed_at=None, auth_failed_mark=""))
                return
            except StoreConflict:
                continue

    # ------------------------------------------------------------ lifecycle

    def _spawn(self, coro: Awaitable[None]) -> None:
        task = asyncio.ensure_future(self._guard(coro))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    @staticmethod
    async def _guard(coro: Awaitable[None]) -> None:
        try:
            await coro
        except Exception:
            log.warning("background task of the per-user service failed", exc_info=True)

    def _retire(self, ctx: UserContext) -> None:
        self._contexts.pop((ctx.user_id, ctx.grant_id), None)
        ctx.retired = True
        self._retired.append(ctx)
        if ctx.active == 0:
            self._spawn(self._close(ctx))

    async def _close(self, ctx: UserContext) -> None:
        if ctx.active > 0:  # release() closes it when the last call is done
            return
        with suppress(ValueError):
            self._retired.remove(ctx)
        if self._contexts.get((ctx.user_id, ctx.grant_id)) is ctx:
            del self._contexts[(ctx.user_id, ctx.grant_id)]
        await ctx.router.close_for_good()

    def forget_user(self, user_id: str) -> int:
        """Close every cached context (and with it the mail connections) of a user, e.g. after
        the user deleted their data. Calls in flight finish first. Returns the number of
        contexts retired."""
        mine = [c for c in self._contexts.values() if c.user_id == user_id]
        for ctx in mine:
            self._retire(ctx)
        return len(mine)

    def _trim(self, keep: UserContext | None = None) -> None:
        """Keep at most ``max_cached_users`` contexts: drop the least recently used idle ones."""
        excess = len(self._contexts) - self.op.pool.max_cached_users
        if excess <= 0:
            return
        idle = sorted(
            (c for c in self._contexts.values() if c.active == 0 and c is not keep), key=_last_used
        )
        for ctx in idle[:excess]:
            self._retire(ctx)

    async def sweep(self) -> None:
        """Close idle mail connections and drop contexts nobody has used for a while."""
        now = self._clock()
        idle_ttl = self.op.pool.connection_idle_ttl
        for ctx in self._all():
            ctx.router.close_idle(idle_ttl)
        for ctx in list(self._contexts.values()):
            if ctx.active == 0 and now - max(ctx.last_used, ctx.router.last_activity()) > (
                self.op.pool.user_idle_ttl
            ):
                self._retire(ctx)

    async def _sweep_loop(self, interval: float) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                await self.sweep()
            except Exception:
                log.exception("sweeping the per-user pool failed")

    def start(self, interval: float = SWEEP_INTERVAL) -> None:
        if self._sweeper is None:
            self._sweeper = asyncio.ensure_future(self._sweep_loop(interval))

    async def aclose(self) -> None:
        if self._sweeper is not None:
            self._sweeper.cancel()
            with suppress(asyncio.CancelledError):
                await self._sweeper
            self._sweeper = None
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        contexts = self._all()
        self._contexts.clear()
        self._retired.clear()
        await asyncio.gather(*(c.router.close_for_good() for c in contexts), return_exceptions=True)


def _last_used(ctx: UserContext) -> float:
    return ctx.last_used
