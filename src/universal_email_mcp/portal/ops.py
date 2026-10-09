"""Operations of the portal on the store: accounts, identities, grants.

No HTTP in here. The functions keep the records consistent with each other (removing an
account also removes what was derived from it and revokes the clients that could use it;
the sign-in mailbox becomes a real account on the first sign-in) and are what the tests
drive. Passwords are only ever handed from one sealed record to another, never returned.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Any

from universal_email_mcp.jsonlog import log_event
from universal_email_mcp.mail.compose import clean_email
from universal_email_mcp.models import Endpoint, ServerProfile, TlsMode
from universal_email_mcp.oauth.config import (
    ACCOUNT_SCOPES,
    SCOPE_READ,
    SCOPE_SEND,
    SCOPES,
    permission_of,
)
from universal_email_mcp.oauth.identity import Address
from universal_email_mcp.presets import PRESETS, profile_for_host
from universal_email_mcp.store import (
    Grant,
    Identity,
    MailAccount,
    Store,
    StoreConflict,
    User,
)
from universal_email_mcp.store.store import R

log = logging.getLogger(__name__)

PERMISSIONS: tuple[str, ...] = tuple(permission_of(s) for s in ACCOUNT_SCOPES)
"""``read``, ``organize``, ``delete``, ``drafts`` - the permissions of an account."""
PRIMARY_NAME = "Main"
PRIMARY_PERMISSIONS = frozenset({"read", "organize", "drafts"})
LEGACY_PRIMARY = "primary"
"""Id of the pseudo account / identity the consent page offered before the portal existed
(3c). Grants that still reference it are rewritten on the owner's next sign-in."""


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def to_record_tls(tls: TlsMode) -> str:
    return "implicit" if tls == "tls" else "starttls"


def to_endpoint_tls(tls: str) -> TlsMode:
    return "tls" if tls == "implicit" else "starttls"


def account_endpoint(account: MailAccount) -> Endpoint:
    return Endpoint(account.host, account.port, to_endpoint_tls(account.tls))


def identity_smtp_endpoint(identity: Identity) -> Endpoint | None:
    if not identity.smtp_host:
        return None
    return Endpoint(identity.smtp_host, identity.smtp_port, to_endpoint_tls(identity.smtp_tls))


def smtp_endpoint_of(account: MailAccount, known: Iterable[ServerProfile] = ()) -> Endpoint | None:
    """The submission server that belongs to an account: the profile it was added from, or
    - for a server the user named - the same host on the standard implicit-TLS port."""
    for profile in (*known, *PRESETS.values()):
        if account.preset and profile.name == account.preset:
            return profile.smtp
    if account.preset:
        return None
    return profile_for_host(account.host).smtp


def unique_name(base: str, taken: Iterable[str]) -> str:
    names = {t.casefold() for t in taken}
    if base.casefold() not in names:
        return base
    for n in range(2, 100):
        candidate = f"{base} {n}"
        if candidate.casefold() not in names:
            return candidate
    return f"{base} {secrets.token_hex(2)}"


async def update_retry(
    store: Store, cls: type[R], rec_id: str, mutate: Callable[[R], R | None]
) -> R | None:
    """Read-modify-write with a few retries (the sliding-expiry touches race with us).
    ``mutate`` returns the new record, or ``None`` to leave it alone."""
    for _ in range(4):
        rec = await store.get(cls, rec_id)
        if rec is None:
            return None
        new = mutate(rec)
        if new is None:
            return rec
        try:
            return await store.update(new)
        except StoreConflict:
            continue
    raise StoreConflict(f"{cls.__name__} {rec_id} changed concurrently")


# ---------------------------------------------------------------- grants


def compute_scope(
    offered: Iterable[str], account_scopes: dict[str, set[str]], identity_ids: Iterable[str]
) -> str:
    """The OAuth scope string of a grant: the union of what is granted, ``mail.read``
    wherever anything is, ``mail.send`` when an identity is."""
    granted: set[str] = set()
    for scopes in account_scopes.values():
        if scopes:
            granted.update(scopes)
            granted.add(SCOPE_READ)
    if list(identity_ids):
        granted.update((SCOPE_SEND, SCOPE_READ))
    return " ".join(s for s in offered if s in granted)


def account_scope_strings(account_scopes: dict[str, set[str]]) -> dict[str, str]:
    """``{account: {mail.read, mail.organize}}`` -> ``{account: "read organize"}``."""
    return {
        a: " ".join(permission_of(s) for s in ACCOUNT_SCOPES if s in sc)
        for a, sc in account_scopes.items()
        if sc
    }


def grant_account_scopes(grant: Grant) -> dict[str, set[str]]:
    """The per-account scopes of a grant as ``mail.*`` sets (unknown words dropped)."""
    out: dict[str, set[str]] = {}
    for account_id, perms in grant.account_scopes.items():
        out[account_id] = {f"mail.{p}" for p in perms.split() if p in PERMISSIONS}
    return out


async def reduce_grant(
    store: Store,
    grant_id: str,
    offered: Iterable[str],
    account_scopes: dict[str, set[str]],
    identity_ids: Iterable[str],
) -> Grant | None:
    """Set a grant to *at most* what it has: each account's scopes are intersected with
    ``account_scopes`` and the identities with ``identity_ids`` (nothing is ever added)."""
    keep_idents = set(identity_ids)
    offered_t = tuple(offered)

    def mutate(g: Grant) -> Grant | None:
        have = grant_account_scopes(g)
        new: dict[str, set[str]] = {}
        for account_id, scopes in have.items():
            kept = scopes & account_scopes.get(account_id, set())
            if kept:
                new[account_id] = kept | {SCOPE_READ}
        idents = tuple(i for i in g.identity_ids if i in keep_idents)
        return replace(
            g,
            account_ids=tuple(new),
            account_scopes=account_scope_strings(new),
            identity_ids=idents,
            scope=compute_scope(offered_t, new, idents),
        )

    return await update_retry(store, Grant, grant_id, mutate)


async def clamp_grants(
    store: Store, user_id: str, offered: Iterable[str], only: Iterable[str] | None = None
) -> None:
    """Bring every grant of the user back within what the user allows *now*: an account's
    permissions and the identities with ``send``. Called after anything that lowers them, so
    a connected client never keeps more than the portal shows. A grant with nothing left is
    revoked."""
    offered_t = tuple(offered)
    allowed: dict[str, set[str]] = {
        a.id: {f"mail.{p}" for p in a.permissions}
        for a in await store.list_for_user(MailAccount, user_id)
    }
    senders = [i.id for i in await store.list_for_user(Identity, user_id) if i.send]
    chosen = None if only is None else set(only)
    for grant in await store.list_for_user(Grant, user_id):
        if chosen is not None and grant.id not in chosen:
            continue
        new = await reduce_grant(store, grant.id, offered_t, allowed, senders)
        if new is not None and not new.account_ids and not new.identity_ids:
            await store.revoke_grant(grant.id)


# ---------------------------------------------------------------- accounts


@dataclass(frozen=True, slots=True)
class Removal:
    grants_revoked: int
    identities_removed: int


async def remove_account(
    store: Store, user_id: str, account_id: str, offered: Iterable[str] = SCOPES
) -> Removal | None:
    """Delete an account and what hangs off it: identities that took their SMTP login from
    it are removed, others lose the link; every connected client that could use the account
    (or a removed identity) is revoked. ``None`` if there is no such account of the user."""
    account = await store.get(MailAccount, account_id)
    if account is None or account.user_id != user_id:
        return None
    gone_identities: set[str] = set()
    for ident in await store.list_for_user(Identity, user_id):
        if ident.smtp_account_id == account_id:
            gone_identities.add(ident.id)
            await store.delete(Identity, ident.id)
        elif ident.copies_account_id == account_id:
            await update_retry(
                store,
                Identity,
                ident.id,
                lambda i: replace(i, copies_account_id="", send=False),
            )
    revoked = 0
    for grant in await store.list_for_user(Grant, user_id):
        if account_id in grant.account_ids or gone_identities & set(grant.identity_ids):
            await store.revoke_grant(grant.id)
            revoked += 1
    await store.delete(MailAccount, account_id)
    await clamp_grants(store, user_id, offered)
    await _fix_default_identity(store, user_id)
    await update_retry(
        store,
        User,
        user_id,
        lambda u: (
            replace(u, settings={**u.settings, "primary_account": ""})
            if u.settings.get("primary_account") == account_id
            else None
        ),
    )
    return Removal(revoked, len(gone_identities))


async def _fix_default_identity(store: Store, user_id: str) -> None:
    """Exactly one identity is the default (if there is any)."""
    idents = await store.list_for_user(Identity, user_id)
    user = await store.get(User, user_id)
    if user is None:
        return
    defaults = [i for i in idents if i.is_default]
    target = defaults[0] if defaults else (idents[0] if idents else None)
    for ident in idents:
        want = target is not None and ident.id == target.id
        if ident.is_default != want:
            await update_retry(
                store, Identity, ident.id, lambda i, w=want: replace(i, is_default=w)
            )
    tid = target.id if target else ""
    if user.default_identity_id != tid:
        await update_retry(store, User, user_id, lambda u: replace(u, default_identity_id=tid))


async def set_password(store: Store, user_id: str, account_id: str, password: str) -> bool:
    """New mail password of an account; identities that copied the login follow."""
    account = await store.get(MailAccount, account_id)
    if account is None or account.user_id != user_id:
        return False
    await update_retry(store, MailAccount, account_id, lambda a: replace(a, password=password))
    for ident in await store.list_for_user(Identity, user_id):
        if ident.smtp_account_id == account_id:
            await update_retry(
                store, Identity, ident.id, lambda i: replace(i, smtp_password=password)
            )
    return True


def smtp_fields(account: MailAccount, endpoint: Endpoint | None) -> dict[str, Any]:
    """Identity fields that copy an account's submission server and login."""
    if endpoint is None:
        return {}
    return {
        "smtp_host": endpoint.host,
        "smtp_port": endpoint.port,
        "smtp_tls": to_record_tls(endpoint.tls),
        "smtp_username": account.username,
        "smtp_password": account.password,
        "smtp_account_id": account.id,
    }


async def set_default_identity(store: Store, user_id: str, identity_id: str) -> bool:
    idents = await store.list_for_user(Identity, user_id)
    if not any(i.id == identity_id for i in idents):
        return False
    for ident in idents:
        want = ident.id == identity_id
        if ident.is_default != want:
            await update_retry(
                store, Identity, ident.id, lambda i, w=want: replace(i, is_default=w)
            )
    await update_retry(store, User, user_id, lambda u: replace(u, default_identity_id=identity_id))
    return True


async def remove_identity(store: Store, user_id: str, identity_id: str) -> int | None:
    """Delete an identity; clients that were allowed to send as it lose that (a grant that
    has nothing left is revoked). Returns the number of grants touched, ``None`` if unknown."""
    ident = await store.get(Identity, identity_id)
    if ident is None or ident.user_id != user_id:
        return None
    touched = 0
    for grant in await store.list_for_user(Grant, user_id):
        if identity_id in grant.identity_ids:
            touched += 1
            rest = tuple(i for i in grant.identity_ids if i != identity_id)
            if not grant.account_ids and not rest:
                await store.revoke_grant(grant.id)
            else:
                await update_retry(
                    store,
                    Grant,
                    grant.id,
                    lambda g, r=rest: _without_send(g, r),
                )
    await store.delete(Identity, identity_id)
    await _fix_default_identity(store, user_id)
    return touched


def _without_send(grant: Grant, rest: tuple[str, ...]) -> Grant:
    scopes = grant.scope.split()
    if not rest:
        scopes = [s for s in scopes if s != SCOPE_SEND]
    return replace(grant, identity_ids=rest, scope=" ".join(scopes))


# ---------------------------------------------------------------- the sign-in mailbox


async def ensure_primary(
    store: Store,
    user: User,
    address: Address,
    password: str,
    profile: ServerProfile,
    *,
    create: bool,
) -> User:
    """Make the sign-in mailbox a real account, once - if the user opted in.

    Signing in only verifies the password. With ``create`` (the user ticked "use this
    mailbox with AI clients") and no "Main" yet: create the account from the login server
    and the typed password, plus an identity when the server has a submission endpoint,
    and rewrite old grants that referenced the pseudo account ``primary``. Without
    ``create`` nothing is stored. An existing "Main" only has its password refreshed if
    it changed (whatever ``create`` says). A user who removed the account does not get it
    back by a later sign-in, ticked or not.
    """
    primary_id = str(user.settings.get("primary_account", ""))
    if primary_id:
        acc = await store.get(MailAccount, primary_id)
        if acc is not None and acc.password != password:
            await set_password(store, user.id, primary_id, password)
        return user
    if not create or user.settings.get("primary_done") or profile.imap is None:
        return user

    now = store.now()
    ep = profile.imap
    taken = [a.name for a in await store.list_for_user(MailAccount, user.id)]
    grants = [
        g
        for g in await store.list_for_user(Grant, user.id)
        if LEGACY_PRIMARY in g.account_ids or LEGACY_PRIMARY in g.identity_ids
    ]
    perms = set(PRIMARY_PERMISSIONS)
    for g in grants:
        perms.update(
            p for p in g.account_scopes.get(LEGACY_PRIMARY, "").split() if p in PERMISSIONS
        )
    account = MailAccount(
        id=new_id("a"),
        user_id=user.id,
        name=unique_name(PRIMARY_NAME, taken),
        protocol="imap",
        host=ep.host,
        port=ep.port,
        tls=to_record_tls(ep.tls),
        preset=profile.name,
        username=address.login,
        password=password,
        permissions=tuple(p for p in PERMISSIONS if p in perms),
        created_at=now,
    )
    identity: Identity | None = None
    mail = clean_email(address.login)
    smtp_ep = profile.smtp
    if mail and smtp_ep:
        identity = Identity(
            id=new_id("i"),
            user_id=user.id,
            addresses=(mail,),
            copies_account_id=account.id,
            is_default=not await store.list_for_user(Identity, user.id),
            created_at=now,
            **smtp_fields(account, smtp_ep),
        )
    await store.create(account)
    if identity is not None:
        await store.create(identity)
    settings = {**user.settings, "primary_account": account.id, "primary_done": True}
    default_id = user.default_identity_id
    if identity is not None and identity.is_default:
        default_id = identity.id
    try:
        user = await store.update(replace(user, settings=settings, default_identity_id=default_id))
    except StoreConflict:  # a concurrent sign-in won; undo ours
        await store.delete(MailAccount, account.id)
        if identity is not None:
            await store.delete(Identity, identity.id)
        again = await store.get(User, user.id)
        return again or user
    for g in grants:
        await update_retry(store, Grant, g.id, lambda x: _migrate_grant(x, account.id, identity))
    if grants:
        await clamp_grants(
            store, user.id, SCOPES, [g.id for g in grants]
        )  # the new identity may not send yet
    log_event(
        log, logging.INFO, "sign-in mailbox became an account",
        event="portal.primary_account", grants=len(grants),
    )  # fmt: skip
    return user


def _migrate_grant(g: Grant, account_id: str, identity: Identity | None) -> Grant:
    scopes = {(account_id if a == LEGACY_PRIMARY else a): s for a, s in g.account_scopes.items()}
    accounts = tuple(account_id if a == LEGACY_PRIMARY else a for a in g.account_ids)
    idents: list[str] = []
    for i in g.identity_ids:
        if i != LEGACY_PRIMARY:
            idents.append(i)
        elif identity is not None:
            idents.append(identity.id)
    return replace(
        g,
        account_ids=tuple(dict.fromkeys(accounts)),
        account_scopes=scopes,
        identity_ids=tuple(dict.fromkeys(idents)),
    )
