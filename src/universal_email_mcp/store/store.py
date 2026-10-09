"""The async ``Store``: typed records on top of a :class:`Backend`, with sealing and expiry.

Generic operations (``create`` / ``get`` / ``update`` / ``delete`` / ``list_for_user``) work for
every record type; the flows that need atomicity or hashing have their own methods (portal
sessions, authorization codes, grants and tokens with refresh rotation and replay detection,
activity feed, GDPR export and delete). Expired records read as missing (injectable clock);
backends with TTL policies delete them eventually, ``purge_expired()`` does it by hand.
"""

from __future__ import annotations

import dataclasses
import hashlib
import secrets
import types
import typing
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar, cast

from universal_email_mcp.errors import MailError
from universal_email_mcp.store.backend import (
    VERSION_KEY,
    AlreadyExists,
    Backend,
    Doc,
    Op,
    StoreConflict,
)
from universal_email_mcp.store.crypto import Aad, CryptoError, KeyRing, hash_token, new_token
from universal_email_mcp.store.records import (
    ALL_RECORDS,
    DELETE_ORDER,
    USER_OWNED,
    ActivityEntry,
    AuthCode,
    Grant,
    OAuthClient,
    PendingApproval,
    PortalSession,
    Record,
    Token,
    User,
)

R = TypeVar("R", bound=Record)

SEALED_KEY = "_sealed"
_META_FIELDS = frozenset({"id", "version", "extra", "extra_sealed"})
ACTIVITY_MAX_TEXT = 64
_BATCH = 400  # Firestore transactions allow 500 writes


class InvalidToken(MailError):
    code = "STORE_INVALID_TOKEN"


class CodeReplay(InvalidToken):
    """An authorization code was redeemed twice: the grant (and its tokens) was revoked."""

    code = "STORE_CODE_REPLAY"


class TokenReuse(InvalidToken):
    """A rotated refresh token was presented again: the whole grant was revoked."""

    code = "STORE_TOKEN_REUSE"


@dataclass(frozen=True, slots=True)
class SessionPolicy:
    """Lifetimes (design section 6.1). A zero ``refresh_ttl`` / ``absolute_max`` = unlimited."""

    access_ttl: timedelta = timedelta(hours=1)
    refresh_ttl: timedelta = timedelta(days=30)
    absolute_max: timedelta = timedelta(days=90)
    pending_grant_ttl: timedelta = timedelta(minutes=10)
    auth_code_ttl: timedelta = timedelta(minutes=1)
    consumed_code_ttl: timedelta = timedelta(minutes=10)
    client_unused_ttl: timedelta = timedelta(days=30)
    activity_ttl: timedelta = timedelta(days=30)
    approval_ttl: timedelta = timedelta(minutes=10)
    touch_interval: timedelta = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class IssuedTokens:
    """Raw tokens, shown to the client once; the store keeps only their digests."""

    access_token: str = dataclasses.field(repr=False)
    refresh_token: str = dataclasses.field(repr=False)
    access_expires_at: datetime
    refresh_expires_at: datetime | None
    grant: Grant


# --- record <-> document ----------------------------------------------------------------

_hints: dict[type, dict[str, Any]] = {}


def _field_hints(cls: type[Record]) -> dict[str, Any]:
    if cls not in _hints:
        _hints[cls] = typing.get_type_hints(cls)
    return _hints[cls]


def _is_tuple(hint: Any) -> bool:
    if typing.get_origin(hint) is tuple:
        return True
    if typing.get_origin(hint) in (typing.Union, types.UnionType):
        return any(_is_tuple(a) for a in typing.get_args(hint))
    return False


def _check_datetimes(value: Any) -> None:
    if isinstance(value, datetime) and value.tzinfo is None:
        raise ValueError("store datetimes must be timezone-aware")


def _plain(value: Any) -> Any:
    """JSON/Firestore friendly: tuples become lists."""
    if isinstance(value, tuple | list):
        return [_plain(v) for v in cast("Sequence[Any]", value)]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in cast("dict[str, Any]", value).items()}
    return value


class Store:
    def __init__(
        self,
        backend: Backend,
        keys: KeyRing,
        *,
        clock: Callable[[], datetime] | None = None,
        policy: SessionPolicy | None = None,
    ) -> None:
        self.backend = backend
        self.keys = keys
        self.policy = policy or SessionPolicy()
        self._clock = clock or (lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        return f"Store({type(self.backend).__name__}, {self.keys!r})"

    def now(self) -> datetime:
        return self._clock()

    async def close(self) -> None:
        await self.backend.close()

    # -- codec ------------------------------------------------------------------------

    def _aad(self, rec_cls: type[Record], owner: str, rec_id: str) -> Aad:
        return Aad(owner, rec_cls.KIND, rec_id, SEALED_KEY)

    def encode(self, rec: Record, version: int) -> Doc:
        cls = type(rec)
        doc: Doc = {}
        sealed: dict[str, Any] = {}
        for f in dataclasses.fields(rec):
            if f.name in _META_FIELDS:
                continue
            value = getattr(rec, f.name)
            _check_datetimes(value)
            (sealed if f.name in cls.SEALED else doc)[f.name] = _plain(value)
        for k, v in rec.extra.items():  # fields of a newer code version, kept as they are
            doc.setdefault(k, v)
        for k, v in rec.extra_sealed.items():
            sealed.setdefault(k, v)
        if sealed:
            doc[SEALED_KEY] = self.keys.seal_json(sealed, self._aad(cls, rec.owner, rec.id))
        doc[VERSION_KEY] = version
        return doc

    def decode(self, cls: type[R], rec_id: str, doc: Doc) -> R:
        values: dict[str, Any] = {
            k: v for k, v in doc.items() if k not in (SEALED_KEY, VERSION_KEY)
        }
        if cls.SEALED or SEALED_KEY in doc:
            if not isinstance(doc.get(SEALED_KEY), str):
                raise CryptoError("record has no sealed data")
            owner = rec_id if cls is User else str(doc.get("user_id", ""))
            sealed = self.keys.open_json(doc[SEALED_KEY], self._aad(cls, owner, rec_id))
        else:
            sealed = {}
        values.update(sealed)
        hints = _field_hints(cls)
        for name, value in values.items():
            if isinstance(value, list) and _is_tuple(hints.get(name)):
                values[name] = tuple(cast("list[Any]", value))
        known = {f.name for f in dataclasses.fields(cls)} - _META_FIELDS
        return cls(
            id=rec_id,
            version=int(doc[VERSION_KEY]),
            extra={k: v for k, v in values.items() if k not in known and k not in sealed},
            extra_sealed={k: v for k, v in sealed.items() if k not in known},
            **{k: v for k, v in values.items() if k in known},
        )

    def _expired(self, doc: Doc) -> bool:
        exp = doc.get("expires_at")
        return isinstance(exp, datetime) and exp <= self.now()

    # -- generic operations -----------------------------------------------------------

    async def create(self, rec: R) -> R:
        """Store a new record (version becomes 1); ``AlreadyExists`` if the id is taken."""
        await self.backend.commit([Op("create", rec.KIND, rec.id, self.encode(rec, 1))])
        return replace(rec, version=1)

    async def get(self, cls: type[R], rec_id: str) -> R | None:
        doc = await self.backend.get(cls.KIND, rec_id)
        if doc is None or self._expired(doc):
            return None
        return self.decode(cls, rec_id, doc)

    async def update(self, rec: R) -> R:
        """Replace the record if ``rec.version`` is still current; ``StoreConflict`` otherwise.

        The new version is ``rec.version + 1``. The write seals with the active key, which
        is how old blobs migrate to a new key.
        """
        if rec.version < 1:
            raise ValueError("update() needs a stored record (version >= 1)")
        new = rec.version + 1
        await self.backend.commit(
            [Op("replace", rec.KIND, rec.id, self.encode(rec, new), rec.version)]
        )
        return replace(rec, version=new)

    async def delete(
        self, cls: type[Record], rec_id: str, *, expected_version: int | None = None
    ) -> None:
        """Delete; unconditional unless ``expected_version`` is given. Missing is fine."""
        await self.backend.commit([Op("delete", cls.KIND, rec_id, None, expected_version)])

    async def get_any(self, cls: type[R], rec_id: str) -> R | None:
        """Like :meth:`get`, but an expired record that has not been purged yet is returned
        too (the portal shows "expired" for a user's own approval)."""
        doc = await self.backend.get(cls.KIND, rec_id)
        return None if doc is None else self.decode(cls, rec_id, doc)

    async def list_for_user(
        self, cls: type[R], user_id: str, *, include_expired: bool = False
    ) -> list[R]:
        """The user's live records of one type, oldest first."""
        if cls not in USER_OWNED:
            raise ValueError(f"{cls.__name__} has no user_id")
        out = [
            self.decode(cls, i, d)
            for i, d in await self.backend.find(cls.KIND, "user_id", user_id)
            if include_expired or not self._expired(d)
        ]
        return sorted(out, key=lambda r: (_when(r), r.id))

    async def take(self, cls: type[R], rec_id: str) -> R | None:
        """Get and delete in one step; of two concurrent callers only one gets the record."""
        rec = await self.get(cls, rec_id)
        if rec is None:
            return None
        try:
            await self.delete(cls, rec_id, expected_version=rec.version)
        except StoreConflict:
            return None
        return rec

    # -- users ------------------------------------------------------------------------

    async def get_or_create_user(self, user_id: str, primary_address: str) -> User:
        for _ in range(5):
            existing = await self.get(User, user_id)
            if existing:
                return existing
            try:
                return await self.create(
                    User(id=user_id, primary_address=primary_address, created_at=self.now())
                )
            except StoreConflict:  # lost a race (AlreadyExists) or contention: look again
                continue
        raise StoreConflict("could not create the user record")

    # -- portal sessions --------------------------------------------------------------

    async def create_portal_session(
        self, user_id: str, ttl: timedelta = timedelta(hours=12), *, fresh_login: bool = False
    ) -> tuple[str, PortalSession]:
        """Returns ``(cookie value, record)``; only the digest is stored. ``fresh_login``:
        the password was just typed, so the session counts as re-authenticated."""
        raw, now = new_token("uem_ps"), self.now()
        rec = PortalSession(
            id=hash_token(raw),
            user_id=user_id,
            created_at=now,
            last_seen=now,
            reauth_at=now if fresh_login else None,
            expires_at=now + ttl,
        )
        return raw, await self.create(rec)

    def reauth_fresh(self, session: PortalSession, window: timedelta) -> bool:
        """Did the user type the password within ``window``?"""
        return session.reauth_at is not None and self.now() - session.reauth_at <= window

    async def mark_reauth(self, session: PortalSession) -> PortalSession:
        """Record that the password was just typed again (retries on a concurrent touch)."""
        current = session
        for _ in range(4):
            try:
                return await self.update(replace(current, reauth_at=self.now()))
            except StoreConflict:
                again = await self.get(PortalSession, session.id)
                if again is None:
                    return session
                current = again
        return current

    async def get_portal_session(self, raw: str) -> PortalSession | None:
        return await self.get(PortalSession, hash_token(raw))

    async def authenticate_portal_session(
        self, raw: str, *, idle_timeout: timedelta
    ) -> PortalSession | None:
        """The live session, or None when unknown, past its absolute expiry or idle for
        longer than ``idle_timeout``. ``last_seen`` is refreshed at most once per
        ``touch_interval`` (a lost race is harmless)."""
        rec = await self.get_portal_session(raw)
        if rec is None:
            return None
        now = self.now()
        if now - rec.last_seen > idle_timeout:
            await self.delete(PortalSession, rec.id)
            return None
        if now - rec.last_seen >= self.policy.touch_interval:
            try:
                rec = await self.update(replace(rec, last_seen=now))
            except StoreConflict:
                pass
        return rec

    async def delete_portal_session(self, raw: str) -> None:
        await self.delete(PortalSession, hash_token(raw))

    # -- oauth clients ----------------------------------------------------------------

    async def register_client(self, client_id: str, **fields: Any) -> OAuthClient:
        now = self.now()
        return await self.create(
            OAuthClient(
                id=client_id,
                created_at=now,
                last_used=now,
                expires_at=now + self.policy.client_unused_ttl,
                **fields,
            )
        )

    async def touch_client(self, client: OAuthClient) -> OAuthClient:
        """Extend the unused-TTL (at most once per ``touch_interval``)."""
        now = self.now()
        if now - client.last_used < self.policy.touch_interval:
            return client
        new = replace(client, last_used=now, expires_at=now + self.policy.client_unused_ttl)
        try:
            return await self.update(new)
        except StoreConflict:
            return client

    # -- authorization codes ----------------------------------------------------------

    async def issue_auth_code(
        self,
        *,
        user_id: str,
        client_id: str,
        grant_id: str,
        redirect_uri: str,
        code_challenge: str,
        resource: str = "",
        scope: str = "",
    ) -> str:
        raw = new_token("uem_ac")
        await self.create(
            AuthCode(
                id=hash_token(raw),
                user_id=user_id,
                client_id=client_id,
                grant_id=grant_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                resource=resource,
                scope=scope,
                expires_at=self.now() + self.policy.auth_code_ttl,
            )
        )
        return raw

    async def redeem_auth_code(self, raw: str) -> AuthCode | None:
        """Single use. None for an unknown or expired code.

        The code stays as ``consumed`` for ``consumed_code_ttl``; presenting it again (or
        racing another redeem) revokes the grant with the tokens issued from the code and
        raises :class:`CodeReplay` (RFC 6749 section 4.1.2).
        """
        cur = await self.get(AuthCode, hash_token(raw))
        if cur is None:
            return None
        if cur.consumed:
            await self.revoke_grant(cur.grant_id)
            raise CodeReplay("authorization code was already used; session revoked")
        used = replace(cur, consumed=True, expires_at=self.now() + self.policy.consumed_code_ttl)
        try:
            await self.update(used)
        except StoreConflict:
            await self.revoke_grant(cur.grant_id)
            raise CodeReplay("authorization code was used concurrently; session revoked") from None
        return cur

    # -- grants and tokens ------------------------------------------------------------

    def _refresh_expiry(self, grant: Grant, now: datetime) -> datetime | None:
        limits = [grant.absolute_expires_at]
        if self.policy.refresh_ttl:
            limits.append(now + self.policy.refresh_ttl)
        real = [x for x in limits if x is not None]
        return min(real) if real else None

    async def create_grant(
        self,
        *,
        user_id: str,
        client_id: str,
        client_name: str = "",
        account_ids: Sequence[str] = (),
        account_scopes: dict[str, str] | None = None,
        identity_ids: Sequence[str] = (),
        scope: str = "",
    ) -> Grant:
        """Consent result. Lives ``pending_grant_ttl`` until tokens are issued for it."""
        now = self.now()
        absolute = now + self.policy.absolute_max if self.policy.absolute_max else None
        return await self.create(
            Grant(
                id="g_" + secrets.token_hex(12),
                user_id=user_id,
                client_id=client_id,
                client_name=client_name,
                account_ids=tuple(account_ids),
                account_scopes=dict(account_scopes or {}),
                identity_ids=tuple(identity_ids),
                scope=scope,
                created_at=now,
                absolute_expires_at=absolute,
                expires_at=now + self.policy.pending_grant_ttl,
            )
        )

    def _token_pair(
        self, grant: Grant, client_id: str, resource: str, now: datetime
    ) -> tuple[IssuedTokens, list[Op]]:
        refresh_exp = self._refresh_expiry(grant, now)
        access_exp = now + self.policy.access_ttl
        if refresh_exp is not None:
            access_exp = min(access_exp, refresh_exp)
        raw_a, raw_r = new_token("uem_at"), new_token("uem_rt")
        ops: list[Op] = []
        for raw, kind, exp in ((raw_a, "access", access_exp), (raw_r, "refresh", refresh_exp)):
            tok = Token(
                id=hash_token(raw),
                user_id=grant.user_id,
                grant_id=grant.id,
                client_id=client_id,
                token_type=kind,
                resource=resource,
                scope=grant.scope,
                created_at=now,
                expires_at=exp,
            )
            ops.append(Op("create", tok.KIND, tok.id, self.encode(tok, 1)))
        new_grant = replace(grant, last_used=now, expires_at=refresh_exp, version=grant.version + 1)
        ops.append(
            Op(
                "replace",
                grant.KIND,
                grant.id,
                self.encode(new_grant, new_grant.version),
                grant.version,
            )
        )
        return IssuedTokens(raw_a, raw_r, access_exp, refresh_exp, new_grant), ops

    async def issue_tokens(self, grant: Grant, *, resource: str = "") -> IssuedTokens:
        """First token pair of a pending grant (after the code was redeemed); once only."""
        for _ in range(3):
            fresh = await self.get(Grant, grant.id)
            if fresh is None or fresh.last_used is not None:
                raise InvalidToken("the grant is gone or already has tokens")
            issued, ops = self._token_pair(fresh, fresh.client_id, resource, self.now())
            try:
                await self.backend.commit(ops)
                return issued
            except StoreConflict:
                continue
        raise StoreConflict("grant changed concurrently")

    async def rotate_refresh_token(self, raw: str, *, client_id: str) -> IssuedTokens:
        """Exchange a refresh token for a new pair, atomically.

        The old token stays as ``consumed`` until its expiry. Presenting it again (or racing
        another exchange) revokes the whole grant and raises :class:`TokenReuse`. A concurrent
        change of the grant alone (e.g. ``last_used``) is retried, not treated as replay.
        """
        grant_id = ""
        for _ in range(3):
            old = await self.get(Token, hash_token(raw))
            if old is None or old.token_type != "refresh" or old.client_id != client_id:
                raise InvalidToken("unknown or expired refresh token")
            grant = await self.get(Grant, old.grant_id)
            if grant is None:
                raise InvalidToken("the session no longer exists")
            grant_id = grant.id
            if old.consumed:
                await self.revoke_grant(grant.id)
                raise TokenReuse("refresh token was already used; session revoked")
            issued, ops = self._token_pair(grant, client_id, old.resource, self.now())
            used = replace(old, consumed=True)
            ops.append(
                Op("replace", old.KIND, old.id, self.encode(used, old.version + 1), old.version)
            )
            try:
                await self.backend.commit(ops)
                return issued
            except StoreConflict:
                continue  # re-read: if the token was consumed meanwhile, that is replay
        await self.revoke_grant(grant_id)
        raise TokenReuse("refresh token was used concurrently; session revoked")

    async def authenticate_access_token(self, raw: str) -> tuple[Token, Grant] | None:
        """The live access token and its grant, or None. Touches ``last_used`` rarely."""
        tok = await self.get(Token, hash_token(raw))
        if tok is None or tok.token_type != "access":
            return None
        grant = await self.get(Grant, tok.grant_id)
        if grant is None:
            return None
        now = self.now()
        if grant.last_used is None or now - grant.last_used >= self.policy.touch_interval:
            try:
                grant = await self.update(replace(grant, last_used=now))
            except StoreConflict:
                pass  # someone else touched it; not worth failing the request
        return tok, grant

    async def revoke_grant(self, grant_id: str) -> None:
        """Delete a grant with all its tokens and pending codes."""
        ops: list[Op] = [Op("delete", Grant.KIND, grant_id)]
        for cls in (Token, AuthCode):
            for i, _ in await self.backend.find(cls.KIND, "grant_id", grant_id):
                ops.append(Op("delete", cls.KIND, i))
        await self._commit_chunks(ops)

    async def revoke_token(self, raw: str) -> None:
        """RFC 7009: revoking a refresh token ends the grant, an access token only itself."""
        tok = await self.get(Token, hash_token(raw))
        if tok is None:
            return
        if tok.token_type == "refresh":
            await self.revoke_grant(tok.grant_id)
        else:
            await self.delete(Token, tok.id)

    # -- pending approvals ------------------------------------------------------------

    async def create_approval(
        self, *, user_id: str, grant_id: str, identity_id: str, content_hash: str, draft_ref: str
    ) -> PendingApproval:
        now = self.now()
        return await self.create(
            PendingApproval(
                id="a_" + secrets.token_hex(12),
                user_id=user_id,
                grant_id=grant_id,
                identity_id=identity_id,
                content_hash=content_hash,
                draft_ref=draft_ref,
                created_at=now,
                expires_at=now + self.policy.approval_ttl,
            )
        )

    async def decide_approval(
        self, approval_id: str, user_id: str, approve: bool
    ) -> PendingApproval | None:
        """Pending -> approved/declined (once), only by the owning user. None if gone,
        expired, foreign or already decided; ``StoreConflict`` if decided concurrently."""
        cur = await self.get(PendingApproval, approval_id)
        if cur is None or cur.user_id != user_id or cur.status != "pending":
            return None
        return await self.update(replace(cur, status="approved" if approve else "declined"))

    async def consume_approval(
        self, approval_id: str, user_id: str, content_hash: str
    ) -> PendingApproval | None:
        """Single use: take an *approved* approval of this user for exactly this content."""
        cur = await self.get(PendingApproval, approval_id)
        if (
            cur is None
            or cur.user_id != user_id
            or cur.status != "approved"
            or cur.content_hash != content_hash
        ):
            return None
        return await self.take(PendingApproval, approval_id)

    # -- sent-message markers ---------------------------------------------------------

    @staticmethod
    def _send_marker_id(user_id: str, content_hash: str) -> str:
        digest = hashlib.sha256(f"uem-send-marker\0{user_id}\0{content_hash}".encode())
        return "s_" + digest.hexdigest()[:24]

    async def claim_send(self, user_id: str, content_hash: str, ttl: timedelta) -> bool:
        """Mark "this message of this user goes out now" for ``ttl``; ``False`` when the
        same content was claimed already (a replayed confirmation, a double click, a second
        instance). Markers are ``approvals`` records with the status ``sent`` and no draft."""
        now = self.now()
        try:
            await self.create(
                PendingApproval(
                    id=self._send_marker_id(user_id, content_hash),
                    user_id=user_id,
                    grant_id="",
                    identity_id="",
                    content_hash=content_hash,
                    draft_ref="",
                    status="sent",
                    created_at=now,
                    expires_at=now + ttl,
                )
            )
        except AlreadyExists:
            marker = self._send_marker_id(user_id, content_hash)
            stale = await self.get_any(PendingApproval, marker)
            if stale is None:  # purged between the two calls: the way is free again
                return await self.claim_send(user_id, content_hash, ttl)
            if stale.expires_at > now:
                return False
            try:
                # An expired, not yet purged marker: renew it in place. The replace only
                # succeeds for the version that was read, so of several racers exactly one
                # wins (a delete followed by a create would reuse version 1 and let a slow
                # racer delete the winner's fresh marker).
                await self.update(replace(stale, created_at=now, expires_at=now + ttl))
            except StoreConflict:
                return False
        return True

    async def release_send(self, user_id: str, content_hash: str) -> None:
        """Undo :meth:`claim_send` (the send failed, so trying again is fine)."""
        await self.delete(PendingApproval, self._send_marker_id(user_id, content_hash))

    # -- activity ---------------------------------------------------------------------

    async def record_activity(
        self,
        user_id: str,
        event: str,
        *,
        client: str = "",
        tool: str = "",
        account: str = "",
        outcome: str = "",
        counts: dict[str, int] | None = None,
        coalesce: bool = False,
    ) -> ActivityEntry:
        """Own-activity feed entry. Only short labels and integers are accepted, so that
        subjects, addresses or other mail data cannot slip in by accident.

        ``client`` is the id of the grant (the portal resolves it to the application's name
        when it shows the entry), ``account`` an account id or name.

        ``coalesce`` merges repeated events of the same kind within one hour into a single
        entry whose ``calls`` count grows (and whose counts add up), so that a busy client
        cannot fill the feed (and the send rate limit's scan of it) with read calls. Racing
        writers of one entry retry a few times; under heavy contention a call raises
        ``StoreConflict`` and its count is not recorded (the entry never over-counts)."""
        for text in (event, client, tool, account, outcome):
            if len(text) > ACTIVITY_MAX_TEXT or "@" in text:
                raise ValueError("activity labels must be short names, not addresses or text")
        counts = counts or {}
        if any(type(v) is not int or len(k) > ACTIVITY_MAX_TEXT for k, v in counts.items()):
            raise ValueError("activity counts must be integers")
        now = self.now()
        entry_id = "e_" + secrets.token_hex(12)
        if coalesce:
            hour = int(now.timestamp() // 3600)
            key = "\0".join((user_id, event, client, tool, account, outcome, str(hour)))
            entry_id = "ec_" + hashlib.sha256(key.encode()).hexdigest()[:24]
            counts = {**counts, "calls": 1}
        entry = ActivityEntry(
            id=entry_id,
            user_id=user_id,
            at=now,
            event=event,
            client=client,
            tool=tool,
            account=account,
            outcome=outcome,
            counts=dict(counts),
            expires_at=now + self.policy.activity_ttl,
        )
        if not coalesce:
            return await self.create(entry)
        for _ in range(3):
            try:
                return await self.create(entry)
            except AlreadyExists:
                pass
            current = await self.get(ActivityEntry, entry_id)
            if current is None:  # expired between the two calls
                continue
            merged = {
                k: current.counts.get(k, 0) + counts.get(k, 0) for k in {*current.counts, *counts}
            }
            try:
                return await self.update(replace(current, at=now, counts=merged))
            except StoreConflict:
                continue
        raise StoreConflict("activity entry is changing too fast")

    async def list_activity(self, user_id: str, limit: int = 100) -> list[ActivityEntry]:
        """Newest first."""
        rows = await self.list_for_user(ActivityEntry, user_id)
        return rows[::-1][:limit]

    # -- GDPR -------------------------------------------------------------------------

    async def export_user(self, user_id: str) -> dict[str, Any]:
        """Everything stored about the user as plain data: settings, accounts, identities,
        sessions, activity. Passwords, token digests and keys are left out."""
        user = await self.get(User, user_id)
        out: dict[str, Any] = {"user": _export(user) if user else None}
        for cls in USER_OWNED:
            out[cls.KIND] = [_export(r) for r in await self.list_for_user(cls, user_id)]
        return out

    async def delete_user(self, user_id: str) -> dict[str, int]:
        """Remove every record of the user (also expired ones) and return counts per kind.

        Order (``DELETE_ORDER``): grants first, so access and refresh tokens, which need
        their grant, are dead from the first step on; accounts and the rest follow; the user
        record goes last. An interrupted run leaves a user who can sign in and repeat it;
        every step is a plain delete by id, so repeating is safe. A last sweep catches
        records a request in flight wrote meanwhile.
        """
        counts: dict[str, int] = {}
        for cls in DELETE_ORDER:
            counts[cls.KIND] = await self._delete_owned(cls, user_id)
        existed = await self.backend.get(User.KIND, user_id) is not None
        await self.delete(User, user_id)
        counts[User.KIND] = int(existed)
        for cls in DELETE_ORDER:
            counts[cls.KIND] += await self._delete_owned(cls, user_id)
        return counts

    async def _delete_owned(self, cls: type[Record], user_id: str) -> int:
        rows = await self.backend.find(cls.KIND, "user_id", user_id)
        await self._commit_chunks([Op("delete", cls.KIND, i) for i, _ in rows])
        return len(rows)

    # -- maintenance ------------------------------------------------------------------

    async def purge_expired(self) -> int:
        """Delete expired records (Firestore does this itself via TTL policies)."""
        ops: list[Op] = []
        for cls in ALL_RECORDS:
            async for i, d in self.backend.scan(cls.KIND):
                if self._expired(d):
                    ops.append(Op("delete", cls.KIND, i))
        await self._commit_chunks(ops)
        return len(ops)

    async def _commit_chunks(self, ops: list[Op]) -> None:
        for i in range(0, len(ops), _BATCH):
            await self.backend.commit(ops[i : i + _BATCH])


def _when(rec: Record) -> datetime:
    for name in ("created_at", "at"):
        value = getattr(rec, name, None)
        if isinstance(value, datetime):
            return value
    return datetime.min.replace(tzinfo=UTC)


def _export(rec: Record) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in dataclasses.fields(rec):
        if f.name in rec.EXPORT_EXCLUDE or f.name in _META_FIELDS - {"id"}:
            continue
        value = getattr(rec, f.name)
        out[f.name] = value.isoformat() if isinstance(value, datetime) else _plain(value)
    return out
