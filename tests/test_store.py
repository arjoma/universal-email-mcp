"""Store contract tests: every test runs against the memory backend and the Firestore emulator."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from tests.firestore_emulator import emulator
from universal_email_mcp.store import (
    ActivityEntry,
    AlreadyExists,
    AuthCode,
    Backend,
    CodeReplay,
    CryptoError,
    Grant,
    Identity,
    InvalidToken,
    KeyRing,
    MailAccount,
    MemoryBackend,
    OAuthClient,
    PendingApproval,
    PortalSession,
    SessionPolicy,
    Store,
    StoreConflict,
    Token,
    TokenReuse,
    User,
    UserGone,
    rotate_keys,
)
from universal_email_mcp.store.backend import Op
from universal_email_mcp.store.records import ALL_RECORDS, DELETE_ORDER, USER_OWNED, Record
from universal_email_mcp.store.store import _mac_input  # pyright: ignore[reportPrivateUsage]

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
KEY1, KEY2 = bytes(range(32)), bytes(range(1, 33))
PASSWORD = "hunter2-Pa$$word"
SMTP_PASSWORD = "smtp-Pa$$word"


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw: float) -> None:
        self.t += timedelta(**kw)


@pytest.fixture(scope="session")
def firestore_host() -> Iterator[str]:
    with emulator(os.environ.get("UEM_TEST_FIRESTORE_HOST")) as host:
        if host is None:
            if os.environ.get("UEM_TEST_REQUIRE_INTEGRATION"):
                pytest.fail("Firestore emulator required but not available")
            pytest.skip("no Firestore emulator (needs podman/docker and the emulators image)")
        yield host


@pytest.fixture(
    params=["memory", pytest.param("firestore", marks=pytest.mark.integration)],
)
async def backend(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Backend]:
    if request.param == "memory":
        yield MemoryBackend()
        return
    from universal_email_mcp.store.firestore import FirestoreBackend

    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", request.getfixturevalue("firestore_host"))
    fb = FirestoreBackend(project="uem-test", prefix=f"t{uuid.uuid4().hex[:10]}_")
    yield fb
    await fb.close()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(backend: Backend, clock: Clock) -> Store:
    return Store(backend, KeyRing({"k1": KEY1}), clock=clock)


async def with_users(store: Store, *uids: str) -> None:
    """The users whose records a test writes: per-user writes need the user (Store.create_owned)."""
    for uid in uids or ("u_1", "u_2"):
        await store.create(make(User, uid))


# --- record factories -------------------------------------------------------------------


def make(cls: type[Record], uid: str = "u_1", rid: str = "r1", now: datetime = T0) -> Record:
    exp = now + timedelta(days=1)
    if cls is User:
        return User(
            id=uid, primary_address="alice@example.org", settings={"lang": "de"}, created_at=now
        )
    if cls is MailAccount:
        return MailAccount(
            id=rid, user_id=uid, name="Work", host="imap.example.org", port=993,
            username="alice@example.org", password=PASSWORD, permissions=("read", "organize"),
            created_at=now,
        )  # fmt: skip
    if cls is Identity:
        return Identity(
            id=rid, user_id=uid, addresses=("alice@example.org",), display_name="Alice",
            signature="-- Alice", smtp_host="smtp.example.org", smtp_username="alice",
            smtp_password=SMTP_PASSWORD, created_at=now,
        )  # fmt: skip
    if cls is PortalSession:
        return PortalSession(id=rid, user_id=uid, created_at=now, last_seen=now, expires_at=exp)
    if cls is OAuthClient:
        return OAuthClient(id=rid, name="Claude", redirect_uris=("https://c.example/cb",), created_at=now, last_used=now, expires_at=exp)  # fmt: skip
    if cls is AuthCode:
        return AuthCode(id=rid, user_id=uid, client_id="c", grant_id="g", redirect_uri="https://c.example/cb", code_challenge="x", expires_at=exp)  # fmt: skip
    if cls is Grant:
        return Grant(id=rid, user_id=uid, client_id="c", account_ids=("a1", "a2"), created_at=now, expires_at=exp)  # fmt: skip
    if cls is Token:
        return Token(id=rid, user_id=uid, grant_id="g", client_id="c", token_type="access", created_at=now, expires_at=exp)  # fmt: skip
    if cls is PendingApproval:
        return PendingApproval(id=rid, user_id=uid, grant_id="g", identity_id="i", content_hash="h", draft_ref="DRAFT-REF-SECRET", created_at=now, expires_at=exp)  # fmt: skip
    if cls is ActivityEntry:
        return ActivityEntry(id=rid, user_id=uid, at=now, event="tool.call", tool="search_messages", account="Work", counts={"results": 3}, expires_at=exp)  # fmt: skip
    raise AssertionError(cls)


def changed(rec: Record) -> Record:
    for name, value in (("name", "Renamed"), ("display_name", "Other"), ("client_id", "c2"),
                        ("status", "approved"), ("tool", "x"), ("settings", {"lang": "en"}),
                        ("last_seen", T0 + timedelta(hours=1)), ("name", "N"),
                        ("consumed", True)):  # fmt: skip
        if hasattr(rec, name) and getattr(rec, name) != value:
            return replace(rec, **{name: value})
    raise AssertionError(rec)


# --- generic contract -------------------------------------------------------------------


@pytest.mark.parametrize("cls", ALL_RECORDS, ids=lambda c: c.__name__)
async def test_crud_roundtrip(store: Store, cls: type[Record]) -> None:
    rec = make(cls, rid="u_1" if cls is User else "r1")
    assert await store.get(cls, rec.id) is None
    stored = await store.create(rec)
    assert stored.version == 1
    assert await store.get(cls, rec.id) == stored

    with pytest.raises(AlreadyExists):
        await store.create(rec)

    new = changed(stored)
    updated = await store.update(new)
    assert updated.version == 2
    assert await store.get(cls, rec.id) == updated

    with pytest.raises(StoreConflict):  # stale version
        await store.update(new)
    with pytest.raises(StoreConflict):
        await store.delete(cls, rec.id, expected_version=1)
    await store.delete(cls, rec.id, expected_version=2)
    assert await store.get(cls, rec.id) is None
    await store.delete(cls, rec.id)  # idempotent
    with pytest.raises(StoreConflict):  # update of a deleted record
        await store.update(updated)
    with pytest.raises(ValueError):
        await store.update(rec)  # never stored


@pytest.mark.parametrize("cls", USER_OWNED, ids=lambda c: c.__name__)
async def test_list_for_user_is_scoped(store: Store, cls: type[Record]) -> None:
    await store.create(make(cls, "u_1", "r1", T0))
    await store.create(make(cls, "u_1", "r2", T0 + timedelta(minutes=1)))
    await store.create(make(cls, "u_2", "r3"))
    assert [r.id for r in await store.list_for_user(cls, "u_1")] == ["r1", "r2"]
    assert [r.id for r in await store.list_for_user(cls, "u_2")] == ["r3"]
    assert await store.list_for_user(cls, "u_3") == []


async def test_list_for_user_rejects_shared_kinds(store: Store) -> None:
    with pytest.raises(ValueError):
        await store.list_for_user(OAuthClient, "u_1")  # type: ignore[type-var]  # pyright: ignore


async def test_types_survive_roundtrip(store: Store) -> None:
    await store.create(make(MailAccount))
    await store.create(make(Identity))
    acc = await store.get(MailAccount, "r1")
    ident = await store.get(Identity, "r1")
    assert acc and acc.permissions == ("read", "organize") and acc.password == PASSWORD
    assert ident and ident.addresses == ("alice@example.org",) and ident.signature == "-- Alice"
    await store.create(make(User))
    user = await store.get(User, "u_1")
    assert user and user.settings == {"lang": "de"} and user.created_at == T0


async def test_naive_datetimes_rejected(store: Store) -> None:
    with pytest.raises(ValueError):
        await store.create(replace(make(PortalSession), expires_at=datetime(2030, 1, 1)))  # type: ignore[arg-type]


# --- encryption at rest -----------------------------------------------------------------


async def test_secrets_are_not_stored_in_clear(store: Store) -> None:
    await store.create(make(User))
    await store.create(make(MailAccount))
    await store.create(make(Identity))
    await store.create(make(PendingApproval))
    await store.create(make(ActivityEntry))
    for cls, secrets_ in (
        (User, ["alice@example.org", "lang"]),
        (MailAccount, [PASSWORD, "alice@example.org"]),
        (Identity, [SMTP_PASSWORD, "-- Alice", "Alice", "alice@example.org"]),
        (PendingApproval, ["DRAFT-REF-SECRET"]),
        (ActivityEntry, ["search_messages", "tool.call", "Work"]),
    ):
        doc = await store.backend.get(cls.KIND, "u_1" if cls is User else "r1")
        assert doc is not None
        text = repr(doc)
        for s in secrets_:
            assert s not in text, (cls.__name__, s)
        assert doc["_sealed"].startswith("e1.k1.")


async def test_blob_swapped_between_records_fails(store: Store) -> None:
    await store.create(make(MailAccount, "u_1", "a1"))
    await store.create(replace(make(MailAccount, "u_1", "a2"), password="other"))
    await store.create(make(MailAccount, "u_2", "a3"))
    docs = {i: await store.backend.get("accounts", i) for i in ("a1", "a2", "a3")}
    from universal_email_mcp.store.backend import Op

    for target, source in (("a2", "a1"), ("a3", "a1")):  # same user / other user
        bad = dict(docs[target] or {})
        bad["_sealed"] = (docs[source] or {})["_sealed"]
        await store.backend.commit([Op("replace", "accounts", target, bad, 1)])
        with pytest.raises(CryptoError):
            await store.get(MailAccount, target)


async def test_repr_hides_secrets(store: Store) -> None:
    text = repr(make(MailAccount)) + repr(make(Identity)) + repr(make(User)) + repr(store)
    for s in (PASSWORD, SMTP_PASSWORD, "alice@example.org", "-- Alice"):
        assert s not in text


async def test_key_rotation(backend: Backend, clock: Clock) -> None:
    old = Store(backend, KeyRing({"k1": KEY1}), clock=clock)
    await old.create(make(MailAccount))
    await old.create(make(User))
    await old.create(make(Token, rid="t1"))  # no sealed part: only its MAC names k1
    new = Store(backend, KeyRing({"k1": KEY1, "k2": KEY2}), clock=clock)
    acc = await new.get(MailAccount, "r1")
    assert acc and acc.password == PASSWORD  # old blobs still open
    only_k2 = Store(backend, KeyRing({"k2": KEY2}), clock=clock)
    with pytest.raises(CryptoError):
        await only_k2.get(MailAccount, "r1")

    # a write re-seals with the active key ...
    await new.update(acc)
    doc = await backend.get("accounts", "r1")
    assert doc and doc["_sealed"].startswith("e1.k2.")
    # ... and rotate_keys migrates the rest
    first = await rotate_keys(new)
    assert first.resealed == {k.KIND: 0 for k in ALL_RECORDS} | {"users": 1, "tokens": 1}
    assert first.unreadable == {} and not first.dry_run
    again_run = await rotate_keys(new)
    assert again_run.resealed == {k.KIND: 0 for k in ALL_RECORDS}
    again = await only_k2.get(MailAccount, "r1")
    assert again and again.password == PASSWORD
    assert (await only_k2.get(User, "u_1")) is not None
    assert (await only_k2.get(Token, "t1")) is not None  # MAC re-issued under k2


# --- expiry -----------------------------------------------------------------------------


async def test_expired_records_read_as_missing(store: Store, clock: Clock) -> None:
    await store.create(make(PortalSession, rid="s1"))
    await store.create(make(Token, rid="t1"))
    assert await store.get(PortalSession, "s1")
    clock.advance(hours=23)
    assert await store.get(PortalSession, "s1")
    clock.advance(hours=1)  # exactly at expires_at
    assert await store.get(PortalSession, "s1") is None
    assert await store.list_for_user(Token, "u_1") == []
    assert await store.purge_expired() == 2
    assert await store.backend.get("tokens", "t1") is None


async def test_records_without_expiry_stay(store: Store, clock: Clock) -> None:
    await store.create(make(MailAccount))
    clock.advance(days=3650)
    assert await store.get(MailAccount, "r1")
    assert await store.purge_expired() == 0


# --- portal sessions, oauth clients, codes ----------------------------------------------


async def test_portal_session(store: Store, clock: Clock) -> None:
    await with_users(store)
    raw, rec = await store.create_portal_session("u_1", timedelta(hours=1))
    assert rec.id == store.secret_id(PortalSession, raw) and raw not in repr(
        await store.backend.get("portal_sessions", rec.id)
    )
    got = await store.get_portal_session(raw)
    assert got and got.user_id == "u_1"
    assert await store.get_portal_session(raw + "x") is None
    clock.advance(hours=1)
    assert await store.get_portal_session(raw) is None
    raw2, _ = await store.create_portal_session("u_1")
    await store.delete_portal_session(raw2)
    assert await store.get_portal_session(raw2) is None


async def test_oauth_client_unused_ttl_and_touch(store: Store, clock: Clock) -> None:
    c = await store.register_client("https://c.example/meta.json", name="Claude")
    clock.advance(days=29)
    c = await store.touch_client(c)
    assert c.version == 2
    assert await store.touch_client(c) == c  # throttled
    clock.advance(days=29)
    assert await store.get(OAuthClient, c.id)  # extended by the touch
    clock.advance(days=2)
    assert await store.get(OAuthClient, c.id) is None


async def test_auth_code_single_use_and_expiry(store: Store, clock: Clock) -> None:
    await with_users(store)
    args: dict[str, Any] = dict(user_id="u_1", client_id="c", grant_id="g", redirect_uri="https://c/cb", code_challenge="ch")  # fmt: skip
    raw = await store.issue_auth_code(**args)
    assert (await store.backend.get("auth_codes", store.secret_id(AuthCode, raw))) is not None
    assert raw not in repr(await store.backend.get("auth_codes", store.secret_id(AuthCode, raw)))
    code = await store.redeem_auth_code(raw)
    assert code and code.code_challenge == "ch"
    with pytest.raises(CodeReplay):
        await store.redeem_auth_code(raw)

    raw = await store.issue_auth_code(**args)
    clock.advance(minutes=2)
    assert await store.redeem_auth_code(raw) is None

    raw = await store.issue_auth_code(**args)
    results = await asyncio.gather(
        *(store.redeem_auth_code(raw) for _ in range(4)), return_exceptions=True
    )
    assert sum(isinstance(r, AuthCode) for r in results) <= 1
    assert all(r is None or isinstance(r, AuthCode | CodeReplay) for r in results), results


async def test_auth_code_replay_revokes_the_tokens_issued_from_it(
    store: Store, clock: Clock
) -> None:
    await with_users(store)
    grant = await store.create_grant(user_id="u_1", client_id="c")
    raw = await store.issue_auth_code(
        user_id="u_1", client_id="c", grant_id=grant.id, redirect_uri="https://c/cb",
        code_challenge="ch",
    )  # fmt: skip
    assert await store.redeem_auth_code(raw)
    issued = await store.issue_tokens(grant)
    assert await store.authenticate_access_token(issued.access_token)
    with pytest.raises(CodeReplay):
        await store.redeem_auth_code(raw)
    assert await store.authenticate_access_token(issued.access_token) is None
    assert await store.get(Grant, grant.id) is None
    clock.advance(minutes=11)  # the consumed marker is gone: plain unknown code
    assert await store.redeem_auth_code(raw) is None


async def test_portal_session_idle_and_absolute_timeout(store: Store, clock: Clock) -> None:
    await with_users(store)
    idle = timedelta(minutes=30)
    raw, _ = await store.create_portal_session("u_1", ttl=timedelta(hours=2))
    clock.advance(minutes=20)
    first = await store.authenticate_portal_session(raw, idle_timeout=idle)
    assert first and first.last_seen == clock.t  # touched
    clock.advance(minutes=20)  # 20 min idle only: the touch restarted the clock
    assert await store.authenticate_portal_session(raw, idle_timeout=idle)
    clock.advance(minutes=31)
    assert await store.authenticate_portal_session(raw, idle_timeout=idle) is None
    raw2, _ = await store.create_portal_session("u_1", ttl=timedelta(hours=1))
    got = None
    for _ in range(3):
        clock.advance(minutes=25)
        got = await store.authenticate_portal_session(raw2, idle_timeout=idle)
    assert got is None  # absolute limit (1 h) reached although never idle


async def test_portal_session_reauth(store: Store, clock: Clock) -> None:
    await with_users(store)
    window = timedelta(minutes=5)
    raw, rec = await store.create_portal_session("u_1")
    assert not store.reauth_fresh(rec, window)  # nobody typed a password yet
    rec = await store.mark_reauth(rec)
    assert rec.reauth_at == clock.t and store.reauth_fresh(rec, window)
    clock.advance(minutes=5)
    assert store.reauth_fresh(rec, window)
    clock.advance(seconds=1)
    assert not store.reauth_fresh(rec, window)
    # a stale copy of the record (the sliding touch won the race) still ends up marked
    got = await store.authenticate_portal_session(raw, idle_timeout=timedelta(hours=1))
    assert got is not None and got.version > rec.version
    fresh = await store.mark_reauth(rec)
    assert store.reauth_fresh(fresh, window)
    again = await store.get_portal_session(raw)
    assert again and again.reauth_at == clock.t
    raw2, rec2 = await store.create_portal_session("u_1", fresh_login=True)
    assert store.reauth_fresh(rec2, window)
    del raw2


# --- grants and tokens ------------------------------------------------------------------


async def connect(store: Store) -> tuple[Grant, Any]:
    grant = await store.create_grant(user_id="u_1", client_id="c", account_ids=["a1"])
    return grant, await store.issue_tokens(grant, resource="https://mcp.example/")


async def test_token_issue_and_authenticate(store: Store, clock: Clock) -> None:
    await with_users(store)
    grant, t = await connect(store)
    assert t.access_token.startswith("uem_at_") and t.refresh_token.startswith("uem_rt_")
    # only digests are stored
    for raw in (t.access_token, t.refresh_token):
        assert await store.backend.get("tokens", raw) is None
        doc = await store.backend.get("tokens", store.secret_id(Token, raw))
        assert doc and raw not in repr(doc)
    auth = await store.authenticate_access_token(t.access_token)
    assert auth
    tok, g = auth
    assert tok.resource == "https://mcp.example/" and g.account_ids == ("a1",)
    assert await store.authenticate_access_token(t.refresh_token) is None  # wrong type
    assert await store.authenticate_access_token("nope") is None
    clock.advance(hours=1)
    assert await store.authenticate_access_token(t.access_token) is None


async def test_pending_grant_expires_without_tokens(store: Store, clock: Clock) -> None:
    await with_users(store)
    grant = await store.create_grant(user_id="u_1", client_id="c")
    assert grant.last_used is None
    clock.advance(minutes=10)
    assert await store.get(Grant, grant.id) is None


async def test_refresh_rotation_slides_but_stops_at_absolute_max(
    store: Store, clock: Clock
) -> None:
    await with_users(store)
    grant, t = await connect(store)
    refresh = t.refresh_token
    for _ in range(3):  # 3 x 29 days of sliding
        clock.advance(days=29)
        t = await store.rotate_refresh_token(refresh, client_id="c")
        assert t.refresh_expires_at is not None
        assert t.refresh_expires_at <= grant.absolute_expires_at  # type: ignore[operator]  # pyright: ignore
        refresh = t.refresh_token
    clock.advance(days=4)  # day 91 > absolute 90
    with pytest.raises(InvalidToken):
        await store.rotate_refresh_token(refresh, client_id="c")


async def test_refresh_expires_when_idle(store: Store, clock: Clock) -> None:
    await with_users(store)
    _, t = await connect(store)
    clock.advance(days=30)
    with pytest.raises(InvalidToken):
        await store.rotate_refresh_token(t.refresh_token, client_id="c")


async def test_refresh_checks_client_and_type(store: Store) -> None:
    await with_users(store)
    _, t = await connect(store)
    with pytest.raises(InvalidToken):
        await store.rotate_refresh_token(t.refresh_token, client_id="other")
    with pytest.raises(InvalidToken):
        await store.rotate_refresh_token(t.access_token, client_id="c")
    with pytest.raises(InvalidToken):
        await store.rotate_refresh_token("garbage", client_id="c")


async def test_refresh_rotation_and_replay_revokes_grant(store: Store) -> None:
    await with_users(store)
    grant, t1 = await connect(store)
    t2 = await store.rotate_refresh_token(t1.refresh_token, client_id="c")
    assert t2.refresh_token != t1.refresh_token
    assert await store.authenticate_access_token(t2.access_token)
    with pytest.raises(TokenReuse):  # replay of the old refresh token
        await store.rotate_refresh_token(t1.refresh_token, client_id="c")
    assert await store.get(Grant, grant.id) is None
    assert await store.authenticate_access_token(t2.access_token) is None
    with pytest.raises(InvalidToken):
        await store.rotate_refresh_token(t2.refresh_token, client_id="c")
    assert await store.list_for_user(Token, "u_1") == []


async def test_concurrent_refresh_yields_one_winner(store: Store) -> None:
    await with_users(store)
    _, t = await connect(store)
    results = await asyncio.gather(
        *(store.rotate_refresh_token(t.refresh_token, client_id="c") for _ in range(3)),
        return_exceptions=True,
    )
    assert sum(not isinstance(r, BaseException) for r in results) == 1
    assert all(isinstance(r, InvalidToken) for r in results if isinstance(r, BaseException))


async def test_revoke_grant_and_revoke_token(store: Store) -> None:
    await with_users(store)
    g1, t1 = await connect(store)
    g2, t2 = await connect(store)
    await store.revoke_token(t1.access_token)  # access token only
    assert await store.authenticate_access_token(t1.access_token) is None
    assert await store.get(Grant, g1.id)
    await store.revoke_token(t1.refresh_token)  # refresh -> whole grant
    assert await store.get(Grant, g1.id) is None
    await store.revoke_token("unknown")  # no error
    assert await store.authenticate_access_token(t2.access_token)
    await store.revoke_grant(g2.id)
    assert await store.authenticate_access_token(t2.access_token) is None
    assert await store.list_for_user(Token, "u_1") == []


async def test_unlimited_policy(backend: Backend, clock: Clock) -> None:
    policy = SessionPolicy(refresh_ttl=timedelta(0), absolute_max=timedelta(0))
    store = Store(backend, KeyRing({"k1": KEY1}), clock=clock, policy=policy)
    await with_users(store)
    grant, t = await connect(store)
    assert grant.absolute_expires_at is None and t.refresh_expires_at is None
    clock.advance(days=3650)
    t2 = await store.rotate_refresh_token(t.refresh_token, client_id="c")
    assert t2.refresh_expires_at is None


async def test_access_use_touches_grant_rarely(store: Store, clock: Clock) -> None:
    await with_users(store)
    _, t = await connect(store)
    auth = await store.authenticate_access_token(t.access_token)
    assert auth
    v = auth[1].version  # issuing set last_used; a use right after changes nothing
    auth = await store.authenticate_access_token(t.access_token)
    assert auth and auth[1].version == v
    clock.advance(minutes=6)
    auth = await store.authenticate_access_token(t.access_token)
    assert auth and auth[1].version == v + 1 and auth[1].last_used == clock()


# --- approvals, activity, users ---------------------------------------------------------


async def test_approval_flow(store: Store, clock: Clock) -> None:
    await with_users(store)
    ap = await store.create_approval(user_id="u_1", grant_id="g", identity_id="i", content_hash="h", draft_ref="ref")  # fmt: skip
    assert ap.status == "pending"
    done = await store.decide_approval(ap.id, "u_1", True)
    assert done and done.status == "approved"
    assert await store.decide_approval(ap.id, "u_1", False) is None  # decided once
    ap2 = await store.create_approval(user_id="u_1", grant_id="g", identity_id="i", content_hash="h", draft_ref="ref")  # fmt: skip
    clock.advance(minutes=10)
    assert await store.decide_approval(ap2.id, "u_1", True) is None


async def test_activity_feed(store: Store, clock: Clock) -> None:
    await with_users(store)
    for i in range(5):
        await store.record_activity("u_1", "tool.call", tool="search_messages", account="Work", counts={"results": i})  # fmt: skip
        clock.advance(minutes=1)
    await store.record_activity("u_2", "login")
    feed = await store.list_activity("u_1", limit=3)
    assert [e.counts["results"] for e in feed] == [4, 3, 2]
    assert feed[0].tool == "search_messages"
    clock.advance(days=30)
    assert await store.list_activity("u_1") == []


async def test_coalesced_activity_merges_per_hour(store: Store, clock: Clock) -> None:
    await with_users(store)
    kw: dict[str, Any] = dict(client="g_1", tool="find_messages", outcome="ok", coalesce=True)
    await store.record_activity("u_1", "tool.call", counts={"messages": 2}, **kw)
    clock.advance(minutes=5)
    await store.record_activity("u_1", "tool.call", counts={"messages": 3}, **kw)
    await store.record_activity("u_1", "tool.call", **{**kw, "outcome": "error"})  # other key
    await store.record_activity("u_2", "tool.call", **kw)  # other user
    feed = await store.list_activity("u_1")
    assert len(feed) == 2
    merged = next(e for e in feed if e.outcome == "ok")
    assert merged.counts == {"messages": 5, "calls": 2}
    clock.advance(hours=1)
    await store.record_activity("u_1", "tool.call", **kw)
    assert len(await store.list_activity("u_1")) == 3  # a new hour, a new entry


async def test_coalesced_activity_survives_parallel_calls(store: Store) -> None:
    await with_users(store)
    got = await asyncio.gather(
        *(store.record_activity("u_1", "tool.call", tool="t", coalesce=True) for _ in range(4)),
        return_exceptions=True,
    )
    assert all(isinstance(g, ActivityEntry | StoreConflict) for g in got), got
    won = sum(isinstance(g, ActivityEntry) for g in got)
    assert won >= 1
    (entry,) = await store.list_activity("u_1")
    assert entry.counts["calls"] == won  # a lost race loses its count, never double counts


@pytest.mark.parametrize(
    "kwargs",
    [
        {"account": "alice@example.org"},
        {"tool": "x" * 65},
        {"outcome": "Re: Your invoice from bob@corp.example"},
        {"counts": {"n": "3"}},
        {"counts": {"n": True}},
    ],
)
async def test_activity_rejects_mail_data(store: Store, kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        await store.record_activity("u_1", "tool.call", **kwargs)


async def test_get_or_create_user_race(store: Store) -> None:
    users = await asyncio.gather(
        *(store.get_or_create_user("u_9", "bob@example.org") for _ in range(4))
    )
    assert {u.id for u in users} == {"u_9"}
    assert (await store.get(User, "u_9")) is not None


# --- GDPR -------------------------------------------------------------------------------


async def populate(store: Store, uid: str) -> None:
    await store.create(make(User, uid))
    await store.create(make(MailAccount, uid, "acc-" + uid))
    await store.create(make(Identity, uid, "id-" + uid))
    await store.create_portal_session(uid)
    grant = await store.create_grant(user_id=uid, client_id="c")
    await store.issue_tokens(grant)
    await store.issue_auth_code(user_id=uid, client_id="c", grant_id=grant.id, redirect_uri="x", code_challenge="y")  # fmt: skip
    await store.create_approval(user_id=uid, grant_id=grant.id, identity_id="i", content_hash="h", draft_ref="r")  # fmt: skip
    await store.record_activity(uid, "login")
    assert await store.claim_send(uid, "hash-" + uid, timedelta(minutes=10))
    await store.register_client(f"https://c.example/{uid}.json")


async def test_export_user_has_no_secrets(store: Store) -> None:
    await populate(store, "u_1")
    raw, _ = await store.create_portal_session("u_1")
    data = await store.export_user("u_1")
    text = repr(data)
    assert PASSWORD not in text and SMTP_PASSWORD not in text and raw not in text
    assert data["user"]["primary_address"] == "alice@example.org"
    assert data["accounts"][0]["name"] == "Work" and "password" not in data["accounts"][0]
    assert data["identities"][0]["addresses"] == ["alice@example.org"]
    assert len(data["activity"]) == 1 and len(data["grants"]) == 1
    assert all("id" not in t for t in data["tokens"])
    assert (await store.export_user("nobody"))["user"] is None


async def test_delete_user_leaves_nothing(store: Store, clock: Clock) -> None:
    await populate(store, "u_1")
    await populate(store, "u_2")
    raw, _ = await store.create_portal_session("u_1")
    clock.advance(days=365)  # expired leftovers must go too
    counts = await store.delete_user("u_1")
    assert counts["users"] == 1 and counts["accounts"] == 1 and counts["tokens"] >= 2
    for cls in USER_OWNED:
        assert await store.backend.find(cls.KIND, "user_id", "u_1") == []
    assert await store.backend.get("users", "u_1") is None
    assert await store.get_portal_session(raw) is None
    # the other user is untouched
    assert (await store.get(User, "u_2")) and await store.backend.find("accounts", "user_id", "u_2")
    assert (await store.delete_user("u_1"))["users"] == 0  # idempotent


def _all_record_types() -> set[str]:
    """Names of every Record subclass (``dataclass(slots=True)`` leaves a pre-slots twin of
    each class behind, hence names)."""
    found: set[type[Record]] = set()
    todo = list(Record.__subclasses__())
    while todo:
        cls = todo.pop()
        found.add(cls)
        todo.extend(cls.__subclasses__())
    return {c.__qualname__ for c in found}


def test_every_record_type_is_registered_and_its_ownership_decided() -> None:
    """Adding a record type without deciding who owns it (and how it is deleted) fails here."""
    import dataclasses

    assert _all_record_types() == {c.__qualname__ for c in ALL_RECORDS}
    shared = {User, OAuthClient}  # the user record itself (deleted last) and shared clients
    for cls in ALL_RECORDS:
        has_user_id = "user_id" in {f.name for f in dataclasses.fields(cls)}
        assert (cls in USER_OWNED) == has_user_id, cls
        assert (cls in shared) != (cls in USER_OWNED), cls
    assert len(DELETE_ORDER) == len(set(DELETE_ORDER))
    assert set(DELETE_ORDER) == set(USER_OWNED)
    assert DELETE_ORDER[0] is Grant  # revoke first: tokens die with their grant
    kinds = [cls.KIND for cls in ALL_RECORDS]
    assert len(kinds) == len(set(kinds))


async def test_delete_user_leaves_no_document_with_the_user_id(store: Store) -> None:
    await populate(store, "u_1")
    await populate(store, "u_2")
    await store.delete_user("u_1")
    if isinstance(store.backend, MemoryBackend):  # every collection, not only the known ones
        for col in list(store.backend._data):  # pyright: ignore[reportPrivateUsage]
            for doc in store.backend.raw(col).values():
                assert doc.get("user_id") != "u_1", col
    for cls in USER_OWNED:  # the other user keeps one of everything that has a document
        if cls is PortalSession or cls is Token or cls is PendingApproval:
            assert await store.backend.find(cls.KIND, "user_id", "u_2"), cls


async def test_delete_user_interrupted_midway_is_safe_and_repeatable(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    await populate(store, "u_1")
    access = await store.issue_tokens(await store.create_grant(user_id="u_1", client_id="c"))
    original = store.backend.commit
    calls = 0

    async def flaky(ops: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:  # after grants and tokens
            raise RuntimeError("crash")
        await original(ops)

    monkeypatch.setattr(store.backend, "commit", flaky)
    with pytest.raises(RuntimeError):
        await store.delete_user("u_1")
    monkeypatch.undo()
    # tokens are dead already, the user and the accounts are still there
    assert await store.authenticate_access_token(access.access_token) is None
    assert await store.backend.find("grants", "user_id", "u_1") == []
    assert await store.get(User, "u_1") is not None and await store.list_for_user(
        MailAccount, "u_1"
    )
    counts = await store.delete_user("u_1")  # the retry finishes the job
    assert counts["users"] == 1
    for cls in USER_OWNED:
        assert await store.backend.find(cls.KIND, "user_id", "u_1") == []
    assert await store.get(User, "u_1") is None


async def test_approval_ownership_and_single_use(store: Store) -> None:
    await with_users(store)
    ap = await store.create_approval(user_id="u_1", grant_id="g", identity_id="i", content_hash="h", draft_ref="r")  # fmt: skip
    assert await store.decide_approval(ap.id, "u_2", True) is None  # foreign user
    assert await store.consume_approval(ap.id, "u_1", "h") is None  # not approved yet
    assert await store.decide_approval(ap.id, "u_1", True)
    assert await store.consume_approval(ap.id, "u_1", "other") is None  # other content
    assert await store.consume_approval(ap.id, "u_2", "h") is None
    assert await store.consume_approval(ap.id, "u_1", "h")
    assert await store.consume_approval(ap.id, "u_1", "h") is None


async def test_refresh_survives_concurrent_grant_touch(store: Store, clock: Clock) -> None:
    await with_users(store)
    grant, t = await connect(store)
    clock.advance(minutes=6)
    # a request touching last_used between the read and the commit of a rotation
    auth, rotated = await asyncio.gather(
        store.authenticate_access_token(t.access_token),
        store.rotate_refresh_token(t.refresh_token, client_id="c"),
    )
    assert rotated.refresh_token
    assert await store.get(Grant, grant.id) is not None


async def test_issue_tokens_only_once(store: Store) -> None:
    await with_users(store)
    grant, _ = await connect(store)
    with pytest.raises(InvalidToken):
        await store.issue_tokens(grant)


async def test_missing_sealed_blob_is_a_crypto_error(store: Store) -> None:
    from universal_email_mcp.store.backend import Op

    await store.create(make(MailAccount))
    doc = dict(await store.backend.get("accounts", "r1") or {})
    del doc["_sealed"]
    await store.backend.commit([Op("replace", "accounts", "r1", doc, 1)])
    with pytest.raises(CryptoError):
        await store.get(MailAccount, "r1")


HOSTILE_IDS = [".", "..", "__name__", "__x__", "a/b/c", "x" * 5000, "https://c.example/" + "p" * 3000,
               "ünï/cödé\u202e%2F", " ", "\x00"]  # fmt: skip


@pytest.mark.parametrize("client_id", HOSTILE_IDS)
async def test_hostile_record_ids(store: Store, client_id: str) -> None:
    c = await store.register_client(client_id, name="x")
    assert (await store.get(OAuthClient, client_id)) == c
    assert [i async for i, _ in store.backend.scan("oauth_clients")] == [client_id]
    await store.update(c)
    await store.delete(OAuthClient, client_id)
    assert await store.get(OAuthClient, client_id) is None


async def test_unknown_fields_survive_update(store: Store) -> None:
    from universal_email_mcp.store.backend import Op
    from universal_email_mcp.store.crypto import Aad

    await store.create(make(MailAccount))
    doc = dict(await store.backend.get("accounts", "r1") or {})
    aad = Aad("u_1", "accounts", "r1", "_sealed")
    sealed = store.keys.open_json(doc["_sealed"], aad)
    sealed["future_secret"] = "S3CRET-FUTURE"
    doc["_sealed"] = store.keys.seal_json(sealed, aad)
    doc["future_flag"] = {"a": [1, 2]}
    doc["_mac"] = store.keys.mac(
        _mac_input("accounts", "r1", "u_1", doc, getattr(store.backend, "namespace", ""))
    )  # as a newer instance
    await store.backend.commit([Op("replace", "accounts", "r1", doc, 1)])

    acc = await store.get(MailAccount, "r1")
    assert acc and acc.extra == {"future_flag": {"a": [1, 2]}}
    assert acc.extra_sealed == {"future_secret": "S3CRET-FUTURE"}
    await store.update(replace(acc, name="Renamed"))
    raw = await store.backend.get("accounts", "r1") or {}
    assert raw["future_flag"] == {"a": [1, 2]}
    assert "S3CRET-FUTURE" not in repr(raw)  # still sealed
    again = await store.get(MailAccount, "r1")
    assert again and again.name == "Renamed" and again.extra_sealed == acc.extra_sealed


async def test_export_omits_draft_refs(store: Store) -> None:
    await with_users(store)
    await store.create_approval(user_id="u_1", grant_id="g", identity_id="i", content_hash="h", draft_ref="DRAFT-REF-X")  # fmt: skip
    assert "DRAFT-REF-X" not in repr(await store.export_user("u_1"))


async def test_account_failure_flag_follows_the_login(store: Store) -> None:
    from universal_email_mcp.store.records import login_mark

    acc = cast(MailAccount, make(MailAccount))
    assert not acc.needs_reauth
    flagged = replace(
        acc,
        auth_failed_at=datetime.now(UTC),
        auth_failed_mark=login_mark(acc.username, acc.password),
    )
    assert flagged.needs_reauth
    assert not replace(flagged, password="a new password").needs_reauth  # lifted by a new login
    stored = await store.create(flagged)
    doc = await store.backend.get(MailAccount.KIND, stored.id)
    assert doc is not None and login_mark(acc.username, acc.password) not in repr(doc)  # sealed
    back = await store.get(MailAccount, stored.id)
    assert back is not None and back.needs_reauth
    # records written before the flag existed decode with the defaults
    old = await store.create(cast(MailAccount, make(MailAccount, "u_1", "old1")))
    again = await store.get(MailAccount, old.id)
    assert again is not None and again.auth_failed_at is None and not again.needs_reauth


# ---------------------------------------------------------------- WP 3f: markers, expired reads, derived keys


async def test_claim_send_is_once_per_user_and_content(store: Store, clock: Clock) -> None:
    await with_users(store)
    from datetime import timedelta

    ttl = timedelta(minutes=10)
    assert await store.claim_send("u_1", "h" * 64, ttl) is True
    assert await store.claim_send("u_1", "h" * 64, ttl) is False  # replay
    assert await store.claim_send("u_2", "h" * 64, ttl) is True  # other user, same text
    assert await store.claim_send("u_1", "g" * 64, ttl) is True  # other content
    await store.release_send("u_1", "h" * 64)  # the send failed: try again
    assert await store.claim_send("u_1", "h" * 64, ttl) is True
    assert await store.claim_send("u_1", "h" * 64, ttl) is False
    clock.advance(minutes=11)  # markers expire on their own
    assert await store.claim_send("u_1", "h" * 64, ttl) is True


async def test_expired_records_can_be_read_explicitly(store: Store, clock: Clock) -> None:
    await with_users(store)
    ap = await store.create_approval(user_id="u_1", grant_id="g", identity_id="i", content_hash="h", draft_ref="r")  # fmt: skip
    clock.advance(minutes=11)
    assert await store.get(PendingApproval, ap.id) is None
    assert await store.list_for_user(PendingApproval, "u_1") == []
    seen = await store.get_any(PendingApproval, ap.id)
    assert seen is not None and seen.user_id == "u_1"
    assert [a.id for a in await store.list_for_user(PendingApproval, "u_1", include_expired=True)] == [ap.id]  # fmt: skip


def test_derived_secrets_are_stable_distinct_and_follow_the_ring() -> None:
    ring = KeyRing({"k1": b"a" * 32, "k2": b"b" * 32})
    first = ring.derive("purpose-a")
    assert first == KeyRing({"k1": b"a" * 32, "k2": b"b" * 32}).derive(
        "purpose-a"
    )  # every instance
    assert len(first) == 2 and all(len(x) == 32 for x in first)
    assert first[0] != first[1] and first != ring.derive("purpose-b")
    assert b"a" * 32 not in first and b"b" * 32 not in first
    # the active key comes first; an older key stays usable for unsealing
    old = KeyRing({"k1": b"a" * 32}).derive("purpose-a")
    assert ring.derive("purpose-a")[0] != old[0] and old[0] in ring.derive("purpose-a")


async def test_claim_send_expired_marker_is_replaced_once(store: Store, clock: Clock) -> None:
    await with_users(store)
    import asyncio
    from datetime import timedelta

    ttl = timedelta(minutes=10)
    assert await store.claim_send("u_1", "h" * 64, ttl)
    clock.advance(minutes=11)  # expired, not purged
    got = await asyncio.gather(*(store.claim_send("u_1", "h" * 64, ttl) for _ in range(4)))
    assert sum(got) == 1


# --- one damaged record must not stop rotation or export -----------------------------------


async def damage(backend: Backend, collection: str, rec_id: str) -> None:
    """Break the sealed blob of a stored record (as a bad write or tampering would)."""
    doc = await backend.get(collection, rec_id)
    assert doc is not None
    version = doc["_v"]
    if "_sealed" in doc:
        broken = {**doc, "_sealed": doc["_sealed"][:-6] + "AAAAAA"}
    else:  # nothing sealed (tokens): lose a required field instead
        broken = {k: v for k, v in doc.items() if k != "client_id"}
    await backend.commit([Op("replace", collection, rec_id, broken, version)])


async def sealed_by(backend: Backend, rec_id: str) -> str:
    doc = await backend.get("accounts", rec_id)
    assert doc is not None
    return doc["_sealed"].split(".")[1]


async def test_rotate_keys_skips_and_counts_a_damaged_record(
    backend: Backend, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    old = Store(backend, KeyRing({"k1": KEY1}), clock=clock)
    for rid in ("r1", "r2", "r3"):
        await old.create(make(MailAccount, rid=rid))
    await damage(backend, "accounts", "r2")
    new = Store(backend, KeyRing({"k1": KEY1, "k2": KEY2}), clock=clock)

    caplog.set_level(logging.WARNING)
    dry = await rotate_keys(new, dry_run=True)
    assert dry.dry_run and dry.resealed["accounts"] == 2 and dry.unreadable == {"accounts": 1}
    assert await sealed_by(backend, "r1") == "k1"  # nothing written

    report = await rotate_keys(new)
    assert report.resealed["accounts"] == 2 and report.unreadable == {"accounts": 1}
    assert report.total_unreadable == 1
    for rid, key in (("r1", "k2"), ("r3", "k2"), ("r2", "k1")):
        assert await sealed_by(backend, rid) == key
    text = caplog.text
    assert "1 unreadable accounts" in text
    assert PASSWORD not in text and "r2" not in text and "alice" not in text  # no content, no id
    # a second run: the good ones are done, the damaged one is still reported
    again = await rotate_keys(new)
    assert again.resealed["accounts"] == 0 and again.unreadable == {"accounts": 1}


async def test_rotate_keys_counts_a_record_with_a_key_that_is_gone(
    backend: Backend, clock: Clock
) -> None:
    old = Store(backend, KeyRing({"k1": KEY1}), clock=clock)
    await old.create(make(MailAccount))
    only_k2 = Store(backend, KeyRing({"k2": KEY2}), clock=clock)
    report = await rotate_keys(only_k2)
    assert report.unreadable == {"accounts": 1}


async def test_export_marks_a_damaged_record_and_goes_on(
    backend: Backend, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    store = Store(backend, KeyRing({"k1": KEY1}), clock=clock)
    await store.create(make(User))
    await store.create(make(MailAccount, rid="a1"))
    await store.create(make(MailAccount, rid="a2"))
    await store.create(make(Token, rid="t" * 64))
    await damage(backend, "accounts", "a2")
    await damage(backend, "tokens", "t" * 64)
    caplog.set_level(logging.WARNING)
    data = await store.export_user("u_1")
    assert data["user"]["primary_address"] == "alice@example.org"
    names = [a for a in data["accounts"] if "name" in a]
    assert len(names) == 1 and names[0]["name"] == "Work"
    assert {"id": "a2", "unreadable": True} in data["accounts"]
    assert data["tokens"] == [{"unreadable": True}]  # a token's id is a secret: not exported
    assert PASSWORD not in repr(data) and PASSWORD not in caplog.text
    assert "unreadable accounts record" in caplog.text

    await damage(backend, "users", "u_1")
    assert (await store.export_user("u_1"))["user"] == {"unreadable": True}


# --- a write racing delete_user must not leave an orphan -------------------------------------


async def test_writes_for_a_deleted_user_are_dropped_or_refused(store: Store) -> None:
    await with_users(store, "u_1")
    grant = await store.create_grant(user_id="u_1", client_id="c")
    await store.delete_user("u_1")

    entry = await store.record_activity("u_1", "tool.call", tool="find_messages")
    assert entry.user_id == "u_1"  # handed back, but not stored
    again = await store.record_activity("u_1", "tool.call", tool="find_messages", coalesce=True)
    assert again.counts == {"calls": 1}
    assert not await store.claim_send("u_1", "hash", timedelta(minutes=10))
    for call in (
        store.create_approval(
            user_id="u_1", grant_id=grant.id, identity_id="i", content_hash="h", draft_ref="r"
        ),
        store.create_grant(user_id="u_1", client_id="c"),
        store.issue_auth_code(
            user_id="u_1", client_id="c", grant_id="g", redirect_uri="x", code_challenge="y"
        ),
        store.create_portal_session("u_1"),
    ):
        with pytest.raises(UserGone):
            await call
    for cls in USER_OWNED:
        assert await store.list_for_user(cls, "u_1", include_expired=True) == [], cls.__name__


class DeleteBeforeCreate(MemoryBackend):
    """Runs a hook just before the first create of a collection lands - after the writer's
    own "does the user exist" check - as a concurrent ``delete_user`` would."""

    def __init__(self) -> None:
        super().__init__()
        self.hook: Callable[[], Awaitable[Any]] | None = None
        self.collection = ""

    async def commit(self, ops: Sequence[Op]) -> None:
        if self.hook and any(o.kind == "create" and o.collection == self.collection for o in ops):
            hook, self.hook = self.hook, None
            await hook()
        await super().commit(ops)


@pytest.mark.parametrize(
    ("collection", "write"),
    [
        ("activity", lambda s: s.record_activity("u_1", "tool.call", tool="find_messages")),
        ("activity", lambda s: s.record_activity("u_1", "tool.call", tool="x", coalesce=True)),
        ("approvals", lambda s: s.claim_send("u_1", "hash", timedelta(minutes=10))),
        (
            "approvals",
            lambda s: s.create_approval(
                user_id="u_1", grant_id="g", identity_id="i", content_hash="h", draft_ref="r"
            ),
        ),
        ("grants", lambda s: s.create_grant(user_id="u_1", client_id="c")),
        ("portal_sessions", lambda s: s.create_portal_session("u_1")),
    ],
    ids=["activity", "activity-coalesced", "claim_send", "approval", "grant", "portal_session"],
)
async def test_a_write_racing_the_delete_leaves_no_orphan(
    clock: Clock, collection: str, write: Callable[[Store], Awaitable[Any]]
) -> None:
    backend = DeleteBeforeCreate()
    store = Store(backend, KeyRing({"k1": KEY1}), clock=clock)
    await with_users(store, "u_1")
    backend.collection = collection
    backend.hook = lambda: store.delete_user("u_1")  # the whole delete, sweep included
    try:
        await write(store)
    except UserGone:
        pass
    assert [i async for i, _ in backend.scan(collection)] == []
    assert await backend.get("users", "u_1") is None


# --- a database writer without keys cannot forge or change records (security review M1) -----


async def raw_replace(store: Store, cls: type[Record], rec_id: str, **changes: Any) -> None:
    """What somebody with write access to the database (but no key) can do: change plain
    fields of a stored document, keeping its version, MAC and sealed blob."""
    doc = dict(await store.backend.get(cls.KIND, rec_id) or {})
    version = doc["_v"]
    doc.update(changes)
    await store.backend.commit([Op("replace", cls.KIND, rec_id, doc, version)])


@pytest.mark.parametrize(
    ("cls", "changes"),
    [
        (Token, {"scope": "mail.read mail.send"}),
        (Token, {"expires_at": T0 + timedelta(days=3650)}),
        (Grant, {"scope": "mail.read mail.delete mail.send"}),
        (Grant, {"account_scopes": {"a1": "read organize delete drafts"}}),
        (Grant, {"identity_ids": ["i_attacker"]}),
        (MailAccount, {"permissions": ["read", "organize", "delete", "drafts"]}),
        (Identity, {"send": True}),
        (OAuthClient, {"redirect_uris": ["https://evil.example/cb"]}),
        (PortalSession, {"user_id": "u_victim"}),
        (PortalSession, {"expires_at": T0 + timedelta(days=3650)}),
        (PortalSession, {"reauth_at": T0}),
        (AuthCode, {"redirect_uri": "https://evil.example/cb"}),
        (PendingApproval, {"status": "approved"}),
    ],
    ids=lambda v: v.__name__ if isinstance(v, type) else str(next(iter(v))),
)
async def test_changed_plain_field_is_rejected(
    store: Store, cls: type[Record], changes: dict[str, Any]
) -> None:
    await store.create(make(User))
    stored = await store.create(make(cls))
    assert await store.get(cls, stored.id)
    await raw_replace(store, cls, stored.id, **changes)
    with pytest.raises(CryptoError):
        await store.get(cls, stored.id)


async def test_unauthenticated_and_foreign_records_are_rejected(store: Store) -> None:
    await store.create(make(User))
    mine = await store.create(make(Grant))
    doc = dict(await store.backend.get("grants", mine.id) or {})
    # no MAC at all
    nomac = {k: v for k, v in doc.items() if k != "_mac"}
    await store.backend.commit([Op("create", "grants", "g_nomac", nomac)])
    # a MAC under a key the writer made up
    other = KeyRing({"k1": b"x" * 32})
    forged = {**doc, "scope": "mail.read mail.send"}
    forged["_mac"] = other.mac(
        _mac_input("grants", "g_forged", "u_1", forged, getattr(store.backend, "namespace", ""))
    )
    await store.backend.commit([Op("create", "grants", "g_forged", forged)])
    # a genuine record copied to another id (MAC binds the id)
    await store.backend.commit([Op("create", "grants", "g_copy", dict(doc))])
    for rec_id in ("g_nomac", "g_forged", "g_copy"):
        with pytest.raises(CryptoError):
            await store.get(Grant, rec_id)
    # a genuine record moved to another owner
    moved = {**doc, "user_id": "u_2"}
    await store.backend.commit([Op("create", "grants", "g_moved", moved)])
    with pytest.raises(CryptoError):
        await store.get(Grant, "g_moved")


async def test_forged_token_ids_are_not_found(store: Store) -> None:
    """The reviewer's proof: a token record written under the unkeyed SHA-256 of a chosen
    token (or under any guessable id) is never found."""
    import hashlib

    await store.create(make(User))
    grant = await store.create(make(Grant, rid="g_1"))
    mine = "uem_at_attacker_chosen_token_value_1234567890"
    doc = {
        "user_id": "u_1", "grant_id": grant.id, "client_id": "c", "token_type": "access",
        "resource": "", "scope": "mail.read mail.send", "consumed": False,
        "created_at": T0, "expires_at": T0 + timedelta(days=3650), "_v": 1,
    }  # fmt: skip
    for forged_id in (hashlib.sha256(mine.encode()).hexdigest(), mine, "t1"):
        await store.backend.commit([Op("create", "tokens", forged_id, dict(doc))])
    assert await store.authenticate_access_token(mine) is None
    # an id that is right (a writer who somehow learned it) still fails: no valid MAC
    await store.backend.commit([Op("create", "tokens", store.secret_id(Token, mine), dict(doc))])
    with pytest.raises(CryptoError):
        await store.authenticate_access_token(mine)
    # same for sessions and authorization codes
    sess = "uem_ps_attacker_chosen_session_value_12345"
    sdoc = {"user_id": "u_1", "created_at": T0, "last_seen": T0, "reauth_at": T0,
            "expires_at": T0 + timedelta(days=3650), "_v": 1}  # fmt: skip
    await store.backend.commit(
        [Op("create", "portal_sessions", hashlib.sha256(sess.encode()).hexdigest(), sdoc)]
    )
    assert await store.get_portal_session(sess) is None


async def test_secret_ids_are_keyed_per_purpose_and_follow_the_ring(
    backend: Backend, clock: Clock
) -> None:
    old = Store(backend, KeyRing({"k1": KEY1}), clock=clock)
    await old.create(make(User))
    raw, rec = await old.create_portal_session("u_1")
    new = Store(backend, KeyRing({"k1": KEY1, "k2": KEY2}), clock=clock)
    found = await new.get_portal_session(raw)  # issued under k1, still found with k2 active
    assert found and found.id == rec.id
    raw2, rec2 = await new.create_portal_session("u_1")
    assert rec2.id != new.keys.secret_ids("session-id-v1", raw)[0]
    assert (await old.get_portal_session(raw2)) is None  # k2 unknown to the old ring
    assert len({rec.id, new.secret_id(Token, raw), new.secret_id(AuthCode, raw)}) == 3
    await new.delete_portal_session(raw)
    assert await new.get_portal_session(raw) is None


async def test_rotation_remacs_records_with_plain_fields_only(
    backend: Backend, clock: Clock
) -> None:
    old = Store(backend, KeyRing({"k1": KEY1}), clock=clock)
    await old.create(make(User))
    await old.create(make(Grant))
    new = Store(backend, KeyRing({"k1": KEY1, "k2": KEY2}), clock=clock)
    doc = await backend.get("grants", "r1")
    assert doc and doc["_mac"].startswith("m1.k1.")
    report = await rotate_keys(new)
    assert report.resealed["grants"] == 1 and not report.unreadable
    doc = await backend.get("grants", "r1")
    assert doc and doc["_mac"].startswith("m1.k2.")
    assert await Store(backend, KeyRing({"k2": KEY2}), clock=clock).get(Grant, "r1")


async def test_bearer_verifier_refuses_forged_and_changed_records(store: Store) -> None:
    """The reviewer's end-to-end proof (dbwriter.py): forged token, escalated grant."""
    from universal_email_mcp.oauth.bearer import StoreTokenVerifier
    from universal_email_mcp.oauth.config import OAuthConfig

    verifier = StoreTokenVerifier(store, OAuthConfig(issuer="https://mcp.example.org"))
    resource = "https://mcp.example.org/mcp"
    await store.create(make(User))
    grant = await store.create_grant(
        user_id="u_1", client_id="c", account_ids=["a_1"], account_scopes={"a_1": "read"},
        scope="mail.read",
    )  # fmt: skip
    issued = await store.issue_tokens(grant, resource=resource)
    principal = await verifier(issued.access_token)
    assert principal and principal.scopes == ("mail.read",)

    mine = "uem_at_attacker_chosen_token_value_1234567890"
    import hashlib

    forged = {
        "user_id": "u_1", "grant_id": grant.id, "client_id": "c", "token_type": "access",
        "resource": resource, "scope": "mail.read mail.send", "consumed": False,
        "created_at": T0, "expires_at": T0 + timedelta(days=3650), "_v": 1,
    }  # fmt: skip
    await store.backend.commit(
        [Op("create", "tokens", hashlib.sha256(mine.encode()).hexdigest(), forged)]
    )
    assert await verifier(mine) is None

    await raw_replace(store, Grant, grant.id, scope="mail.read mail.send")
    assert await verifier(issued.access_token) is None  # fails closed, no 500


# --- MAC scope: namespace, user_id stays plain ------------------------------------------


class _Namespaced(MemoryBackend):
    def __init__(self, namespace: str) -> None:
        super().__init__()
        self.namespace = namespace


async def test_record_mac_binds_the_collection_prefix(clock: Clock) -> None:
    a = Store(_Namespaced("uem1_"), KeyRing({"k1": KEY1}), clock=clock)
    b = Store(_Namespaced("uem2_"), KeyRing({"k1": KEY1}), clock=clock)
    await a.create(make(User, "u_1"))
    doc = await a.backend.get("users", "u_1")
    assert doc is not None
    assert (await a.get(User, "u_1")) is not None
    # the same genuine document, copied into another deployment's collections
    await b.backend.commit([Op("create", "users", "u_1", dict(doc))])
    with pytest.raises(CryptoError):
        await b.get(User, "u_1")


def test_user_id_is_never_sealed() -> None:
    """The record MAC and the sealed blob's AAD take the owner from the plain ``user_id`` field
    (``Store.decode``); a record class that seals it would break that and the ``find`` by owner."""
    for cls in ALL_RECORDS:
        names = {f.name for f in dataclasses.fields(cls)}
        if "user_id" in names:
            assert "user_id" not in cls.SEALED, cls.__name__


# --- a damaged record does not break listings -------------------------------------------


async def test_list_for_user_skips_damaged_records(
    store: Store, caplog: pytest.LogCaptureFixture
) -> None:
    await with_users(store, "u_1")
    good = await store.create(make(MailAccount, rid="r_good"))
    bad = await store.create(make(MailAccount, rid="r_bad"))
    worse = await store.create(make(MailAccount, rid="r_worse"))
    await raw_replace(store, MailAccount, bad.id, permissions=["read", "send"])  # MAC fails
    await raw_replace(store, MailAccount, worse.id, _sealed="not-a-blob")  # MAC fails first
    with caplog.at_level("WARNING"):
        rows = await store.list_for_user(MailAccount, "u_1")
    assert [r.id for r in rows] == [good.id]
    assert store.unreadable["accounts"] == 2
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "accounts" in text and "r_bad" not in text and PASSWORD not in text
    assert await store.list_for_user(Identity, "u_1") == []


async def test_list_activity_survives_a_damaged_row(store: Store) -> None:
    await with_users(store, "u_1")
    good = await store.create(make(ActivityEntry, rid="a_good"))
    bad = await store.create(make(ActivityEntry, rid="a_bad"))
    await raw_replace(store, ActivityEntry, bad.id, event="tampered")
    assert [e.id for e in await store.list_activity("u_1")] == [good.id]
