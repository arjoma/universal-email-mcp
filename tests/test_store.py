"""Store contract tests: every test runs against the memory backend and the Firestore emulator."""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Iterator
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
    hash_token,
    rotate_keys,
)
from universal_email_mcp.store.records import ALL_RECORDS, USER_OWNED, Record

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
    assert await rotate_keys(new) == {"users": 1, "accounts": 0, "identities": 0,
                                      "approvals": 0, "activity": 0}  # fmt: skip
    assert await rotate_keys(new) == {k: 0 for k in ("users", "accounts", "identities", "approvals", "activity")}  # fmt: skip
    again = await only_k2.get(MailAccount, "r1")
    assert again and again.password == PASSWORD
    assert (await only_k2.get(User, "u_1")) is not None


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
    raw, rec = await store.create_portal_session("u_1", timedelta(hours=1))
    assert rec.id == hash_token(raw) and raw not in repr(
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
    args: dict[str, Any] = dict(user_id="u_1", client_id="c", grant_id="g", redirect_uri="https://c/cb", code_challenge="ch")  # fmt: skip
    raw = await store.issue_auth_code(**args)
    assert (await store.backend.get("auth_codes", hash_token(raw))) is not None
    assert raw not in repr(await store.backend.get("auth_codes", hash_token(raw)))
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
    grant, t = await connect(store)
    assert t.access_token.startswith("uem_at_") and t.refresh_token.startswith("uem_rt_")
    # only digests are stored
    for raw in (t.access_token, t.refresh_token):
        assert await store.backend.get("tokens", raw) is None
        doc = await store.backend.get("tokens", hash_token(raw))
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
    grant = await store.create_grant(user_id="u_1", client_id="c")
    assert grant.last_used is None
    clock.advance(minutes=10)
    assert await store.get(Grant, grant.id) is None


async def test_refresh_rotation_slides_but_stops_at_absolute_max(
    store: Store, clock: Clock
) -> None:
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
    _, t = await connect(store)
    clock.advance(days=30)
    with pytest.raises(InvalidToken):
        await store.rotate_refresh_token(t.refresh_token, client_id="c")


async def test_refresh_checks_client_and_type(store: Store) -> None:
    _, t = await connect(store)
    with pytest.raises(InvalidToken):
        await store.rotate_refresh_token(t.refresh_token, client_id="other")
    with pytest.raises(InvalidToken):
        await store.rotate_refresh_token(t.access_token, client_id="c")
    with pytest.raises(InvalidToken):
        await store.rotate_refresh_token("garbage", client_id="c")


async def test_refresh_rotation_and_replay_revokes_grant(store: Store) -> None:
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
    _, t = await connect(store)
    results = await asyncio.gather(
        *(store.rotate_refresh_token(t.refresh_token, client_id="c") for _ in range(3)),
        return_exceptions=True,
    )
    assert sum(not isinstance(r, BaseException) for r in results) == 1
    assert all(isinstance(r, InvalidToken) for r in results if isinstance(r, BaseException))


async def test_revoke_grant_and_revoke_token(store: Store) -> None:
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
    grant, t = await connect(store)
    assert grant.absolute_expires_at is None and t.refresh_expires_at is None
    clock.advance(days=3650)
    t2 = await store.rotate_refresh_token(t.refresh_token, client_id="c")
    assert t2.refresh_expires_at is None


async def test_access_use_touches_grant_rarely(store: Store, clock: Clock) -> None:
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
    ap = await store.create_approval(user_id="u_1", grant_id="g", identity_id="i", content_hash="h", draft_ref="ref")  # fmt: skip
    assert ap.status == "pending"
    done = await store.decide_approval(ap.id, "u_1", True)
    assert done and done.status == "approved"
    assert await store.decide_approval(ap.id, "u_1", False) is None  # decided once
    ap2 = await store.create_approval(user_id="u_1", grant_id="g", identity_id="i", content_hash="h", draft_ref="ref")  # fmt: skip
    clock.advance(minutes=10)
    assert await store.decide_approval(ap2.id, "u_1", True) is None


async def test_activity_feed(store: Store, clock: Clock) -> None:
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


async def test_approval_ownership_and_single_use(store: Store) -> None:
    ap = await store.create_approval(user_id="u_1", grant_id="g", identity_id="i", content_hash="h", draft_ref="r")  # fmt: skip
    assert await store.decide_approval(ap.id, "u_2", True) is None  # foreign user
    assert await store.consume_approval(ap.id, "u_1", "h") is None  # not approved yet
    assert await store.decide_approval(ap.id, "u_1", True)
    assert await store.consume_approval(ap.id, "u_1", "other") is None  # other content
    assert await store.consume_approval(ap.id, "u_2", "h") is None
    assert await store.consume_approval(ap.id, "u_1", "h")
    assert await store.consume_approval(ap.id, "u_1", "h") is None


async def test_refresh_survives_concurrent_grant_touch(store: Store, clock: Clock) -> None:
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
    import asyncio
    from datetime import timedelta

    ttl = timedelta(minutes=10)
    assert await store.claim_send("u_1", "h" * 64, ttl)
    clock.advance(minutes=11)  # expired, not purged
    got = await asyncio.gather(*(store.claim_send("u_1", "h" * 64, ttl) for _ in range(4)))
    assert sum(got) == 1
