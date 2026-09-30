"""Service layer with fake backends: multi-account paging, cursors, header index,
time windows, and the MCP tool surface (schemas, error results)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from mcp import Client
from mcp.types import TextContent

from universal_email_mcp.errors import (
    AuthFailed,
    InvalidArgument,
    InvalidCursor,
    ServerUnreachable,
    StaleCursor,
)
from universal_email_mcp.mail.imap import SearchCriteria
from universal_email_mcp.server.app import build_server
from universal_email_mcp.service.cursor import Cursor, CursorCodec, SourcePos, query_hash
from universal_email_mcp.service.fuzzy import FuzzyQuery
from universal_email_mcp.service.index import HeaderIndex
from universal_email_mcp.service.mail import MailService
from universal_email_mcp.service.router import AccountRouter
from universal_email_mcp.service.timewindow import resolve_window

from .fakes import Connector, FakeSession, config, summary

# ---------------------------------------------------------------- cursors


def test_cursor_roundtrip_and_binding():
    codec = CursorCodec(b"k" * 32)
    cur = Cursor("list_messages", "q1", {("A", "INBOX"): SourcePos(7, 20, 99, 42)})
    text = codec.encode(cur)
    assert codec.decode(text, tool="list_messages", query="q1") == cur
    with pytest.raises(InvalidCursor, match="search_messages"):
        codec.decode(text, tool="search_messages", query="q1")
    with pytest.raises(InvalidCursor, match="different arguments"):
        codec.decode(text, tool="list_messages", query="q2")
    with pytest.raises(InvalidCursor, match="signature"):
        CursorCodec(b"x" * 32).decode(text, tool="list_messages", query="q1")


@pytest.mark.parametrize("bad", ["", "c1.", "c1.abc", "c1.!!.??", "x" * 20000, "m1.abc.def"])
def test_cursor_garbage(bad: str):
    with pytest.raises(InvalidCursor):
        CursorCodec().decode(bad, tool="t", query="q")


def test_cursor_tamper_payload():
    codec = CursorCodec()
    text = codec.encode(Cursor("t", "q", offset=5))
    body, mac = text[3:].split(".")
    forged = "c1." + body[:-2] + ("AA" if body[-2:] != "AA" else "BB") + "." + mac
    with pytest.raises(InvalidCursor):
        codec.decode(forged, tool="t", query="q")


def test_query_hash_stable():
    assert query_hash({"a": 1, "b": [1, 2]}) == query_hash({"b": [1, 2], "a": 1})
    assert query_hash({"since": date(2026, 9, 1)}) != query_hash({"since": date(2026, 9, 2)})


# ---------------------------------------------------------------- time windows

NOW = datetime(2026, 9, 30, 15, 0).astimezone()  # a Wednesday


@pytest.mark.parametrize(
    ("preset", "since", "before"),
    [
        ("today", "2026-09-30", None),
        ("yesterday", "2026-09-29", "2026-09-30"),
        ("this_week", "2026-09-28", None),
        ("last_week", "2026-09-21", "2026-09-28"),
        ("last_7_days", "2026-09-24", None),
        ("this_month", "2026-09-01", None),
        ("last_month", "2026-08-01", "2026-09-01"),
        ("this year", "2026-01-01", None),
    ],
)
def test_time_window_presets(preset: str, since: str, before: str | None):
    w = resolve_window(preset, now=NOW)
    assert str(w.since) == since and (str(w.before) if w.before else None) == before


def test_time_window_explicit_and_errors():
    w = resolve_window("this_month", before="2026-09-15", now=NOW)
    assert (str(w.since), str(w.before)) == ("2026-09-01", "2026-09-15")
    assert w.describe() == "2026-09-01 – 2026-09-14"
    assert resolve_window(now=NOW).describe() == "all time"
    with pytest.raises(InvalidArgument):
        resolve_window("fortnight", now=NOW)
    with pytest.raises(InvalidArgument):
        resolve_window(since="yesterday", now=NOW)
    with pytest.raises(InvalidArgument):
        resolve_window(since="2026-09-10", before="2026-09-01", now=NOW)


# ---------------------------------------------------------------- header index


def test_index_caches_and_extends_incrementally():
    s = FakeSession("A", {"INBOX": list(range(1, 11))})
    idx = HeaderIndex()
    got = idx.summaries(s, "INBOX", 1, [10, 9, 8])  # pyright: ignore[reportArgumentType]
    assert [m.ref.uid for m in got] == [10, 9, 8]
    assert s.calls == ["FETCH INBOX 3"]
    s.calls.clear()
    assert [m.ref.uid for m in idx.summaries(s, "INBOX", 1, [9, 8])] == [9, 8]  # pyright: ignore[reportArgumentType]
    assert s.calls == [] and idx.stats.hits == 2
    # new mail: fetched incrementally above the high-water mark
    s.folders["INBOX"][11] = summary("A", "INBOX", 11)
    s.folders["INBOX"][12] = summary("A", "INBOX", 12)
    idx.summaries(s, "INBOX", 1, [12, 11, 10])  # pyright: ignore[reportArgumentType]
    assert s.calls == ["SINCE INBOX 10"] and idx.stats.incremental == 1
    # vanished UIDs are skipped
    assert idx.summaries(s, "INBOX", 1, [99, 9]) != []  # pyright: ignore[reportArgumentType]


def test_index_invalidates_on_uidvalidity_ttl_and_bounds():
    now = [0.0]
    s = FakeSession("A", {"INBOX": list(range(1, 50)), "Sent": [1], "X": [1]})
    idx = HeaderIndex(max_per_folder=10, max_folders=2, ttl=100, clock=lambda: now[0])
    idx.summaries(s, "INBOX", 1, list(range(49, 29, -1)))  # pyright: ignore[reportArgumentType]
    assert len(idx._entries[("A", "INBOX")].items) == 10  # pyright: ignore[reportPrivateUsage]
    s.calls.clear()
    s.uidvalidity = 2
    s.folders["INBOX"] = {u: m for u, m in s.folders["INBOX"].items()}
    with pytest.raises(Exception, match="changed"):
        idx.summaries(s, "INBOX", 1, [1])  # pyright: ignore[reportArgumentType]
    idx.summaries(s, "INBOX", 2, [49])  # pyright: ignore[reportArgumentType]
    assert idx.stats.invalidations == 1
    idx.summaries(s, "Sent", 2, [1])  # pyright: ignore[reportArgumentType]
    idx.summaries(s, "X", 2, [1])  # pyright: ignore[reportArgumentType]
    assert len(idx) == 2 and ("A", "INBOX") not in idx._entries  # pyright: ignore[reportPrivateUsage]
    s.calls.clear()
    now[0] = 500  # TTL expired: rebuilt
    idx.summaries(s, "X", 2, [1])  # pyright: ignore[reportArgumentType]
    assert s.calls == ["FETCH X 1"]


# ---------------------------------------------------------------- paging


def _service(**sessions: FakeSession) -> tuple[MailService, Connector]:
    conn = Connector(dict(sessions))
    cfg = config(*sessions)
    return MailService(cfg, router=AccountRouter(cfg, connectors={"imap": conn})), conn


async def _page(svc: MailService, cursor: str | None = None, limit: int = 3, **kw: Any):
    return await svc.list_messages(
        tool="list_messages",
        args={"k": 1},
        accounts=None,
        folders=kw.get("folders"),
        criteria=SearchCriteria(),
        limit=limit,
        cursor=cursor,
    )


async def test_paging_merges_accounts_newest_first_without_gaps():
    svc, _ = _service(
        A=FakeSession("A", {"INBOX": [1, 3, 5, 7]}), B=FakeSession("B", {"INBOX": [2, 4, 6]})
    )
    seen: list[tuple[str, int]] = []
    cursor = None
    while True:
        page = await _page(svc, cursor)
        assert page.total == 7
        seen += [(h.account, h.summary.ref.uid) for h in page.hits]
        cursor = page.cursor
        if cursor is None:
            break
    assert [u for _a, u in seen] == [7, 6, 5, 4, 3, 2, 1]
    await svc.aclose()


async def test_paging_is_stable_when_new_mail_arrives():
    a = FakeSession("A", {"INBOX": [1, 2, 3, 4, 5]})
    svc, _ = _service(A=a)
    first = await _page(svc, limit=2)
    assert [h.summary.ref.uid for h in first.hits] == [5, 4]
    a.folders["INBOX"][6] = summary("A", "INBOX", 6)  # new arrival
    second = await _page(svc, first.cursor, limit=2)
    assert [h.summary.ref.uid for h in second.hits] == [3, 2]
    assert second.offset == 2 and second.total == 5


async def test_stale_cursor_after_uidvalidity_change():
    a = FakeSession("A", {"INBOX": [1, 2, 3]})
    svc, _ = _service(A=a)
    first = await _page(svc, limit=1)
    a.uidvalidity = 9
    page = await _page(svc, first.cursor, limit=1)
    assert page.hits == [] and page.problems[0].code == StaleCursor.code


async def test_failed_account_keeps_its_cursor_position():
    a, b = FakeSession("A", {"INBOX": [1, 3]}), FakeSession("B", {"INBOX": [2, 4]})
    svc, conn = _service(A=a, B=b)
    first = await _page(svc, limit=2)
    assert [h.account for h in first.hits] == ["B", "A"]
    await svc.router.aclose()
    conn.fail["B"] = ServerUnreachable("down")
    second = await _page(svc, first.cursor, limit=2)
    assert [h.summary.ref.uid for h in second.hits] == [1]
    assert [p.account for p in second.problems] == ["B"] and second.cursor
    del conn.fail["B"]
    third = await _page(svc, second.cursor, limit=2)
    assert [h.summary.ref.uid for h in third.hits] == [2]
    assert third.cursor is None


async def test_fuzzy_search_ranks_and_pages():
    a = FakeSession("A", {"INBOX": [1, 2, 3]})
    for uid, subject in ((1, "Rechnung Huber"), (2, "Angebot Website"), (3, "Rechnung Müller")):
        a.folders["INBOX"][uid] = summary("A", "INBOX", uid, subject=subject)
    svc, _ = _service(A=a)

    async def run(cursor: str | None = None):
        return await svc.fuzzy_search(
            tool="search_messages",
            args={"s": "rechnung"},
            accounts=None,
            folders=None,
            base=SearchCriteria(),
            exact=SearchCriteria(subject="rechnung"),
            query=FuzzyQuery(subject="rechnung"),
            threshold=75,
            limit=1,
            cursor=cursor,
        )

    p1 = await run()
    assert p1.total >= 2 and not p1.exact and p1.hits[0].score is not None
    p2 = await run(p1.cursor)
    assert p2.offset == 1 and p2.hits[0].summary.ref.uid != p1.hits[0].summary.ref.uid
    with pytest.raises(InvalidArgument):
        await svc.fuzzy_search(
            tool="search_messages",
            args={},
            accounts=None,
            folders=None,
            base=SearchCriteria(),
            exact=SearchCriteria(),
            query=FuzzyQuery(),
            threshold=75,
            limit=1,
            cursor=None,
        )


# ---------------------------------------------------------------- MCP surface


async def test_mcp_tools_schema_and_errors():
    svc, conn = _service(A=FakeSession("A", {"INBOX": [1, 2], "Sent": [1]}))
    async with Client(build_server(svc)) as c:
        r = await c.call_tool("list_messages", {"limit": 1})
        assert not r.is_error and r.structured_content is not None
        data = r.structured_content
        assert data["total"] == 2 and data["next_cursor"]
        assert set(data["messages"][0]) >= {"id", "from", "subject", "viewer_url", "unread"}
        block = r.content[0]
        assert isinstance(block, TextContent) and "| # | Date |" in block.text
        r = await c.call_tool("list_messages", {"cursor": "c1.bogus.bogus"})
        assert r.is_error
        assert isinstance(r.content[0], TextContent) and "INVALID_CURSOR" in r.content[0].text
        r = await c.call_tool("get_message", {"id": "m1.nope"})
        assert r.is_error and "INVALID_REF" in r.content[0].text  # pyright: ignore[reportAttributeAccessIssue]
        r = await c.call_tool("search_messages", {})
        assert r.is_error and "INVALID_ARGUMENT" in r.content[0].text  # pyright: ignore[reportAttributeAccessIssue]
        r = await c.call_tool("list_messages", {"window": "someday"})
        assert r.is_error and "INVALID_ARGUMENT" in r.content[0].text  # pyright: ignore[reportAttributeAccessIssue]
        conn.fail["A"] = AuthFailed("nope")
        await svc.router.aclose()
        r = await c.call_tool("list_messages", {})
        assert r.is_error and r.structured_content is not None
        assert r.structured_content["problems"][0]["code"] == "AUTH_FAILED"
    await svc.aclose()


async def test_permanent_failure_does_not_keep_paging():
    a = FakeSession("A", {"INBOX": [1], "Clients": [1, 2]})
    b = FakeSession("B", {"INBOX": [1]})
    svc, _ = _service(A=a, B=b)
    page = await _page(svc, limit=5, folders=["Clients"])
    assert [h.summary.ref.uid for h in page.hits] == [2, 1]
    assert [(p.account, p.code) for p in page.problems] == [("B", "FOLDER_NOT_FOUND")]
    assert page.cursor is None


async def test_paging_survives_expunge_between_pages():
    a = FakeSession("A", {"INBOX": list(range(1, 11))})
    svc, _ = _service(A=a)
    first = await _page(svc, limit=3)
    assert [h.summary.ref.uid for h in first.hits] == [10, 9, 8]
    del a.folders["INBOX"][10], a.folders["INBOX"][9]  # expunged meanwhile
    second = await _page(svc, first.cursor, limit=3)
    assert [h.summary.ref.uid for h in second.hits] == [7, 6, 5]  # not 5, 4, 3
    del a.folders["INBOX"][5]  # the resume point itself vanished
    third = await _page(svc, second.cursor, limit=3)
    assert [h.summary.ref.uid for h in third.hits] == [4, 3, 2]
    fourth = await _page(svc, third.cursor, limit=3)
    assert [h.summary.ref.uid for h in fourth.hits] == [1] and fourth.cursor is None


# ---------------------------------------------------------------- threads


def _msg(folder: str, uid: int, *, hours: int, msgid: str, **kw: Any):
    when = datetime(2026, 9, 1, tzinfo=UTC) + timedelta(hours=hours)
    return replace(summary("A", folder, uid), received=when, date=when, message_id=msgid, **kw)


async def test_thread_forged_duplicate_cannot_hide_sent_and_order_is_arrival():
    a = FakeSession("A", {"INBOX": [], "Sent": []})
    a.folders["INBOX"][1] = _msg("INBOX", 1, hours=1, msgid="<root@x>")
    a.folders["Sent"][1] = _msg("Sent", 1, hours=2, msgid="<reply@x>", in_reply_to="<root@x>")
    # forged: reuses the Sent message's Message-ID, backdates its Date header
    forged = _msg("INBOX", 2, hours=3, msgid="<reply@x>", in_reply_to="<root@x>")
    a.folders["INBOX"][2] = replace(forged, date=datetime(2020, 1, 1, tzinfo=UTC))
    svc, _ = _service(A=a)
    res = await svc.get_thread(a.folders["INBOX"][1].ref.encode(), limit=None)
    got = [(h.summary.ref.folder, h.summary.ref.uid) for h in res.hits]
    assert got == [("INBOX", 1), ("Sent", 1), ("INBOX", 2)]


async def test_thread_search_prioritises_own_ids_and_latest_references():
    a = FakeSession("A", {"INBOX": []})
    refs = tuple(f"<r{i:02d}@x>" for i in range(40))
    a.folders["INBOX"][1] = _msg(
        "INBOX", 1, hours=1, msgid="<me@x>", in_reply_to="<r39@x>", references=refs
    )
    svc, _ = _service(A=a)
    await svc.get_thread(a.folders["INBOX"][1].ref.encode(), limit=None)
    first = a.related_queries[0]
    assert first[:4] == ["<me@x>", "<r39@x>", "<r38@x>", "<r37@x>"]
    assert "<r00@x>" not in first[:30]


async def test_pages_show_current_flags_not_cached_ones():
    a = FakeSession("A", {"INBOX": [1, 2, 3]})
    svc, _ = _service(A=a)
    first = await _page(svc, limit=3)
    assert all(not h.summary.flagged for h in first.hits)
    a.folders["INBOX"][3] = replace(a.folders["INBOX"][3], flags=("\\Flagged", "\\Seen"))
    a.calls.clear()
    again = await _page(svc, limit=3)
    assert [h.summary.flagged for h in again.hits] == [True, False, False]
    assert "FLAGS INBOX 3" in a.calls and not any(c.startswith("FETCH") for c in a.calls)


async def test_cursor_stops_retrying_a_persistently_failing_account():
    a, b = FakeSession("A", {"INBOX": [1]}), FakeSession("B", {"INBOX": [1]})
    svc, conn = _service(A=a, B=b)
    conn.fail["B"] = ServerUnreachable("down")
    page = await _page(svc, limit=5)
    pages = 1
    while page.cursor is not None:
        assert pages < 10, "endless empty pages"
        page = await _page(svc, page.cursor, limit=5)
        pages += 1
    assert pages == 4  # the first page + 3 retry pages (MAX_CURSOR_RETRIES), then no cursor
    assert any("stopped retrying" in n for n in page.notes)


async def test_list_folders_keeps_tree_indentation():
    a = FakeSession(
        "A", {"INBOX": [1], "Clients": [], "Clients/Huber": [], "Clients/Huber/2025": []}
    )
    svc, _ = _service(A=a)
    async with Client(build_server(svc)) as c:
        r = await c.call_tool("list_folders", {})
        text = r.content[0].text  # pyright: ignore[reportAttributeAccessIssue]
    rows = {line.split(" | ")[1] for line in text.splitlines() if line.startswith("| A ")}
    assert {"Clients", "└ Huber", "│ └ 2025"} <= rows
    await svc.aclose()
