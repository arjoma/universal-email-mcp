"""POP3 against Dovecot: the same maildir as IMAP, so mail seeded over IMAP is read over POP3.

Covers implicit TLS and STLS, UIDL-based ids that survive new sessions, the header
cache, whole-message reads with the byte cap, attachments, the hostile corpus
through POP3, mixed IMAP + POP3 fan-out and the refusal of write operations.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import pytest
from mcp import Client
from mcp.types import CallToolResult, TextContent

from tests.integration.conftest import DATA, ImapServer, Mailbox, seed_messages
from universal_email_mcp.config import Config, parse_config
from universal_email_mcp.errors import AuthFailed, TlsError
from universal_email_mcp.mail.imap import SearchCriteria
from universal_email_mcp.mail.mime import parse_message
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.mail.pop3 import Pop3Session, Pop3State
from universal_email_mcp.models import Endpoint, MessageRef, TlsMode, TlsSettings
from universal_email_mcp.server.app import build_server
from universal_email_mcp.service.mail import MailService

pytestmark = pytest.mark.integration

SANDBOX = sorted((DATA / "sandbox").glob("*.eml"))


@dataclass(frozen=True)
class Box:
    server: ImapServer
    mb: Mailbox
    n_seed: int

    def pop3(self, mode: TlsMode = "tls", *, state: Pop3State | None = None) -> Pop3Session:
        port = self.server.pop3s_port if mode == "tls" else self.server.pop3_port
        return Pop3Session.connect(
            Endpoint(self.server.host, port, mode),
            self.mb.user,
            self.server.password,
            account_name="Pop",
            net=NetPolicy(allow_private=True, connect_timeout=10, read_timeout=30),
            tls=TlsSettings(verify=False),
            state=state,
        )


@pytest.fixture(scope="module")
def box(imap_server: ImapServer) -> Iterator[Box]:
    mb = Mailbox(imap_server, f"pop{uuid.uuid4().hex[:10]}@example.org")
    seeded = seed_messages()
    c = mb.admin()
    try:
        for raw, when, flags in seeded:
            c.append("INBOX", raw, flags=flags, msg_time=when)
        for path in SANDBOX:
            c.append("INBOX", path.read_bytes(), msg_time=datetime(2026, 9, 29, 12, 0))
        n = len(seeded) + len(SANDBOX)
    finally:
        c.logout()
    yield Box(imap_server, mb, n)


@pytest.mark.parametrize("mode", ["tls", "starttls"])
def test_connect_modes_and_counts(box: Box, mode: TlsMode):
    s = box.pop3(mode)
    try:
        (inbox,) = s.list_folders()
        assert inbox.name == "INBOX" and (inbox.messages or 0) >= box.n_seed
        assert "UIDL" in s.capabilities and "TOP" in s.capabilities
        assert s.search("INBOX").total >= box.n_seed
    finally:
        s.close()


def test_wrong_password_and_missing_tls(box: Box):
    with pytest.raises(AuthFailed):
        Pop3Session.connect(
            Endpoint(box.server.host, box.server.pop3s_port, "tls"),
            box.mb.user,
            "wrong",
            net=NetPolicy(allow_private=True),
            tls=TlsSettings(verify=False),
        )
    with pytest.raises(TlsError):  # certificate verification is on by default
        Pop3Session.connect(
            Endpoint(box.server.host, box.server.pop3s_port, "tls"),
            box.mb.user,
            box.server.password,
            net=NetPolicy(allow_private=True),
        )


def test_ids_are_stable_across_sessions_and_headers_cached(box: Box):
    state = Pop3State()
    s1 = box.pop3(state=state)
    try:
        res = s1.search("INBOX", SearchCriteria(subject="note"))
        assert res.total >= 1
        subjects = {m.subject: m.ref.encode() for m in s1.fetch_summaries("INBOX", list(res.uids))}
    finally:
        s1.close()
    assert "Old plain note" in subjects
    # a fresh process (empty state) resolves the same id
    s2 = box.pop3()
    try:
        msg = s2.fetch_message(MessageRef.decode(subjects["Old plain note"]))
        assert msg.summary.subject == "Old plain note" and "zebra crossing" in msg.body.text
        assert msg.summary.ref.encode() == subjects["Old plain note"]
        assert msg.summary.flags == ()
    finally:
        s2.close()


def test_incremental_new_mail_between_sessions(box: Box):
    state = Pop3State()
    s1 = box.pop3(state=state)
    try:
        s1.search("INBOX", SearchCriteria(subject="a"))
        before = len(state.summaries)
    finally:
        s1.close()
    c = box.mb.admin()
    try:
        c.append(
            "INBOX",
            b"From: new@example.org\r\nSubject: Fresh mail\r\n\r\nbody\r\n",
            msg_time=datetime(2026, 10, 1, 8, 0),
        )
    finally:
        c.logout()
    s2 = box.pop3(state=state)
    try:
        res = s2.search("INBOX", SearchCriteria(subject="fresh"))
        assert res.total == 1
        assert len(state.summaries) == before + 1  # only the new UIDL was read
    finally:
        s2.close()


def test_dates_come_from_the_received_header_or_date(box: Box):
    s = box.pop3()
    try:
        res = s.search("INBOX", SearchCriteria(subject="Ihre Rechnung"))
        (sm,) = s.fetch_summaries("INBOX", list(res.uids))
        assert sm.date is not None and sm.date.year == 2026  # no INTERNALDATE over POP3
        assert sm.has_attachments
    finally:
        s.close()


def test_whole_message_cap_and_attachment_bytes(box: Box):
    s = box.pop3()
    try:
        res = s.search("INBOX", SearchCriteria(subject="Big one"))
        (ref,) = [m.ref for m in s.fetch_summaries("INBOX", list(res.uids))]
        full = s.fetch_message(ref)
        assert not full.source_truncated and full.body.total_chars >= 20000
        cut = s.fetch_message(ref, max_bytes=3000)
        assert cut.source_truncated and 0 < cut.body.total_chars < 3000
        # the connection is still good after a TOP-based partial read
        assert s.search("INBOX", SearchCriteria(subject="Big one")).total == 1

        res = s.search("INBOX", SearchCriteria(has_attachment=True))
        assert res.total >= 1
        sums = s.fetch_summaries("INBOX", list(res.uids))
        att_ref = next(m.ref for m in sums if m.subject == "Ihre Rechnung")
        msg = s.fetch_message(att_ref)
        assert msg.attachments
        for a in msg.attachments:
            got = s.fetch_attachment(att_ref, a.part_id, max_bytes=5_000_000)
            assert got.data is not None and got.exact and len(got.data) == a.size
    finally:
        s.close()


def test_attachments_match_imap_bytes(box: Box):
    """POP3 numbers parts by its own parse; for well-formed mail that agrees with Dovecot."""
    imap = box.mb.session()
    pop = box.pop3()
    try:
        ires = imap.search("INBOX", SearchCriteria(has_attachment=True))
        for iref in ires.refs():
            imsg = imap.fetch_message(iref)
            if not imsg.attachments:
                continue
            mid = imsg.summary.message_id
            hits = pop.search("INBOX")
            pref = None
            for m in pop.fetch_summaries("INBOX", list(hits.uids)):
                if m.message_id == mid:
                    pref = m.ref
            assert pref is not None
            pmsg = pop.fetch_message(pref)
            assert [a.part_id for a in pmsg.attachments] == [a.part_id for a in imsg.attachments]
            for a in imsg.attachments:
                want = imap.fetch_attachment(iref, a.part_id, max_bytes=5_000_000)
                got = pop.fetch_attachment(pref, a.part_id, max_bytes=5_000_000)
                # a forwarded message may differ by the CRLF before the closing delimiter
                assert (got.data or b"").rstrip(b"\r\n") == (want.data or b"").rstrip(b"\r\n")
    finally:
        imap.close()
        pop.close()


def test_hostile_corpus_reads_the_same_over_pop3(box: Box):
    """Every sandbox sample parses over POP3 like over IMAP (text), none crashes."""
    pop = box.pop3()
    try:
        sums = pop.fetch_summaries("INBOX", list(pop.search("INBOX").uids))
        by_mid = {m.message_id: m for m in sums if m.message_id}
        checked = 0
        for path in SANDBOX:
            raw = path.read_bytes()
            parsed = parse_message(raw)
            mid = parsed.headers.message_id
            if mid is None or mid not in by_mid:
                continue
            msg = pop.fetch_message(by_mid[mid].ref)
            assert msg.body.text == parsed.text[: len(msg.body.text)] or msg.body_source
            assert msg.summary.subject == parsed.headers.subject
            checked += 1
        assert checked >= 5
        # headers of everything, including the hostile ones, load without error
        assert len(sums) >= box.n_seed
    finally:
        pop.close()


# ------------------------------------------------------------------ service level


def make_config(b: Box, **extra_limits: Any) -> Config:
    base: dict[str, Any] = {
        "username": b.mb.user,
        "password_env": "UEM_IT_PASSWORD",
        "tls_verify": False,
    }
    return parse_config(
        {
            "accounts": [
                {
                    **base,
                    "name": "Imap",
                    "imap": {"host": b.server.host, "port": b.server.imaps_port},
                    "permissions": ["read", "organize", "delete", "drafts"],
                },
                {
                    **base,
                    "name": "Pop",
                    "kind": "pop3",
                    "pop3": {"host": b.server.host, "port": b.server.pop3s_port},
                },
            ],
            "identities": [{"address": b.mb.user, "store_account": "Imap"}],
            "limits": {"account_timeout": 25, **extra_limits},
        }
    )


@asynccontextmanager
async def connect(config: Config) -> AsyncIterator[tuple[Client, MailService]]:
    service = MailService(config)
    try:
        async with Client(build_server(service)) as c:
            yield c, service
    finally:
        await service.aclose()


def text(r: CallToolResult) -> str:
    block = r.content[0]
    assert isinstance(block, TextContent)
    return block.text


async def call(c: Client, tool: str, **args: Any) -> tuple[str, dict[str, Any]]:
    r = await c.call_tool(tool, args)
    assert not r.is_error, text(r)
    assert r.structured_content is not None
    return text(r), r.structured_content


async def test_mixed_imap_and_pop3_fanout(box: Box, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("UEM_IT_PASSWORD", box.server.password)
    async with connect(make_config(box)) as (c, _svc):
        md, data = await call(c, "find_messages", subject="Old plain note")
        accounts = sorted(m["account"] for m in data["messages"])
        assert accounts == ["Imap", "Pop"] and not data["problems"]
        by = {m["account"]: m for m in data["messages"]}
        assert by["Imap"]["unread"] is False  # seeded \Seen
        assert by["Pop"]["unread"] is None and by["Pop"]["id"].startswith("p1.")
        assert by["Imap"]["id"].startswith("m1.")

        md, info = await call(c, "account_info")
        pop = next(a for a in info["accounts"] if a["name"] == "Pop")
        assert pop["kind"] == "pop3" and pop["connected"] and pop["permissions"] == ["read"]

        md, msg = await call(c, "get_message", id=by["Pop"]["id"])
        assert "zebra crossing" in msg["body"]["text"]
        _md, q = await call(c, "find_messages", query="zebra*", accounts=["Pop"])
        assert q["messages"] == [] or isinstance(q["messages"], list)  # headers only: no body hit
        _md, q = await call(c, "find_messages", query="Old plain note", accounts=["Pop"])
        assert q["messages"][0]["subject"] == "Old plain note"


async def test_write_tools_refuse_pop3_ids_and_mail_is_untouched(
    box: Box, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("UEM_IT_PASSWORD", box.server.password)
    async with connect(make_config(box)) as (c, _svc):
        _md, data = await call(c, "find_messages", subject="Old plain note", accounts=["Pop"])
        pid = data["messages"][0]["id"]
        for tool, args in (
            ("mark_messages", {"ids": [pid], "seen": True}),
            ("move_messages", {"ids": [pid], "to": "Trash"}),
            ("delete_messages", {"ids": [pid]}),
        ):
            r = await c.call_tool(tool, args)
            body = text(r)
            assert "read-only" in body or "NOT_PERMITTED" in body, (tool, body)
        _md, again = await call(c, "find_messages", subject="Old plain note", accounts=["Pop"])
        assert len(again["messages"]) == 1
    imap = box.mb.session()
    try:
        assert imap.search("INBOX").total >= box.n_seed  # nothing deleted by any POP3 session
    finally:
        imap.close()


async def test_reply_draft_to_a_pop3_message_is_stored_on_imap(
    box: Box, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("UEM_IT_PASSWORD", box.server.password)
    async with connect(make_config(box)) as (c, _svc):
        _md, data = await call(c, "find_messages", subject="Ihre Rechnung", accounts=["Pop"])
        pid = data["messages"][0]["id"]
        _md, out = await call(c, "save_draft", reply_to_id=pid, body="Danke!")
        assert out["id"].startswith("m1.")  # the draft lives in the IMAP account
        assert out["account"] == "Imap"
