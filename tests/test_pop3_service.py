"""POP3 accounts through the service and the MCP tools (scripted POP3 server, fake IMAP):
mixed fan-out, reading, attachments, and everything that must stay refused."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from mcp import Client
from mcp.types import CallToolResult, TextContent

from universal_email_mcp.config import Config, parse_config
from universal_email_mcp.errors import InvalidRef, NotPermitted
from universal_email_mcp.models import MessageRef
from universal_email_mcp.server.app import build_server
from universal_email_mcp.service import fuzzy
from universal_email_mcp.service.mail import MailService
from universal_email_mcp.service.router import AccountRouter

from .fakes import Connector, FakeSession
from .pop3_server import ScriptedPop3Server, make_attachment_message, make_message

PAYLOAD = bytes(range(200)) * 3


def messages() -> list[tuple[str, bytes]]:
    return [
        ("u1", make_message("Invoice 2026-17", sender="Huber <anna@huber.at>", message_id="i1@x")),
        ("u2", make_message("Lunch on friday", sender="Bob <bob@example.com>")),
        ("u3", make_attachment_message("Photos", "cat.bin", PAYLOAD)),
        (
            "u4",
            make_message(
                "Re: Invoice 2026-17",
                sender="Huber <anna@huber.at>",
                extra="In-Reply-To: <i1@x>\r\n",
            ),
        ),
    ]


def cfg(port: int, *, with_imap: bool = False, imap_perms: tuple[str, ...] = ("read",)) -> Config:
    accounts: list[dict[str, Any]] = [
        {
            "name": "Old",
            "kind": "pop3",
            "username": "user",
            "password_env": "UEM_POP3_PASSWORD",
            "tls_verify": False,
            "pop3": {"host": "127.0.0.1", "port": port},
        }
    ]
    if with_imap:
        accounts.append(
            {
                "name": "Imap",
                "username": "imap@example.org",
                "server": "imap.example.org",
                "permissions": list(imap_perms),
            }
        )
    return parse_config({"accounts": accounts, "limits": {"account_timeout": 10}})


@pytest.fixture(autouse=True)
def _password(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("UEM_POP3_PASSWORD", "secret")


@asynccontextmanager
async def service_for(
    srv: ScriptedPop3Server, *, with_imap: bool = False, imap_perms: tuple[str, ...] = ("read",)
) -> AsyncIterator[MailService]:
    config = cfg(srv.port, with_imap=with_imap, imap_perms=imap_perms)
    router = AccountRouter(config)
    if with_imap:
        router._connectors["imap"] = Connector(  # pyright: ignore[reportPrivateUsage]
            {"Imap": FakeSession("Imap", {"INBOX": [1, 2, 3]})}
        )
    service = MailService(config, router=router)
    try:
        yield service
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


async def test_list_and_fuzzy_search_in_one_fanout_with_imap():
    with ScriptedPop3Server(messages()) as srv:
        async with service_for(srv, with_imap=True) as svc:
            from universal_email_mcp.mail.imap import SearchCriteria

            page = await svc.list_messages(
                tool="t",
                args={},
                accounts=None,
                folders=None,
                criteria=SearchCriteria(),
                limit=20,
                cursor=None,
            )
            by_acc = {h.account for h in page.hits}
            assert by_acc == {"Old", "Imap"} and page.total == 7 and not page.problems
            assert all(h.summary.ref.is_pop3 for h in page.hits if h.account == "Old")
            # the POP3 mail is newer than the fake IMAP mail, so it comes first
            assert page.hits[0].account == "Old"
            assert "DELE" not in srv.names

            from universal_email_mcp.service import query as query_mod

            q = query_mod.parse("invoce")
            assert q is not None
            page = await svc.query_search(
                tool="t",
                args={},
                accounts=["Old"],
                folders=None,
                criteria=SearchCriteria(),
                query=q,
                threshold=fuzzy.DEFAULT_THRESHOLD,
                limit=10,
                cursor=None,
            )
            subjects = [h.summary.subject for h in page.hits]
            assert "Invoice 2026-17" in subjects and "Lunch on friday" not in subjects[:1]
            q = query_mod.parse("*lunch*")
            assert q is not None
            page = await svc.query_search(
                tool="t",
                args={},
                accounts=["Old"],
                folders=None,
                criteria=SearchCriteria(),
                query=q,
                threshold=fuzzy.DEFAULT_THRESHOLD,
                limit=10,
                cursor=None,
            )
            assert [h.summary.subject for h in page.hits] == ["Lunch on friday"]


async def test_paging_with_cursor_over_pop3():
    from universal_email_mcp.mail.imap import SearchCriteria

    with ScriptedPop3Server(messages()) as srv:
        async with service_for(srv) as svc:
            seen: list[str] = []
            cursor = None
            for _ in range(5):
                page = await svc.list_messages(
                    tool="t",
                    args={},
                    accounts=None,
                    folders=None,
                    criteria=SearchCriteria(),
                    limit=3,
                    cursor=cursor,
                )
                seen += [h.summary.subject for h in page.hits]
                cursor = page.cursor
                if cursor is None:
                    break
            assert len(seen) == 4 and len(set(seen)) == 4
            assert seen[0] == "Re: Invoice 2026-17"  # newest first


async def test_tools_end_to_end_on_pop3():
    with ScriptedPop3Server(messages()) as srv:
        async with service_for(srv) as svc, Client(build_server(svc)) as c:
            tools = {t.name for t in (await c.list_tools()).tools}
            assert "mark_messages" not in tools and "save_draft" not in tools

            md, info = await call(c, "account_info")
            (acc,) = info["accounts"]
            assert acc["kind"] == "pop3" and acc["connected"]
            assert acc["folder_roles"] == {"inbox": "INBOX"}
            assert any("POP3 account" in n for n in acc["notes"])
            assert acc["overview"]["special"][0]["unread"] is None
            assert "4 messages" in md and "0 unread" not in md

            md, data = await call(c, "list_folders")
            assert [f["name"] for f in data["folders"]] == ["INBOX"]
            assert data["folders"][0]["unread"] is None and "POP3 account" in md

            md, data = await call(c, "find_messages", subject="invoice")
            assert [m["subject"] for m in data["messages"]] == [
                "Re: Invoice 2026-17",
                "Invoice 2026-17",
            ]
            assert all(m["unread"] is None for m in data["messages"])
            assert all(m["id"].startswith("p1.") for m in data["messages"])
            _md, data = await call(c, "find_messages", window="this_week")
            assert isinstance(data["messages"], list)

            _md, data = await call(c, "find_messages", has_attachment=True)
            photo = data["messages"][0]
            assert photo["subject"] == "Photos"

            md, msg = await call(c, "get_message", id=photo["id"])
            assert "see attached" in msg["body"]["text"] and msg["message"]["unread"] is None
            (att,) = msg["attachments"]
            assert att["part_id"] == "2" and att["filename"] == "cat.bin"
            assert att.get("download_url") is None and msg["eml_url"] is None
            assert "read state unknown" in md

            r = await c.call_tool("get_attachment", {"id": photo["id"], "attachment": "2"})
            assert not r.is_error
            assert any(getattr(getattr(b, "resource", None), "blob", None) for b in r.content), (
                "binary attachment is returned as an embedded resource"
            )

            _md, inv = await call(c, "find_messages", subject="invoice")
            _md, thread = await call(
                c, "get_message", id=_id_of(inv, "Invoice 2026-17"), thread=True
            )
            assert {m["subject"] for m in thread["thread"]} == {
                "Invoice 2026-17",
                "Re: Invoice 2026-17",
            }

            _md, contacts = await call(c, "find_contacts", query="huber")
            assert contacts["contacts"][0]["email"] == "anna@huber.at"
            assert contacts["contacts"][0]["sent_to"] is None
        assert "DELE" not in srv.names and "RSET" not in srv.names


def _id_of(data: dict[str, Any], subject: str) -> str:
    for m in data["messages"]:
        if m["subject"] == subject:
            return m["id"]
    raise AssertionError(subject)


async def test_thread_within_the_pop3_inbox():
    with ScriptedPop3Server(messages()) as srv:
        async with service_for(srv) as svc:
            first = await svc.get_message(
                (await _first_id(svc, "Invoice 2026-17")), offset=0, max_chars=None
            )
            res = await svc.get_thread(first.id, limit=None)
            assert {h.summary.subject for h in res.hits} == {
                "Invoice 2026-17",
                "Re: Invoice 2026-17",
            }


async def _first_id(svc: MailService, subject: str) -> str:
    from universal_email_mcp.mail.imap import SearchCriteria

    page = await svc.list_messages(
        tool="t",
        args={},
        accounts=None,
        folders=None,
        criteria=SearchCriteria(subject=subject),
        limit=5,
        cursor=None,
    )
    return next(h.summary.id for h in page.hits if h.summary.subject == subject)


async def test_download_links_are_not_offered_for_pop3():
    class Links:
        def attachment_url(self, ref: MessageRef, section: str) -> str | None:
            return "http://127.0.0.1/never"

        def message_url(self, ref: MessageRef) -> str | None:
            return "http://127.0.0.1/never"

    with ScriptedPop3Server(messages()) as srv:
        config = cfg(srv.port)
        svc = MailService(config, download_links=Links())
        try:
            mid = await _first_id(svc, "Photos")
            ref = MessageRef.decode(mid)
            assert svc.attachment_url(ref, "2") is None and svc.message_url(ref) is None
            imap_ref = MessageRef("Imap", "INBOX", 1, 1)
            assert svc.attachment_url(imap_ref, "2") == "http://127.0.0.1/never"
        finally:
            await svc.aclose()


async def test_write_tools_refuse_pop3_ids():
    with ScriptedPop3Server(messages()) as srv:
        async with service_for(
            srv, with_imap=True, imap_perms=("read", "organize", "delete", "drafts")
        ) as svc:
            mid = await _first_id(svc, "Lunch on friday")
            for res in (
                await svc.organize.mark([mid], seen=True, flagged=None),
                await svc.organize.move([mid], to="Archive"),
                await svc.organize.delete([mid]),
            ):
                (out,) = res.outcomes
                assert out.status == "failed" and out.code == "NOT_PERMITTED"
                assert "read-only" in out.message
            assert srv.names.count("RETR") == 0 and "DELE" not in srv.names
            with pytest.raises(NotPermitted, match="read-only"):
                await svc.drafts.save(
                    to=["a@b.org"],
                    cc=None,
                    bcc=None,
                    subject="x",
                    body="y",
                    sender=None,
                    reply_to_id=None,
                    reply_all=False,
                    forward_id=None,
                    draft_id=mid,
                    account=None,
                )
            # a POP3 account addressed by name for a write is refused with the reason
            with pytest.raises(NotPermitted, match="POP3 accounts are read-only"):
                svc.router.account("Old", "organize")


async def test_ids_must_match_their_account_kind():
    with ScriptedPop3Server(messages()) as srv:
        async with service_for(srv, with_imap=True) as svc:
            with pytest.raises(InvalidRef):
                await svc.get_message(
                    MessageRef("Old", "INBOX", 1, 3).encode(), offset=0, max_chars=None
                )
            with pytest.raises(InvalidRef):
                await svc.get_message(
                    MessageRef("Imap", "INBOX", 1, 0, "uid-1").encode(), offset=0, max_chars=None
                )
