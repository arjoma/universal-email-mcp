"""The sandbox corpus seeded into Dovecot, used through the generated config and the tools.

Same seeding and config code as ``scripts/dev_mailbox.py``, but on the test
server with fresh user names, so it also runs in CI (no named container).
Every message is fetched once; the hostile ones must come out escaped and fenced.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp.types import CallToolResult, TextContent

from tests.dovecot import admin_client
from tests.sandbox import (
    HOSTILE_FOLDER,
    PRIVATE,
    WORK,
    SeedMail,
    build_corpus,
    render_config,
    seed,
)
from universal_email_mcp.config import Config, load_config
from universal_email_mcp.server.app import build_server
from universal_email_mcp.service.mail import MailService

from .conftest import ImapServer

pytestmark = pytest.mark.integration

PASSWORD_ENV = "UEM_IT_SANDBOX_PASSWORD"
# Things a Markdown renderer would turn into a fetch, a link or markup.
ACTIVE = ("](", "<img", "<script", "https://", "http://", "javascript:")


@dataclass(frozen=True)
class Sandbox:
    config: Config
    corpus: list[SeedMail]


@pytest.fixture(scope="module")
def sandbox(imap_server: ImapServer, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Sandbox]:
    users = {
        WORK: f"sw{uuid.uuid4().hex[:10]}@example.org",
        PRIVATE: f"sp{uuid.uuid4().hex[:10]}@example.org",
    }
    corpus = build_corpus()
    seed(
        lambda user: admin_client(
            imap_server.host, imap_server.imaps_port, user, imap_server.password
        ),
        users,
        corpus,
    )
    path: Path = tmp_path_factory.mktemp("sandbox") / "sandbox.local.toml"
    path.write_text(
        render_config(
            imap_server.host, imap_server.imaps_port, users=users, password_env=PASSWORD_ENV
        )
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(PASSWORD_ENV, imap_server.password)
        yield Sandbox(load_config(path), corpus)


@asynccontextmanager
async def connect(config: Config) -> AsyncIterator[Client]:
    service = MailService(config)
    try:
        async with Client(build_server(service)) as c:
            yield c
    finally:
        await service.aclose()


async def call(c: Client, tool: str, **args: Any) -> tuple[str, dict[str, Any]]:
    r: CallToolResult = await c.call_tool(tool, args)
    block = r.content[0]
    assert isinstance(block, TextContent)
    assert not r.is_error, block.text
    assert r.structured_content is not None
    return block.text, r.structured_content


def subjects(data: dict[str, Any]) -> list[str]:
    return [m["subject"] for m in data["messages"]]


def thread_subjects(data: dict[str, Any]) -> list[str]:
    return [m["subject"] for m in data["thread"]]


async def test_folder_overview_and_hostile_folder_name(sandbox: Sandbox):
    async with connect(sandbox.config) as client:
        md, data = await call(client, "list_folders", accounts=[WORK])
        clients = next(n for n in data["folders"] if n["name"] == "Clients")
        assert clients["subfolders"] >= 100 and data["total"] < 20  # top level only
        assert HOSTILE_FOLDER.split(" ![")[0] in md
        assert not any(a in md for a in ACTIVE) and "`rm`" not in md
        assert "Rechnungen exe.fdp" in md and "\u202e" not in md  # bidi override dropped
        _md, data = await call(
            client, "find_messages", folders=["clients/mueller consulting"], since="2000-01-01"
        )
        assert subjects(data) == ["Workshop Q4"]


async def test_folder_drill_down_and_query(sandbox: Sandbox):
    async with connect(sandbox.config) as client:
        _md, data = await call(client, "list_folders", accounts=[WORK], parent="Kunden")
        assert data["parent"] == ["Clients"] and data["total"] >= 100
        assert len(data["folders"]) == 50 and data["next_cursor"]
        assert all(n["path"].count("/") == 1 for n in data["folders"])
        _md, data = await call(client, "list_folders", accounts=[WORK], query="müller*")
        paths = {n["path"] for n in data["folders"]}
        assert {"Clients/Müller & Söhne", "Clients/Mueller Consulting"} <= paths
        assert all("ller" in p for p in paths)
        _md, data = await call(client, "list_folders", accounts=[WORK], query="clients/*/2026")
        assert data["folders"] and all(n["path"].endswith("/2026") for n in data["folders"])
        md, data = await call(client, "list_folders", accounts=[WORK], query="Huber Bauu*")
        assert data["folders"] == [] and "Clients/Huber Bau" in data["similar"]
        assert not any(a in md for a in ACTIVE)


async def test_contacts_overview_and_search(sandbox: Sandbox):
    async with connect(sandbox.config) as client:
        md, data = await call(client, "find_contacts")
        assert data["mode"] == "overview" and 0 < len(data["contacts"]) <= 20
        assert not any(a in md for a in ACTIVE)
        _md, data = await call(client, "find_contacts", query="Jurgen Muller")
        emails = [c["email"] for c in data["contacts"]]
        assert "juergen.mueller@mueller-soehne.example" in emails[:2]
        md, data = await call(client, "find_contacts", query="*attacker*")
        assert data["contacts"] and not any(a in md for a in ACTIVE)


async def test_today_and_cross_account_fuzzy(sandbox: Sandbox):
    async with connect(sandbox.config) as client:
        _md, data = await call(client, "find_messages", window="today")
        assert "Kurze Frage zum Logo" in subjects(data)
        _md, data = await call(client, "find_messages", query="Mueller")
        assert {"Termin nächste Woche", "Radtour Sonntag?"} <= set(subjects(data))
        assert {m["account"] for m in data["messages"]} == {WORK, PRIVATE}


async def test_every_message_renders_safely(sandbox: Sandbox):
    hostile_subjects = 0
    async with connect(sandbox.config) as client:
        folders: list[tuple[str, str]] = []
        page_cursor: str | None = None
        while True:  # every folder at any level, a page at a time (counts per page)
            md, page = await call(
                client,
                "list_folders",
                accounts=[WORK, PRIVATE],
                query="*",
                **({"cursor": page_cursor} if page_cursor else {}),
            )
            assert not any(a in md for a in ACTIVE), md
            assert not page["counts_capped"]
            folders += [(n["account"], n["path"]) for n in page["folders"] if n["messages"]]
            if not (page_cursor := page["next_cursor"]):
                break
        seen = 0
        for account, folder in folders:
            listed: list[dict[str, Any]] = []
            cursor: str | None = None
            while True:  # INBOX is close to the page cap (max_results 50)
                md, data = await call(
                    client,
                    "find_messages",
                    accounts=[account],
                    folders=[folder],
                    since="2000-01-01",
                    limit=50,
                    **({"cursor": cursor} if cursor else {}),
                )
                assert not any(a in md for a in ACTIVE), (folder, md)
                listed += data["messages"]
                if not (cursor := data.get("next_cursor")):
                    break
            for m in listed:
                md, msg = await call(client, "get_message", id=m["id"])
                seen += 1
                body = msg["body"]["text"]
                if msg["body"]["source"] == "unparseable":  # the MIME bomb: headers only, no text
                    assert m["subject"] == "Twelve thousand empty parts" and not body
                else:
                    nonce = re.search(r'nonce="([0-9a-f]+)"', body)
                    assert nonce and body.count(nonce.group(1)) == 2, m["subject"]
                for form in (md, body):
                    assert not any(a in form for a in ACTIVE), (m["subject"], form[:2000])
                hostile_subjects += "attacker" in str(m["from"])
        assert seen == len(sandbox.corpus)
    assert hostile_subjects >= 10


async def test_oversized_mail_is_paged_and_truncated(sandbox: Sandbox):
    async with connect(sandbox.config) as client:
        _md, data = await call(client, "find_messages", subject="Protokoll", accounts=[WORK])
        _md, msg = await call(client, "get_message", id=data["messages"][0]["id"])
        assert msg["body"]["length"] == sandbox.config.limits.max_body_chars
        assert msg["body"]["next_offset"] is not None
        _md, data = await call(client, "find_messages", subject="Baustelle", accounts=[WORK])
        md, _msg = await call(client, "get_message", id=data["messages"][0]["id"])
        assert "only its beginning was read" in md


async def test_duplicate_message_id_does_not_displace_original(sandbox: Sandbox):
    async with connect(sandbox.config) as client:
        _md, data = await call(client, "find_messages", query="Bankverbindung", accounts=[WORK])
        _md, thread = await call(client, "get_message", id=data["messages"][0]["id"], thread=True)
    # Outside the client context, which would wrap the failure in an ExceptionGroup.
    assert "Angebot Website-Relaunch" in thread_subjects(thread)
    # The forged copy is kept too, and both are marked.
    shared = [m for m in thread["thread"] if m["shared_message_id"]]
    assert len(shared) == 2 and any("same Message-ID" in n for n in thread["notes"])


async def test_threading_loops_and_reference_bomb_terminate(sandbox: Sandbox):
    threads: dict[str, list[str]] = {}
    async with connect(sandbox.config) as client:
        _md, data = await call(
            client, "find_messages", **{"from": "loop@attacker.test"}, accounts=[WORK]
        )
        for m in data["messages"]:
            _md, thread = await call(client, "get_message", id=m["id"], thread=True)
            threads[m["subject"]] = sorted(thread_subjects(thread))
        _md, data = await call(client, "find_messages", subject="Long thread", accounts=[WORK])
        _md, bomb = await call(client, "get_message", id=data["messages"][0]["id"], thread=True)
        _md, data = await call(client, "find_messages", query="minimal message", accounts=[WORK])
        _md, alone = await call(client, "get_message", id=data["messages"][0]["id"], thread=True)
    cycle = ["Re: Chicken or egg (A)", "Re: Chicken or egg (B)"]
    assert threads == {
        "Re: Re: Re: I am my own parent": ["Re: Re: Re: I am my own parent"],
        cycle[0]: cycle,
        cycle[1]: cycle,
    }
    # 5001 References (one of them real) join the real thread, nothing more.
    assert "Re: Long thread" in thread_subjects(bomb) and len(bomb["thread"]) < 15
    assert thread_subjects(alone) == ["No sender, no date, no Message-ID"]


async def test_utf7_body_is_decoded_and_defanged(sandbox: Sandbox):
    async with connect(sandbox.config) as client:
        _md, data = await call(client, "find_messages", subject="Legacy charset", accounts=[WORK])
        md, msg = await call(client, "get_message", id=data["messages"][0]["id"])
    body = msg["body"]["text"]
    assert "+ADw-" not in body and "alert(1)" in body  # decoded, not shown as UTF-7
    for form in (md, body):
        assert not any(a in form for a in ACTIVE), form


async def test_wide_multipart_does_not_hide_text_parts(sandbox: Sandbox):
    async with connect(sandbox.config) as client:
        _md, data = await call(client, "find_messages", subject="2000 parts", accounts=[WORK])
        md, msg = await call(client, "get_message", id=data["messages"][0]["id"])
    assert "part 1999" in msg["body"]["text"] or msg["attachments"], md
    body = msg["body"]["text"]
    assert "part 0" in body and "part 99" in body and "──── part 2 (text) ────" in body
    assert any("2000 text parts" in n for n in msg["notes"]) and "2000 text parts" in md
