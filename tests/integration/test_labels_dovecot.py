"""WP 2b against Dovecot: ``move_messages(to="archive")`` with flat / yearly / monthly
archives, and ``with_conversation`` / ``dry_run`` - through the MCP client."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import format_datetime
from typing import Any

import pytest
from mcp import Client

from universal_email_mcp.config import Config, parse_config

from .conftest import ImapServer, Mailbox
from .test_organize_tools import call, code_of, connect, ids, text

pytestmark = pytest.mark.integration

ME = "me@example.org"
HUBER = "Anna Huber <anna@huber-bau.at>"


def when(year: int, month: int, day: int = 15) -> datetime:
    return datetime(year, month, day, 12, 0, tzinfo=UTC)


def mail(
    subject: str,
    msgid: str,
    *,
    sender: str = HUBER,
    to: str = ME,
    parent: str | None = None,
    references: tuple[str, ...] = (),
    date: datetime | None = None,
) -> bytes:
    head = [
        f"From: {sender}",
        f"To: {to}",
        f"Subject: {subject}",
        f"Message-ID: <{msgid}>",
        f"Date: {format_datetime(date or when(2024, 5))}",
    ]
    if parent:
        head.append(f"In-Reply-To: <{parent}>")
    refs = references or ((parent,) if parent else ())
    if refs:
        head.append("References: " + " ".join(f"<{r}>" for r in refs))
    head += ["MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8"]
    return ("\r\n".join(head) + "\r\n\r\nbody\r\n").encode()


@dataclass(frozen=True)
class Box:
    server: ImapServer
    mb: Mailbox

    def config(self, scheme: str | None = None, **limits: Any) -> Config:
        account: dict[str, Any] = {
            "name": "Work",
            "username": self.mb.user,
            "password_env": "UEM_IT_PASSWORD",
            "tls_verify": False,
            "permissions": ["read", "organize", "delete"],
            "imap": {"host": self.server.host, "port": self.server.imaps_port},
        }
        if scheme:
            account["archive_scheme"] = scheme
        return parse_config(
            {"accounts": [account], "limits": {"account_timeout": 20, **limits}, "policy": {}}
        )

    def put(self, folder: str, raw: bytes, at: datetime | None = None, flags: Any = ()) -> None:
        c = self.mb.admin()
        try:
            c.append(folder, raw, flags=flags, msg_time=at or when(2024, 5))
        finally:
            c.logout()

    def folders(self) -> list[str]:
        c = self.mb.admin()
        try:
            return sorted(name for _flags, _d, name in c.list_folders())
        finally:
            c.logout()

    def make(self, *names: str) -> None:
        c = self.mb.admin()
        try:
            for n in names:
                c.create_folder(n)
        finally:
            c.logout()


@pytest.fixture
def box(imap_server: ImapServer) -> Iterator[Box]:
    mb = Mailbox(imap_server, f"l{uuid.uuid4().hex[:10]}@example.org")
    b = Box(imap_server, mb)
    b.make("Clients", "Clients/Huber", "Trash", "Junk", "Drafts")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("UEM_IT_PASSWORD", imap_server.password)
        yield b


def item(data: dict[str, Any], subject: str) -> dict[str, Any]:
    return next(r for r in data["results"] if r["subject"] == subject)


# ---------------------------------------------------------------- archive schemes


async def test_empty_archive_is_flat_and_creates_nothing(box: Box):
    box.make("Archive")
    box.put("INBOX", mail("A1", "a1@x", date=when(2023, 3)), when(2023, 3))
    async with connect(box.config()) as c:
        got = await ids(c, "Work")
        _md, data = await call(c, "move_messages", ids=[got["A1"]], to="archive")
        r = data["results"][0]
        assert r["status"] == "ok" and r["destination"] == "Archive" and r["new_id"]
        assert any("scheme flat (detected)" in n for n in data["notes"])
        assert (await ids(c, "Work", "Archive"))["A1"] == r["new_id"]
    assert not any(f.startswith("Archive/") for f in box.folders())


async def test_yearly_archive_each_message_goes_to_its_year_and_folders_are_made_once(box: Box):
    box.make("Archive", "Archive/2023")
    for subject, year in (("Y23", 2023), ("Y25a", 2025), ("Y25b", 2025), ("Y24", 2024)):
        box.put("INBOX", mail(subject, f"{subject}@x", date=when(year, 6)), when(year, 6))
    async with connect(box.config()) as c:
        got = await ids(c, "Work")
        _md, data = await call(c, "move_messages", ids=list(got.values()), to="Archive")
        assert data["succeeded"] == 4 and data["failed"] == 0
        assert {r["subject"]: r["destination"] for r in data["results"]} == {
            "Y23": "Archive/2023",
            "Y24": "Archive/2024",
            "Y25a": "Archive/2025",
            "Y25b": "Archive/2025",
        }
        assert all(r["new_id"] for r in data["results"])
        assert set(await ids(c, "Work", "Archive/2025")) == {"Y25a", "Y25b"}
        assert set(await ids(c, "Work", "Archive/2023")) == {"Y23"}
        assert await ids(c, "Work") == {}
        # the new ids work
        _md, msg = await call(c, "get_message", id=item(data, "Y24")["new_id"])
        assert msg["message"]["subject"] == "Y24"
    created = [f for f in box.folders() if f.startswith("Archive/")]
    assert created == ["Archive/2023", "Archive/2024", "Archive/2025"]


async def test_monthly_nested_archive_reuses_unpadded_and_creates_padded(box: Box):
    box.make("Archive", "Archive/2024", "Archive/2024/5")
    box.put("INBOX", mail("May", "may@x", date=when(2024, 5)), when(2024, 5))
    box.put("INBOX", mail("Jul", "jul@x", date=when(2024, 7)), when(2024, 7))
    async with connect(box.config()) as c:
        got = await ids(c, "Work")
        _md, data = await call(c, "move_messages", ids=list(got.values()), to="archive")
        assert {r["subject"]: r["destination"] for r in data["results"]} == {
            "May": "Archive/2024/5",
            "Jul": "Archive/2024/07",
        }
        assert any("monthly (YYYY/MM) (detected)" in n for n in data["notes"])


async def test_monthly_dashed_archive(box: Box):
    box.make("Archive", "Archive/2024-04")
    box.put("INBOX", mail("Sep", "sep@x", date=when(2024, 9)), when(2024, 9))
    async with connect(box.config()) as c:
        got = await ids(c, "Work")
        _md, data = await call(c, "move_messages", ids=list(got.values()), to="archive")
        assert data["results"][0]["destination"] == "Archive/2024-09"


async def test_configured_scheme_overrides_detection(box: Box):
    box.make("Archive")  # empty: detection says flat
    box.put("INBOX", mail("Cfg", "cfg@x", date=when(2022, 11)), when(2022, 11))
    async with connect(box.config("yearly")) as c:
        got = await ids(c, "Work")
        _md, data = await call(c, "move_messages", ids=list(got.values()), to="archive")
        assert data["results"][0]["destination"] == "Archive/2022"
        assert any("(configured)" in n for n in data["notes"])


async def test_no_archive_folder_fails_clearly_and_changes_nothing(box: Box):
    box.put("INBOX", mail("Lost", "lost@x"))
    async with connect(box.config()) as c:
        got = await ids(c, "Work")
        r = await c.call_tool("move_messages", {"ids": list(got.values()), "to": "archive"})
        assert code_of(r) == "NO_ARCHIVE_FOLDER"
        assert "folders.archive" in text(r)
        assert "Lost" in await ids(c, "Work")


async def test_date_header_when_plausible_else_internaldate(box: Box):
    box.make("Archive")
    # migrated: old Date, import-time INTERNALDATE
    box.put("INBOX", mail("Migrated", "mig@x", date=when(2019, 4)), when(2024, 3))
    # forged future Date, ancient Date, and an INTERNALDATE in the future
    box.put("INBOX", mail("FutureDate", "fd@x", date=when(2090, 1)), when(2024, 3))
    box.put("INBOX", mail("Ancient", "anc@x", date=when(1975, 1)), when(2024, 3))
    box.put("INBOX", mail("FutureArrival", "fa@x", date=when(2090, 3)), when(2090, 3))
    async with connect(box.config("yearly")) as c:
        got = await ids(c, "Work")
        _md, data = await call(c, "move_messages", ids=list(got.values()), to="archive")
        dest = {r["subject"]: r["destination"] for r in data["results"]}
        assert dest["Migrated"] == "Archive/2019"
        assert dest["FutureDate"] == "Archive/2024"
        assert dest["Ancient"] == "Archive/2024"
        assert dest["FutureArrival"] == f"Archive/{datetime.now().year}"
    created = [f for f in box.folders() if f.startswith("Archive/")]
    assert all(f.split("/")[1].isdigit() and len(f.split("/")[1]) == 4 for f in created)


async def test_dry_run_footer_lists_the_ids_to_pass_on(box: Box):
    seed_conversation(box)
    async with connect(box.config()) as c:
        got = await ids(c, "Work")
        md, data = await call(
            c,
            "move_messages",
            ids=[got["Angebot"]],
            to="Clients/Huber",
            with_conversation=True,
            dry_run=True,
        )
        planned = [r["id"] for r in data["results"] if r["status"] == "planned"]
        assert len(planned) == 3
        assert "exactly the ids" in md and all(i in md for i in planned)
        # the confirmed list moves as plain ids: no search, same three messages
        _md, done = await call(c, "move_messages", ids=planned, to="Clients/Huber")
        assert done["succeeded"] == 3 and len(done["results"]) == 3


async def test_mail_already_in_the_archive_stays(box: Box):
    box.make("Archive", "Archive/2024")
    box.put("Archive/2024", mail("Filed", "filed@x"))
    async with connect(box.config()) as c:
        got = await ids(c, "Work", "Archive/2024")
        _md, data = await call(c, "move_messages", ids=[got["Filed"]], to="archive")
        r = data["results"][0]
        assert r["status"] == "unchanged" and "already in the archive" in r["message"]
        assert set(await ids(c, "Work", "Archive/2024")) == {"Filed"}


async def test_dry_run_changes_nothing_not_even_folders(box: Box):
    box.make("Archive", "Archive/2023")
    box.put("INBOX", mail("Plan", "plan@x", date=when(2025, 2)), when(2025, 2))
    box.put("INBOX", mail("Old", "old@x", date=when(2023, 2)), when(2023, 2))
    before = box.folders()
    async with connect(box.config()) as c:
        got = await ids(c, "Work")
        md, data = await call(
            c, "move_messages", ids=list(got.values()), to="archive", dry_run=True
        )
        assert data["dry_run"] is True and data["planned"] == 2 and data["succeeded"] == 0
        by = {r["subject"]: r for r in data["results"]}
        assert by["Plan"]["status"] == "planned" and by["Plan"]["destination"] == "Archive/2025"
        assert by["Plan"]["new_id"] is None
        assert by["Old"]["destination"] == "Archive/2023"
        assert "DRY RUN" in md
        assert set(await ids(c, "Work")) == {"Plan", "Old"}
    assert box.folders() == before


async def test_plain_move_dry_run(box: Box):
    box.put("INBOX", mail("Plain", "plain@x"))
    async with connect(box.config()) as c:
        got = await ids(c, "Work")
        _md, data = await call(
            c, "move_messages", ids=list(got.values()), to="Clients/Huber", dry_run=True
        )
        assert data["results"][0]["status"] == "planned"
        assert set(await ids(c, "Work")) == {"Plain"}
        assert await ids(c, "Work", "Clients/Huber") == {}


# ---------------------------------------------------------------- conversations


def seed_conversation(box: Box) -> None:
    """Root in INBOX, my answer in Sent, a follow-up in INBOX; a reply the user filed
    in Projects/X; copies in Trash, Junk and Drafts; and an unrelated mail."""
    box.make("Sent", "Projects", "Projects/X")
    box.put("INBOX", mail("Angebot", "root@x", date=when(2024, 5, 2)), when(2024, 5, 2))
    box.put(
        "Sent",
        mail("Re: Angebot", "ans@x", sender=ME, to=HUBER, parent="root@x", date=when(2024, 5, 3)),
        when(2024, 5, 3),
        flags=[b"\\Seen"],
    )
    box.put(
        "INBOX",
        mail(
            "Re: Angebot",
            "more@x",
            parent="ans@x",
            references=("root@x", "ans@x"),
            date=when(2024, 5, 4),
        ),
        when(2024, 5, 4),
    )
    box.put(
        "Projects/X",
        mail(
            "Re: Angebot (filed)",
            "filed@x",
            parent="more@x",
            references=("root@x", "ans@x", "more@x"),
            date=when(2024, 5, 5),
        ),
        when(2024, 5, 5),
    )
    for folder in ("Trash", "Junk", "Drafts"):
        box.put(
            folder,
            mail(
                f"Re: Angebot ({folder})",
                f"{folder.lower()}@x",
                parent="root@x",
                date=when(2024, 5, 6),
            ),
            when(2024, 5, 6),
        )
    box.put("INBOX", mail("Unrelated", "unrelated@x", date=when(2024, 5, 7)), when(2024, 5, 7))


async def conversation_move(c: Client, box: Box, **kw: Any) -> dict[str, Any]:
    got = await ids(c, "Work")
    _md, data = await call(
        c, "move_messages", ids=[got["Angebot"]], to="Clients/Huber", with_conversation=True, **kw
    )
    return data


async def test_conversation_moves_inbox_and_sent_and_leaves_the_rest(box: Box):
    seed_conversation(box)
    async with connect(box.config()) as c:
        data = await conversation_move(c, box)
        moved = {r["subject"]: r for r in data["results"] if r["status"] == "ok"}
        assert set(moved) == {"Angebot", "Re: Angebot"}  # root, Sent answer, INBOX follow-up
        assert data["succeeded"] == 3
        assert all(r["new_id"] for r in moved.values())
        members = [r for r in data["results"] if r["conversation_member"]]
        assert {m["subject"] for m in members} == {
            "Re: Angebot",
            "Re: Angebot (filed)",
        }
        filed = item(data, "Re: Angebot (filed)")
        assert filed["status"] == "unchanged" and "left in" in filed["message"]
        assert "Projects/X" in filed["message"]
        # nothing from Trash/Junk/Drafts is even listed, and nothing there moved
        assert all("(Trash)" not in r["subject"] for r in data["results"])
        for folder, subject in (
            ("Trash", "Re: Angebot (Trash)"),
            ("Junk", "Re: Angebot (Junk)"),
            ("Drafts", "Re: Angebot (Drafts)"),
        ):
            assert subject in await ids(c, "Work", folder)
        assert set(await ids(c, "Work")) == {"Unrelated"}
        assert set(await ids(c, "Work", "Clients/Huber")) == {"Angebot", "Re: Angebot"}
        assert set(await ids(c, "Work", "Sent")) == set()
        assert "Re: Angebot (filed)" in await ids(c, "Work", "Projects/X")


async def test_conversation_dry_run_lists_and_changes_nothing(box: Box):
    seed_conversation(box)
    async with connect(box.config()) as c:
        data = await conversation_move(c, box, dry_run=True)
        assert data["dry_run"] and data["planned"] == 3
        assert {r["subject"] for r in data["results"] if r["status"] == "planned"} == {
            "Angebot",
            "Re: Angebot",
        }
        assert all(r["new_id"] is None for r in data["results"])
        assert "Angebot" in await ids(c, "Work")
        assert "Re: Angebot" in await ids(c, "Work", "Sent")
        assert await ids(c, "Work", "Clients/Huber") == {}


async def test_conversation_members_in_the_destination_are_unchanged(box: Box):
    seed_conversation(box)
    async with connect(box.config()) as c:
        await conversation_move(c, box)
        # the same conversation again, from its new place: nothing is left to move
        got = await ids(c, "Work", "Clients/Huber")
        _md, data = await call(
            c,
            "move_messages",
            ids=[got["Angebot"]],
            to="Clients/Huber",
            with_conversation=True,
        )
        assert data["succeeded"] == 0 and data["failed"] == 0


async def test_conversation_into_the_archive_follows_each_message_date(box: Box):
    seed_conversation(box)
    box.make("Archive", "Archive/2023")
    box.put(
        "Sent",
        mail(
            "Re: Angebot",
            "late@x",
            sender=ME,
            to=HUBER,
            parent="more@x",
            references=("root@x", "ans@x", "more@x"),
            date=when(2025, 1, 9),
        ),
        when(2025, 1, 9),
    )
    async with connect(box.config()) as c:
        got = await ids(c, "Work")
        _md, data = await call(
            c, "move_messages", ids=[got["Angebot"]], to="archive", with_conversation=True
        )
        assert data["succeeded"] == 4
        dests = sorted(r["destination"] for r in data["results"] if r["status"] == "ok")
        assert dests == ["Archive/2024", "Archive/2024", "Archive/2024", "Archive/2025"]


async def test_hostile_reply_cannot_pull_unrelated_mail_into_a_conversation_move(box: Box):
    box.make("Sent")
    box.put("INBOX", mail("Angebot", "root@x", date=when(2024, 5, 2)), when(2024, 5, 2))
    box.put("INBOX", mail("Secret thing", "victim@x", date=when(2024, 4, 1)), when(2024, 4, 1))
    box.put(
        "INBOX",
        mail("Reply to the victim", "vreply@x", parent="victim@x", date=when(2024, 4, 2)),
        when(2024, 4, 2),
    )
    # a reply to the root whose References also name the unrelated mail
    box.put(
        "INBOX",
        mail(
            "Re: Angebot (hostile)",
            "hostile@x",
            sender="Evil <e@attacker.test>",
            parent="root@x",
            references=("victim@x", "root@x"),
            date=when(2024, 5, 8),
        ),
        when(2024, 5, 8),
    )
    # a forged copy of the victim's Message-ID that replies to the root
    box.put(
        "INBOX",
        mail(
            "Forged id",
            "victim@x",
            sender="Evil <e@attacker.test>",
            parent="root@x",
            date=when(2024, 5, 9),
        ),
        when(2024, 5, 9),
    )
    async with connect(box.config()) as c:
        got = await ids(c, "Work")
        _md, data = await call(
            c,
            "move_messages",
            ids=[got["Angebot"]],
            to="Clients/Huber",
            with_conversation=True,
            dry_run=True,
        )
        subjects = {r["subject"] for r in data["results"]}
        assert "Secret thing" not in subjects and "Reply to the victim" not in subjects
        assert {"Angebot", "Re: Angebot (hostile)"} <= subjects


async def test_batch_cap_counts_conversation_members_and_changes_nothing(box: Box):
    seed_conversation(box)
    async with connect(box.config(max_batch_messages=2)) as c:
        got = await ids(c, "Work")
        r = await c.call_tool(
            "move_messages",
            {"ids": [got["Angebot"]], "to": "Clients/Huber", "with_conversation": True},
        )
        assert r.is_error and "INVALID_ARGUMENT" in text(r) and "limit is 2" in text(r)
        assert "Angebot" in await ids(c, "Work")
        assert await ids(c, "Work", "Clients/Huber") == {}
