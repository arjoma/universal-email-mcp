"""Write operations of :class:`ImapSession` against a real Dovecot server.

Every test gets its own fresh mailbox (the server accepts any user name), because
these tests change it.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from universal_email_mcp.errors import (
    FolderNotFound,
    InvalidArgument,
    NotPermitted,
    UidValidityChanged,
    UnsupportedByServer,
)
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.models import FolderInfo

from .conftest import ImapServer, Mailbox, _msg  # pyright: ignore[reportPrivateUsage]

pytestmark = pytest.mark.integration


@pytest.fixture
def box(imap_server: ImapServer) -> Iterator[Mailbox]:
    mb = Mailbox(imap_server, f"o{uuid.uuid4().hex[:12]}@example.org")
    c = mb.admin()
    try:
        for n in range(1, 5):
            c.append("INBOX", _msg(f"Mail {n}", "Carol <carol@example.net>", f"body {n}"))
        for folder in ("Zielordner", "Trash"):
            c.create_folder(folder)
    finally:
        c.logout()
    yield mb


@pytest.fixture
def session(box: Mailbox) -> Iterator[ImapSession]:
    s = box.session()
    yield s
    s.close()


def inbox(session: ImapSession) -> tuple[int, list[int]]:
    r = session.search("INBOX")
    return r.uidvalidity, sorted(r.uids)


def flags(session: ImapSession, uids: list[int]) -> dict[int, tuple[str, ...]]:
    """Flags without \\Recent (which depends on the session, not the message)."""
    got = session.fetch_flags("INBOX", uids)
    return {u: tuple(f for f in fl if f != "\\Recent") for u, fl in got.items()}


def subjects(session: ImapSession, folder: str) -> list[str]:
    r = session.search(folder)
    return [s.subject for s in session.fetch_summaries(folder, sorted(r.uids))]


def without(session: ImapSession, *caps: str) -> None:
    kept = tuple(c for c in session.capabilities if c not in caps)
    session.login_info = dataclasses.replace(session.login_info, capabilities=kept)


# ---------------------------------------------------------------- flags


def test_set_flags_adds_and_removes_only_the_named_flags(session: ImapSession):
    validity, uids = inbox(session)
    res = session.set_flags("INBOX", uids[:2], uidvalidity=validity, add=["\\Seen", "\\Flagged"])
    assert res.missing == ()
    assert all({"\\Seen", "\\Flagged"} <= set(f) for f in res.flags.values())
    res = session.set_flags("INBOX", uids[:2], uidvalidity=validity, remove=["\\Flagged"])
    assert all("\\Seen" in f and "\\Flagged" not in f for f in res.flags.values())
    # untouched messages keep their (empty) flags
    assert flags(session, uids[2:]) == {u: () for u in uids[2:]}


def test_set_flags_reports_missing_uids_and_changes_the_rest(session: ImapSession):
    validity, uids = inbox(session)
    res = session.set_flags("INBOX", [uids[0], 9999], uidvalidity=validity, add=["\\Seen"])
    assert res.missing == (9999,) and set(res.flags) == {uids[0]}


def test_set_flags_refuses_other_flags(session: ImapSession):
    validity, uids = inbox(session)
    for bad in ("\\Deleted", "\\Answered", "$Phishing", "\\Seen \\Deleted"):
        with pytest.raises(InvalidArgument):
            session.set_flags("INBOX", uids, uidvalidity=validity, add=[bad])
    assert flags(session, uids) == {u: () for u in uids}


def test_stale_uidvalidity_changes_nothing(session: ImapSession):
    validity, uids = inbox(session)
    with pytest.raises(UidValidityChanged):
        session.set_flags("INBOX", uids, uidvalidity=validity + 1, add=["\\Seen"])
    with pytest.raises(UidValidityChanged):
        session.move_messages("INBOX", uids, "Zielordner", uidvalidity=validity + 1)
    assert flags(session, uids) == {u: () for u in uids}
    assert subjects(session, "Zielordner") == []


def test_unknown_source_folder(session: ImapSession):
    with pytest.raises(FolderNotFound):
        session.set_flags("Gibt es nicht", [1], uidvalidity=1, add=["\\Seen"])


# ---------------------------------------------------------------- move


def test_move_with_move_command_returns_new_uids(session: ImapSession):
    assert session.has("MOVE")
    validity, uids = inbox(session)
    res = session.move_messages("INBOX", uids[:2], "Zielordner", uidvalidity=validity)
    assert res.method == "move" and res.missing == () and res.copied_only == ()
    assert set(res.moved) == set(uids[:2]) and res.dest_uidvalidity
    assert all(isinstance(n, int) for n in res.moved.values())
    assert sorted(subjects(session, "Zielordner")) == ["Mail 1", "Mail 2"]
    assert sorted(subjects(session, "INBOX")) == ["Mail 3", "Mail 4"]
    # the reported new UIDs really name those messages
    moved = session.fetch_summaries(
        "Zielordner", sorted(n for n in res.moved.values() if n), uidvalidity=res.dest_uidvalidity
    )
    assert {s.subject for s in moved} == {"Mail 1", "Mail 2"}


def test_move_fallback_copy_and_uid_expunge(session: ImapSession):
    without(session, "MOVE")
    assert not session.has("MOVE") and session.has("UIDPLUS")
    validity, uids = inbox(session)
    res = session.move_messages("INBOX", uids[:2], "Zielordner", uidvalidity=validity)
    assert res.method == "copy" and res.copied_only == ()
    assert set(res.moved) == set(uids[:2]) and all(res.moved.values())
    assert sorted(subjects(session, "Zielordner")) == ["Mail 1", "Mail 2"]
    assert sorted(subjects(session, "INBOX")) == ["Mail 3", "Mail 4"]


def test_move_fallback_never_expunges_other_deleted_mail(box: Mailbox, session: ImapSession):
    """A plain EXPUNGE would also remove Mail 4, which somebody flagged \\Deleted."""
    without(session, "MOVE")
    validity, uids = inbox(session)
    c: Any = box.admin()
    try:
        c.select_folder("INBOX")
        c.add_flags([uids[3]], [b"\\Deleted"], silent=True)
    finally:
        c.logout()
    session.move_messages("INBOX", uids[:2], "Zielordner", uidvalidity=validity)
    c = box.admin()
    try:
        c.select_folder("INBOX", readonly=True)
        left = c.search(["ALL"])
        assert uids[3] in left and uids[2] in left and len(left) == 2
        assert "\\Deleted" in {x.decode() for x in c.get_flags([uids[3]])[uids[3]]}
    finally:
        c.logout()


def test_move_refused_without_move_and_uidplus(session: ImapSession):
    without(session, "MOVE", "UIDPLUS")
    validity, uids = inbox(session)
    with pytest.raises(UnsupportedByServer):
        session.move_messages("INBOX", uids, "Zielordner", uidvalidity=validity)
    assert inbox(session)[1] == uids and subjects(session, "Zielordner") == []


def test_move_missing_uids_and_nothing_left(session: ImapSession):
    validity, uids = inbox(session)
    res = session.move_messages("INBOX", [uids[0], 4242], "Zielordner", uidvalidity=validity)
    assert res.missing == (4242,) and set(res.moved) == {uids[0]}
    res = session.move_messages("INBOX", [uids[0]], "Zielordner", uidvalidity=validity)
    assert res.method == "none" and res.moved == {} and res.missing == (uids[0],)


def test_move_to_missing_folder_and_to_itself(session: ImapSession):
    validity, uids = inbox(session)
    with pytest.raises(FolderNotFound):
        session.move_messages("INBOX", uids, "Nicht da", uidvalidity=validity)
    with pytest.raises(InvalidArgument):
        session.move_messages("INBOX", uids, "INBOX", uidvalidity=validity)
    assert inbox(session)[1] == uids


def test_fallback_copy_to_missing_folder_leaves_the_source_alone(session: ImapSession):
    without(session, "MOVE")
    validity, uids = inbox(session)
    with pytest.raises(FolderNotFound):
        session.move_messages("INBOX", uids, "Nicht da", uidvalidity=validity)
    assert inbox(session)[1] == uids


@pytest.mark.parametrize(
    "dest",
    [
        'Zielordner" INBOX',  # quote injection into the command line
        "Ziel\\ordner",
        "Ziel*",
        "Ziel%",
    ],
)
def test_destination_names_are_quoted_not_interpreted(session: ImapSession, dest: str):
    validity, uids = inbox(session)
    with pytest.raises((FolderNotFound, InvalidArgument)):
        session.move_messages("INBOX", uids, dest, uidvalidity=validity)
    assert inbox(session)[1] == uids


def test_foreign_namespaces_are_refused(session: ImapSession):
    validity, uids = inbox(session)
    session._foreign = ("Other Users/", "#shared/")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(NotPermitted):
        session.move_messages("INBOX", uids, "Other Users/bob/INBOX", uidvalidity=validity)
    with pytest.raises(NotPermitted):
        session.set_flags("#shared/x", uids, uidvalidity=validity, add=["\\Seen"])
    with pytest.raises(NotPermitted):
        session.create_folder("Other Users/bob/New")
    assert session.is_foreign("#shared") and not session.is_foreign("Shared Stuff")


# ---------------------------------------------------------------- create folder


def names(session: ImapSession) -> set[str]:
    return {f.display_name for f in session.list_folders(refresh=True)}


def subscribed(box: Mailbox) -> set[str]:
    c: Any = box.admin()
    try:
        return {n.decode() if isinstance(n, bytes) else n for _f, _d, n in c.list_sub_folders()}
    finally:
        c.logout()


def test_create_folder_nested_umlaut_and_subscribed(box: Mailbox, session: ImapSession):
    assert session.create_folder("Kunden") is True
    assert session.create_folder("Kunden/M&APw-ller") is True  # Müller in modified UTF-7
    assert session.create_folder("R&-D") is True  # a literal ampersand
    found = names(session)
    assert {"Kunden", "Kunden/Müller", "R&D"} <= found
    assert {"Kunden", "Kunden/Müller", "R&D"} <= subscribed(box)
    assert session.subscribe_failed == []
    assert session.create_folder("Kunden") is False  # existing: no error


def test_created_folder_accepts_mail(session: ImapSession):
    session.create_folder("Neu")
    validity, uids = inbox(session)
    res = session.move_messages("INBOX", uids[:1], "Neu", uidvalidity=validity)
    assert len(res.moved) == 1 and subjects(session, "Neu") == ["Mail 1"]


def test_folder_list_shows_roles(session: ImapSession):
    trash = session.folder_for_role("trash")
    assert isinstance(trash, FolderInfo) and trash.name == "Trash"
