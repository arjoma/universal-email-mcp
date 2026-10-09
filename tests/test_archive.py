"""Archive scheme detection, archive dates, conversation-move membership, the
configuration key and the conversation search's time budget."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

import pytest

from tests.fakes import FakeSession, summary
from tests.test_service import _msg, _service  # pyright: ignore[reportPrivateUsage]
from universal_email_mcp.config import parse_config
from universal_email_mcp.errors import ConfigError
from universal_email_mcp.models import MessageSummary
from universal_email_mcp.service import archive, mail
from universal_email_mcp.service.mail import move_members

NOW = datetime(2026, 10, 9, 12, 0)


def paths(*names: str) -> list[tuple[str, ...]]:
    return [tuple(n.split("/")) for n in names]


@pytest.mark.parametrize(
    ("children", "scheme", "form"),
    [
        ([], "flat", "nested"),
        (paths("Taxes", "Misc/x"), "flat", "nested"),
        (paths("2024", "2025"), "yearly", "nested"),
        (paths("2025", "2025/10", "2025/9"), "monthly", "nested"),
        (paths("2025-09", "2025-10"), "monthly", "dashed"),
        (paths("2025.10"), "monthly", "dashed"),
        (paths("2025", "2025/13", "2025/ab"), "yearly", "nested"),  # not months
        (paths("0099", "20250", "٢٠٢٥"), "flat", "nested"),  # only ASCII years 19xx/20xx
    ],
)
def test_detect(children: list[tuple[str, ...]], scheme: str, form: str):
    got = archive.detect(children)
    assert (got.scheme, got.month_form) == (scheme, form)


def test_configured_scheme_wins_but_keeps_the_month_form():
    dashed = paths("2025-10")
    assert archive.layout_for("yearly", dashed).scheme == "yearly"
    assert archive.layout_for("flat", paths("2025")).scheme == "flat"
    monthly = archive.layout_for("monthly", dashed)
    assert (monthly.scheme, monthly.month_form, monthly.detected) == ("monthly", "dashed", False)
    assert archive.layout_for("monthly", []).month_form == "nested"
    assert archive.layout_for("auto", paths("2025")).scheme == "yearly"


def test_relative_path_is_built_from_integers():
    when = datetime(2025, 3, 4)
    assert archive.relative_path(archive.ArchiveLayout("flat"), when) == ()
    assert archive.relative_path(archive.ArchiveLayout("yearly"), when) == ("2025",)
    assert archive.relative_path(archive.ArchiveLayout("monthly"), when) == ("2025", "03")
    dashed = archive.ArchiveLayout("monthly", "dashed")
    assert archive.relative_path(dashed, when) == ("2025-03",)


def test_canon_level_ignores_padding_and_case():
    assert archive.canon_level("09") == archive.canon_level("9")
    assert archive.canon_level("2025-09") == archive.canon_level("2025-9")
    assert archive.canon_level("Huber") == archive.canon_level("huber")


def _dated(received: datetime | None, date: datetime | None) -> MessageSummary:
    return replace(summary("A", "INBOX", 1), received=received, date=date)


def test_archive_moment_prefers_a_plausible_date_header():
    # migrated mail: old Date, import-time INTERNALDATE -> the Date year
    assert archive.archive_moment(
        _dated(datetime(2026, 9, 1), datetime(2019, 4, 2)), NOW
    ) == datetime(2019, 4, 2)
    # Date up to a day after arrival is fine (time zones)
    d = datetime(2026, 9, 2, 1)
    assert archive.archive_moment(_dated(datetime(2026, 9, 1, 12), d), NOW) == d


def test_archive_moment_distrusts_future_and_ancient_dates():
    received = datetime(2024, 3, 3, 10)
    assert archive.archive_moment(_dated(received, datetime(2031, 1, 1)), NOW) == received
    assert archive.archive_moment(_dated(received, datetime(1970, 1, 1)), NOW) == received
    assert archive.archive_moment(_dated(received, datetime(2024, 3, 5)), NOW) == received


def test_archive_moment_falls_back_and_clamps():
    assert archive.archive_moment(_dated(None, datetime(2022, 5, 1)), NOW) == datetime(2022, 5, 1)
    assert archive.archive_moment(_dated(datetime(1970, 1, 1), None), NOW) == NOW
    assert archive.archive_moment(_dated(None, None), NOW) == NOW
    assert archive.archive_moment(_dated(datetime(2090, 1, 1), datetime(2090, 1, 1)), NOW) == NOW
    assert archive.archive_moment(_dated(None, datetime(2090, 1, 1)), NOW) == NOW


# ---------------------------------------------------------------- config


def _cfg(extra: dict[str, object]):
    return parse_config(
        {
            "accounts": [
                {
                    "name": "W",
                    "username": "u",
                    "password_env": "X",
                    "server": "mail.example.org",
                    **extra,
                }
            ]
        }
    )


def test_archive_scheme_config():
    assert _cfg({}).accounts[0].archive_scheme == "auto"
    assert _cfg({"archive_scheme": "monthly"}).accounts[0].archive_scheme == "monthly"
    with pytest.raises(ConfigError, match="archive_scheme"):
        _cfg({"archive_scheme": "weekly"})


# ---------------------------------------------------------------- move_members


def _m(uid: int, msgid: str, parent: str | None = None, refs: tuple[str, ...] = (), hours: int = 0):
    base = _msg("INBOX", uid, hours=hours or uid, msgid=msgid, subject=msgid)
    return replace(
        base, in_reply_to=parent, references=refs or ((parent,) if parent else ()), message_id=msgid
    )


def _ids(members: list[MessageSummary]) -> set[str]:
    return {m.message_id or "" for m in members}


def test_move_members_follows_replies_down_and_ancestors_up():
    root = _m(2, "<b@x>", "<a@x>")
    msgs = [
        _m(1, "<a@x>"),
        root,
        _m(3, "<c@x>", "<b@x>", ("<a@x>", "<b@x>")),
        _m(4, "<z@x>"),  # unrelated
    ]
    assert _ids(move_members(root, msgs)) == {"<a@x>", "<b@x>", "<c@x>"}


def test_move_members_hostile_references_do_not_pivot_upward():
    root = _m(1, "<r@x>")
    victim = _m(2, "<v@x>")
    victim_reply = _m(3, "<vr@x>", "<v@x>")
    hostile = _m(4, "<h@x>", "<r@x>", ("<v@x>", "<r@x>"))
    got = _ids(move_members(root, [root, victim, victim_reply, hostile]))
    assert got == {"<r@x>", "<h@x>"}


def test_move_members_forged_claimant_of_an_owned_id_does_not_extend_the_set():
    root = _m(1, "<r@x>")
    real = _m(2, "<p@x>", "<r@x>", hours=2)
    forged = _m(3, "<p@x>", "<r@x>", ("<evil@x>",), hours=9)  # later claimant of <p@x>
    evil = _m(4, "<evil@x>")
    got = move_members(root, [root, real, forged, evil])
    assert "<evil@x>" not in _ids(got)
    assert len(got) == 3  # root, genuine reply and the forged reply (it does reply to root)


def test_move_members_identical_copy_comes_along():
    root = _m(1, "<r@x>")
    copy = replace(root, ref=replace(root.ref, folder="Archive", uid=7))
    assert len(move_members(root, [root, copy])) == 2


# ---------------------------------------------------------------- time budget


async def test_thread_search_stops_at_the_time_budget_and_says_so(monkeypatch: pytest.MonkeyPatch):
    folders = {"INBOX": [], "Sent": [], "A": [], "B": [], "C": []}
    a = FakeSession("A", folders)
    a.folders["INBOX"][1] = _msg("INBOX", 1, hours=1, msgid="<r@x>", subject="root")
    a.folders["C"][1] = _msg("C", 1, hours=2, msgid="<c@x>", in_reply_to="<r@x>", subject="late")
    svc, _ = _service(A=a)
    clock = {"t": 0.0}

    def tick() -> float:
        clock["t"] += 100.0  # every check costs far more than the budget
        return clock["t"]

    monkeypatch.setattr(mail, "_now", tick)
    res = await svc.get_thread(a.folders["INBOX"][1].ref.encode(), limit=None)
    assert any("time budget" in n and "not searched" in n for n in res.notes)
    assert [h.summary.subject for h in res.hits] == ["root"]


async def test_thread_search_reaches_every_folder_within_the_budget():
    many = {"INBOX": [], **{f"F{i:02d}": [] for i in range(40)}}
    a = FakeSession("A", many)
    a.folders["INBOX"][1] = _msg("INBOX", 1, hours=1, msgid="<r@x>", subject="root")
    a.folders["F39"][1] = _msg(
        "F39", 1, hours=2, msgid="<c@x>", in_reply_to="<r@x>", subject="far away"
    )
    svc, _ = _service(A=a)
    res = await svc.get_thread(a.folders["INBOX"][1].ref.encode(), limit=None)
    assert [h.summary.subject for h in res.hits] == ["root", "far away"]
    assert not any("not searched" in n for n in res.notes)
