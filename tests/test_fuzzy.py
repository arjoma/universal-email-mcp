"""Fuzzy matching corpus: German/English names, umlauts, typos, name order,
subjects and hierarchical folders — with expected rankings."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from universal_email_mcp.models import Address, FolderInfo, MessageRef, MessageSummary
from universal_email_mcp.service import fuzzy
from universal_email_mcp.service.fuzzy import FuzzyQuery, rank_messages, score, variants

PEOPLE = [
    "Jürgen Müller <juergen.mueller@example.de>",
    "Maria Mueller <maria.mueller@firma.at>",
    "Anna Huber <anna.huber@huber-bau.at>",
    "Hubert Maier <h.maier@maier-gmbh.at>",
    "Maier GmbH <office@maier-gmbh.at>",
    "Günther Weiß <g.weiss@example.at>",
    "François Dupont <f.dupont@example.fr>",
    "Alice Example <alice@example.com>",
    "Bob Smith <bob@example.com>",
    "Zoë Schröder <zoe@schroeder.example>",
]


def _people_text(p: str) -> str:
    return p


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("Müller", "Jürgen Müller"),
        ("Mueller Jürgen", "Jürgen Müller"),
        ("Muller", "Jürgen Müller"),
        ("juergen muller", "Jürgen Müller"),
        ("Hubr", "Anna Huber"),
        ("Huber Anna", "Anna Huber"),
        ("anna.huber@huber-bau.at", "Anna Huber"),
        ("Weiss", "Günther Weiß"),
        ("Gunther Weis", "Günther Weiß"),
        ("francois", "François Dupont"),
        ("Example Alice", "Alice Example"),
        ("Schroder", "Zoë Schröder"),
        ("Zoe", "Zoë Schröder"),
        ("maier gmbh", "Maier GmbH"),
    ],
)
def test_people_best_match(query: str, expected: str):
    ranked = sorted(PEOPLE, key=lambda p: -score(query, p))
    assert ranked[0].startswith(expected), (query, [(p, score(query, p)) for p in ranked[:3]])
    assert score(query, ranked[0]) >= fuzzy.DEFAULT_THRESHOLD


@pytest.mark.parametrize(
    "query",
    ["Xaver Obermoser", "zzz", "Rechnung"],
)
def test_no_false_positives(query: str):
    assert all(score(query, p) < fuzzy.DEFAULT_THRESHOLD for p in PEOPLE), [
        (p, score(query, p)) for p in PEOPLE
    ]


def test_variants_meet():
    assert variants("Müller") == ("mueller", "muller")
    assert variants("Straße") == ("strasse",)
    assert variants("Café Crème") == ("cafe creme",)
    assert score("Mueller", "Müller") == 100
    assert score("Muller", "Müller") == 100
    assert score("MÜLLER", "mueller") == 100


def test_prefix_and_extra_words():
    assert score("rech", "Rechnung 2026-117") >= 85
    assert fuzzy.strip_subject_prefixes("Re: AW: Fwd[2]: Angebot") == "Angebot"
    assert score("Angebot", "Re: Re: Angebot Website") >= 90
    assert score("Angebot Website", "Angebot Website") == 100
    assert score("angebt websit", "Angebot Website") >= 85


def _msg(
    uid: int, sender: str, subject: str, day: int, to: str = "me@example.org"
) -> MessageSummary:
    name, _, email = sender.partition(" <")
    return MessageSummary(
        ref=MessageRef("A", "INBOX", 1, uid),
        date=datetime(2026, 9, day, tzinfo=UTC),
        received=None,
        from_=(Address(name, email.rstrip(">")),),
        to=(Address("", to),),
        cc=(),
        reply_to=(),
        subject=subject,
        flags=(),
        size=None,
        has_attachments=False,
        message_id=None,
        in_reply_to=None,
        references=(),
    )


CORPUS = [
    _msg(1, "Anna Huber <anna.huber@huber-bau.at>", "Angebot Website", 10),
    _msg(2, "Maier GmbH <office@maier-gmbh.at>", "Rechnung 2026-117", 12),
    _msg(3, "Jürgen Müller <juergen.mueller@example.de>", "Termin nächste Woche", 14),
    _msg(4, "Hubert Maier <h.maier@maier-gmbh.at>", "Lieferung Huber-Baustelle", 15),
    _msg(5, "Anna Huber <anna.huber@huber-bau.at>", "Re: Angebot Website", 20),
    _msg(6, "Newsletter <news@shop.example>", "Invoice for your order", 21),
]


def _subjects(hits: list[tuple[float, MessageSummary]]) -> list[str]:
    return [m.subject for _s, m in hits]


def test_rank_messages_sender_typo_newest_first():
    hits = rank_messages(FuzzyQuery(from_="Hubr"), CORPUS)
    assert _subjects(hits)[:2] == ["Re: Angebot Website", "Angebot Website"]
    assert "Termin nächste Woche" not in _subjects(hits)


def test_rank_messages_and_semantics():
    hits = rank_messages(FuzzyQuery(from_="Huber", subject="Angebot"), CORPUS)
    assert _subjects(hits) == ["Re: Angebot Website", "Angebot Website"]
    assert rank_messages(FuzzyQuery(from_="Müller", subject="Rechnung"), CORPUS) == []


def test_rank_messages_umlaut_and_text():
    assert _subjects(rank_messages(FuzzyQuery(from_="Mueller"), CORPUS)) == ["Termin nächste Woche"]
    assert _subjects(rank_messages(FuzzyQuery(text="naechste woche"), CORPUS)) == [
        "Termin nächste Woche"
    ]
    assert rank_messages(FuzzyQuery(to="me@example.org"), CORPUS)
    assert FuzzyQuery().is_empty() and FuzzyQuery(subject="  ").is_empty()


# ---------------------------------------------------------------- folders


def _f(name: str, role: str | None = None, delim: str = "/", selectable: bool = True) -> FolderInfo:
    return FolderInfo(
        name=name,
        display_name=name,
        delimiter=delim,
        flags=(),
        role=role,  # pyright: ignore[reportArgumentType]
        selectable=selectable,
    )


FOLDERS = [
    _f("INBOX", "inbox"),
    _f("Sent", "sent"),
    _f("Archive", "archive"),
    _f("Archive/2025"),
    _f("Archive/2026"),
    _f("Clients", selectable=False),
    _f("Clients/Huber"),
    _f("Clients/Maier GmbH"),
    _f("Clients/Mayer"),
    _f("Projects/2026-Website"),
    _f("Rechnungen 2026"),
]


def _pick(query: str, folders: list[FolderInfo] = FOLDERS, prefix: str = ""):
    return fuzzy.pick_folder(fuzzy.match_folders(query, folders, personal_prefix=prefix))


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("clients/huber", "Clients/Huber"),
        ("Kunden/Hubr", "Clients/Huber"),
        ("client > huber", "Clients/Huber"),
        ("Huber", "Clients/Huber"),
        ("huber gmbh", "Clients/Huber"),
        ("maier gmbh", "Clients/Maier GmbH"),
        ("archive/2025", "Archive/2025"),
        ("archiv/2026", "Archive/2026"),
        ("sent", "Sent"),
        ("rechnungen", "Rechnungen 2026"),
        ("projekte/website", "Projects/2026-Website"),
    ],
)
def test_folder_resolution(query: str, expected: str):
    picked = _pick(query)
    assert isinstance(picked, fuzzy.FolderMatch), (query, picked)
    assert picked.folder.name == expected


def test_folder_ambiguity_is_a_choice():
    folders = [*FOLDERS, _f("Projects/Huber")]
    picked = _pick("huber", folders)
    assert isinstance(picked, list)
    assert {m.folder.name for m in picked} == {"Clients/Huber", "Projects/Huber"}
    picked = _pick("clients/huber", folders)  # the group decides
    assert isinstance(picked, fuzzy.FolderMatch) and picked.folder.name == "Clients/Huber"
    picked = _pick("clients/maier")  # "Maier GmbH" beats "Mayer" clearly
    assert isinstance(picked, fuzzy.FolderMatch) and picked.folder.name == "Clients/Maier GmbH"
    assert _pick("nowhere/else") is None


def test_folder_namespace_prefix():
    folders = [
        _f("INBOX", "inbox", "."),
        _f("INBOX.Clients.Huber", delim="."),
        _f("INBOX.Sent", "sent", "."),
    ]
    picked = _pick("clients/huber", folders, prefix="INBOX.")
    assert isinstance(picked, fuzzy.FolderMatch)
    assert picked.folder.name == "INBOX.Clients.Huber"
    assert fuzzy.folder_path(folders[1], "INBOX.") == ("Clients", "Huber")
    assert fuzzy.folder_path(folders[0], "INBOX.") == ("INBOX",)
