"""Fuzzy matching corpus: German/English names, umlauts, typos, name order,
subjects and hierarchical folders — with expected rankings."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from universal_email_mcp.errors import AmbiguousFolder, FolderNotFound
from universal_email_mcp.models import Address, FolderInfo, MessageRef, MessageSummary
from universal_email_mcp.service import folder_list, fuzzy
from universal_email_mcp.service.fuzzy import score, variants
from universal_email_mcp.service.query import parse, score_message

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


def _rank(text: str) -> list[str]:
    """Subjects scoring ≥ the default threshold for a query, best first, newest
    first on ties (as find_messages ranks)."""
    q = parse(text)
    assert q is not None
    hits = [(sc, m) for m in CORPUS if (sc := score_message(q, m)) >= fuzzy.DEFAULT_THRESHOLD]
    hits.sort(key=lambda h: (-round(h[0]), -(h[1].date.timestamp() if h[1].date else 0)))
    return [m.subject for _s, m in hits]


def test_rank_sender_typo_newest_first():
    hits = _rank("Hubr")
    assert hits[:2] == ["Re: Angebot Website", "Angebot Website"]
    assert "Termin nächste Woche" not in hits


def test_rank_umlaut_subject_and_recipient():
    assert _rank("Mueller") == ["Termin nächste Woche"]
    assert _rank("naechste woche") == ["Termin nächste Woche"]
    assert _rank("me@example.org")  # recipients count too
    assert set(_rank("hub*")) == {  # wildcard: word starts (Huber, Hubert, Huber-Baustelle)
        "Re: Angebot Website",
        "Angebot Website",
        "Lieferung Huber-Baustelle",
    }


def test_words_spread_over_fields_add_up():
    # "Huber" is the sender, "Rechnung" the subject: neither field alone matches both words
    m = replace(CORPUS[1], from_=(Address("Anna Huber", "anna@huber-bau.at"),))
    q = parse("rechnung huber")
    assert q is not None and score_message(q, m) >= 90
    other = replace(CORPUS[1], from_=(Address("Maier GmbH", "office@maier-gmbh.at"),))
    assert score_message(q, other) < fuzzy.DEFAULT_THRESHOLD


def test_message_texts_are_bounded():
    many = tuple(Address(f"Person {i}", f"p{i}@example.org") for i in range(500))
    m = replace(CORPUS[0], to=many)
    q = parse("p499@example.org")
    assert q is not None and score_message(q, m) < 100  # beyond the recipient cap
    q = parse("p3@example.org")
    assert q is not None and score_message(q, m) == 100


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


def _pick(query: str, folders: list[FolderInfo] = FOLDERS, prefix: str = "") -> str:
    node, _note = folder_list.resolve(
        folder_list.build(folders, prefix), query, selectable_only=True
    )
    return node.full_name


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
    assert _pick(query) == expected


def test_folder_ambiguity_is_a_choice():
    folders = [*FOLDERS, _f("Projects/Huber")]
    with pytest.raises(AmbiguousFolder) as e:
        _pick("huber", folders)
    assert set(e.value.choices) == {"Clients/Huber", "Projects/Huber"}
    assert _pick("clients/huber", folders) == "Clients/Huber"  # the group decides
    assert _pick("clients/maier") == "Clients/Maier GmbH"  # beats "Mayer" clearly
    with pytest.raises(FolderNotFound):
        _pick("nowhere/else")
    with pytest.raises((FolderNotFound, AmbiguousFolder)):
        _pick("Clients")  # never the group itself: it cannot hold mail


def test_folder_namespace_prefix():
    folders = [
        _f("INBOX", "inbox", "."),
        _f("INBOX.Clients.Huber", delim="."),
        _f("INBOX.Sent", "sent", "."),
    ]
    assert _pick("clients/huber", folders, prefix="INBOX.") == "INBOX.Clients.Huber"
    assert fuzzy.folder_path(folders[1], "INBOX.") == ("Clients", "Huber")
    assert fuzzy.folder_path(folders[0], "INBOX.") == ("INBOX",)
