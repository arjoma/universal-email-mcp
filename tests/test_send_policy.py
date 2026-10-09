"""Send-time recipient check, policy decisions, limiter, confirmation text and the
elicitation adapter (no servers)."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.server.mcpserver import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
    Elicit,
)

from universal_email_mcp.config import parse_config
from universal_email_mcp.errors import InvalidArgument, RateLimited
from universal_email_mcp.mail.outgoing import parse_outgoing
from universal_email_mcp.models import Address, Identity
from universal_email_mcp.server.app import (
    SendConfirmation,
    Skipped,
    confirmation_for,
    decision_of,
)
from universal_email_mcp.service.recipients import (
    Classified,
    Field,
    classify,
    count_by_class,
    mixed_scripts,
    skeleton,
    unicode_domain,
)
from universal_email_mcp.service.send import (
    SendLimiter,
    confirmation_reasons,
    confirmation_text,
    domain_allowed,
    send_offered,
)

OWN = {"me@example.org"}
HISTORY = {
    "oliver.grant@firma.example",
    "anna@huber-bau.at",
    "bob@example.com",
    "ceo@corp.example",
}


def cls(
    addr: str,
    *,
    known: Mapping[str, bool | None] | None = None,
    history: set[str] = HISTORY,
    internal: tuple[str, ...] = (),
    fld: Field = "to",
) -> Classified:
    (c,) = classify(
        [(fld, Address("", addr))],
        own=OWN,
        internal_domains=internal,
        known=known if known is not None else {addr: False},
        history=history,
    )
    return c


# ---------------------------------------------------------------- classification


def test_internal_known_new():
    assert cls("me@example.org").klass == "internal"
    assert cls("x@corp.example", internal=("corp.example",)).klass == "internal"
    assert cls("anna@huber-bau.at", known={"anna@huber-bau.at": True}).klass == "known"
    c = cls("stranger@elsewhere.example")
    assert c.klass == "new" and not c.history_unknown
    u = cls("stranger@elsewhere.example", known={"stranger@elsewhere.example": None})
    assert u.klass == "new" and u.history_unknown


def test_a_whole_domain_is_not_internal_unless_listed():
    # same domain as an own identity address, but not listed: not internal
    assert cls("colleague@example.org").klass != "internal"


@pytest.mark.parametrize(
    ("typo", "real"),
    [
        ("oliver.grnat@firma.example", "oliver.grant@firma.example"),  # transposition
        ("anna@huber-ba.at", "anna@huber-bau.at"),  # domain typo
        ("anna@huber-bau.com", "anna@huber-bau.at"),  # other TLD, same name
        ("bob@examp1e.com", "bob@example.com"),  # digit for letter
        ("bob@exmaple.com", "bob@example.com"),
        ("someone@exampie.com", "bob@example.com"),  # other local part, look-alike domain
        ("ceo@c0rp.example", "ceo@corp.example"),
    ],
)
def test_lookalikes_of_known_addresses(typo: str, real: str):
    c = cls(typo)
    assert c.klass == "lookalike", c
    assert c.similar_to


def test_homoglyph_and_idn_homograph():
    cyr = "bob@exаmple.com"  # Cyrillic a  # noqa: RUF001
    c = cls(cyr)
    assert c.klass == "lookalike"
    puny = "bob@" + "exаmple.com".encode("idna").decode()  # xn--... form  # noqa: RUF001
    assert puny.startswith("bob@xn--")
    c = cls(puny)
    assert c.klass == "lookalike"
    assert unicode_domain(puny.split("@")[1]) == "exаmple.com"  # noqa: RUF001
    assert skeleton("exаmple.com") == skeleton("example.com")  # noqa: RUF001


def test_mixed_script_domain_is_flagged_without_a_counterpart():
    assert mixed_scripts("pаypal.com") == ["CYRILLIC", "LATIN"]  # noqa: RUF001
    c = cls("x@" + "pаypal.com".encode("idna").decode(), history=set())  # noqa: RUF001
    assert c.klass == "lookalike" and "mixes" in c.notes[-1]


def test_known_typo_address_that_was_written_to_before_is_still_flagged():
    # The user mistyped once, the mail went out: the typo is "known" itself.
    known = {"oliver.grnat@firma.example": True}
    history = HISTORY | {"oliver.grnat@firma.example"}
    c = cls("oliver.grnat@firma.example", known=known, history=history)
    assert c.klass == "lookalike"
    assert "written to this address and to oliver.grant@firma.example" in c.notes[0]
    # ... and the correct one is flagged for the same reason.
    c = cls(
        "oliver.grant@firma.example", known={"oliver.grant@firma.example": True}, history=history
    )
    assert c.klass == "lookalike"


def test_unrelated_addresses_are_not_lookalikes():
    assert cls("zoe@other-company.example").klass == "new"
    assert cls("li@firma.example").klass == "new"  # short local parts are not compared


def test_lookalike_of_an_internal_domain():
    c = cls("x@corp.exampel", history=set(), internal=("corp.example",))
    assert c.klass == "lookalike" and c.similar_to == "@corp.example"


def test_idn_domain_is_noted():
    c = cls("x@" + "münchen.example".encode("idna").decode(), history=set())
    assert c.klass == "new" and "internationalized domain" in c.notes[0]


def test_dedupes_and_counts():
    items = classify(
        [
            ("to", Address("", "a@b.example")),
            ("cc", Address("", "A@B.example")),
            ("bcc", Address("", "me@example.org")),
        ],
        own=OWN,
        internal_domains=(),
        known={},
        history=set(),
    )
    assert len(items) == 2
    assert count_by_class(items) == {"internal": 1, "known": 0, "new": 1, "lookalike": 0}


# ---------------------------------------------------------------- policy


def test_confirmation_reasons_per_mode():
    internal = [cls("me@example.org")]
    external = [cls("anna@huber-bau.at", known={"anna@huber-bau.at": True})]
    look = [cls("bob@examp1e.com")]
    assert confirmation_reasons("confirm", internal)
    assert not confirmation_reasons("confirm-external", internal)
    assert confirmation_reasons("confirm-external", external)
    assert not confirmation_reasons("on", external)
    assert not confirmation_reasons("on", [cls("stranger@elsewhere.example")])
    for mode in ("on", "confirm-external", "confirm"):
        assert any("look like" in r for r in confirmation_reasons(mode, look)), mode  # type: ignore[arg-type]


def test_domain_allowed():
    assert domain_allowed("anything.example", [])
    assert domain_allowed("corp.example", ["corp.example"])
    assert domain_allowed("mail.corp.example", ["corp.example"])
    assert not domain_allowed("evilcorp.example", ["corp.example"])
    assert not domain_allowed("corp.example.evil.test", ["corp.example"])


def test_limiter_per_hour_and_day():
    now = [1_000_000.0]
    lim = SendLimiter(2, 3, clock=lambda: now[0])
    lim.check("a")
    lim.record("a")
    lim.record("a")
    with pytest.raises(RateLimited, match="last hour"):
        lim.check("a")
    lim.check("other-account")
    now[0] += 3_601
    lim.check("a")
    lim.record("a")
    with pytest.raises(RateLimited, match="24 hours"):
        lim.check("a")
    now[0] += 86_400
    lim.check("a")


def _cfg(identities: list[dict[str, Any]], policy: dict[str, Any] | None = None):
    acc = {
        "name": "Work",
        "username": "me@example.org",
        "server": "mail.example.org",
        "permissions": ["read", "drafts"],
    }
    return parse_config({"accounts": [acc], "identities": identities, "policy": policy or {}})


def test_send_offered_needs_policy_identity_smtp_and_store():
    ident = {"address": "me@example.org", "account": "Work", "send": True}
    assert send_offered(_cfg([ident]))
    assert not send_offered(_cfg([ident], {"read_only": True}))
    assert not send_offered(_cfg([ident], {"send": "off"}))
    assert send_offered(_cfg([ident], {"send": "draft"}))
    assert not send_offered(_cfg([{**ident, "send": False}]))
    from universal_email_mcp.errors import ConfigError

    with pytest.raises(ConfigError, match="needs an SMTP account"):
        _cfg([{"address": "me@example.org", "store_account": "Work", "send": True}])
    with pytest.raises(ConfigError, match="Drafts and Sent"):
        _cfg([{"address": "me@example.org", "smtp_account": "Work", "send": True}])
    no_drafts = {
        "name": "Work",
        "username": "me@example.org",
        "server": "mail.example.org",
        "permissions": ["read"],
    }
    cfg = parse_config({"accounts": [no_drafts], "identities": [ident]})
    assert not send_offered(cfg)


def test_config_policy_and_identity_keys():
    cfg = _cfg(
        [
            {
                "address": "me@example.org",
                "account": "Work",
                "file_replies": "both",
                "save_sent": "never",
            }
        ],
        {"internal_domains": ["Corp.Example"], "max_sends_per_hour": 3, "send": "on"},
    )
    assert cfg.policy.internal_domains == ("corp.example",) and cfg.policy.max_sends_per_hour == 3
    assert cfg.identities[0].file_replies == "both" and cfg.identities[0].save_sent == "never"
    from universal_email_mcp.errors import ConfigError

    with pytest.raises(ConfigError, match="file_replies"):
        _cfg([{"address": "me@example.org", "account": "Work", "file_replies": "x"}])
    with pytest.raises(ConfigError, match="send"):
        _cfg([{"address": "me@example.org", "account": "Work"}], {"send": "maybe"})


# ---------------------------------------------------------------- confirmation text

RAW = (
    "From: Max <me@example.org>\r\nTo: Bob <bob@examp1e.com>\r\n"
    "Cc: =?utf-8?q?Evil=E2=80=AE?= <anna@huber-bau.at>\r\n"
    "Subject: Hallo\x07 Welt\r\nMessage-ID: <1@example.org>\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n\r\n"
    "See http://evil.example/x ‮and \x1b[31mred\r\nline2\r\n"
).encode()


def test_confirmation_text_is_sanitised_and_complete():
    out = parse_outgoing(RAW)
    ident = Identity("Me‮", ("me@example.org",), send=True)
    classified = classify(
        [("to", out.to[0]), ("cc", out.cc[0])],
        own=OWN,
        internal_domains=(),
        known={"anna@huber-bau.at": True},
        history=HISTORY,
    )
    text = confirmation_text(ident, out, classified, ["why"])
    assert "From: Max <me@example.org>" in text
    assert "bob@examp1e.com" in text and "LOOK-ALIKE" in text and "written to before" in text
    assert "Subject: Hallo Welt" in text
    for bad in ("‮", "\x1b", "\x07"):
        assert bad not in text
    assert "http://evil.example" not in text  # defanged
    assert "Confirmation needed because why." in text
    assert len(text) <= 10_000


def test_confirmation_shows_the_whole_new_text_and_announces_cuts():
    out = parse_outgoing(RAW)
    ident = Identity("Me", ("me@example.org",), send=True)
    lines = [f"line {i} " + "x" * 20 for i in range(1, 201)]
    body = "\n".join(lines)
    text = confirmation_text(ident, out, [], [], text=body, quoted="a\nb\nc")
    assert "> line 80 " in text and "line 81 " not in text  # 80 lines
    n_cut = len(body) - len("\n".join(lines[:80]))
    assert f"{n_cut} more characters (120 lines) of the text NOT shown" in text
    assert "[quoted original: 3 lines, not shown]" in text
    # text after the old 15-line limit is visible
    short = confirmation_text(ident, out, [], [], text="\n".join(f"l{i}" for i in range(1, 41)))
    assert "> l40" in short and "NOT shown" not in short


def test_confirmation_lists_attachments_up_to_20_then_counts():
    raw = b"From: a@x.example\nTo: b@y.example\n\nhi\n"
    out = parse_outgoing(raw)
    out = dataclasses.replace(out, attachments=tuple((f"f{i}.bin", 1000 + i) for i in range(23)))
    text = confirmation_text(Identity("Me", ("a@x.example",)), out, [], [])
    assert "Attachments (23):" in text and "f19.bin" in text and "f20.bin" not in text
    assert "and 3 more attachment(s) NOT listed" in text


# ---------------------------------------------------------------- outgoing parser


def test_parse_outgoing_collects_all_recipient_header_instances():
    raw = (
        b"From: me@example.org\nTo: a@x.example\nTo: b@x.example\nCc: c@x.example\n"
        b"Bcc: d@x.example, e@x.example\nSubject: s\n\nhi\n"
    )
    out = parse_outgoing(raw)
    assert [a.email for a in out.recipients] == [f"{c}@x.example" for c in "abcde"]
    assert [a.email for a in out.bcc] == ["d@x.example", "e@x.example"]
    assert b"\r\n" in out.raw and b"\n" not in out.raw.replace(b"\r\n", b"")


@pytest.mark.parametrize(
    "raw",
    [
        b"To: a@x.example\n\nno from\n",
        b"From: a@x.example\nFrom: b@x.example\nTo: c@x.example\n\ntwo froms\n",
        b"From: a@x.example, b@x.example\nTo: c@x.example\n\ntwo senders\n",
        b"From: a@x.example\nTo: not an address\n\nbroken\n",
        b"From: a@x.example\nTo: a@x.example, <broken@>\n\nbroken\n",
        "From: a@x.example\nTo: müller@x.example\n\nnon-ascii local part\n".encode(),
    ],
)
def test_parse_outgoing_refuses_unclean_drafts(raw: bytes):
    with pytest.raises(InvalidArgument):
        parse_outgoing(raw)


# ---------------------------------------------------------------- elicitation adapter


def _prepared(*, needs: bool = True, keep: str | None = None) -> Any:
    return SimpleNamespace(
        needs_confirmation=needs and keep is None, prompt="the prompt", keep_reason=keep
    )


FORM = SimpleNamespace(elicitation=SimpleNamespace(form=SimpleNamespace(), url=None))
BARE = SimpleNamespace(elicitation=SimpleNamespace(form=None, url=None))  # old "elicitation: {}"
URL_ONLY = SimpleNamespace(elicitation=SimpleNamespace(form=None, url=SimpleNamespace()))


def test_confirmation_for_asks_only_capable_clients_when_needed():
    q = confirmation_for(FORM, _prepared())
    assert isinstance(q, Elicit) and q.message == "the prompt" and q.schema is SendConfirmation
    assert isinstance(confirmation_for(BARE, _prepared()), Elicit)
    for caps in (None, SimpleNamespace(elicitation=None), URL_ONLY):
        assert confirmation_for(caps, _prepared()) == Skipped("unavailable")
    assert confirmation_for(FORM, _prepared(needs=False)) == Skipped("not_needed")
    assert confirmation_for(FORM, _prepared(keep="policy")) == Skipped("not_needed")
    assert confirmation_for(FORM, InvalidArgument("x")) == Skipped("error")


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (AcceptedElicitation(data=SendConfirmation(send=True)), "accepted"),
        (AcceptedElicitation(data=SendConfirmation(send=False)), "declined"),
        (DeclinedElicitation(), "declined"),
        (CancelledElicitation(), "cancelled"),
        (AcceptedElicitation[Any].model_construct(data=Skipped("unavailable")), "unavailable"),
        (AcceptedElicitation[Any].model_construct(data=Skipped("not_needed")), "not_needed"),
        (AcceptedElicitation[Any].model_construct(data=Skipped("error")), "not_needed"),
        (AcceptedElicitation[Any].model_construct(data="surprise"), "unavailable"),
    ],
)
def test_decision_of(outcome: Any, expected: str):
    assert decision_of(outcome) == expected
