"""Message ids carry the stable key of their mailbox (security review, network L7)."""

from __future__ import annotations

import pytest

from universal_email_mcp.config import parse_config
from universal_email_mcp.errors import WRONG_MAILBOX, InvalidRef
from universal_email_mcp.models import MAX_ACCOUNT_KEY, MessageRef, account_key
from universal_email_mcp.service.mail import MailService
from universal_email_mcp.service.router import AccountRouter

from .fakes import Connector, FakeSession


def test_ids_roundtrip_with_the_key_and_stay_short() -> None:
    key = account_key("imap\0imap.example.org\0alice@example.org")
    assert len(key) == 8 and key == account_key("imap\0imap.example.org\0alice@example.org")
    ref = MessageRef("Work", "INBOX/Kunden", 1700000000, 42, key=key)
    ident = ref.encode()
    assert ident.startswith("m2.") and MessageRef.decode(ident) == ref
    assert MessageRef.decode(ident).key == key
    assert len(ident) < 120
    pop = MessageRef("Mail", "INBOX", 1, 0, "uidl-1", key)
    assert pop.encode().startswith("p2.") and MessageRef.decode(pop.encode()) == pop


def test_the_key_is_part_of_the_identity() -> None:
    a = MessageRef("Work", "INBOX", 1, 1, key="AAAAAAAA")
    b = MessageRef("Work", "INBOX", 1, 1, key="BBBBBBBB")
    assert a != b and len({a, b}) == 2 and a.encode() != b.encode()


def test_old_and_malformed_ids_are_refused() -> None:
    old = "m1.WyJXb3JrIiwiSU5CT1giLDEsMV0"  # the former format (no key)
    for bad in (old, "p1.WyJhIiwiYiJd", "m2.WyJXb3JrIiwiSU5CT1giLDEsMV0"):
        with pytest.raises(InvalidRef):
            MessageRef.decode(bad)
    for key in ("a b", "x" * (MAX_ACCOUNT_KEY + 1), "ü", "a\n"):
        with pytest.raises(InvalidRef):
            MessageRef("Work", "INBOX", 1, 1, key=key)


def _service(username: str, name: str = "A") -> tuple[MailService, Connector]:
    cfg = parse_config(
        {
            "accounts": [
                {
                    "name": name,
                    "username": username,
                    "server": "imap.example.org",
                    "permissions": ["read", "organize"],
                }
            ]
        }
    )
    conn = Connector({name: FakeSession(name, {"INBOX": [1, 2]})})
    return MailService(cfg, router=AccountRouter(cfg, connectors={"imap": conn})), conn


def test_a_config_account_key_follows_host_and_login_not_the_name() -> None:
    (a,) = _service("a@example.org", "Work")[0].config.accounts
    (renamed,) = _service("a@example.org", "Private")[0].config.accounts
    (other,) = _service("b@example.org", "Work")[0].config.accounts
    assert a.key and a.key == renamed.key  # a rename keeps the ids valid
    assert a.key != other.key  # the same name for another login does not


async def test_an_id_of_a_former_mailbox_with_the_same_name_is_refused() -> None:
    old_service, _ = _service("alice@example.org")
    (acc,) = old_service.config.accounts
    ident = MessageRef("A", "INBOX", 1, 1, key=acc.key).encode()
    assert old_service.resolve(ident)[0].key == acc.key  # fine for its own mailbox

    new_service, _ = _service("mallory@example.org")  # the name "A" now means another mailbox
    with pytest.raises(InvalidRef) as err:
        await new_service.get_message(ident, offset=0, max_chars=None)
    assert WRONG_MAILBOX in err.value.message and "search again" in err.value.message
    with pytest.raises(InvalidRef):
        new_service.resolve(ident)


async def test_writes_on_an_id_of_a_former_mailbox_change_nothing() -> None:
    old_service, _ = _service("alice@example.org")
    (acc,) = old_service.config.accounts
    ident = MessageRef("A", "INBOX", 1, 1, key=acc.key).encode()
    new_service, conn = _service("mallory@example.org")
    result = await new_service.organize.mark([ident], seen=True, flagged=None)
    (outcome,) = result.outcomes
    assert outcome.status == "failed" and "different mailbox" in (outcome.message or "")
    assert conn.connects == []  # nothing was even opened
