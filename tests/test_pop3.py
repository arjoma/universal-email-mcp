"""POP3 backend against a scripted localhost server (protocol-level behaviour)."""

from __future__ import annotations

import threading
import time
from datetime import date

import pytest

from universal_email_mcp.errors import (
    AttachmentNotFound,
    AuthFailed,
    InvalidRef,
    MailError,
    MessageNotFound,
    ServerUnreachable,
    TlsError,
    UnsupportedByServer,
)
from universal_email_mcp.mail.imap import SearchCriteria
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.mail.pop3 import Pop3Session, Pop3State
from universal_email_mcp.models import Endpoint, MessageRef, TlsMode, TlsSettings

from .pop3_server import ScriptedPop3Server, make_attachment_message, make_message


def connect(
    srv: ScriptedPop3Server,
    mode: TlsMode = "tls",
    *,
    state: Pop3State | None = None,
    password: str = "secret",
    read_timeout: float = 20.0,
) -> Pop3Session:
    return Pop3Session.connect(
        Endpoint("localhost", srv.port, mode),
        "user",
        password,
        account_name="P",
        net=NetPolicy(allow_private=True, read_timeout=read_timeout),
        tls=TlsSettings(verify=False),
        state=state,
        resolver=lambda _h, _p: ["127.0.0.1"],
    )


def mailbox(n: int = 5) -> list[tuple[str, bytes]]:
    return [
        (f"uid-{i}", make_message(f"Subject {i}", message_id=f"m{i}@x")) for i in range(1, n + 1)
    ]


def tops(srv: ScriptedPop3Server) -> list[str]:
    return [c for c in srv.commands if c.upper().startswith("TOP")]


# ------------------------------------------------------------------ refs


def test_pop3_ref_roundtrip_and_distinct_from_imap():
    ref = MessageRef("Acc", "INBOX", 1, 17, "abc.DEF-1")
    assert ref.encode().startswith("p1.") and ref.is_pop3
    back = MessageRef.decode(ref.encode())
    assert back == ref and back.uid == 0 and hash(back) == hash(ref)  # uid is not identity
    imap = MessageRef("Acc", "INBOX", 1, 17)
    assert imap.encode().startswith("m1.") and imap != ref and not imap.is_pop3
    assert MessageRef("Acc", "INBOX", 1, 17) == MessageRef("Acc", "INBOX", 1, 17)


@pytest.mark.parametrize("uidl", ["", "x" * 71, "a b", "a\nb", "é"])
def test_pop3_ref_rejects_bad_uidl(uidl: str):
    with pytest.raises(InvalidRef):
        MessageRef("A", "INBOX", 1, 0, uidl)


def test_pop3_ref_decode_rejects_forgeries():
    import base64
    import json

    def forge(prefix: str, payload: object) -> str:
        raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return prefix + raw

    for bad in (
        forge("p1.", ["A"]),
        forge("p1.", ["A", 5]),
        forge("p1.", ["A", "ok", 3]),
        forge("p1.", ["A", "has space"]),
        forge("m1.", ["A", "INBOX"]),
        "p1.",
    ):
        with pytest.raises(InvalidRef):
            MessageRef.decode(bad)


# ------------------------------------------------------------------ connection


@pytest.mark.parametrize("mode", ["tls", "starttls"])
def test_connect_secures_before_login_and_lists(mode: TlsMode):
    with ScriptedPop3Server(mailbox(3), implicit_tls=mode == "tls") as srv:
        s = connect(srv, mode)
        assert [f.name for f in s.list_folders()] == ["INBOX"]
        s.close()
        names = srv.names
        if mode == "starttls":
            assert names.index("STLS") < names.index("USER")
        assert names[-1] == "QUIT"
        assert "DELE" not in names and "RSET" not in names


def test_starttls_mandatory():
    with ScriptedPop3Server(mailbox(1), implicit_tls=False, offer_stls=False) as srv:
        with pytest.raises(TlsError):
            connect(srv, "starttls")
        assert "USER" not in srv.names and "PASS" not in srv.names


def test_wrong_password():
    with ScriptedPop3Server(mailbox(1)) as srv:
        with pytest.raises(AuthFailed):
            connect(srv, password="nope")


def test_server_without_uidl_is_refused():
    with ScriptedPop3Server(mailbox(2), uidl=False) as srv:
        with pytest.raises(UnsupportedByServer) as e:
            connect(srv)
        assert "UIDL" in e.value.message
        assert srv.peer_closed.wait(3) or srv.dropped.wait(3)


def test_server_without_top_is_refused():
    with ScriptedPop3Server(mailbox(2), top=False) as srv:
        with pytest.raises(UnsupportedByServer):
            connect(srv)


def test_sasl_only_server_uses_auth_plain():
    with ScriptedPop3Server(mailbox(1), sasl_only=True) as srv:
        s = connect(srv)
        s.close()
        assert "AUTH" in srv.names and "USER" not in srv.names


def test_abort_unblocks_a_stalled_read():
    with ScriptedPop3Server(mailbox(2), stall=frozenset({"TOP"})) as srv:
        s = connect(srv)
        out: dict[str, object] = {}

        def worker() -> None:
            try:
                s.search("INBOX", SearchCriteria(subject="x"))
            except MailError as e:
                out["error"] = e

        th = threading.Thread(target=worker, daemon=True)
        th.start()
        assert srv.stalled.wait(5)
        t0 = time.monotonic()
        s.abort()
        th.join(3)
        assert not th.is_alive() and time.monotonic() - t0 < 2
        assert isinstance(out["error"], ServerUnreachable)
        s.close()


# ------------------------------------------------------------------ uids, cache, diff


def test_no_header_criteria_reads_no_headers_and_orders_newest_first():
    with ScriptedPop3Server(mailbox(5)) as srv:
        s = connect(srv)
        res = s.search("INBOX")
        assert res.total == 5 and list(res.uids) == sorted(res.uids, reverse=True) and res.exact
        assert tops(srv) == []
        got = s.fetch_summaries("INBOX", list(res.uids[:2]))
        assert [x.subject for x in got] == ["Subject 5", "Subject 4"]
        assert len(tops(srv)) == 2
        s.close()


def test_header_search_is_newest_first_pipelined_and_cached():
    with ScriptedPop3Server(mailbox(6)) as srv:
        st = Pop3State(max_headers=4)
        s = connect(srv, state=st)
        res = s.search("INBOX", SearchCriteria(subject="subject"))
        assert res.total == 4 and not res.exact  # only the newest 4 headers are read
        assert any("newest 4 of 6" in n for n in res.notes)
        # TOP n 0 for the highest message numbers only
        assert sorted(tops(srv)) == sorted(f"TOP {n} 0" for n in (3, 4, 5, 6))
        n_before = len(tops(srv))
        again = s.search("INBOX", SearchCriteria(subject="Subject 6"))
        assert again.total == 1 and len(tops(srv)) == n_before  # served from the cache
        s.close()


def test_incremental_uidl_diff_across_sessions_and_stable_ids():
    msgs = mailbox(3)
    with ScriptedPop3Server(msgs) as srv:
        st = Pop3State()
        s1 = connect(srv, state=st)
        s1.search("INBOX", SearchCriteria(subject="Subject"))
        first = {x.subject: x.ref for x in st.summaries.values()}
        ids = {k: v.encode() for k, v in first.items()}
        s1.close()
        assert len(tops(srv)) == 3
        # new mail arrives, and the oldest message is removed by another client:
        # message numbers shift, UIDLs do not
        srv.messages[:] = [*msgs[1:], ("uid-4", make_message("Subject 4"))]
        s2 = connect(srv, state=st)
        res = s2.search("INBOX", SearchCriteria(subject="Subject"))
        assert res.total == 3
        assert len(tops(srv)) == 4  # only the new UIDL was fetched
        assert tops(srv)[-1] == "TOP 3 0"
        # the same message keeps its id; a brand-new process (empty state) resolves it too
        s3 = connect(srv, state=Pop3State())
        for subject, mid in ids.items():
            ref = MessageRef.decode(mid)
            if subject == "Subject 1":
                with pytest.raises(MessageNotFound):
                    s3.resolve_ref(ref)
            else:
                assert s3.fetch_message(ref).summary.subject == subject
        for s in (s2, s3):
            s.close()


def test_listing_reconnects_to_see_new_mail(monkeypatch: pytest.MonkeyPatch):
    import universal_email_mcp.mail.pop3 as mod

    monkeypatch.setattr(mod, "REFRESH_AFTER", 0.0)
    with ScriptedPop3Server(mailbox(2)) as srv:
        s = connect(srv)
        assert s.search("INBOX").total == 2
        srv.messages.append(("uid-3", make_message("Late")))
        time.sleep(0.01)
        assert s.search("INBOX").total == 3
        assert srv.connections > 1  # the snapshot was too old: a new connection
        s.close()


def test_hostile_uidls_are_skipped_not_trusted():
    msgs = [
        ("good-1", make_message("Good")),
        ("good-1", make_message("Duplicate")),
        ("x" * 80, make_message("Too long")),
        ("ok\tbad", make_message("Control")),
        ("good-2", make_message("Also good")),
    ]
    with ScriptedPop3Server(msgs) as srv:
        s = connect(srv)
        res = s.search("INBOX")
        assert res.total == 2
        assert any("skipped" in n for n in s.notes)
        s.close()


# ------------------------------------------------------------------ search semantics


def test_local_criteria():
    msgs = [
        ("a", make_message("Invoice 17", sender="Huber <anna@huber.at>", to="me@x.org")),
        ("b", make_message("Lunch", sender="Bob <bob@x.com>", to="me@x.org, c@y.org")),
        ("c", make_attachment_message("Photos", "a.png", b"\x89PNG....")),
    ]
    with ScriptedPop3Server(msgs) as srv:
        s = connect(srv)

        def count(**kw: object) -> int:
            return s.search("INBOX", SearchCriteria(**kw)).total  # pyright: ignore[reportArgumentType]

        assert count(from_="huber") == 1
        assert count(to="c@y.org") == 1
        assert count(subject="LUNCH") == 1
        assert count(since=date(2026, 10, 6)) == 1  # the Received header of "Photos"
        assert count(before=date(2026, 10, 6)) == 2
        assert count(has_attachment=True) == 1
        assert count(larger=10_000) == 0
        res = s.search("INBOX", SearchCriteria(unseen=True, from_="bob"))
        assert (
            res.total == 1 and not res.exact and any("no read or flagged" in n for n in res.notes)
        )
        res = s.search("INBOX", SearchCriteria(body="anything"))
        assert any("cannot search message bodies" in n for n in res.notes)
        s.close()
        assert "DELE" not in srv.names


def test_received_date_ignores_the_future_and_summaries_carry_no_flags():
    far = "from x by y; Mon, 05 Oct 2099 10:00:00 +0000"
    with ScriptedPop3Server([("a", make_message("Future", received=far))]) as srv:
        s = connect(srv)
        (sm,) = s.fetch_summaries("INBOX", list(s.search("INBOX").uids))
        assert sm.received is None and sm.flags == () and sm.ref.is_pop3
        s.close()


# ------------------------------------------------------------------ messages


def test_fetch_message_retr_and_no_dele():
    with ScriptedPop3Server(mailbox(2)) as srv:
        s = connect(srv)
        res = s.search("INBOX")
        ref = s.fetch_summaries("INBOX", [res.uids[0]])[0].ref
        msg = s.fetch_message(MessageRef.decode(ref.encode()))
        assert msg.summary.subject == "Subject 2" and "hello" in msg.body.text
        assert not msg.source_truncated and msg.summary.ref == ref
        s.close()
        assert "RETR" in srv.names and "DELE" not in srv.names and "RSET" not in srv.names


def test_oversize_message_is_read_partially_with_top():
    big = make_message("Big", body="line of text\r\n" * 5000)
    with ScriptedPop3Server([("big", big)]) as srv:
        s = connect(srv)
        ref = s.fetch_summaries("INBOX", [s.search("INBOX").uids[0]])[0].ref
        before = srv.connections
        msg = s.fetch_message(ref, max_bytes=4000)
        assert msg.source_truncated and 0 < len(msg.body.text) < 4000
        assert "RETR" not in srv.names and any(c.startswith("TOP 1 ") for c in srv.commands)
        assert srv.connections == before  # the connection survived
        s.close()


def test_response_beyond_the_cap_cuts_the_connection_and_reconnects():
    big = make_message("Liar", body="y" * 200_000)
    with ScriptedPop3Server([("big", big)]) as srv:
        s = connect(srv)
        ref = s.fetch_summaries("INBOX", [s.search("INBOX").uids[0]])[0].ref
        # LIST says small enough, RETR delivers more: the read stops at the cap
        s._size["big"] = 10  # pyright: ignore[reportPrivateUsage]
        msg = s.fetch_message(ref, max_bytes=20_000)
        assert msg.source_truncated and len(msg.body.text) < 25_000
        assert srv.dropped.wait(3) or srv.peer_closed.wait(3)
        assert s.search("INBOX").total == 1  # the next call reconnects
        assert srv.connections == 2
        s.close()


def test_attachments_are_numbered_by_the_python_parse():
    payload = bytes(range(256)) * 4
    with ScriptedPop3Server([("att", make_attachment_message("Doc", "data.bin", payload))]) as srv:
        s = connect(srv)
        ref = s.fetch_summaries("INBOX", [s.search("INBOX").uids[0]])[0].ref
        msg = s.fetch_message(ref)
        (att,) = msg.attachments
        assert att.part_id == "2" and att.filename == "data.bin"
        got = s.fetch_attachment(ref, "2", max_bytes=10_000)
        assert got.data == payload and got.leaf.filename == "data.bin" and got.exact
        small = s.fetch_attachment(ref, "2", max_bytes=100)
        assert small.data is None and small.size == len(payload)
        for bad in ("3", "1.1", "0", "TEXT", "1.MIME"):
            with pytest.raises(AttachmentNotFound):
                s.fetch_attachment(ref, bad, max_bytes=10_000)
        s.close()


def test_ref_of_another_account_or_kind_is_refused():
    with ScriptedPop3Server(mailbox(1)) as srv:
        s = connect(srv)
        with pytest.raises(InvalidRef):
            s.resolve_ref(MessageRef("Other", "INBOX", 1, 0, "uid-1"))
        with pytest.raises(InvalidRef):
            s.resolve_ref(MessageRef("P", "INBOX", 1, 1))
        s.close()


def test_conversation_lookup_by_message_id():
    msgs = [
        ("a", make_message("Q", message_id="root@x")),
        ("b", make_message("Re: Q", message_id="r1@x", extra="In-Reply-To: <root@x>\r\n")),
        ("c", make_message("Other", message_id="o@x")),
    ]
    with ScriptedPop3Server(msgs) as srv:
        s = connect(srv)
        res = s.search_related("INBOX", ["<root@x>"])
        subjects = {x.subject for x in s.fetch_summaries("INBOX", list(res.uids))}
        assert subjects == {"Q", "Re: Q"}
        s.close()
