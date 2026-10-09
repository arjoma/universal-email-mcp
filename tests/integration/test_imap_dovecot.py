"""Read-only IMAP backend against a real Dovecot server (see conftest.py)."""

from __future__ import annotations

import dataclasses
import socket
import ssl
import uuid
from datetime import date, datetime
from pathlib import Path

import pytest
from cryptography import x509

from universal_email_mcp.errors import (
    AuthFailed,
    FolderNotFound,
    InvalidRef,
    MailError,
    MessageNotFound,
    ProtocolError,
    ServerUnreachable,
    TlsError,
    UidValidityChanged,
)
from universal_email_mcp.mail.imap import ImapSession, SearchCriteria
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import Endpoint, MessageRef, TlsSettings
from universal_email_mcp.probe import format_report, run_probe

from .conftest import ImapServer, Mailbox

pytestmark = pytest.mark.integration

NET = NetPolicy(allow_private=True, connect_timeout=10, read_timeout=30)
INSECURE = TlsSettings(verify=False)


@pytest.fixture
def session(mailbox: Mailbox):
    s = mailbox.session()
    yield s
    s.close()


# ---------------------------------------------------------------- connect / auth / TLS


def test_login_and_capabilities(session: ImapSession):
    info = session.login_info
    assert info.tls == "implicit TLS"
    assert "IMAP4REV1" in info.capabilities
    assert info.auth_mechanism == "AUTHENTICATE PLAIN"
    f = session.features
    assert f.sort and f.move and f.uidplus and f.special_use and f.namespace
    assert session.namespace() is not None
    assert session.quota() is None  # image has no quota plugin


def test_starttls(mailbox: Mailbox):
    with ImapSession.connect(
        Endpoint(mailbox.server.host, mailbox.server.starttls_port, "starttls"),
        mailbox.user,
        mailbox.server.password,
        net=NET,
        tls=INSECURE,
    ) as s:
        assert s.login_info.tls == "STARTTLS"
        assert "STARTTLS" not in s.login_info.pre_auth_capabilities  # post-TLS list
        assert s.list_folders()


def test_implicit_tls_on_plain_port_fails(mailbox: Mailbox):
    with pytest.raises((TlsError, ServerUnreachable)):
        ImapSession.connect(
            Endpoint(mailbox.server.host, mailbox.server.starttls_port, "tls"),
            mailbox.user,
            mailbox.server.password,
            net=NetPolicy(allow_private=True, connect_timeout=5, read_timeout=5),
            tls=INSECURE,
        )


def test_default_tls_rejects_self_signed(mailbox: Mailbox):
    with pytest.raises(TlsError, match="certificate verification failed"):
        ImapSession.connect(
            Endpoint(mailbox.server.host, mailbox.server.imaps_port, "tls"),
            mailbox.user,
            mailbox.server.password,
            net=NET,
        )


def test_private_address_refused_by_default(mailbox: Mailbox):
    from universal_email_mcp.errors import AddressNotAllowed

    with pytest.raises(AddressNotAllowed):
        ImapSession.connect(
            Endpoint(mailbox.server.host, mailbox.server.imaps_port, "tls"),
            mailbox.user,
            mailbox.server.password,
            net=NetPolicy(),
            tls=INSECURE,
        )


def test_verified_tls_with_pinned_ca_and_sni(mailbox: Mailbox, tmp_path: Path):
    server = mailbox.server
    pem = ssl.get_server_certificate((server.host, server.imaps_port))
    ca = tmp_path / "server.pem"
    ca.write_text(pem)
    cert = x509.load_pem_x509_certificate(pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    cert_host = san.get_values_for_type(x509.DNSName)[0]
    ip = socket.gethostbyname(server.host)

    def resolver(host: str, port: int) -> list[str]:
        return [ip]

    with ImapSession.connect(
        Endpoint(cert_host, server.imaps_port, "tls"),
        mailbox.user,
        server.password,
        net=NET,
        tls=TlsSettings(verify=True, ca_file=str(ca)),
        resolver=resolver,
    ) as s:
        assert s.list_folders()

    with pytest.raises(TlsError):
        ImapSession.connect(
            Endpoint("wrong-name.test", server.imaps_port, "tls"),
            mailbox.user,
            server.password,
            net=NET,
            tls=TlsSettings(verify=True, ca_file=str(ca)),
            resolver=resolver,
        )


# ---------------------------------------------------------------- folders


def test_folders_and_roles(session: ImapSession):
    folders = {f.display_name: f for f in session.list_folders(with_counts=True)}
    roles = {f.role: name for name, f in folders.items() if f.role}
    assert roles == {
        "inbox": "INBOX",
        "sent": "Sent",
        "drafts": "Drafts",
        "trash": "Trash",
        "junk": "Junk",
        "archive": "Archiv",  # name heuristic (no \Archive flag on this server)
    }
    assert folders["Projekte/Archive"].role is None
    umlaut = folders["Ümlaut Ordner"]
    assert umlaut.name == "&ANw-mlaut Ordner" and umlaut.delimiter == "/"
    inbox = folders["INBOX"]
    assert (inbox.messages, inbox.unseen) == (8, 4)
    assert folders["Archiv"].messages == 1


def test_folder_role_override(mailbox: Mailbox):
    with mailbox.session(folder_roles={"archive": "Projekte"}) as s:
        assert s.resolve_folder("archive").name == "Projekte"
        assert s.folder_for_role("archive") is not None
        assert s.role_warnings == []


def test_resolve_folder(session: ImapSession):
    assert session.resolve_folder("ümlaut ordner").name == "&ANw-mlaut Ordner"
    assert session.resolve_folder("&ANw-mlaut Ordner").display_name == "Ümlaut Ordner"
    assert session.resolve_folder("trash").name == "Trash"
    with pytest.raises(FolderNotFound):
        session.resolve_folder("does not exist")


def test_folder_status_and_missing_folder(session: ImapSession):
    st = session.folder_status("INBOX")
    assert st.messages == 8 and st.unseen == 4 and st.uidvalidity
    with pytest.raises(FolderNotFound):
        session.search("No/Such/Folder")
    # non-ASCII display names are encoded to the wire form
    assert session.search("Ümlaut Ordner").uids == ()


# ---------------------------------------------------------------- search


def uids(session: ImapSession, **criteria: object) -> list[int]:
    return list(session.search("INBOX", SearchCriteria(**criteria)).uids)  # pyright: ignore[reportArgumentType]


def test_search_all_newest_first(session: ImapSession):
    result = session.search("INBOX")
    assert result.order == "arrival"
    assert list(result.uids) == [8, 7, 6, 5, 4, 3, 2, 1]
    assert result.exact and result.total == 8
    refs = result.refs(0, 2)
    assert [r.uid for r in refs] == [8, 7] and refs[0].account == "test"


def test_search_criteria(session: ImapSession):
    assert uids(session, from_="Müller") == [7]  # UTF-8 search, RFC 2047 header
    assert uids(session, cc="Öztürk") == [3]
    assert uids(session, subject="Rechnung") == [4]
    assert uids(session, to="bob@example.org") == [7]
    assert uids(session, unseen=True) == [8, 6, 4, 3]
    assert uids(session, flagged=True) == [7, 4]
    assert uids(session, flagged=True, unseen=False) == [7]
    assert uids(session, since=date(2026, 9, 12), before=date(2026, 9, 21)) == [6, 5, 4]
    assert uids(session, larger=15000) == [8]
    assert uids(session, smaller=15000, since=date(2026, 9, 26)) == []
    assert uids(session, body="zebra") == [1]
    assert uids(session, text="zebra") == [1]
    assert uids(session, subject='quote " and \\ backslash') == []
    assert uids(session, subject="a\r\nA1 LOGOUT") == []  # CRLF cannot inject commands
    assert session.list_folders()  # connection still usable


def test_search_has_attachment(session: ImapSession):
    assert uids(session, has_attachment=True) == [4, 2]
    assert uids(session, has_attachment=False) == [8, 7, 6, 5, 3, 1]


def _mime(ctype: str, parts: str) -> bytes:
    return (
        "From: a@example.com\r\nTo: b@example.org\r\nSubject: t\r\nMIME-Version: 1.0\r\n"
        f'Content-Type: {ctype}; boundary="B"\r\n\r\n'
        "--B\r\nContent-Type: text/plain\r\n\r\nHello\r\n"
        f"--B\r\n{parts}\r\n--B--\r\n"
    ).encode()


PDF_PART = (
    'Content-Type: application/pdf; name="x.pdf"\r\n'
    'Content-Disposition: attachment; filename="x.pdf"\r\n'
    "Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK"
)


def test_search_has_attachment_in_signed_related_report(imap_server: ImapServer):
    mb = Mailbox(imap_server, f"att-{uuid.uuid4().hex[:10]}@example.org")
    c = mb.admin()
    try:
        c.append("INBOX", _mime('multipart/signed; protocol="application/pgp-signature"', PDF_PART))
        c.append("INBOX", _mime('multipart/related; type="text/plain"', PDF_PART))
        c.append("INBOX", _mime("multipart/report; report-type=delivery-status", PDF_PART))
        c.append("INBOX", b"From: a@example.com\r\nSubject: plain\r\n\r\nno attachment\r\n")
    finally:
        c.logout()
    with mb.session() as s:
        res = s.search("INBOX", SearchCriteria(has_attachment=True))
        assert sorted(res.uids) == [1, 2, 3]
        assert not res.exact  # heuristic pre-filter + BODYSTRUCTURE: never claimed exact


def test_search_without_sort_orders_by_uid(session: ImapSession):
    caps = tuple(c for c in session.login_info.capabilities if not c.startswith("SORT"))
    session.login_info = dataclasses.replace(session.login_info, capabilities=caps)
    result = session.search("INBOX", SearchCriteria(unseen=True))
    assert result.order == "uid" and list(result.uids) == [8, 6, 4, 3]


def test_search_utf8_fallback_when_charset_rejected(
    session: ImapSession, monkeypatch: pytest.MonkeyPatch
):
    real = session._run_search  # pyright: ignore[reportPrivateUsage]

    def picky(args: list[bytes], charset: str | None):
        if charset == "UTF-8":
            raise ProtocolError("SEARCH failed: NO [BADCHARSET (US-ASCII)]")
        return real(args, charset)

    monkeypatch.setattr(session, "_run_search", picky)
    result = session.search("INBOX", SearchCriteria(from_="Müller", unseen=False))
    assert list(result.uids) == [7]
    assert not result.exact and result.notes
    body = session.search("INBOX", SearchCriteria(body="Grüße"))
    assert not body.exact
    assert any("headers only" in n for n in body.notes)


# ---------------------------------------------------------------- summaries


def test_fetch_summaries(session: ImapSession):
    result = session.search("INBOX")
    summaries = session.fetch_summaries("INBOX", [7, 4, 6, 999], uidvalidity=result.uidvalidity)
    assert [s.ref.uid for s in summaries] == [7, 4, 6]  # order kept, unknown UID skipped
    alt, att, html = summaries
    assert alt.subject == "Grüße aus Wien"
    assert alt.from_[0].name == "Jürgen Müller"
    assert alt.seen and alt.flagged
    assert alt.message_id == "<alt-1@example.com>"
    assert alt.date == datetime.fromisoformat("2026-09-29T10:15:00+02:00")
    assert alt.received is not None and alt.received.tzinfo is not None
    assert att.has_attachments and not alt.has_attachments and not html.has_attachments
    assert att.size and att.size > 500
    assert MessageRef.decode(alt.id) == alt.ref

    threaded = session.fetch_summaries("INBOX", [3])[0]
    assert threaded.in_reply_to == "<reply-2@example.com>"
    assert threaded.references == ("<root-1@example.com>", "<reply-2@example.com>")


def test_fetch_flags(session: ImapSession):
    flags = session.fetch_flags("INBOX", [4, 7, 999])
    assert set(flags) == {4, 7}  # vanished/unknown UIDs are left out
    assert "\\Flagged" in flags[4] and {"\\Seen", "\\Flagged"} <= set(flags[7])
    with pytest.raises(UidValidityChanged):
        session.fetch_flags("INBOX", [4], uidvalidity=1)


def test_fetch_summaries_stale_uidvalidity(session: ImapSession):
    current = session.search("INBOX").uidvalidity
    with pytest.raises(UidValidityChanged):
        session.fetch_summaries("INBOX", [1], uidvalidity=current + 1)


def test_fetch_summaries_since_uid(session: ImapSession):
    uv = session.search("INBOX").uidvalidity
    batch = session.fetch_summaries_since_uid("INBOX", uv, 0, limit=3)
    assert [s.ref.uid for s in batch.summaries] == [1, 2, 3]
    assert batch.last_uid == 3 and batch.more
    rest = session.fetch_summaries_since_uid("INBOX", uv, batch.last_uid, limit=100)
    assert [s.ref.uid for s in rest.summaries] == [4, 5, 6, 7, 8] and not rest.more
    # "UID 9:*" matches the highest message (8) on the server; it must be filtered out.
    none = session.fetch_summaries_since_uid("INBOX", uv, 8)
    assert none.summaries == () and none.last_uid == 8 and not none.more
    with pytest.raises(UidValidityChanged):
        session.fetch_summaries_since_uid("INBOX", uv + 1, 0)
    first = session.fetch_summaries_since_uid("INBOX", None, 7)
    assert [s.ref.uid for s in first.summaries] == [8]


# ---------------------------------------------------------------- full messages


def _ref(session: ImapSession, uid: int) -> MessageRef:
    return session.search("INBOX").refs()[8 - uid]


def test_fetch_message_does_not_set_seen(session: ImapSession):
    ref = _ref(session, 6)
    assert ref.uid == 6
    msg = session.fetch_message(ref)
    assert msg.body_source == "html"
    assert "Visible paragraph one." in msg.body.text
    assert "HIDDEN" not in msg.body.text
    assert not msg.summary.seen
    again = session.fetch_summaries("INBOX", [6])[0]
    assert not again.seen
    assert session.folder_status("INBOX").unseen == 4


def test_fetch_message_attachments(session: ImapSession):
    msg = session.fetch_message(_ref(session, 4))
    assert msg.body.text == "Anbei die Rechnung."
    names = {a.filename for a in msg.attachments if not a.inline}
    assert names == {"Rechnung März.pdf", "notes.txt"}
    assert msg.summary.has_attachments and msg.summary.flagged
    fwd = session.fetch_message(_ref(session, 2))
    assert [a.content_type for a in fwd.attachments] == ["message/rfc822"]


def test_fetch_message_limits(session: ImapSession):
    ref = _ref(session, 8)
    full = session.fetch_message(ref, max_body_chars=100)
    assert full.body.truncated and full.body.next_offset == 100 and full.body.total_chars == 20000
    nxt = session.fetch_message(ref, max_body_chars=100, body_offset=19950)
    assert len(nxt.body.text) == 50 and not nxt.body.truncated
    partial = session.fetch_message(ref, max_bytes=2000)
    assert partial.source_truncated
    assert partial.body.total_chars < 2000
    assert partial.summary.subject == "Big one"


def test_fetch_message_bad_refs(session: ImapSession):
    ref = _ref(session, 1)
    with pytest.raises(InvalidRef):
        session.fetch_message(dataclasses.replace(ref, account="other"))
    with pytest.raises(UidValidityChanged):
        session.fetch_message(dataclasses.replace(ref, uidvalidity=ref.uidvalidity + 1))
    with pytest.raises(MessageNotFound):
        session.fetch_message(dataclasses.replace(ref, uid=4242))
    with pytest.raises(FolderNotFound):
        session.fetch_message(dataclasses.replace(ref, folder="Nope"))


def test_uidvalidity_change_invalidates_refs(mailbox: Mailbox):
    admin = mailbox.admin()
    try:
        admin.create_folder("Volatile")
        admin.append("Volatile", b"Subject: v1\r\n\r\nv1\r\n")
        with mailbox.session() as s:
            ref = s.search("Volatile").refs()[0]
            assert s.fetch_message(ref).summary.subject == "v1"
            admin.delete_folder("Volatile")
            admin.create_folder("Volatile")
            admin.append("Volatile", b"Subject: v2\r\n\r\nv2\r\n")
            new_uv = s.search("Volatile").uidvalidity
            if new_uv == ref.uidvalidity:  # pragma: no cover - server reused the value
                pytest.skip("server reused UIDVALIDITY")
            with pytest.raises(UidValidityChanged) as exc:
                s.fetch_message(ref)
            assert exc.value.code == "UIDVALIDITY_CHANGED"
    finally:
        admin.logout()


# ---------------------------------------------------------------- probe


def test_probe_report(mailbox: Mailbox, imap_server: ImapServer):
    report = run_probe(
        Endpoint(imap_server.host, imap_server.imaps_port, "tls"),
        mailbox.user,
        imap_server.password,
        net=NET,
        tls=INSECURE,
    )
    assert report.features.sort and report.utf8_search is True
    assert report.delimiter == "/"
    assert any(f.role == "inbox" and f.messages == 8 for f in report.folders)
    text = format_report(report)
    assert "[inbox]" in text and "SORT available" in text and "UID MOVE" in text
    for secret in ("Grüße", "Rechnung", "zebra", imap_server.password):
        assert secret not in text  # no message content, no password
    assert report.to_dict()["host"] == imap_server.host


def test_errors_are_mail_errors(mailbox: Mailbox):
    with pytest.raises(MailError):
        ImapSession.connect(
            Endpoint(mailbox.server.host, 1, "tls"),
            mailbox.user,
            mailbox.server.password,
            net=NetPolicy(allow_private=True, connect_timeout=2),
            tls=INSECURE,
        )


@pytest.mark.parametrize("name", ['a"b@example.org', "a\\b@example.org", "x{1}@example.org", "*"])
def test_hostile_login_name_is_a_clean_auth_failure(mailbox: Mailbox, name: str):
    """Quote/brace/wildcard characters in the login name never desync the protocol."""
    with pytest.raises(AuthFailed) as exc:
        ImapSession.connect(
            Endpoint(mailbox.server.host, mailbox.server.imaps_port, "tls"),
            name,
            "wrong-password",
            net=NET,
            tls=INSECURE,
        )
    assert exc.value.code == "AUTH_FAILED"


# Last on purpose: Dovecot delays logins from an IP after a failed one.
def test_wrong_password(mailbox: Mailbox):
    with pytest.raises(AuthFailed) as exc:
        ImapSession.connect(
            Endpoint(mailbox.server.host, mailbox.server.imaps_port, "tls"),
            mailbox.user,
            "wrong-password",
            net=NET,
            tls=INSECURE,
        )
    assert exc.value.code == "AUTH_FAILED"
