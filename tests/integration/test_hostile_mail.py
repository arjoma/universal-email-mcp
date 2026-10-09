"""Hostile headers and structures against a real server: no single message may kill
the process (H1), drop an account from a listing (H2) or make a message unreadable
(M1) — the payloads of the security review. The stdio test uses the real transport:
the in-memory client never serialises results to JSON and hides surrogate errors."""

from __future__ import annotations

import os
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from .conftest import ImapServer, Mailbox
from .test_mcp_tools import Seeded, ago, call, connect, mail, text

pytestmark = pytest.mark.integration


def _raw(subject: str, extra: str = "", body: str = "hello") -> bytes:
    return (
        f"From: x@attacker.example\r\nTo: victim@example.org\r\nSubject: {subject}\r\n"
        f"Message-ID: <{uuid.uuid4().hex}@attacker.example>\r\n{extra}\r\n{body}\r\n"
    ).encode()


SURROGATE_SUBJECT = _raw("=?utf-7?q?+2D0-?=")
BAD_CHARSET_SUBJECT = _raw("=?undefined?q?hi?=")
NUL_CHARSET_SUBJECT = _raw("=?\x00?q?a?=")
BAD_BODY_CHARSET = _raw("utf-7 body", "Content-Type: text/plain; charset=utf-7\r\n", "+2D0- end")
BAD_PARAM = (
    b"From: y@attacker.example\r\nTo: victim@example.org\r\nSubject: part\r\n"
    b"Message-ID: <badparam@attacker.example>\r\nMIME-Version: 1.0\r\n"
    b"Content-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\n"
    b"Content-Type: text/plain\r\n\r\nvisible text\r\n--XX\r\n"
    b"Content-Type: application/pdf; name*0*\r\n\r\nPDF\r\n--XX--\r\n"
)
BAD_TOP_PARAM = _raw("top", "Content-Type: text/plain; filename*0*\r\n", "still readable")
MANY_PARTS = (
    b"From: z@attacker.example\r\nTo: victim@example.org\r\nSubject: many parts\r\n"
    b"Message-ID: <many@attacker.example>\r\nMIME-Version: 1.0\r\n"
    b"Content-Type: multipart/mixed; boundary=X\r\n\r\n" + b"--X\r\n\r\n" * 12_000 + b"--X--\r\n"
)
EIGHT_BIT_HEADER = (
    b"From: x@attacker.example\r\nTo: victim@example.org\r\nSubject: Gr\xfc\xdfe\r\n"
    b"X-Mailer: \xe4\r\nMessage-ID: <8bit@attacker.example>\r\n\r\nhi\r\n"
)

HOSTILE = [
    SURROGATE_SUBJECT,
    BAD_CHARSET_SUBJECT,
    NUL_CHARSET_SUBJECT,
    BAD_BODY_CHARSET,
    BAD_PARAM,
    BAD_TOP_PARAM,
    MANY_PARTS,
    EIGHT_BIT_HEADER,
]


@pytest.fixture(scope="module")
def seeded(imap_server: ImapServer) -> Iterator[Seeded]:
    work = Mailbox(imap_server, f"w{uuid.uuid4().hex[:10]}@example.org")
    private = Mailbox(imap_server, f"p{uuid.uuid4().hex[:10]}@example.org")
    c = work.admin()
    try:
        c.append(
            "INBOX",
            mail("Good one", "Bob <bob@example.com>", work.user, when=ago(1)),
            msg_time=ago(1),
        )
        for raw in HOSTILE:
            c.append("INBOX", raw, msg_time=ago(0.5))
    finally:
        c.logout()
    c = private.admin()
    try:
        c.append(
            "INBOX",
            mail("Private ok", "Bob <bob@example.com>", private.user, when=ago(1)),
            msg_time=ago(1),
        )
    finally:
        c.logout()
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("UEM_IT_PASSWORD", imap_server.password)
        yield Seeded(imap_server, work.user, private.user)


async def test_listing_keeps_every_account_and_every_message(seeded: Seeded):
    async with connect(seeded.config()) as c:
        _t, data = await call(c, "find_messages", since=ago(3).date().isoformat())
        subjects = [m["subject"] for m in data["messages"]]
        assert "Good one" in subjects and "Private ok" in subjects  # both accounts listed
        assert len(subjects) == 2 + len(HOSTILE)
        assert not any("\ud83d" in s for s in subjects)
        for _ in range(2):  # the same call again: nothing is poisoned
            r = await c.call_tool("find_messages", {"query": "good"})
            assert not r.is_error
            r.model_dump_json()  # what the stdio writer does


async def test_message_with_malformed_param_is_readable(seeded: Seeded):
    async with connect(seeded.config()) as c:
        _t, data = await call(c, "find_messages", since=ago(3).date().isoformat(), account="Work")
        by_subject = {m["subject"]: m["id"] for m in data["messages"]}
        body, _d = await call(c, "get_message", id=by_subject["part"])
        assert "visible text" in body
        body, _d = await call(c, "get_message", id=by_subject["top"])
        assert "still readable" in body
        body, _d = await call(c, "get_message", id=by_subject["many parts"])
        assert "many parts" in body
        r = await c.call_tool("get_message", {"id": by_subject["utf-7 body"]})
        assert not r.is_error
        r.model_dump_json()


async def test_stdio_server_survives_hostile_mail(seeded: Seeded, tmp_path: Path):
    cfg = tmp_path / "c.toml"
    cfg.write_text(
        f"""
[settings]
allow_private_networks = true
[[accounts]]
name = "Work"
username = "{seeded.work}"
password_env = "UEM_IT_PASSWORD"
tls_verify = false
[accounts.imap]
host = "{seeded.server.host}"
port = {seeded.server.imaps_port}
"""
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "universal_email_mcp", "local", "--config", str(cfg)],
        env={**os.environ, "UEM_IT_PASSWORD": seeded.server.password},
    )
    async with Client(params) as c:
        for _ in range(2):
            r = await c.call_tool("find_messages", {"since": ago(3).date().isoformat()})
            assert not r.is_error, text(r)
            assert r.structured_content is not None
            assert len(r.structured_content["messages"]) == 1 + len(HOSTILE)
        # the process is still alive and answers
        r = await c.call_tool("find_messages", {"query": "good"})
        assert not r.is_error
