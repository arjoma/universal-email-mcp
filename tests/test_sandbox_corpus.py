"""The sandbox corpus (tests/sandbox.py) is well-formed and the generated config loads."""

from __future__ import annotations

import re
import tomllib
from collections import Counter
from datetime import datetime, timedelta
from email import policy
from email.parser import BytesParser

import pytest

from tests.sandbox import (
    CLIENT_FOLDERS,
    HOSTILE_FOLDER,
    PASSWORD_ENV,
    PRIVATE,
    WORK,
    SeedMail,
    build_corpus,
    folders_for,
    render_config,
)
from universal_email_mcp.config import parse_config
from universal_email_mcp.mail.mime import parse_header_block, parse_message

NOW = datetime(2026, 10, 9, 12, 0).astimezone()
DEFAULT_FOLDERS = {"INBOX", "Sent", "Drafts", "Junk", "Trash"}
FAKE_DOMAIN = re.compile(r"(^|\.)(example|test|invalid|example\.(com|org|net))$")


def _decoded_text(raw: bytes) -> str:
    """Unfolded headers and decoded text parts (no transfer-encoding line breaks)."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    out: list[str] = []
    for part in msg.walk():
        out += [f"{k}: {v}" for k, v in part.items()]
        if part.get_content_maintype() == "text":
            try:
                out.append(part.get_content())
            except (LookupError, ValueError):
                out.append(raw.decode("utf-8", "replace"))
    return "\n".join(out)


@pytest.fixture(scope="module")
def corpus() -> list[SeedMail]:
    return build_corpus(NOW, large_attachment_bytes=4096)


def test_every_mail_parses(corpus: list[SeedMail]):
    for m in corpus:
        parse_header_block(m.raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n")
        parsed = parse_message(m.raw)
        if m.hostile is None:
            assert parsed.text.strip(), parsed.headers.subject
            assert parsed.headers.subject


def test_only_fictitious_domains(corpus: list[SeedMail]):
    domains: set[str] = set()
    for m in corpus:
        text = _decoded_text(m.raw)
        domains |= {d.lower().rstrip(".") for d in re.findall(r"[\w.+-]+@([\w.-]+)", text)}
        domains |= {d.lower() for d in re.findall(r"(?:https?|ftp)://([\w.-]+)", text)}
    assert domains
    assert sorted(d for d in domains if not FAKE_DOMAIN.search(d)) == []


def test_folders_dates_and_flags(corpus: list[SeedMail]):
    for m in corpus:
        assert m.folder in DEFAULT_FOLDERS or m.folder in folders_for(m.account), m.folder
        assert m.when <= NOW
    recent = [m for m in corpus if not m.folder.startswith(("Archive", "Tax"))]
    assert all(m.when > NOW - timedelta(days=70) for m in recent)
    assert any(m.when.date() == NOW.date() for m in corpus)  # `today` finds something
    assert {m.account for m in corpus} == {WORK, PRIVATE}
    flags = Counter(f for m in corpus for f in m.flags)
    assert flags[b"\\Seen"] and flags[b"\\Flagged"] and flags[b"\\Answered"]
    assert any(not m.flags for m in corpus)  # unread mail


def test_large_folder_tree():
    work = folders_for(WORK)
    assert len(set(work)) == len(work)
    clients = [f for f in work if f.startswith("Clients/") and f.count("/") == 1]
    assert len(clients) >= 100
    assert any(f.endswith("/2025") for f in CLIENT_FOLDERS)
    assert {"Clients/Müller", "Clients/Mueller Consulting", "Tax/2024", "Tax/2025"} <= set(work)
    for f in work:  # every parent exists (Dovecot would create it, the role check would not)
        if "/" in f and f != HOSTILE_FOLDER:
            assert f.rsplit("/", 1)[0] in work, f


def test_threads_and_hostile_samples(corpus: list[SeedMail]):
    ids = Counter(parse_message(m.raw).headers.message_id for m in corpus)
    dupes = {i for i, n in ids.items() if n > 1}
    assert dupes == {"<angebot-2026-001@huber-bau.example>"}  # the header-tricks sample
    for m in corpus:
        h = parse_message(m.raw).headers
        if m.hostile is None and h.in_reply_to:
            assert h.in_reply_to in ids, h.subject
    labels = [m.hostile for m in corpus if m.hostile]
    assert len(labels) == len(set(labels)) >= 15
    assert {
        "prompt-injection",
        "markdown-exfil",
        "header-tricks",
        "broken-encodings",
        "oversized-body",
        "oversized-attachment",
    } <= set(labels)


def test_rendered_config_loads():
    text = render_config("127.0.0.1", 10993, users={WORK: "w@example.org", PRIVATE: "p@x.test"})
    cfg = parse_config(tomllib.loads(text))
    assert [a.name for a in cfg.accounts] == [WORK, PRIVATE]
    work = cfg.account(WORK)
    assert work.username == "w@example.org" and work.endpoint.port == 10993
    assert work.credential.name == PASSWORD_ENV and work.tls.verify is False
    assert work.permissions.organize and not cfg.account(PRIVATE).permissions.organize
    assert cfg.settings.allow_private_networks and cfg.policy.send == "off"
    assert cfg.default_identity and cfg.default_identity.store_account == WORK
