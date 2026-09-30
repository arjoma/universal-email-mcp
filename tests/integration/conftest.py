"""Fixtures for integration tests against a real Dovecot IMAP server in a container.

Server selection:

- ``UEM_TEST_IMAP_HOST`` set (CI: a ``services:`` container): use it, with ports
  from ``UEM_TEST_IMAPS_PORT`` (default 31993) and ``UEM_TEST_STARTTLS_PORT``
  (default 31143) and the password from ``UEM_TEST_IMAP_PASSWORD``.
- otherwise start ``DOVECOT_IMAGE`` with podman (or a working docker) on random
  local ports and remove it afterwards.
- neither available: the tests are skipped — unless ``UEM_TEST_REQUIRE_INTEGRATION=1``
  (set in CI), then they fail.

The Dovecot image accepts any user name with the password from ``USER_PASSWORD``,
so every test module gets its own fresh mailbox.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pytest
from imapclient import IMAPClient

from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import Endpoint, TlsSettings

DOVECOT_IMAGE = (
    "docker.io/dovecot/dovecot:2.4.5"
    "@sha256:c807be4fb5a97d9c3a90770569d3a6c4cbdcb36742ad41f90409cbd929166553"
)
DEFAULT_PASSWORD = "uem-test-password"
DATA = Path(__file__).parent.parent / "data"


@dataclass(frozen=True)
class ImapServer:
    host: str
    imaps_port: int
    starttls_port: int
    password: str


def _unavailable(reason: str) -> None:
    if os.environ.get("UEM_TEST_REQUIRE_INTEGRATION") == "1":
        pytest.fail(f"integration server required but unavailable: {reason}")
    pytest.skip(f"integration tests skipped: {reason}")


def _container_runtime() -> str | None:
    for rt in ("podman", "docker"):
        if shutil.which(rt) is None:
            continue
        try:
            ok = subprocess.run([rt, "info"], capture_output=True, timeout=30).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        if ok:
            return rt
    return None


def _insecure_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _wait_ready(host: str, port: int, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3) as raw:
                with _insecure_ctx().wrap_socket(raw) as tls:
                    tls.settimeout(3)
                    if tls.recv(64).startswith(b"* OK"):
                        return
        except OSError as e:
            last = e
        time.sleep(0.5)
    _unavailable(f"IMAP server at {host}:{port} not ready ({last})")


def _host_port(rt: str, cid: str, container_port: int) -> int:
    out = subprocess.run(
        [rt, "port", cid, f"{container_port}/tcp"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    return int(out.strip().splitlines()[0].rsplit(":", 1)[1])


@pytest.fixture(scope="session")
def imap_server() -> Iterator[ImapServer]:
    host = os.environ.get("UEM_TEST_IMAP_HOST")
    if host:
        server = ImapServer(
            host=host,
            imaps_port=int(os.environ.get("UEM_TEST_IMAPS_PORT", "31993")),
            starttls_port=int(os.environ.get("UEM_TEST_STARTTLS_PORT", "31143")),
            password=os.environ.get("UEM_TEST_IMAP_PASSWORD", DEFAULT_PASSWORD),
        )
        _wait_ready(server.host, server.imaps_port)
        yield server
        return

    rt = _container_runtime()
    if rt is None:
        _unavailable("no container runtime (podman/docker) and UEM_TEST_IMAP_HOST not set")
        return
    try:
        cid = subprocess.run(
            [
                rt,
                "run",
                "-d",
                "--rm",
                "-e",
                f"USER_PASSWORD={DEFAULT_PASSWORD}",
                "-p",
                "127.0.0.1::31993",
                "-p",
                "127.0.0.1::31143",
                DOVECOT_IMAGE,
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=600,
        ).stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        _unavailable(f"could not start {DOVECOT_IMAGE} with {rt}: {e}")
        return
    try:
        server = ImapServer(
            host="127.0.0.1",
            imaps_port=_host_port(rt, cid, 31993),
            starttls_port=_host_port(rt, cid, 31143),
            password=DEFAULT_PASSWORD,
        )
        _wait_ready(server.host, server.imaps_port)
        yield server
    finally:
        subprocess.run([rt, "rm", "-f", cid], capture_output=True, timeout=60)


# ---------------------------------------------------------------- seeding


@dataclass(frozen=True)
class Mailbox:
    server: ImapServer
    user: str

    def admin(self) -> IMAPClient:
        """Plain imapclient connection for seeding/mutating (tests only)."""
        c = IMAPClient(
            self.server.host, self.server.imaps_port, ssl_context=_insecure_ctx(), timeout=30
        )
        c.login(self.user, self.server.password)
        return c

    def session(self, **kw: object) -> ImapSession:
        return ImapSession.connect(
            Endpoint(self.server.host, self.server.imaps_port, "tls"),
            self.user,
            self.server.password,
            account_name="test",
            net=NetPolicy(allow_private=True, connect_timeout=10, read_timeout=30),
            tls=TlsSettings(verify=False),
            **kw,  # pyright: ignore[reportArgumentType]
        )


def _msg(subject: str, sender: str, body: str, *, extra: str = "") -> bytes:
    return (
        f"From: {sender}\r\nTo: alice@example.org\r\nSubject: {subject}\r\n"
        f"Message-ID: <{uuid.uuid4().hex}@example.com>\r\n{extra}"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        f"{body}\r\n"
    ).encode()


# (file or bytes, internaldate, flags) — appended in this order (UIDs ascending).
def seed_messages() -> list[tuple[bytes, datetime, tuple[bytes, ...]]]:
    def when(day: int) -> datetime:
        return datetime.fromisoformat(f"2026-09-{day:02d}T10:00:00+02:00")

    def f(name: str) -> bytes:
        return (DATA / name).read_bytes()

    return [
        (
            _msg("Old plain note", "Carol <carol@example.net>", "zebra crossing"),
            when(1),
            (b"\\Seen",),
        ),
        (f("nested_rfc822.eml"), when(5), (b"\\Seen",)),
        (f("references.eml"), when(10), ()),
        (f("attachments.eml"), when(12), (b"\\Flagged",)),
        (f("broken_charset.eml"), when(15), (b"\\Seen",)),
        (f("html_only_hidden.eml"), when(20), ()),
        (f("multipart_alternative.eml"), when(25), (b"\\Seen", b"\\Flagged")),
        (_msg("Big one", "Dave <dave@example.com>", "x" * 20000), when(28), ()),
    ]


@pytest.fixture(scope="module")
def mailbox(imap_server: ImapServer) -> Mailbox:
    mb = Mailbox(imap_server, f"u{uuid.uuid4().hex[:12]}@example.org")
    c = mb.admin()
    try:
        for raw, when, flags in seed_messages():
            c.append("INBOX", raw, flags=flags, msg_time=when)
        for folder in ("Archiv", "Projekte", "Projekte/Archive", "Ümlaut Ordner"):
            c.create_folder(folder)
        c.append("Archiv", _msg("Archived", "x@example.com", "old"), msg_time=datetime(2025, 1, 1))
    finally:
        c.logout()
    return mb
