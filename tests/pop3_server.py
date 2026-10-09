"""A scripted POP3 server on localhost for protocol-level unit tests.

Dovecot (tests/integration) covers a real server; this one covers what only a
script can: a command log (so tests can assert that ``DELE``/``RSET`` are never
sent), servers without ``UIDL``/``TOP``/``STLS``, mailboxes that change between
sessions, hostile UIDLs and oversize answers. Each connection sees a snapshot of
the mailbox taken at connect time, like a real maildrop.
"""

from __future__ import annotations

import base64
import socket
import ssl
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from tests.imap_server import self_signed_context


def make_message(
    subject: str,
    *,
    sender: str = "Alice <alice@example.org>",
    to: str = "bob@example.net",
    body: str = "hello",
    message_id: str | None = None,
    extra: str = "",
    received: str = "from mx.example.net by pop.example.net; Mon, 05 Oct 2026 10:00:00 +0000",
) -> bytes:
    mid = f"Message-ID: <{message_id}>\r\n" if message_id else ""
    return (
        f"Received: {received}\r\n"
        f"From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n{mid}{extra}"
        "Date: Mon, 05 Oct 2026 09:59:00 +0000\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        f"{body}\r\n"
    ).encode()


def make_attachment_message(subject: str, filename: str, payload: bytes) -> bytes:
    b64 = base64.encodebytes(payload).decode().replace("\n", "\r\n")
    return (
        "Received: from mx.example.net by pop.example.net; Tue, 06 Oct 2026 10:00:00 +0000\r\n"
        f"From: Carol <carol@example.com>\r\nTo: bob@example.net\r\nSubject: {subject}\r\n"
        "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n"
        "--XX\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nsee attached\r\n"
        f'--XX\r\nContent-Type: application/octet-stream; name="{filename}"\r\n'
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        f"Content-Transfer-Encoding: base64\r\n\r\n{b64}--XX--\r\n"
    ).encode()


@dataclass
class ScriptedPop3Server:
    """``implicit_tls``: TLS from the first byte; otherwise plain + ``STLS`` (when
    ``offer_stls``). ``messages`` is a list of ``(uidl, raw message)``; change it
    between connections to simulate new mail."""

    messages: list[tuple[str, bytes]] = field(default_factory=list[tuple[str, bytes]])
    implicit_tls: bool = True
    offer_stls: bool = True
    uidl: bool = True
    top: bool = True
    pipelining: bool = True
    sasl_only: bool = False
    stall: frozenset[str] = frozenset()
    commands: list[str] = field(default_factory=list[str])
    connections: int = 0
    stalled: threading.Event = field(default_factory=threading.Event)
    peer_closed: threading.Event = field(default_factory=threading.Event)
    dropped: threading.Event = field(default_factory=threading.Event)

    def __post_init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._tls = self_signed_context(Path(self._tmp.name))
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self) -> None:
        self._listener.close()
        self._tmp.cleanup()

    def __enter__(self) -> ScriptedPop3Server:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def names(self) -> list[str]:
        """Upper-case command names received so far (no arguments)."""
        return [c.split(" ", 1)[0] for c in self.commands]

    # ------------------------------------------------------------ server side

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(
                target=self._serve, args=(conn, list(self.messages)), daemon=True
            ).start()

    def _caps(self, tls: bool) -> list[str]:
        caps = ["USER"] if not self.sasl_only else ["SASL PLAIN"]
        if self.top:
            caps.append("TOP")
        if self.uidl:
            caps.append("UIDL")
        if self.pipelining:
            caps.append("PIPELINING")
        if self.offer_stls and not tls:
            caps.append("STLS")
        return caps

    @staticmethod
    def _multi(conn: socket.socket, status: str, data: bytes) -> None:
        out = bytearray(f"{status}\r\n".encode())
        lines = data.split(b"\r\n")
        if lines and lines[-1] == b"":  # data ended with CRLF
            lines.pop()
        for ln in lines:
            out += (b"." + ln if ln.startswith(b".") else ln) + b"\r\n"
        out += b".\r\n"
        conn.sendall(bytes(out))

    def _serve(self, conn: socket.socket, box: list[tuple[str, bytes]]) -> None:
        tls = self.implicit_tls
        try:
            if tls:
                conn = self._tls.wrap_socket(conn, server_side=True)
            f = conn.makefile("rb")
            conn.sendall(b"+OK scripted POP3 ready\r\n")
            while True:
                line = f.readline()
                if not line:
                    self.peer_closed.set()
                    return
                text = line.decode("ascii", "replace").strip()
                self.commands.append(text)
                cmd, _, arg = text.partition(" ")
                cmd = cmd.upper()
                if cmd in self.stall:
                    self.stalled.set()
                    while f.readline():
                        pass
                    self.peer_closed.set()
                    return
                if cmd == "CAPA":
                    self._multi(conn, "+OK", "\r\n".join(self._caps(tls)).encode() + b"\r\n")
                elif cmd == "STLS":
                    if not self.offer_stls or tls:
                        conn.sendall(b"-ERR no\r\n")
                        continue
                    conn.sendall(b"+OK begin TLS\r\n")
                    conn = self._tls.wrap_socket(conn, server_side=True)
                    f = conn.makefile("rb")
                    tls = True
                elif cmd == "USER":
                    conn.sendall(b"+OK\r\n")
                elif cmd == "PASS":
                    conn.sendall(b"+OK logged in\r\n" if arg == "secret" else b"-ERR bad\r\n")
                elif cmd == "AUTH":
                    conn.sendall(b"+ \r\n")
                    f.readline()
                    conn.sendall(b"+OK logged in\r\n")
                elif cmd == "STAT":
                    total = sum(len(raw) for _u, raw in box)
                    conn.sendall(f"+OK {len(box)} {total}\r\n".encode())
                elif cmd == "UIDL" and self.uidl:
                    body = "".join(f"{i} {u}\r\n" for i, (u, _r) in enumerate(box, 1))
                    self._multi(conn, "+OK", body.encode())
                elif cmd == "LIST":
                    body = "".join(f"{i} {len(r)}\r\n" for i, (_u, r) in enumerate(box, 1))
                    self._multi(conn, "+OK", body.encode())
                elif cmd == "TOP" and self.top:
                    n, _, lines = arg.partition(" ")
                    if not n.isdigit() or not 1 <= int(n) <= len(box):
                        conn.sendall(b"-ERR no such message\r\n")
                        continue
                    raw = box[int(n) - 1][1]
                    head, sep, body = raw.partition(b"\r\n\r\n")
                    keep = b"\r\n".join(body.split(b"\r\n")[: int(lines or 0)])
                    out = head + sep + keep if int(lines or 0) else head + sep
                    self._multi(conn, "+OK", out)
                elif cmd == "RETR":
                    if not arg.isdigit() or not 1 <= int(arg) <= len(box):
                        conn.sendall(b"-ERR no such message\r\n")
                        continue
                    self._multi(conn, "+OK", box[int(arg) - 1][1])
                elif cmd == "QUIT":
                    conn.sendall(b"+OK bye\r\n")
                    self.peer_closed.set()
                    return
                else:
                    conn.sendall(b"-ERR unknown command\r\n")
        except (OSError, ssl.SSLError):
            self.dropped.set()
        finally:
            conn.close()
