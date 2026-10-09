"""An in-process SMTP sink for tests: receives mail, never relays it anywhere.

Speaks the submission side of SMTP (EHLO, STARTTLS or implicit TLS, AUTH PLAIN/LOGIN,
SIZE, 8BITMIME, MAIL/RCPT/DATA/RSET/QUIT) on 127.0.0.1 with a throw-away certificate
for ``localhost``, and records what a client sent: envelope, raw message, whether it
authenticated and whether the connection was encrypted. Knobs make it misbehave on
demand: no STARTTLS, refused recipients, an advertised size limit, a rejected DATA, a
connection that drops after the body. It runs in threads (no new dependency) and works
the same locally and in CI.
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


@dataclass
class Received:
    mail_from: str
    rcpt_to: list[str]
    data: bytes
    authenticated: bool
    encrypted: bool


@dataclass
class SmtpSink:
    implicit_tls: bool = False
    offer_starttls: bool = True
    user: str = "alice"
    password: str = "secret"
    offer_auth: bool = True
    advertise_size: int | None = None
    refuse_rcpt: frozenset[str] = frozenset()
    data_reply: str = "250 2.0.0 queued as TESTID"
    drop_after_data: bool = False
    messages: list[Received] = field(default_factory=list[Received])
    commands: list[str] = field(default_factory=list[str])
    auth_failures: int = 0

    def __post_init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._tls = self_signed_context(Path(self._tmp.name))
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        self._lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self) -> None:
        self._listener.close()
        self._tmp.cleanup()

    def __enter__(self) -> SmtpSink:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------ server side

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        encrypted = self.implicit_tls
        authed = False
        mail_from = ""
        rcpts: list[str] = []
        try:
            if encrypted:
                conn = self._tls.wrap_socket(conn, server_side=True)
            f = conn.makefile("rb")

            def reply(*lines: str) -> None:
                conn.sendall("".join(f"{ln}\r\n" for ln in lines).encode())

            reply("220 sink ESMTP ready")
            while True:
                raw = f.readline()
                if not raw:
                    return
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                cmd = line.split(" ", 1)[0].upper()
                with self._lock:
                    self.commands.append(cmd)
                if cmd == "EHLO":
                    caps = ["250-sink", "250-8BITMIME"]
                    if self.advertise_size is not None:
                        caps.append(f"250-SIZE {self.advertise_size}")
                    if not encrypted and self.offer_starttls:
                        caps.append("250-STARTTLS")
                    if self.offer_auth and (encrypted or not self.offer_starttls):
                        caps.append("250-AUTH PLAIN LOGIN")
                    caps.append("250 HELP")
                    reply(*caps)
                elif cmd == "STARTTLS":
                    reply("220 go ahead")
                    conn = self._tls.wrap_socket(conn, server_side=True)
                    f = conn.makefile("rb")
                    encrypted = True
                elif cmd == "AUTH":
                    parts = line.split()
                    mech = parts[1].upper() if len(parts) > 1 else ""
                    if mech == "PLAIN":
                        blob = parts[2] if len(parts) > 2 else ""
                        _, user, pw = base64.b64decode(blob).decode().split("\0")
                    elif mech == "LOGIN":
                        reply("334 " + base64.b64encode(b"Username:").decode())
                        user = base64.b64decode(f.readline().strip()).decode()
                        reply("334 " + base64.b64encode(b"Password:").decode())
                        pw = base64.b64decode(f.readline().strip()).decode()
                    else:
                        reply("504 5.5.4 unsupported mechanism")
                        continue
                    if (user, pw) == (self.user, self.password):
                        authed = True
                        reply("235 2.7.0 authenticated")
                    else:
                        self.auth_failures += 1
                        reply("535 5.7.8 authentication failed")
                elif cmd == "MAIL":
                    mail_from = line.split(":", 1)[1].split()[0].strip("<>")
                    rcpts = []
                    reply("250 2.1.0 ok")
                elif cmd == "RCPT":
                    addr = line.split(":", 1)[1].split()[0].strip("<>")
                    if addr.lower() in self.refuse_rcpt:
                        reply("550 5.1.1 no such user here")
                    else:
                        rcpts.append(addr)
                        reply("250 2.1.5 ok")
                elif cmd == "DATA":
                    reply("354 end with <CRLF>.<CRLF>")
                    body = bytearray()
                    while True:
                        ln = f.readline()
                        if not ln:
                            return
                        if ln == b".\r\n":
                            break
                        body += ln[1:] if ln.startswith(b"..") else ln
                    if self.drop_after_data:
                        return
                    if self.data_reply.startswith("250"):
                        with self._lock:
                            self.messages.append(
                                Received(mail_from, list(rcpts), bytes(body), authed, encrypted)
                            )
                    reply(self.data_reply)
                elif cmd == "RSET":
                    rcpts = []
                    reply("250 2.0.0 ok")
                elif cmd == "QUIT":
                    reply("221 2.0.0 bye")
                    return
                else:
                    reply("502 5.5.2 command not recognised")
        except (OSError, ssl.SSLError, ValueError):
            return
        finally:
            conn.close()
