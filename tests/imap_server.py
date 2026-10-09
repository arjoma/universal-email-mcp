"""A tiny scripted IMAP server on localhost for connection-level unit tests.

Dovecot (tests/integration) covers real protocol behaviour; this server covers
what a well-behaved server never does: stalling mid-command, not offering
STARTTLS, LOGINDISABLED without AUTH=PLAIN. It speaks just enough IMAP for
``imapclient``/``imaplib`` to connect and log in.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def self_signed_context(tmp: Path) -> ssl.SSLContext:
    """Server TLS context with a throw-away certificate for ``localhost``."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp / "cert.pem", tmp / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


@dataclass
class ScriptedImapServer:
    """``implicit_tls``: TLS from the first byte; otherwise plain + STARTTLS (if in
    ``pre_tls_caps``). ``stall``: IMAP commands (upper case) that never get an answer.
    """

    implicit_tls: bool = True
    pre_tls_caps: tuple[str, ...] = ("STARTTLS",)
    post_tls_caps: tuple[str, ...] = ("AUTH=PLAIN",)
    stall: frozenset[str] = frozenset()
    greeting_literal: int = 0
    """Greet with ``* OK {n}`` followed by ``n`` bytes (a hostile literal)."""
    literal_after: dict[str, int] = field(default_factory=dict[str, int])
    """Command -> size of a literal sent as untagged data before its tagged OK."""
    flood_after: dict[str, int] = field(default_factory=dict[str, int])
    """Command -> total bytes of ordinary untagged lines sent before its tagged OK."""
    starttls_inject: bytes = b""
    """Sent in the clear right behind the STARTTLS OK (a man in the middle)."""
    trickle_greeting: float = 0.0
    """Seconds between the bytes of the greeting (0 = send it at once)."""
    commands: list[str] = field(default_factory=list[str])
    stalled: threading.Event = field(default_factory=threading.Event)
    peer_closed: threading.Event = field(default_factory=threading.Event)

    def __post_init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._tls = self_signed_context(Path(self._tmp.name))
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        self._threads: list[threading.Thread] = []
        t = threading.Thread(target=self._accept, daemon=True)
        t.start()

    def close(self) -> None:
        self._listener.close()
        self._tmp.cleanup()

    def __enter__(self) -> ScriptedImapServer:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------ server side

    @staticmethod
    def _send_literal(conn: socket.socket, prefix: bytes, size: int) -> None:
        conn.sendall(prefix + b" {%d}\r\n" % size)
        chunk = b"A" * (1 << 16)
        left = size
        while left > 0:
            conn.sendall(chunk[: min(left, len(chunk))])
            left -= len(chunk)
        conn.sendall(b"\r\n")

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            t = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self._threads.append(t)
            t.start()

    def _serve(self, conn: socket.socket) -> None:
        tls = self.implicit_tls
        try:
            if tls:
                conn = self._tls.wrap_socket(conn, server_side=True)
            f = conn.makefile("rb")
            if self.greeting_literal:
                self._send_literal(conn, b"* OK", self.greeting_literal)
            elif self.trickle_greeting:
                for b in b"* OK scripted server ready\r\n":
                    conn.sendall(bytes([b]))
                    time.sleep(self.trickle_greeting)
            else:
                conn.sendall(b"* OK scripted server ready\r\n")
            while True:
                line = f.readline()
                if not line:
                    self.peer_closed.set()
                    return
                parts = line.decode("ascii", "replace").strip().split(" ", 2)
                tag, cmd = parts[0], (parts[1].upper() if len(parts) > 1 else "")
                self.commands.append(cmd)
                if cmd in self.literal_after:
                    self._send_literal(conn, b"* NOTE", self.literal_after[cmd])
                if cmd in self.flood_after:
                    for _ in range(self.flood_after[cmd] // 1000):
                        conn.sendall(b"* NOTE " + b"x" * 992 + b"\r\n")
                if cmd in self.stall:
                    self.stalled.set()
                    while f.readline():  # never answer; wait for the client to go away
                        pass
                    self.peer_closed.set()
                    return
                if cmd == "CAPABILITY":
                    caps = self.post_tls_caps if tls else self.pre_tls_caps
                    out = "* CAPABILITY IMAP4rev1 " + " ".join(caps)
                    conn.sendall(f"{out}\r\n{tag} OK done\r\n".encode())
                elif cmd == "STARTTLS":
                    conn.sendall(f"{tag} OK begin TLS\r\n".encode() + self.starttls_inject)
                    conn = self._tls.wrap_socket(conn, server_side=True)
                    f = conn.makefile("rb")
                    tls = True
                elif cmd == "AUTHENTICATE":
                    conn.sendall(b"+ \r\n")
                    f.readline()
                    conn.sendall(f"{tag} OK logged in\r\n".encode())
                elif cmd == "LOGOUT":
                    conn.sendall(f"* BYE bye\r\n{tag} OK done\r\n".encode())
                    return
                else:
                    conn.sendall(f"{tag} OK done\r\n".encode())
        except (OSError, ssl.SSLError):
            self.peer_closed.set()
        finally:
            conn.close()
