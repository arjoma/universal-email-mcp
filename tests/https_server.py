"""A throw-away HTTPS document server for the client-metadata fetch tests.

The certificate is self-signed for ``client.test`` and doubles as the CA file the fetcher
trusts; ``client.test`` resolves to 127.0.0.1 through the test resolver, so the whole
SSRF-safe path (resolve once, check, connect to the IP, verify against the host name) runs
for real.
"""

from __future__ import annotations

import datetime as dt
import http.server
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HOST = "client.test"


@dataclass
class Reply:
    status: int = 200
    body: bytes = b"{}"
    content_type: str = "application/json"
    headers: dict[str, str] = field(default_factory=dict[str, str])
    trickle: float = 0.0
    """Seconds to wait between body bytes (a slow server)."""
    declared_length: int | None = None


def make_certificate(tmp: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp / "doc-cert.pem", tmp / "doc-key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


@dataclass
class DocServer:
    port: int
    ca_file: str
    routes: dict[str, Reply]
    hits: list[str]

    def url(self, path: str) -> str:
        return f"https://{HOST}:{self.port}{path}"


def resolver(host: str, port: int) -> list[str]:
    return ["127.0.0.1"] if host == HOST else []


@contextmanager
def doc_server(tmp: Path) -> Iterator[DocServer]:
    cert_file, key_file = make_certificate(tmp)
    routes: dict[str, Reply] = {}
    hits: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

        def do_GET(self) -> None:  # noqa: N802
            hits.append(self.path)
            reply = routes.get(self.path, Reply(404, b"{}"))
            self.send_response(reply.status)
            self.send_header("Content-Type", reply.content_type)
            length = reply.declared_length if reply.declared_length is not None else len(reply.body)
            self.send_header("Content-Length", str(length))
            for k, v in reply.headers.items():
                self.send_header(k, v)
            self.end_headers()
            try:
                if reply.trickle:
                    for i in range(len(reply.body)):
                        self.wfile.write(reply.body[i : i + 1])
                        self.wfile.flush()
                        time.sleep(reply.trickle)
                else:
                    self.wfile.write(reply.body)
            except OSError:
                pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_file, key_file)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    try:
        yield DocServer(server.server_address[1], str(cert_file), routes, hits)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


Responder = Callable[[str], Reply]
