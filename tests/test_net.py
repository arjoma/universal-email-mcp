import datetime as dt
import ipaddress
import socket
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from universal_email_mcp.errors import AddressNotAllowed, ServerUnreachable, TlsError
from universal_email_mcp.mail.net import (
    NetPolicy,
    check_address,
    is_public_address,
    open_connection,
    resolve_checked,
    tls_context,
    wrap_tls,
)

BLOCKED = [
    "10.0.0.1",
    "172.16.5.4",
    "192.168.1.1",
    "127.0.0.1",
    "127.8.8.8",
    "169.254.169.254",  # cloud metadata
    "100.64.0.1",  # CGNAT
    "100.127.255.254",
    "0.0.0.0",
    "224.0.0.1",
    "255.255.255.255",
    "192.0.2.10",  # documentation
    "198.18.0.1",  # benchmarking
    "240.0.0.1",
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "fd00:ec2::254",  # AWS IPv6 metadata (ULA)
    "ff02::1",
    "::ffff:10.0.0.1",
    "::ffff:127.0.0.1",
    "64:ff9b::a00:1",  # NAT64 → 10.0.0.1
    "2002:a00:1::1",  # 6to4 → 10.0.0.1
    "2001:db8::1",  # documentation
]
PUBLIC = ["8.8.8.8", "1.1.1.1", "185.199.108.153", "2a00:1450:4001:80b::200e", "64:ff9b::808:808"]


@pytest.mark.parametrize("addr", BLOCKED)
def test_blocked_addresses(addr: str):
    ip = ipaddress.ip_address(addr)
    assert not is_public_address(ip)
    with pytest.raises(AddressNotAllowed):
        check_address(ip, allow_private=False)


@pytest.mark.parametrize("addr", PUBLIC)
def test_public_addresses(addr: str):
    ip = ipaddress.ip_address(addr)
    assert is_public_address(ip)
    check_address(ip, allow_private=False)


def test_allow_private_still_blocks_unspecified_and_multicast():
    check_address(ipaddress.ip_address("10.0.0.1"), allow_private=True)
    check_address(ipaddress.ip_address("::1"), allow_private=True)
    for addr in ("0.0.0.0", "::", "224.0.0.1", "ff02::1"):
        with pytest.raises(AddressNotAllowed):
            check_address(ipaddress.ip_address(addr), allow_private=True)


def fake_resolver(mapping: dict[str, list[str]]):
    def resolve(host: str, port: int) -> list[str]:
        if host not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        return mapping[host]

    return resolve


def test_resolve_checked_rejects_if_any_address_is_private():
    r = fake_resolver({"mixed.example": ["8.8.8.8", "10.0.0.1"], "ok.example": ["8.8.8.8"]})
    with pytest.raises(AddressNotAllowed):
        resolve_checked("mixed.example", 993, NetPolicy(), r)
    assert [str(a) for a in resolve_checked("ok.example", 993, NetPolicy(), r)] == ["8.8.8.8"]


def test_resolve_checked_ports_and_dns_errors():
    r = fake_resolver({"ok.example": ["8.8.8.8"], "empty.example": [], "bad.example": ["nope"]})
    policy = NetPolicy(allowed_ports=frozenset({993, 995, 465, 587}))
    with pytest.raises(AddressNotAllowed, match="port 22"):
        resolve_checked("ok.example", 22, policy, r)
    with pytest.raises(AddressNotAllowed):
        resolve_checked("ok.example", 0, NetPolicy(), r)
    with pytest.raises(ServerUnreachable):
        resolve_checked("missing.example", 993, NetPolicy(), r)
    with pytest.raises(ServerUnreachable):
        resolve_checked("empty.example", 993, NetPolicy(), r)
    with pytest.raises(AddressNotAllowed):
        resolve_checked("bad.example", 993, NetPolicy(), r)


def test_scoped_ipv6_is_parsed():
    r = fake_resolver({"ll.example": ["fe80::1%eth0"]})
    with pytest.raises(AddressNotAllowed):
        resolve_checked("ll.example", 993, NetPolicy(), r)


@pytest.fixture
def listener() -> Iterator[socket.socket]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    yield srv
    srv.close()


def test_open_connection_connects_to_checked_ip(listener: socket.socket):
    port = listener.getsockname()[1]
    r = fake_resolver({"mail.test": ["127.0.0.1"]})
    with pytest.raises(AddressNotAllowed):
        open_connection("mail.test", port, NetPolicy(), r)
    sock = open_connection("mail.test", port, NetPolicy(allow_private=True, read_timeout=7), r)
    try:
        assert sock.getpeername() == ("127.0.0.1", port)
        assert sock.gettimeout() == 7
    finally:
        sock.close()


def test_open_connection_tries_next_address(listener: socket.socket):
    # The listener is bound to 127.0.0.1 only, so 127.0.0.2 refuses and the
    # connector falls through to the next checked address.
    port = listener.getsockname()[1]
    r = fake_resolver({"multi.test": ["127.0.0.2", "127.0.0.1"]})
    sock = open_connection("multi.test", port, NetPolicy(allow_private=True, connect_timeout=2), r)
    try:
        assert sock.getpeername()[0] == "127.0.0.1"
    finally:
        sock.close()


def test_open_connection_refused():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(ServerUnreachable, match="failed"):
        open_connection("127.0.0.1", port, NetPolicy(allow_private=True, connect_timeout=2))


# ---------------------------------------------------------------- TLS


def _make_cert(tmp: Path, name: str) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[tuple[int, Path, list[str | None]]]:
    cert, key = _make_cert(tmp_path, "mail.test")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    sni_seen: list[str | None] = []

    def on_sni(_sock: ssl.SSLObject, name: str | None, _ctx: ssl.SSLContext) -> None:
        sni_seen.append(name)

    ctx.sni_callback = on_sni  # pyright: ignore[reportAttributeAccessIssue]
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    stop = threading.Event()

    def serve() -> None:
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.sendall(b"hello")
            except (ssl.SSLError, OSError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield srv.getsockname()[1], cert, sni_seen
    stop.set()
    t.join(2)
    srv.close()


def test_tls_verifies_and_sends_sni(tls_server: tuple[int, Path, list[str | None]]):
    port, cert, sni_seen = tls_server
    r = fake_resolver({"mail.test": ["127.0.0.1"], "other.test": ["127.0.0.1"]})
    policy = NetPolicy(allow_private=True, connect_timeout=3, read_timeout=3)

    sock = open_connection("mail.test", port, policy, r)
    with pytest.raises(TlsError, match="certificate verification failed"):
        wrap_tls(sock, tls_context(), "mail.test")  # self-signed, not trusted

    sock = open_connection("mail.test", port, policy, r)
    tls = wrap_tls(sock, tls_context(ca_file=str(cert)), "mail.test")
    assert tls.recv(5) == b"hello"
    tls.close()
    assert "mail.test" in sni_seen

    sock = open_connection("other.test", port, policy, r)
    with pytest.raises(TlsError):  # trusted CA but wrong host name
        wrap_tls(sock, tls_context(ca_file=str(cert)), "other.test")

    sock = open_connection("other.test", port, policy, r)
    tls = wrap_tls(sock, tls_context(verify=False), "other.test")  # explicit opt-out
    tls.close()


def test_tls_context_defaults():
    ctx = tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    off = tls_context(verify=False)
    assert off.verify_mode == ssl.CERT_NONE and not off.check_hostname
