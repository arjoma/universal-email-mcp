"""SSRF-safe outbound connections (design §5).

Connecting to a user-supplied mail server must not become a way to reach internal
services. :func:`open_connection` therefore

1. resolves the host name **once**,
2. validates **every** returned address (public unicast only, unless
   ``allow_private``) and refuses the host if any address is not allowed,
3. connects the socket to the *checked IP* (no second lookup, so no DNS-rebinding
   window), with a strict connect timeout, and
4. leaves TLS to the caller, which uses the *host name* for SNI and certificate
   verification (:func:`tls_context`, :func:`wrap_tls`).

Local mode and tests pass ``allow_private=True`` (a mail server on the LAN or in a
container is legitimate there); remote mode keeps the default ``False``.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from universal_email_mcp.errors import AddressNotAllowed, ServerUnreachable, TlsError

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Sequence[str]]
"""``(host, port) -> [ip, ...]``; injectable for tests."""

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")


@dataclass(frozen=True, slots=True)
class NetPolicy:
    """Connection rules and timeouts (seconds)."""

    allow_private: bool = False
    allowed_ports: frozenset[int] | None = None
    """``None`` = any port; remote free entry uses ``{993, 995, 465, 587}``."""
    connect_timeout: float = 15.0
    read_timeout: float = 60.0


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv4 address tunnelled inside an IPv6 address (mapped, 6to4, Teredo, NAT64)."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    if ip in _NAT64 or ip in _NAT64_LOCAL:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public_address(ip: IPAddress) -> bool:
    """True for globally routable unicast addresses only.

    Rejects private (RFC 1918, ULA), loopback, link-local (incl. the cloud
    metadata address 169.254.169.254), CGNAT (100.64/10), multicast, reserved,
    unspecified, documentation and benchmarking ranges, and IPv6 forms that embed
    such an IPv4 address.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip in _NAT64:
        # Well-known NAT64 prefix: judged by the embedded IPv4 address.
        return is_public_address(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_loopback:
        return False
    if ip.is_link_local or ip.is_private or not ip.is_global:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        inner = _embedded_ipv4(ip)
        if inner is not None and not is_public_address(inner):
            return False
    return True


def check_address(ip: IPAddress, *, allow_private: bool) -> None:
    """Raise :class:`AddressNotAllowed` unless ``ip`` may be connected to."""
    if ip.is_unspecified or ip.is_multicast:
        raise AddressNotAllowed(f"address {ip} is not a unicast host address")
    if not allow_private and not is_public_address(ip):
        raise AddressNotAllowed(f"address {ip} is not a public address")


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    out: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        addr = str(sockaddr[0])
        if addr not in out:
            out.append(addr)
    return out


def resolve_checked(
    host: str, port: int, policy: NetPolicy, resolver: Resolver | None = None
) -> list[IPAddress]:
    """Resolve once and validate every address. Order is preserved."""
    if not 0 < port < 65536:
        raise AddressNotAllowed(f"invalid port {port}")
    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        allowed = ", ".join(str(p) for p in sorted(policy.allowed_ports))
        raise AddressNotAllowed(f"port {port} is not allowed", hint=f"Allowed ports: {allowed}.")
    try:
        raw = list((resolver or system_resolver)(host, port))
    except (OSError, UnicodeError) as e:
        raise ServerUnreachable(
            f"cannot resolve host {host!r}", hint="Check the host name spelling and DNS."
        ) from e
    if not raw:
        raise ServerUnreachable(f"host {host!r} has no addresses")
    addrs: list[IPAddress] = []
    for text in raw:
        try:
            ip = ipaddress.ip_address(text.split("%", 1)[0])
        except ValueError as e:
            raise AddressNotAllowed(f"resolver returned an invalid address {text!r}") from e
        check_address(ip, allow_private=policy.allow_private)
        addrs.append(ip)
    return addrs


def open_connection(
    host: str, port: int, policy: NetPolicy, resolver: Resolver | None = None
) -> socket.socket:
    """Open a TCP connection to a checked address of ``host`` (plain socket, no TLS).

    The returned socket has ``policy.read_timeout`` set.
    """
    addrs = resolve_checked(host, port, policy, resolver)
    last_error: OSError | None = None
    for ip in addrs:
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(policy.connect_timeout)
            sock.connect((str(ip), port))
            sock.settimeout(policy.read_timeout)
            return sock
        except OSError as e:
            sock.close()
            last_error = e
    kind = "timed out" if isinstance(last_error, TimeoutError) else "failed"
    raise ServerUnreachable(
        f"connection to {host}:{port} {kind}: {_describe(last_error)}"
    ) from last_error


def _describe(err: BaseException | None) -> str:
    if err is None:
        return "unknown error"
    return getattr(err, "strerror", None) or type(err).__name__


def tls_context(*, verify: bool = True, ca_file: str | None = None) -> ssl.SSLContext:
    """Client TLS context: TLS ≥ 1.2, certificate + host name verification on.

    ``verify=False`` disables verification and must only be used for explicit
    local/test setups; prefer ``ca_file`` for self-signed servers.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def wrap_tls(sock: socket.socket, ctx: ssl.SSLContext, server_hostname: str) -> ssl.SSLSocket:
    """TLS handshake on ``sock`` using the *host name* for SNI and verification."""
    try:
        return ctx.wrap_socket(sock, server_hostname=server_hostname)
    except ssl.SSLCertVerificationError as e:
        sock.close()
        raise TlsError(
            f"certificate verification failed for {server_hostname}: {e.verify_message}"
        ) from e
    except ssl.SSLError as e:
        sock.close()
        raise TlsError(f"TLS handshake with {server_hostname} failed: {e.reason or e}") from e
    except TimeoutError as e:
        sock.close()
        raise ServerUnreachable(f"TLS handshake with {server_hostname} timed out") from e
    except OSError as e:
        sock.close()
        raise ServerUnreachable(
            f"TLS handshake with {server_hostname} failed: {_describe(e)}"
        ) from e
