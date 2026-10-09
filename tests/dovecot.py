"""Throw-away Dovecot IMAP/POP3 server in a container (rootless podman, docker fallback).

Shared by the integration tests (``tests/integration/conftest.py``: anonymous
container on random ports per test session) and the developer sandbox
(``scripts/dev_mailbox.py``: named container on fixed ports). No pytest here.

The image accepts any user name with the password from ``USER_PASSWORD`` and
serves implicit TLS on 31993 and STARTTLS on 31143 with a self-signed certificate.
POP3 is not enabled in the image's ``protocols``; :data:`DOVECOT_COMMAND` turns it on
(implicit TLS 31995, STLS 31110) from the same maildir, so mail seeded over IMAP is
readable over POP3. CI starts the container with the same command.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import time
from collections.abc import Mapping, Sequence

from imapclient import IMAPClient

DOVECOT_IMAGE = (
    # Dovecot's own GHCR copy (Docker Hub limits anonymous pulls on CI runners).
    "ghcr.io/dovecot/dovecot:2.4.5"
    "@sha256:6b71744668f3da04e28e1fca14eb496224f99030eaef95564d29906dce189c90"
)
IMAPS_PORT = 31993
"""Implicit-TLS IMAP port inside the container."""
STARTTLS_PORT = 31143
"""Plain IMAP + STARTTLS port inside the container."""
POP3S_PORT = 31995
"""Implicit-TLS POP3 port inside the container."""
POP3_PORT = 31110
"""Plain POP3 + STLS port inside the container."""
DOVECOT_COMMAND = ("/dovecot/sbin/dovecot", "-F", "-o", "protocols=imap pop3 submission lmtp sieve")
"""The image's default command plus POP3 (the image enables IMAP, LMTP, submission, sieve)."""
MAIL_TMPFS = "/srv/vmail:rw,mode=1777"
"""Mail storage on tmpfs: Dovecot fsyncs every write, ~100x slower seeding on disk."""


class ContainerError(RuntimeError):
    """The container runtime failed or the server did not come up."""


def run_runtime(cmd: Sequence[str], *, timeout: float = 60) -> str:
    """Run a container runtime command; stdout, or ContainerError with its stderr."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise ContainerError(f"`{' '.join(cmd[:2])}` timed out after {timeout:g}s") from e
    except OSError as e:
        raise ContainerError(f"cannot run {cmd[0]}: {e}") from e
    if r.returncode != 0:
        detail = r.stderr.strip() or r.stdout.strip() or f"exit status {r.returncode}"
        raise ContainerError(f"`{' '.join(cmd[:2])}` failed: {detail}")
    return r.stdout


def container_runtime() -> str | None:
    """First of podman, docker that is installed and answers ``info``."""
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


def insecure_ctx() -> ssl.SSLContext:
    """TLS context for the container's self-signed certificate (tests and seeding only)."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def wait_ready(host: str, port: int, timeout: float = 90.0) -> None:
    """Wait for the IMAP greeting on an implicit-TLS port; raise ContainerError on timeout."""
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3) as raw:
                with insecure_ctx().wrap_socket(raw) as tls:
                    tls.settimeout(3)
                    if tls.recv(64).startswith(b"* OK"):
                        return
        except OSError as e:
            last = e
        time.sleep(0.5)
    raise ContainerError(f"IMAP server at {host}:{port} not ready ({last})")


def run_container(
    rt: str,
    *,
    password: str,
    name: str | None = None,
    imaps_port: int | None = None,
    starttls_port: int | None = None,
    pop3s_port: int | None = None,
    pop3_port: int | None = None,
    remove: bool = True,
    labels: Mapping[str, str] | None = None,
) -> str:
    """Start the image detached on 127.0.0.1 and return the container id.

    Ports ``None`` bind to a random free host port. Mail lives on a tmpfs, so it is
    gone when the container stops. POP3 is enabled (see :data:`DOVECOT_COMMAND`).
    """
    cmd = [rt, "run", "-d", "--tmpfs", MAIL_TMPFS]
    if remove:
        cmd.append("--rm")
    if name:
        cmd += ["--name", name]
    for key, value in (labels or {}).items():
        cmd += ["--label", f"{key}={value}"]
    for host_port, container_port in (
        (imaps_port, IMAPS_PORT),
        (starttls_port, STARTTLS_PORT),
        (pop3s_port, POP3S_PORT),
        (pop3_port, POP3_PORT),
    ):
        cmd += ["-p", f"127.0.0.1:{host_port or ''}:{container_port}"]
    cmd += ["-e", f"USER_PASSWORD={password}", DOVECOT_IMAGE, *DOVECOT_COMMAND]
    return run_runtime(cmd, timeout=600).strip()


def start_container(rt: str, container: str) -> None:
    """Start a stopped container."""
    run_runtime([rt, "start", container])


def host_port(rt: str, container: str, container_port: int) -> int:
    """Host port that ``container_port`` of a running container is published on."""
    out = run_runtime([rt, "port", container, f"{container_port}/tcp"], timeout=30)
    try:
        return int(out.strip().splitlines()[0].rsplit(":", 1)[1])
    except (IndexError, ValueError) as e:
        raise ContainerError(
            f"cannot read the host port of {container}:{container_port} from {out!r}"
        ) from e


def remove_container(rt: str, container: str) -> None:
    """Remove the container and its anonymous volumes; ContainerError on failure."""
    run_runtime([rt, "rm", "-f", "-v", container])


def admin_client(host: str, port: int, user: str, password: str) -> IMAPClient:
    """Plain imapclient connection for seeding (never used by the server code)."""
    c = IMAPClient(host, port, ssl_context=insecure_ctx(), timeout=60)
    # APPEND sends command and literal separately: without this, Nagle and delayed
    # ACKs cost ~40 ms per message.
    c.socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c.login(user, password)
    return c
