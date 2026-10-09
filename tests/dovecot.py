"""Throw-away Dovecot IMAP server in a container (rootless podman, docker fallback).

Shared by the integration tests (``tests/integration/conftest.py``: anonymous
container on random ports per test session) and the developer sandbox
(``scripts/dev_mailbox.py``: named container on fixed ports). No pytest here.

The image accepts any user name with the password from ``USER_PASSWORD`` and
serves implicit TLS on 31993 and STARTTLS on 31143 with a self-signed certificate.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import time
from collections.abc import Sequence

from imapclient import IMAPClient

DOVECOT_IMAGE = (
    "docker.io/dovecot/dovecot:2.4.5"
    "@sha256:c807be4fb5a97d9c3a90770569d3a6c4cbdcb36742ad41f90409cbd929166553"
)
IMAPS_PORT = 31993
"""Implicit-TLS IMAP port inside the container."""
STARTTLS_PORT = 31143
"""Plain IMAP + STARTTLS port inside the container."""
MAIL_TMPFS = "/srv/vmail:rw,mode=1777"
"""Mail storage on tmpfs: Dovecot fsyncs every write, ~100x slower seeding on disk."""


class ContainerError(RuntimeError):
    """The container runtime failed or the server did not come up."""


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
    remove: bool = True,
    labels: Sequence[str] = (),
) -> str:
    """Start the image detached on 127.0.0.1 and return the container id.

    Ports ``None`` bind to a random free host port. Mail lives on a tmpfs, so it is
    gone when the container stops.
    """
    cmd = [rt, "run", "-d", "--tmpfs", MAIL_TMPFS]
    if remove:
        cmd.append("--rm")
    if name:
        cmd += ["--name", name]
    for label in labels:
        cmd += ["--label", label]
    for host_port, container_port in ((imaps_port, IMAPS_PORT), (starttls_port, STARTTLS_PORT)):
        cmd += ["-p", f"127.0.0.1:{host_port or ''}:{container_port}"]
    cmd += ["-e", f"USER_PASSWORD={password}", DOVECOT_IMAGE]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=600)
    except subprocess.CalledProcessError as e:
        raise ContainerError(f"{rt} run failed: {e.stderr.strip() or e}") from e
    except subprocess.TimeoutExpired as e:
        raise ContainerError(f"{rt} run timed out") from e
    return out.stdout.strip()


def host_port(rt: str, container: str, container_port: int) -> int:
    """Host port that ``container_port`` of a running container is published on."""
    out = subprocess.run(
        [rt, "port", container, f"{container_port}/tcp"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    return int(out.strip().splitlines()[0].rsplit(":", 1)[1])


def remove_container(rt: str, container: str) -> None:
    subprocess.run([rt, "rm", "-f", container], capture_output=True, timeout=60)


def admin_client(host: str, port: int, user: str, password: str) -> IMAPClient:
    """Plain imapclient connection for seeding (never used by the server code)."""
    c = IMAPClient(host, port, ssl_context=insecure_ctx(), timeout=60)
    # APPEND sends command and literal separately: without this, Nagle and delayed
    # ACKs cost ~40 ms per message.
    c.socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c.login(user, password)
    return c
