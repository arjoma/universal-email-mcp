"""Firestore emulator for the store contract tests (rootless podman or docker).

``UEM_TEST_FIRESTORE_HOST=host:port`` points at an emulator that is already running (CI);
otherwise a container is started from the Google Cloud CLI emulators image. Returns None
when neither is possible.
"""

from __future__ import annotations

import socket
import subprocess
import time
import urllib.request
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from tests.dovecot import ContainerError, container_runtime, run_runtime

# the ``emulators`` tag, pinned by digest (same as .github/workflows/ci.yml)
EMULATOR_IMAGE = "gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators@sha256:be2f0e582a94c9e06e7a384fe2b3b39d590eeb8da65a110eda991598c100fe80"
PORT = 8080


def _wait(host: str, port: int, timeout: float = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://{host}:{port}/", timeout=2) as r:
                if r.status == 200:
                    return
        except OSError:
            time.sleep(1)
    raise ContainerError("Firestore emulator did not come up")


@contextmanager
def emulator(host: str | None) -> Iterator[str | None]:
    """Yield ``host:port`` of a running emulator, or None if unavailable."""
    if host:
        yield host
        return
    rt = container_runtime()
    if rt is None:
        yield None
        return
    name = f"uem-fs-{uuid.uuid4().hex[:8]}"
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    try:
        run_runtime(
            [
                rt, "run", "-d", "--rm", "--name", name,
                "-p", f"127.0.0.1:{port}:{PORT}",
                EMULATOR_IMAGE,
                "gcloud", "emulators", "firestore", "start", f"--host-port=0.0.0.0:{PORT}",
            ],
            timeout=300,
        )  # fmt: skip
    except ContainerError:
        yield None
        return
    try:
        _wait("127.0.0.1", port)
        yield f"127.0.0.1:{port}"
    except ContainerError:
        yield None
    finally:
        subprocess.run([rt, "rm", "-f", name], capture_output=True, timeout=60, check=False)
