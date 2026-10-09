"""Sandbox mailbox for development: a throw-away local Dovecot with seeded mail.

    uv run scripts/dev_mailbox.py up       # start (or restart) the container, seed, write config
    uv run scripts/dev_mailbox.py status   # container state, ports, config files
    uv run scripts/dev_mailbox.py reset    # remove and start fresh (new mailbox)
    uv run scripts/dev_mailbox.py down     # remove the container (mail is gone)

It runs the same pinned Dovecot image as the integration tests (rootless podman,
docker as fallback) as the named container ``uem-sandbox`` on 127.0.0.1, seeds two
accounts with realistic German/English mail plus hostile samples (see
``tests/sandbox.py``) and writes ``sandbox.local.toml`` and ``.env.sandbox``
(both gitignored). Nothing here touches a real mailbox, ``.env`` or
``config.local.toml``.

Mail lives on a tmpfs inside the container: stopping the container (or a reboot)
empties the mailbox, and the next ``up`` seeds it again. Changes made by tools
(moves, flags, drafts) last until then.

Ports: ``--imaps-port`` / ``--starttls-port`` or ``UEM_SANDBOX_IMAPS_PORT`` /
``UEM_SANDBOX_STARTTLS_PORT`` (defaults 10993 / 10143). They are fixed when the
container is created; use ``reset`` to change them.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # the shared helpers live in tests/

from tests.dovecot import (  # noqa: E402
    DOVECOT_IMAGE,
    IMAPS_PORT,
    STARTTLS_PORT,
    ContainerError,
    admin_client,
    container_runtime,
    host_port,
    remove_container,
    run_container,
    wait_ready,
)
from tests.sandbox import (  # noqa: E402
    CONFIG_MARKER,
    PASSWORD_ENV,
    PRIVATE,
    PRIVATE_USER,
    SANDBOX_PASSWORD,
    WORK,
    WORK_USER,
    build_corpus,
    is_seeded,
    render_config,
    seed,
)

NAME = "uem-sandbox"
LABEL = "io.github.arjoma.universal-email-mcp=sandbox"
HOST = "127.0.0.1"
USERS = {WORK: WORK_USER, PRIVATE: PRIVATE_USER}

# TODO(M2): SMTP sink. Run a second container (e.g. Mailpit) next to Dovecot,
# publish its SMTP port on 127.0.0.1 (default 10025), add an [accounts.smtp] table
# in tests/sandbox.render_config and print the web UI address in usage().


class SandboxError(Exception):
    pass


def _rt(args: argparse.Namespace) -> str:
    rt = args.runtime or container_runtime()
    if rt is None:
        raise SandboxError("no working container runtime: install podman (or docker)")
    return rt


def _state(rt: str) -> str | None:
    """'running', 'exited', ... or None if the container does not exist."""
    r = subprocess.run(
        [rt, "inspect", "--format", "{{.State.Status}}", NAME],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return (r.stdout.strip() or None) if r.returncode == 0 else None


def _ports(rt: str) -> tuple[int, int]:
    return host_port(rt, NAME, IMAPS_PORT), host_port(rt, NAME, STARTTLS_PORT)


def _write_generated(path: Path, content: str) -> str:
    """Write a generated file unless the user took it over (marker line removed)."""
    if path.exists() and not path.read_text(encoding="utf-8").startswith(CONFIG_MARKER):
        return f"kept {path} (no '{CONFIG_MARKER}' header: edited by hand)"
    path.write_text(content, encoding="utf-8")
    return f"wrote {path}"


def _env_file() -> str:
    return (
        f"{CONFIG_MARKER}: environment for the sandbox mailbox.\n"
        "# Only the password: the config is passed with --config, because\n"
        "# `uv run --env-file` does not override an UEM_CONFIG that is already exported.\n"
        "# Throw-away password of the local container, not a secret.\n"
        f"{PASSWORD_ENV}={SANDBOX_PASSWORD}\n"
    )


def cmd_up(args: argparse.Namespace) -> int:
    rt = _rt(args)
    state = _state(rt)
    if state is None:
        print(f"starting {NAME} ({DOVECOT_IMAGE.split('@')[0]}) with {rt} ...", flush=True)
        try:
            run_container(
                rt,
                password=SANDBOX_PASSWORD,
                name=NAME,
                imaps_port=args.imaps_port,
                starttls_port=args.starttls_port,
                remove=False,
                labels=[LABEL],
            )
        except ContainerError:
            remove_container(rt, NAME)  # a failed start (port in use) leaves it "created"
            raise
    elif state != "running":
        print(f"restarting stopped container {NAME} ...")
        subprocess.run([rt, "start", NAME], capture_output=True, check=True, timeout=60)
    else:
        print(f"{NAME} is already running")
    imaps, starttls = _ports(rt)
    if (imaps, starttls) != (args.imaps_port, args.starttls_port):
        print(
            f"note: the container uses ports {imaps}/{starttls}, not the requested "
            f"{args.imaps_port}/{args.starttls_port}; run `reset` to change them"
        )
    wait_ready(HOST, imaps)

    def connect(user: str):
        return admin_client(HOST, imaps, user, SANDBOX_PASSWORD)

    probe = connect(WORK_USER)
    try:
        seeded = is_seeded(probe)
    finally:
        probe.logout()
    if seeded:
        print("mailbox already seeded")
    else:
        counts = seed(connect, USERS, build_corpus())
        print("seeded " + ", ".join(f"{n} mails into {a!r}" for a, n in counts.items()))

    config = args.config.resolve()
    env = args.env_file.resolve()
    print(_write_generated(config, render_config(HOST, imaps, users=USERS)))
    print(_write_generated(env, _env_file()))
    print(usage(config, env))
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    rt = _rt(args)
    if _state(rt) is None:
        print(f"{NAME} does not exist")
        return 0
    remove_container(rt, NAME)
    print(f"removed {NAME} (config files kept: {args.config}, {args.env_file})")
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    cmd_down(args)
    return cmd_up(args)


def cmd_status(args: argparse.Namespace) -> int:
    rt = _rt(args)
    state = _state(rt)
    print(f"container: {NAME} ({rt}): {state or 'not created'}")
    if state == "running":
        imaps, starttls = _ports(rt)
        print(f"IMAP:      {HOST}:{imaps} (TLS), {HOST}:{starttls} (STARTTLS)")
        try:
            wait_ready(HOST, imaps, timeout=5)
            print("server:    answering")
        except ContainerError as e:
            print(f"server:    not answering ({e})")
    print(f"users:     {', '.join(f'{a} = {u}' for a, u in USERS.items())}")
    for path in (args.config, args.env_file):
        print(f"file:      {path} ({'present' if path.exists() else 'missing'})")
    return 0 if state == "running" else 1


def usage(config: Path, env: Path) -> str:
    """The probe and `claude mcp add` commands: absolute paths, explicit --config."""
    run = (
        f"uv run --directory {shlex.quote(str(ROOT))} --env-file {shlex.quote(str(env))} "
        "universal-email-mcp"
    )
    cfg = f"--config {shlex.quote(str(config))}"
    return f"""
Sandbox ready. Accounts: {WORK!r} ({WORK_USER}), {PRIVATE!r} ({PRIVATE_USER}).

  {run} probe {cfg} --account {WORK}
  claude mcp add email-sandbox -- {run} local {cfg}

Hostile samples carry the header 'X-UEM-Sandbox: hostile <kind>'.
Stop with: uv run scripts/dev_mailbox.py down"""


def _port(env: str, default: int) -> int:
    return int(os.environ.get(env, default))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="dev_mailbox.py",
        description="Throw-away local Dovecot mailbox with seeded realistic and hostile mail.",
    )
    p.add_argument("command", choices=("up", "down", "status", "reset"))
    p.add_argument(
        "--imaps-port", type=int, default=_port("UEM_SANDBOX_IMAPS_PORT", 10993), metavar="N"
    )
    p.add_argument(
        "--starttls-port", type=int, default=_port("UEM_SANDBOX_STARTTLS_PORT", 10143), metavar="N"
    )
    p.add_argument("--config", type=Path, default=ROOT / "sandbox.local.toml")
    p.add_argument("--env-file", type=Path, default=ROOT / ".env.sandbox")
    p.add_argument("--runtime", choices=("podman", "docker"), help="default: auto-detect")
    args = p.parse_args(argv)
    commands = {"up": cmd_up, "down": cmd_down, "status": cmd_status, "reset": cmd_reset}
    try:
        return commands[args.command](args)
    except (SandboxError, ContainerError, subprocess.CalledProcessError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
