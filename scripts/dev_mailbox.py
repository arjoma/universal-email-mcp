"""Sandbox mailbox for development: a throw-away local Dovecot with seeded mail.

    uv run scripts/dev_mailbox.py up       # start (or restart) the container, seed, write config
    uv run scripts/dev_mailbox.py status   # container state, ports, seed state, config files
    uv run scripts/dev_mailbox.py reset    # remove and start fresh (new mailbox, fresh dates)
    uv run scripts/dev_mailbox.py down     # remove the container (mail is gone)

It runs the same pinned Dovecot image as the integration tests (rootless podman,
docker as fallback) as the named container ``uem-sandbox`` on 127.0.0.1, seeds two
accounts with realistic German/English mail plus hostile samples (see
``tests/sandbox.py``) and writes ``sandbox.local.toml`` and ``.env.sandbox``
(both gitignored). Nothing here touches a real mailbox, ``.env`` or
``config.local.toml``; it refuses to overwrite a file it did not generate and only
removes a container it created (label ``io.github.arjoma.universal-email-mcp.sandbox``).

Mail lives on a tmpfs inside the container: stopping the container (or a reboot)
empties the mailbox, and the next ``up`` seeds it again. Changes made by tools
(moves, flags, drafts) last until then. Seed dates are relative to the seeding
time, so on a long-running container ``today`` / ``this_week`` slowly run dry:
``reset`` seeds afresh. ``up`` also recreates the container when the image or
``CORPUS_VERSION`` (corpus, seeding or password) changed.

Ports: ``--imaps-port`` / ``--starttls-port`` or ``UEM_SANDBOX_IMAPS_PORT`` /
``UEM_SANDBOX_STARTTLS_PORT`` (defaults 10993 / 10143). They are fixed when the
container is created; use ``reset`` to change them.
"""

from __future__ import annotations

import argparse
import imaplib
import json
import os
import shlex
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from imapclient import IMAPClient

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
    run_runtime,
    start_container,
    wait_ready,
)
from tests.sandbox import (  # noqa: E402
    CONFIG_MARKER,
    CORPUS_VERSION,
    PASSWORD_ENV,
    PRIVATE,
    PRIVATE_USER,
    SANDBOX_PASSWORD,
    USERS,
    WORK,
    WORK_USER,
    build_corpus,
    render_config,
    seed,
    seed_state,
)

NAME = "uem-sandbox"
HOST = "127.0.0.1"
LABEL = "io.github.arjoma.universal-email-mcp.sandbox"
"""Marks the container as ours; ``down`` / ``reset`` refuse to remove any other."""


def wanted_labels() -> dict[str, str]:
    """Labels of a container this version of the script would create."""
    return {LABEL: "1", f"{LABEL}.image": DOVECOT_IMAGE, f"{LABEL}.corpus": CORPUS_VERSION}


# TODO(M2): SMTP sink. Run a second container (e.g. Mailpit) next to Dovecot,
# publish its SMTP port on 127.0.0.1 (default 10025), add an [accounts.smtp] table
# in tests/sandbox.render_config and print the web UI address in usage().


class SandboxError(Exception):
    pass


def say(*parts: object) -> None:
    print(*parts, flush=True)  # progress shows up in order with the runtime's output


@dataclass(frozen=True)
class Container:
    state: str  # running, exited, created, ...
    labels: dict[str, str]

    @property
    def ours(self) -> bool:
        return LABEL in self.labels

    def outdated(self) -> list[str]:
        """What differs from a freshly created container (image, corpus version)."""
        want = wanted_labels()
        return [k.rsplit(".", 1)[1] for k in want if k != LABEL and self.labels.get(k) != want[k]]


def _rt(args: argparse.Namespace) -> str:
    rt = args.runtime or container_runtime()
    if rt is None:
        raise SandboxError("no working container runtime: install podman (or docker)")
    return rt


def _inspect(rt: str) -> Container | None:
    """The container named NAME, or None if it does not exist."""
    try:
        out = run_runtime(
            [rt, "inspect", "--format", "{{.State.Status}}\t{{json .Config.Labels}}", NAME],
            timeout=30,
        )
    except ContainerError as e:
        if "no such" in str(e).lower():
            return None
        raise
    state, _, labels = out.strip().partition("\t")
    try:
        parsed = json.loads(labels) or {}
    except json.JSONDecodeError as e:
        raise ContainerError(f"unexpected `{rt} inspect` output: {out!r}") from e
    return Container(state, {str(k): str(v) for k, v in parsed.items()})


def _ours(rt: str) -> Container | None:
    """Our container, None if there is none; SandboxError for a foreign one."""
    c = _inspect(rt)
    if c is not None and not c.ours:
        raise SandboxError(
            f"a container named {NAME} exists but was not created by this script "
            f"(no {LABEL} label); remove or rename it yourself"
        )
    return c


def _ports(rt: str) -> tuple[int, int]:
    return host_port(rt, NAME, IMAPS_PORT), host_port(rt, NAME, STARTTLS_PORT)


def _check_generated(*paths: Path) -> None:
    """Refuse to overwrite files that this script did not write (marker line missing)."""
    for path in paths:
        if path.exists() and not path.read_text(encoding="utf-8").startswith(CONFIG_MARKER):
            raise SandboxError(
                f"{path} exists and was not generated by this script (first line is not "
                f"'{CONFIG_MARKER}'); move it away or pass another --config / --env-file"
            )


def _env_file() -> str:
    return (
        f"{CONFIG_MARKER}: environment for the sandbox mailbox.\n"
        "# Only the password: the config is passed with --config, because\n"
        "# `uv run --env-file` does not override an UEM_CONFIG that is already exported.\n"
        "# Throw-away password of the local container, not a secret.\n"
        f"{PASSWORD_ENV}={SANDBOX_PASSWORD}\n"
    )


def _create(rt: str, args: argparse.Namespace) -> None:
    say(f"starting {NAME} ({DOVECOT_IMAGE.split('@')[0]}) with {rt} ...")
    try:
        run_container(
            rt,
            password=SANDBOX_PASSWORD,
            name=NAME,
            imaps_port=args.imaps_port,
            starttls_port=args.starttls_port,
            remove=False,
            labels=wanted_labels(),
        )
    except ContainerError:
        # A failed start (port in use) can leave a "created" container behind.
        c = _inspect(rt)
        if c is not None and c.ours:
            remove_container(rt, NAME)
        raise


def _connector(imaps: int) -> Callable[[str], IMAPClient]:
    def connect(user: str) -> IMAPClient:
        return admin_client(HOST, imaps, user, SANDBOX_PASSWORD)

    return connect


def _imap_error(imaps: int, e: Exception) -> SandboxError:
    return SandboxError(f"IMAP error from the sandbox at {HOST}:{imaps}: {e}")


def cmd_up(args: argparse.Namespace) -> int:
    config = args.config.resolve()
    env = args.env_file.resolve()
    _check_generated(config, env)
    rt = _rt(args)
    c = _ours(rt)
    if c is not None and (outdated := c.outdated()):
        say(f"recreating {NAME}: {', '.join(outdated)} changed since it was created")
        remove_container(rt, NAME)
        c = None
    if c is None:
        _create(rt, args)
    elif c.state != "running":
        say(f"restarting stopped container {NAME} ...")
        start_container(rt, NAME)
    else:
        say(f"{NAME} is already running")
    imaps, starttls = _ports(rt)
    if (imaps, starttls) != (args.imaps_port, args.starttls_port):
        say(
            f"note: the container uses ports {imaps}/{starttls}, not the requested "
            f"{args.imaps_port}/{args.starttls_port}; run `reset` to change them"
        )
    wait_ready(HOST, imaps)

    connect = _connector(imaps)
    try:
        state = seed_state(connect, USERS)
        if state == "seeded":
            say("mailbox already seeded")
        elif state == "partial":
            raise SandboxError(
                "the mailbox has mail but no seed marker (an interrupted seed?); "
                "run `reset` for a fresh one"
            )
        else:
            counts = seed(connect, USERS, build_corpus())
            say("seeded " + ", ".join(f"{n} mails into {a!r}" for a, n in counts.items()))
    except (imaplib.IMAP4.error, OSError) as e:
        raise _imap_error(imaps, e) from e

    config.write_text(render_config(HOST, imaps, users=USERS), encoding="utf-8")
    env.write_text(_env_file(), encoding="utf-8")
    say(f"wrote {config}\nwrote {env}")
    say(usage(config, env))
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    rt = _rt(args)
    if _ours(rt) is None:
        say(f"{NAME} does not exist")
        return 0
    remove_container(rt, NAME)
    say(f"removed {NAME} (config files kept: {args.config}, {args.env_file})")
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    _check_generated(args.config.resolve(), args.env_file.resolve())
    cmd_down(args)
    return cmd_up(args)


def cmd_status(args: argparse.Namespace) -> int:
    rt = _rt(args)
    c = _inspect(rt)
    if c is None:
        say(f"container: {NAME} ({rt}): not created")
    elif not c.ours:
        say(f"container: {NAME} ({rt}): {c.state}, NOT created by this script")
    else:
        say(f"container: {NAME} ({rt}): {c.state}")
        if outdated := c.outdated():
            say(f"outdated:  {', '.join(outdated)} changed; `up` recreates it")
    running = c is not None and c.ours and c.state == "running"
    if running:
        imaps, starttls = _ports(rt)
        say(f"IMAP:      {HOST}:{imaps} (TLS), {HOST}:{starttls} (STARTTLS)")
        try:
            wait_ready(HOST, imaps, timeout=5)
            say(f"mailbox:   {seed_state(_connector(imaps), USERS)}")
        except (ContainerError, imaplib.IMAP4.error, OSError) as e:
            say(f"server:    not answering ({e})")
    say(f"users:     {', '.join(f'{a} = {u}' for a, u in USERS.items())}")
    for path in (args.config, args.env_file):
        say(f"file:      {path} ({'present' if path.exists() else 'missing'})")
    return 0 if running else 1


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
Seed dates are relative to the seeding time: `reset` refreshes them.
Stop with: uv run scripts/dev_mailbox.py down"""


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"invalid port {value!r} (1-65535)")
    return port


def _env_port(p: argparse.ArgumentParser, env: str, default: int) -> int:
    value = os.environ.get(env)
    if value is None:
        return default
    try:
        return _port(value)
    except argparse.ArgumentTypeError as e:
        p.error(f"{env}: {e}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="dev_mailbox.py",
        description="Throw-away local Dovecot mailbox with seeded realistic and hostile mail.",
    )
    p.add_argument("command", choices=("up", "down", "status", "reset"))
    p.add_argument("--imaps-port", type=_port, metavar="N", help="default 10993")
    p.add_argument("--starttls-port", type=_port, metavar="N", help="default 10143")
    p.add_argument("--config", type=Path, default=ROOT / "sandbox.local.toml")
    p.add_argument("--env-file", type=Path, default=ROOT / ".env.sandbox")
    p.add_argument("--runtime", choices=("podman", "docker"), help="default: auto-detect")
    args = p.parse_args(argv)
    if args.imaps_port is None:
        args.imaps_port = _env_port(p, "UEM_SANDBOX_IMAPS_PORT", 10993)
    if args.starttls_port is None:
        args.starttls_port = _env_port(p, "UEM_SANDBOX_STARTTLS_PORT", 10143)
    commands = {"up": cmd_up, "down": cmd_down, "status": cmd_status, "reset": cmd_reset}
    try:
        return commands[args.command](args)
    except (SandboxError, ContainerError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
