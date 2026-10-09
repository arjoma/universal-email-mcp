"""Command-line interface: ``universal-email-mcp <command>``."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from collections.abc import Sequence
from typing import Any

from universal_email_mcp import __version__, audit
from universal_email_mcp.config import Config, load_config, resolve_password
from universal_email_mcp.errors import ConfigError, CredentialMissing, MailError
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import Endpoint, FolderRole, TlsSettings
from universal_email_mcp.presets import normalize_hostname, resolve_server_entry

PASSWORD_ENV = "UEM_PASSWORD"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="universal-email-mcp",
        description="Vendor-neutral MCP server for IMAP, POP3 and SMTP mailboxes.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="log progress to stderr")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    probe = sub.add_parser(
        "probe",
        help="log in read-only and report server capabilities, folders and quota",
        description=(
            "Log in read-only and report capabilities, namespace, folders with roles and "
            f"counts, quota and the strategies the bridge will use. The password is read "
            f"from ${PASSWORD_ENV} or prompted for (never echoed); with --account it comes "
            "from the config (password_env or OS keyring). No message content is shown."
        ),
    )
    target = probe.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="IMAP host name")
    target.add_argument("--server", help="preset name (e.g. united-domains) or host name")
    target.add_argument("--account", help="account name from the config file")
    probe.add_argument("--port", type=int, help="port (default 993, or 143 with --starttls)")
    probe.add_argument("--starttls", action="store_true", help="plain connect + STARTTLS")
    probe.add_argument("--user", help="login name (required with --host/--server)")
    probe.add_argument("--config", help="config file (default: $UEM_CONFIG or platform dir)")
    probe.add_argument("--ca-file", help="trust this CA bundle (for self-signed servers)")
    probe.add_argument(
        "--insecure",
        action="store_true",
        help="do NOT verify the TLS certificate (local testing only)",
    )
    probe.add_argument(
        "--public-only",
        action="store_true",
        help="refuse private/loopback addresses (as remote mode does)",
    )
    probe.add_argument("--no-counts", action="store_true", help="skip per-folder STATUS")
    probe.add_argument("--timeout", type=float, default=15.0, help="connect timeout (s)")
    probe.add_argument("--json", action="store_true", help="machine-readable output")

    local = sub.add_parser("local", help="run the MCP server over stdio (local mode)")
    local.add_argument("--config", help="config file (default: $UEM_CONFIG or platform dir)")
    return p


def _load_config(path: str | None) -> Config:
    """Load the config and say on stderr which file it was (stdout may carry MCP)."""
    cfg = load_config(path)
    names = ", ".join(a.name for a in cfg.accounts) or "none"
    print(f"config: {cfg.path} (accounts: {names})", file=sys.stderr, flush=True)
    return cfg


def _read_password(user: str) -> str:
    env = os.environ.get(PASSWORD_ENV)
    if env:
        return env
    if not sys.stdin.isatty():
        raise CredentialMissing(
            f"no password: set {PASSWORD_ENV} or run interactively to be prompted"
        )
    return getpass.getpass(f"Password for {user}: ")


def _cmd_probe(args: argparse.Namespace) -> int:
    from universal_email_mcp.probe import format_report, run_probe

    tls = TlsSettings(verify=not args.insecure, ca_file=args.ca_file)
    net = NetPolicy(
        allow_private=not args.public_only,
        connect_timeout=args.timeout,
        read_timeout=max(args.timeout, 60.0),
    )
    folder_roles: dict[FolderRole, str] = {}
    if args.account:
        cfg = _load_config(args.config)
        account = cfg.account(args.account)
        if account.kind != "imap":
            raise ConfigError(f"account {account.name!r} is not an IMAP account")
        endpoint = account.endpoint
        if args.port or args.starttls:
            endpoint = Endpoint(
                endpoint.host,
                args.port or (143 if args.starttls else endpoint.port),
                "starttls" if args.starttls else endpoint.tls,
            )
        user = args.user or account.username
        if not (args.insecure or args.ca_file):
            tls = account.tls
        net = NetPolicy(
            allow_private=cfg.settings.allow_private_networks and not args.public_only,
            connect_timeout=args.timeout,
            read_timeout=cfg.settings.read_timeout,
        )
        folder_roles = account.effective_folder_roles()
        password = resolve_password(account)
    else:
        if not args.user:
            raise ConfigError("--user is required with --host/--server")
        if args.host:
            host = normalize_hostname(args.host)
            base = Endpoint(host, 993, "tls")
        else:
            profile = resolve_server_entry(args.server)
            if profile.imap is None:
                raise ConfigError(f"preset {args.server!r} has no IMAP server")
            base = profile.imap
            folder_roles = dict(profile.folder_roles)
        mode = "starttls" if args.starttls else base.tls
        port = args.port or (143 if args.starttls else base.port)
        endpoint = Endpoint(base.host, port, mode)
        user = args.user
        password = _read_password(user)

    if args.insecure:
        print("warning: TLS certificate verification is disabled", file=sys.stderr)
    report = run_probe(
        endpoint,
        user,
        password,
        net=net,
        tls=tls,
        folder_roles=folder_roles,
        with_counts=not args.no_counts,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        print(format_report(report))
    return 0


def _cmd_local(args: argparse.Namespace) -> int:
    from universal_email_mcp.server.local import run_local

    run_local(_load_config(args.config))
    return 0


def _print_error(err: MailError, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"error": err.to_dict()}), file=sys.stderr)
        return
    print(f"error [{err.code}]: {err.message}", file=sys.stderr)
    if err.hint:
        print(f"hint: {err.hint}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    # imapclient/imaplib debug logs contain protocol traffic (mail data): keep them off.
    logging.getLogger("imapclient").setLevel(logging.WARNING)
    audit.setup()  # audit events (send attempts: counts only) always go to stderr

    handlers: dict[str, Any] = {"probe": _cmd_probe, "local": _cmd_local}
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2
    try:
        return handlers[args.command](args)
    except MailError as e:
        _print_error(e, bool(getattr(args, "json", False)))
        return 1
    except KeyboardInterrupt:
        return 130
