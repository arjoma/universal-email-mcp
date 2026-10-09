"""``probe``: log in read-only and report what a server offers (design §12).

Prints capabilities, namespace, folders with detected roles and counts, quota and
the strategies the bridge will use. Never prints message content, and never the
password.
"""

from __future__ import annotations

import time
import unicodedata
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from universal_email_mcp.errors import MailError
from universal_email_mcp.mail.imap import (
    ImapSession,
    LoginInfo,
    Namespace,
    QuotaInfo,
    SearchCriteria,
    ServerFeatures,
)
from universal_email_mcp.mail.net import NetPolicy, Resolver
from universal_email_mcp.models import FOLDER_ROLES, Endpoint, FolderInfo, FolderRole, TlsSettings


@dataclass(frozen=True, slots=True)
class ProbeReport:
    host: str
    port: int
    tls: str
    login: LoginInfo
    features: ServerFeatures
    namespace: Namespace | None
    delimiter: str | None
    folders: tuple[FolderInfo, ...]
    quota: tuple[QuotaInfo, ...] | None
    utf8_search: bool | None
    role_warnings: tuple[str, ...]
    total_seconds: float
    plan: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_plan(
    features: ServerFeatures, folders: tuple[FolderInfo, ...], utf8_search: bool | None
) -> list[str]:
    """Human-readable list of strategies the bridge will use with this server."""
    plan: list[str] = []
    if features.sort:
        plan.append("SORT available → newest-first ordering via SORT (REVERSE ARRIVAL)")
    else:
        plan.append("SORT missing → newest-first ordering by UID")
    if features.move:
        plan.append("MOVE available → moves and Trash via UID MOVE")
    elif features.uidplus:
        plan.append("MOVE missing → COPY + \\Deleted + UID EXPUNGE fallback (UIDPLUS present)")
    else:
        plan.append("MOVE and UIDPLUS missing → move/delete tools will be unavailable")
    if features.special_use:
        plan.append("SPECIAL-USE available → folder roles from server flags")
    else:
        plan.append("SPECIAL-USE missing → folder roles from name heuristics (EN/DE)")
    present = {f.role for f in folders if f.role}
    missing: list[FolderRole] = [r for r in FOLDER_ROLES if r not in present]
    if missing:
        plan.append(
            "no folder found for role(s): "
            + ", ".join(missing)
            + " → set [accounts.folders] overrides if they exist"
        )
    if utf8_search is True:
        plan.append("UTF-8 search accepted → umlauts searched server-side")
    elif utf8_search is False:
        plan.append("UTF-8 search rejected → non-ASCII terms matched locally on headers")
    if features.condstore:
        plan.append("CONDSTORE available (usable for incremental flag sync)")
    if not features.quota:
        plan.append("QUOTA missing → no quota information")
    return plan


def run_probe(
    endpoint: Endpoint,
    username: str,
    password: str,
    *,
    net: NetPolicy | None = None,
    tls: TlsSettings | None = None,
    folder_roles: Mapping[FolderRole, str] | None = None,
    with_counts: bool = True,
    resolver: Resolver | None = None,
) -> ProbeReport:
    t0 = time.monotonic()
    with ImapSession.connect(
        endpoint,
        username,
        password,
        account_name="probe",
        net=net,
        tls=tls,
        folder_roles=folder_roles,
        resolver=resolver,
    ) as session:
        features = session.features
        namespace = session.namespace()
        folders = tuple(session.list_folders(with_counts=with_counts))
        delimiter = next((f.delimiter for f in folders if f.name.upper() == "INBOX"), None)
        if delimiter is None and namespace and namespace.personal:
            delimiter = namespace.personal[0][1]
        try:
            quota = session.quota()
        except MailError:
            quota = None
        utf8_search: bool | None
        try:
            utf8_search = session.search("INBOX", SearchCriteria(subject="ä")).exact
        except MailError:
            utf8_search = None
        warnings = tuple(session.role_warnings)
        login = session.login_info
    return ProbeReport(
        host=endpoint.host,
        port=endpoint.port,
        tls=login.tls,
        login=login,
        features=features,
        namespace=namespace,
        delimiter=delimiter,
        folders=folders,
        quota=tuple(quota) if quota is not None else None,
        utf8_search=utf8_search,
        role_warnings=warnings,
        total_seconds=time.monotonic() - t0,
        plan=tuple(build_plan(features, folders, utf8_search)),
    )


def _wrap_caps(caps: tuple[str, ...], indent: str = "    ", width: int = 88) -> str:
    lines: list[str] = []
    line = indent
    for cap in caps:
        if len(line) + len(cap) + 1 > width and line.strip():
            lines.append(line.rstrip())
            line = indent
        line += cap + " "
    if line.strip():
        lines.append(line.rstrip())
    return "\n".join(lines) or indent + "(none)"


def printable(text: str) -> str:
    """Server-supplied text made safe for a terminal: control characters (escape
    sequences, newlines) and invisible/format characters (bidi overrides, zero-width)
    become visible ``\\uXXXX`` escapes."""
    return "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp") else c
        for c in text
    )


def format_report(r: ProbeReport) -> str:
    out: list[str] = []
    out.append(f"Server        {r.host}:{r.port} ({r.tls}, {r.login.auth_mechanism})")
    if r.login.greeting:
        out.append(f"Greeting      {printable(r.login.greeting)}")
    out.append(
        f"Timing        connect+TLS {r.login.connect_seconds:.2f}s, "
        f"login {r.login.login_seconds:.2f}s, total {r.total_seconds:.2f}s"
    )
    out.append("Capabilities before login:")
    out.append(_wrap_caps(r.login.pre_auth_capabilities))
    out.append("Capabilities after login:")
    out.append(_wrap_caps(r.login.capabilities))
    f = r.features
    flags = {
        "SORT": f.sort,
        "THREAD": bool(f.threads),
        "MOVE": f.move,
        "UIDPLUS": f.uidplus,
        "CONDSTORE": f.condstore,
        "QRESYNC": f.qresync,
        "SPECIAL-USE": f.special_use,
        "NAMESPACE": f.namespace,
        "QUOTA": f.quota,
        "IDLE": f.idle,
    }
    out.append(
        "Extensions    " + "  ".join(f"{k} {'yes' if v else 'no'}" for k, v in flags.items())
    )
    if f.threads:
        out.append(f"Thread algos  {', '.join(f.threads)}")
    if r.namespace is None:
        out.append("Namespace     (NAMESPACE not supported)")
    else:
        for label, items in (
            ("personal", r.namespace.personal),
            ("other", r.namespace.other),
            ("shared", r.namespace.shared),
        ):
            if items:
                desc = printable(", ".join(f"{p!r} (delimiter {d!r})" for p, d in items))
                out.append(f"Namespace     {label}: {desc}")
    out.append(f"Delimiter     {r.delimiter!r}")
    out.append(f"Folders       {len(r.folders)}")
    for folder in r.folders:
        role = f"[{folder.role}]" if folder.role else ""
        counts = ""
        if folder.messages is not None:
            counts = f"{folder.messages} messages, {folder.unseen} unseen"
        elif not folder.selectable:
            counts = "(not selectable)"
        shown = printable(folder.display_name)
        if folder.display_name != folder.name:
            shown += f"  (wire: {printable(folder.name)})"
        out.append(f"  {role:<10} {shown:<40} {counts}".rstrip())
    for w in r.role_warnings:
        out.append(f"  warning: {printable(w)}")
    if r.quota is None:
        out.append("Quota         (not available)")
    else:
        for q in r.quota:
            out.append(
                f"Quota         {printable(q.root) or '(root)'} {q.resource}: {q.usage} of {q.limit}"
            )
    out.append("Bridge plan:")
    for line in r.plan:
        out.append(f"  - {line}")
    return "\n".join(printable(line) for line in out)
