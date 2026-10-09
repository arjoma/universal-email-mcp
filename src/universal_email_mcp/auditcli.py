"""``universal-email-mcp audit``: summarise audit log lines (design section 9).

Input is untrusted: anybody who can write to the log can forge lines. So nothing from the
input is trusted as a type, every value that is kept is cleaned (control characters, ANSI
escapes, length) at ingestion, the number of distinct keys per counter is capped, and
garbage never raises - it is counted as skipped.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import sys
import unicodedata
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, BinaryIO

from universal_email_mcp import audit
from universal_email_mcp.errors import ConfigError
from universal_email_mcp.oauth.identity import AddressError, Pseudonyms, parse_address
from universal_email_mcp.operator import MIN_PSEUDONYM_KEY_BYTES, read_key_material

MAX_LINE = 64 * 1024
"""Longer lines are skipped (audit lines are a few hundred bytes)."""
MAX_DOCUMENT = 256 * 1024 * 1024
"""Largest JSON array document (``gcloud logging read --format=json``) that is read."""
MAX_VALUE = 48
MAX_KEYS = 500
"""Distinct keys per counter; the rest is counted as ``(other)``."""
OTHER = "(other)"
TOP_USERS = 10

PSEUDONYM_KINDS = {
    "user": "u",
    "client": "c",
    "account": "a",
    "grant": "g",
    "identity": "i",
    "approval": "p",
    "ip": "n",
}
DUR_ORDER = ("<100ms", "<1s", "<5s", "<30s", ">=30s")

_EVENT = re.compile(r"[a-z_]+(\.[a-z_]+)+")
_ANSI = re.compile(
    r"\x1b\[[0-9;?<=>]*[ -/]*[@-~]"  # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC
    r"|\x1b[@-Z\\-_]"  # two-character escapes
)
_RELATIVE = re.compile(r"(\d{1,6})([smhdw])")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_TEXT_FIELDS = (
    "severity",
    "instance",
    "user",
    "client",
    "account",
    "grant",
    "identity",
    "approval",
    "ip",
    "outcome",
    "code",
    "tool",
    "dur",
    "scope",
    "reason",
    "grant_type",
)


# ------------------------------------------------------------------------ sanitizing


def clean(value: object, cap: int = MAX_VALUE) -> str:
    """``value`` as text that is safe to print: ANSI escapes removed, control, format
    and unassigned characters replaced by ``?``, at most ``cap`` characters."""
    text = _ANSI.sub("", value if isinstance(value, str) else str(value))
    out: list[str] = []
    for ch in text[: cap * 4]:
        out.append("?" if unicodedata.category(ch)[0] == "C" else ch)
    text = "".join(out)
    return text if len(text) <= cap else text[: cap - 1] + "…"


# ------------------------------------------------------------------------ parsing


@dataclass(frozen=True, slots=True)
class Rec:
    """One audit event; every text is already cleaned."""

    event: str
    ts: float | None
    fields: Mapping[str, str]

    def get(self, name: str) -> str:
        return self.fields.get(name, "")


@dataclass(slots=True)
class Stats:
    lines: int = 0
    events: int = 0
    malformed: int = 0
    too_long: int = 0
    not_audit: int = 0
    filtered_out: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "lines_read": self.lines,
            "events_used": self.events,
            "skipped_malformed": self.malformed,
            "skipped_too_long": self.too_long,
            "skipped_not_audit": self.not_audit,
            "filtered_out": self.filtered_out,
        }


def _timestamp(text: object) -> float | None:
    if not isinstance(text, str) or len(text) > 64:
        return None
    try:
        dt = datetime.fromisoformat(text.strip().replace("z", "Z"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


def parse_entry(obj: object) -> Rec | None:
    """An audit event from a raw audit line or a Cloud Logging entry; ``None`` for
    everything else. Never raises."""
    if not isinstance(obj, dict):
        return None
    entry: dict[str, Any] = obj  # pyright: ignore[reportUnknownVariableType]
    payload: Any = entry.get("jsonPayload", entry)
    if not isinstance(payload, dict):
        return None
    data: dict[str, Any] = payload  # pyright: ignore[reportUnknownVariableType]
    name = data.get("event")
    if not isinstance(name, str) or len(name) > 64 or not _EVENT.fullmatch(name):
        return None
    if data.get("message") != name:
        return None
    ts: float | None = None
    raw_ts = data.get("ts")
    if isinstance(raw_ts, (int, float)) and not isinstance(raw_ts, bool):
        ts = float(raw_ts) if math.isfinite(raw_ts) and 0 <= raw_ts < 1e11 else None
    if ts is None and payload is not entry:
        ts = _timestamp(entry.get("timestamp"))
    fields: dict[str, str] = {}
    for key in _TEXT_FIELDS:
        v = data.get(key)
        if isinstance(v, str) and v:
            fields[key] = clean(v)
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            fields[key] = clean(v)
    return Rec(clean(name, 64), ts, fields)


def _lines(stream: BinaryIO, stats: Stats) -> Iterator[bytes]:
    while True:
        raw = stream.readline(MAX_LINE + 1)
        if not raw:
            return
        if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
            stats.lines += 1
            stats.too_long += 1
            while raw and not raw.endswith(b"\n"):
                raw = stream.readline(MAX_LINE)
            continue
        yield raw


def _loads(raw: bytes) -> object:
    try:
        return json.loads(raw)
    except (ValueError, RecursionError, MemoryError):
        return _BAD


_BAD = object()


def read_records(stream: BinaryIO, stats: Stats) -> Iterator[Rec]:
    """Records of one input: a JSON array of Cloud Logging entries, or JSON lines."""
    first: bytes | None = None
    for raw in _lines(stream, stats):
        if raw.strip():
            first = raw
            break
    if first is None:
        return
    if first.lstrip().startswith(b"["):
        rest = stream.read(MAX_DOCUMENT + 1)
        stats.lines += 1 + rest.count(b"\n")
        if len(rest) > MAX_DOCUMENT:
            stats.too_long += 1
            return
        doc = _loads(first + rest)
        if not isinstance(doc, list):
            stats.malformed += 1
            return
        for item in doc:  # pyright: ignore[reportUnknownVariableType]
            rec = parse_entry(item)
            if rec is None:
                stats.not_audit += 1
            else:
                yield rec
        return
    for raw in _chain(first, _lines(stream, stats)):
        if not raw.strip():
            continue
        stats.lines += 1
        obj = _loads(raw)
        if obj is _BAD:
            stats.malformed += 1
            continue
        rec = parse_entry(obj)
        if rec is None:
            stats.not_audit += 1
        else:
            yield rec


def _chain(first: bytes, rest: Iterator[bytes]) -> Iterator[bytes]:
    yield first
    yield from rest


# ------------------------------------------------------------------------ filters


def parse_time(text: str, *, now: float | None = None) -> float:
    """ISO time (``2026-10-09T08:00:00Z``, a date, ...) or relative (``90m``, ``24h``, ``7d``)."""
    t = text.strip()
    m = _RELATIVE.fullmatch(t)
    if m:
        base = datetime.now(UTC).timestamp() if now is None else now
        return base - int(m[1]) * _UNITS[m[2]]
    try:
        dt = datetime.fromisoformat(t.replace("z", "Z"))
    except ValueError:
        raise ConfigError(
            f"cannot read the time {clean(text, 40)!r}",
            hint="Use an ISO time such as 2026-10-09T08:00:00Z, or 90m / 24h / 7d.",
        ) from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


@dataclass(frozen=True, slots=True)
class Filter:
    since: float | None = None
    until: float | None = None
    events: tuple[str, ...] = ()
    where: tuple[tuple[str, str], ...] = ()
    """(field, pseudonym) pairs; all must match."""

    def accepts(self, rec: Rec) -> bool:
        if self.since is not None or self.until is not None:
            if rec.ts is None:
                return False
            if self.since is not None and rec.ts < self.since:
                return False
            if self.until is not None and rec.ts >= self.until:
                return False
        if self.events and not any(fnmatch.fnmatchcase(rec.event, p) for p in self.events):
            return False
        return all(rec.get(k) == v for k, v in self.where)


# ------------------------------------------------------------------------ keys and pseudonyms


def load_key(*, key_file: str | None, local: bool) -> tuple[bytes, bool]:
    """The pseudonym key and whether it is the per-install local one. The key comes from
    ``PSEUDONYM_KEY`` / ``PSEUDONYM_KEY_FILE`` (base64), ``--key-file`` or, with
    ``--local``, the per-install ``audit.key``. Never from an argument value."""
    if local:
        if key_file:
            raise ConfigError("use either --local or --key-file, not both")
        from platformdirs import user_state_dir

        path = os.path.join(user_state_dir("universal-email-mcp"), "audit.key")
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise ConfigError(
                f"cannot read the local audit key ({clean(path, 120)}): {e.strerror}",
                hint="It is created by the first run of `universal-email-mcp local`.",
            ) from None
        if len(data) < 16:
            raise ConfigError("the local audit key file is damaged (too short)")
        return data, True
    env: Mapping[str, str] = {"PSEUDONYM_KEY_FILE": key_file} if key_file else os.environ
    key = read_key_material(env, "PSEUDONYM_KEY")
    if key is None:
        raise ConfigError(
            "no pseudonym key: needed to compute pseudonyms",
            hint="Set PSEUDONYM_KEY (base64) or PSEUDONYM_KEY_FILE, pass --key-file FILE, "
            "or use --local for the per-install key of local mode.",
        )
    if len(key) < MIN_PSEUDONYM_KEY_BYTES:
        raise ConfigError(f"the pseudonym key needs at least {MIN_PSEUDONYM_KEY_BYTES} bytes")
    return key, False


def pseudonym_for(kind: str, value: str, key: bytes) -> str:
    """The pseudonym that audit lines carry for ``value`` of ``kind``."""
    prefix = PSEUDONYM_KINDS[kind]
    if kind == "user":
        try:
            address = parse_address(value)
        except AddressError as e:
            raise ConfigError(f"not a usable e-mail address: {e}") from None
        return Pseudonyms(key).user_id(address.normal)[:14]
    if kind == "ip":
        net = audit.network_of(value)
        if net is None:
            raise ConfigError("not an IP address")
        return audit.pseudonym(prefix, net, key)
    return audit.pseudonym(prefix, value, key)


# ------------------------------------------------------------------------ aggregation


def _bump(counter: Counter[str], key: str, by: int = 1) -> None:
    if key not in counter and len(counter) >= MAX_KEYS:
        key = OTHER
    counter[key] += by


@dataclass(slots=True)
class ToolStat:
    calls: int = 0
    errors: int = 0
    dur: Counter[str] = field(default_factory=Counter[str])
    codes: Counter[str] = field(default_factory=Counter[str])


@dataclass(slots=True)
class Summary:
    first: float | None = None
    last: float | None = None
    events: dict[str, Counter[str]] = field(default_factory=dict[str, Counter[str]])
    tools: dict[str, ToolStat] = field(default_factory=dict[str, ToolStat])
    sends: Counter[str] = field(default_factory=Counter[str])
    failed_sign_ins: Counter[str] = field(default_factory=Counter[str])
    sign_in_outcomes: Counter[str] = field(default_factory=Counter[str])
    rate_limits: Counter[str] = field(default_factory=Counter[str])
    users: Counter[str] = field(default_factory=Counter[str])

    def add(self, rec: Rec) -> None:
        if rec.ts is not None:
            self.first = rec.ts if self.first is None else min(self.first, rec.ts)
            self.last = rec.ts if self.last is None else max(self.last, rec.ts)
        outcome = rec.get("outcome") or "-"
        if rec.event not in self.events and len(self.events) >= MAX_KEYS:
            per = self.events.setdefault(OTHER, Counter())
        else:
            per = self.events.setdefault(rec.event, Counter())
        per[outcome] += 1
        if rec.get("user"):
            _bump(self.users, rec.get("user"))
        if rec.event == "tool.call":
            name = rec.get("tool") or "-"
            if name not in self.tools and len(self.tools) >= MAX_KEYS:
                name = OTHER
            st = self.tools.setdefault(name, ToolStat())
            st.calls += 1
            if outcome != "ok":
                st.errors += 1
                _bump(st.codes, rec.get("code") or outcome)
            _bump(st.dur, rec.get("dur") or "-")
        elif rec.event.startswith("send."):
            _bump(self.sends, f"{rec.event} {outcome}")
        elif rec.event == "auth.sign_in":
            _bump(self.sign_in_outcomes, outcome)
            if outcome != "ok":
                _bump(self.failed_sign_ins, rec.get("ip") or "(no ip logged)")
        elif rec.event == "ratelimit.hit":
            _bump(self.rate_limits, rec.get("scope") or "-")

    def to_dict(self, stats: Stats) -> dict[str, Any]:
        def ordered(c: Counter[str]) -> dict[str, int]:
            return dict(sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))

        return {
            "input": stats.to_dict(),
            "from": _iso(self.first),
            "to": _iso(self.last),
            "events": {e: ordered(c) for e, c in sorted(self.events.items())},
            "tools": {
                t: {
                    "calls": s.calls,
                    "errors": s.errors,
                    "error_rate": round(s.errors / s.calls, 4) if s.calls else 0.0,
                    "duration": {k: s.dur[k] for k in _dur_keys(s.dur)},
                    "error_codes": ordered(s.codes),
                }
                for t, s in sorted(self.tools.items(), key=lambda kv: (-kv[1].calls, kv[0]))
            },
            "sends": ordered(self.sends),
            "sign_ins": ordered(self.sign_in_outcomes),
            "failed_sign_ins_by_network": ordered(self.failed_sign_ins),
            "rate_limit_hits_by_scope": ordered(self.rate_limits),
            "distinct_users": len(self.users),
            "top_users": dict(
                sorted(self.users.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_USERS]
            ),
        }


def _dur_keys(c: Counter[str]) -> list[str]:
    return [k for k in DUR_ORDER if k in c] + sorted(k for k in c if k not in DUR_ORDER)


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def summarize(streams: Iterable[BinaryIO], flt: Filter) -> tuple[Summary, Stats]:
    summary, stats = Summary(), Stats()
    for stream in streams:
        for rec in read_records(stream, stats):
            if flt.accepts(rec):
                stats.events += 1
                summary.add(rec)
            else:
                stats.filtered_out += 1
    return summary, stats


# ------------------------------------------------------------------------ output


def _table(title: str, rows: list[tuple[str, ...]], header: tuple[str, ...]) -> list[str]:
    if not rows:
        return []
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header))]

    def line(r: tuple[str, ...]) -> str:
        return "  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip()

    return ["", title, line(header), *(line(r) for r in rows)]


def format_text(data: dict[str, Any]) -> str:
    inp = data["input"]
    out = [
        f"Audit summary: {data['from'] or '-'} .. {data['to'] or '-'}",
        f"lines read {inp['lines_read']}, events used {inp['events_used']}, "
        f"filtered out {inp['filtered_out']}; skipped: malformed {inp['skipped_malformed']}, "
        f"too long {inp['skipped_too_long']}, not audit {inp['skipped_not_audit']}",
        f"distinct users {data['distinct_users']}",
    ]
    ev: list[tuple[str, ...]] = []
    for name, outcomes in data["events"].items():
        total = sum(outcomes.values())
        detail = ", ".join(f"{o} {n}" for o, n in outcomes.items())
        ev.append((name, str(total), detail))
    out += _table("Events", ev, ("event", "count", "outcomes"))
    tools = [
        (
            t,
            str(s["calls"]),
            str(s["errors"]),
            f"{s['error_rate'] * 100:.1f}%",
            ", ".join(f"{k} {v}" for k, v in s["duration"].items()),
        )
        for t, s in data["tools"].items()
    ]
    out += _table("Tools", tools, ("tool", "calls", "errors", "error rate", "duration"))
    for title, key, col in (
        ("Sends", "sends", "event outcome"),
        ("Sign-in outcomes", "sign_ins", "outcome"),
        ("Failed sign-ins by network", "failed_sign_ins_by_network", "network"),
        ("Rate-limit hits", "rate_limit_hits_by_scope", "scope"),
        ("Most active users", "top_users", "user"),
    ):
        out += _table(title, [(k, str(v)) for k, v in data[key].items()], (col, "count"))
    return "\n".join(out)


# ------------------------------------------------------------------------ command


def add_arguments(p: argparse.ArgumentParser) -> None:
    """Options shared by ``audit`` and ``audit summary``."""
    p.add_argument(
        "files",
        nargs="*",
        metavar="[summary] FILE | pseudonym KIND VALUE",
        help="summary (default) of log files (none or -: stdin); or print the pseudonym of "
        "a user, client, account, grant, identity, approval or ip for log filters",
    )
    p.add_argument("--since", help="ISO time or relative (90m, 24h, 7d)")
    p.add_argument("--until", help="ISO time or relative (exclusive)")
    p.add_argument(
        "--event", action="append", default=[], help="event name or pattern (send.*); repeatable"
    )
    p.add_argument("--user", help="e-mail address: filter to this user (needs the key)")
    p.add_argument("--client", help="client id: filter to its pseudonym (needs the key)")
    p.add_argument("--account", help="account id: filter to its pseudonym (needs the key)")
    p.add_argument("--grant", help="grant id: filter to its pseudonym (needs the key)")
    add_key_arguments(p)
    p.add_argument("--json", action="store_true", help="machine-readable output")


def add_key_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--key-file",
        metavar="FILE",
        help="file with the base64 pseudonym key (default: $PSEUDONYM_KEY / $PSEUDONYM_KEY_FILE)",
    )
    p.add_argument(
        "--local", action="store_true", help="use the per-install key of local mode (audit.key)"
    )


def build_parser(sub: Any) -> None:
    p = sub.add_parser(
        "audit",
        allow_abbrev=False,
        help="summarise audit log lines (per tool, user, failed sign-ins ...)",
        description=(
            "Summarise audit JSON lines from files or stdin: raw audit lines or Cloud Logging "
            "exports (`gcloud logging read --format=json`). Users, clients, accounts and "
            "grants are pseudonyms in the log; --user/--client/--account/--grant recompute "
            "them from the key ($PSEUDONYM_KEY or $PSEUDONYM_KEY_FILE, --key-file, or --local). "
            "The key is never accepted as an argument value and never printed. Everything "
            "taken from the log is sanitised before it is shown."
        ),
    )
    add_arguments(p)


def _open_inputs(files: list[str]) -> Iterator[BinaryIO]:
    if not files or files == ["-"]:
        yield sys.stdin.buffer
        return
    for name in files:
        if name == "-":
            yield sys.stdin.buffer
            continue
        try:
            with open(name, "rb") as f:
                yield f
        except OSError as e:
            raise ConfigError(f"cannot read {clean(name, 120)}: {e.strerror}") from None


def run(args: argparse.Namespace) -> int:
    words: list[str] = list(args.files)
    if words[:1] == ["pseudonym"]:
        if len(words) != 3 or words[1] not in PSEUDONYM_KINDS:
            raise ConfigError(
                "usage: audit pseudonym KIND VALUE",
                hint="KIND is one of: " + ", ".join(sorted(PSEUDONYM_KINDS)) + ".",
            )
        key, _ = load_key(key_file=args.key_file, local=args.local)
        print(pseudonym_for(words[1], words[2], key))
        return 0
    if words[:1] == ["summary"]:
        words = words[1:]
    where: list[tuple[str, str]] = []
    wanted = [
        (k, v) for k, v in (("user", args.user), ("client", args.client),
                            ("account", args.account), ("grant", args.grant)) if v
    ]  # fmt: skip
    if wanted:
        key, local = load_key(key_file=args.key_file, local=args.local)
        if local and args.user:
            raise ConfigError("local mode has no users: --user does not apply with --local")
        for kind, value in wanted:
            where.append((kind, pseudonym_for(kind, value, key)))
    now = datetime.now(UTC).timestamp()
    flt = Filter(
        since=parse_time(args.since, now=now) if args.since else None,
        until=parse_time(args.until, now=now) if args.until else None,
        events=tuple(args.event),
        where=tuple(where),
    )
    summary, stats = summarize(_open_inputs(words), flt)
    data = summary.to_dict(stats)
    if args.json:
        print(json.dumps(data, ensure_ascii=True, indent=2))
    else:
        print(format_text(data))
    return 0
