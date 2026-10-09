"""The ``audit`` command: log lines produced by the real pipeline, summaries, filters,
hostile input."""

from __future__ import annotations

import base64
import io
import json
import time
from pathlib import Path
from typing import Any

import pytest

from universal_email_mcp import audit, auditcli
from universal_email_mcp.cli import main
from universal_email_mcp.oauth.identity import Pseudonyms

KEY = bytes(range(1, 33))
KEY_B64 = base64.b64encode(KEY).decode()
ALICE = "alice@example.org"
BOB = "bob@example.org"


def user_id(address: str) -> str:
    return Pseudonyms(KEY).user_id(address)


def make_log() -> list[str]:
    """Events through the real pipeline (key, strict mode), as raw JSON lines."""
    audit.configure(key=KEY, log_ip=True, instance="rev-1")
    buf = io.StringIO()
    audit.setup(buf)
    alice, bob = user_id(ALICE), user_id(BOB)
    for _ in range(3):
        audit.event(
            "tool.call", user=alice, grant="grant-a", tool="find_messages", outcome="ok", dur="<1s"
        )
    audit.event(
        "tool.call",
        user=alice,
        grant="grant-a",
        tool="find_messages",
        outcome="error",
        code="timeout",
        dur=">=30s",
    )
    audit.event(
        "tool.call", user=bob, grant="grant-b", tool="get_message", outcome="ok", dur="<100ms"
    )
    audit.event("send.sent", user=alice, recipients={"known": 1}, mode="direct")
    audit.event("send.failed", user=alice, recipients={"new": 1}, code="smtp")
    audit.event("auth.sign_in", outcome="bad_password", ip="203.0.113.7")
    audit.event("auth.sign_in", outcome="bad_password", ip="203.0.113.99")
    audit.event("auth.sign_in", outcome="ok", user=bob)
    audit.event("ratelimit.hit", scope="signin", ip="198.51.100.4")
    audit.event(
        "auth.consent", user=alice, client="https://client.example/meta", outcome="approved"
    )
    return buf.getvalue().splitlines()


@pytest.fixture
def log(tmp_path: Path) -> Path:
    lines = make_log()
    audit.reset()
    audit.configure(strict=True)
    p = tmp_path / "audit.jsonl"
    p.write_text("\n".join(lines) + "\n")
    return p


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PSEUDONYM_KEY", KEY_B64)
    monkeypatch.delenv("PSEUDONYM_KEY_FILE", raising=False)


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(["audit", *argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def summary(capsys: pytest.CaptureFixture[str], *argv: str) -> dict[str, Any]:
    code, out, _ = run(capsys, "--json", *argv)
    assert code == 0
    return json.loads(out)


def test_summary_counts(log: Path, capsys: pytest.CaptureFixture[str]):
    d = summary(capsys, str(log))
    assert d["input"]["events_used"] == 12
    assert d["events"]["tool.call"] == {"ok": 4, "error": 1}
    find = d["tools"]["find_messages"]
    assert find["calls"] == 4 and find["errors"] == 1 and find["error_rate"] == 0.25
    assert find["duration"] == {"<1s": 3, ">=30s": 1}
    assert find["error_codes"] == {"timeout": 1}
    assert d["sends"] == {"send.failed -": 1, "send.sent -": 1}
    assert d["sign_ins"] == {"bad_password": 2, "ok": 1}
    nets = d["failed_sign_ins_by_network"]
    assert len(nets) == 1 and next(iter(nets.values())) == 2  # both in 203.0.113.0/24
    assert d["rate_limit_hits_by_scope"] == {"signin": 1}
    assert d["distinct_users"] == 2
    assert d["from"] is not None and d["to"] is not None


def test_text_output_and_default_action(log: Path, capsys: pytest.CaptureFixture[str]):
    code, out, _ = run(capsys, str(log))
    assert code == 0
    assert "find_messages" in out and "Failed sign-ins by network" in out
    code2, out2, _ = run(capsys, "summary", str(log))
    assert code2 == 0 and out2 == out


def test_user_filter_matches_pipeline(log: Path, capsys: pytest.CaptureFixture[str]):
    d = summary(capsys, "--user", "  ALICE@Example.ORG ", str(log))
    assert d["distinct_users"] == 1
    assert d["tools"]["find_messages"]["calls"] == 4
    assert "get_message" not in d["tools"]
    assert d["input"]["events_used"] == 7  # 4 tool calls, 2 sends, 1 consent
    assert d["input"]["filtered_out"] == 5


def test_client_and_grant_filters(log: Path, capsys: pytest.CaptureFixture[str]):
    d = summary(capsys, "--client", "https://client.example/meta", str(log))
    assert d["input"]["events_used"] == 1
    d = summary(capsys, "--grant", "grant-b", str(log))
    assert list(d["tools"]) == ["get_message"]
    d = summary(capsys, "--grant", "nope", str(log))
    assert d["input"]["events_used"] == 0
    d = summary(capsys, "--account", "nope", str(log))
    assert d["input"]["events_used"] == 0


def test_event_filter_and_pattern(log: Path, capsys: pytest.CaptureFixture[str]):
    d = summary(capsys, "--event", "send.*", "--event", "ratelimit.hit", str(log))
    assert set(d["events"]) == {"send.sent", "send.failed", "ratelimit.hit"}


def test_time_filters(log: Path, capsys: pytest.CaptureFixture[str]):
    assert summary(capsys, "--since", "1h", str(log))["input"]["events_used"] == 12
    assert summary(capsys, "--until", "1h", str(log))["input"]["events_used"] == 0
    assert summary(capsys, "--since", "2999-01-01", str(log))["input"]["events_used"] == 0
    future = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
    assert summary(capsys, "--until", future, str(log))["input"]["events_used"] == 12
    code, _, err = run(capsys, "--since", "yesterday-ish", str(log))
    assert code == 1 and "cannot read the time" in err


def cloud_entries(lines: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "insertId": str(i),
            "jsonPayload": json.loads(line),
            "resource": {"type": "cloud_run_revision"},
            "severity": "INFO",
        }
        for i, line in enumerate(lines)
    ]


def test_cloud_logging_array_and_ndjson(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    entries = cloud_entries(make_log())
    entries.append({"textPayload": "plain text", "jsonPayload": {"event": "http_request"}})
    arr = tmp_path / "a.json"
    arr.write_text(json.dumps(entries, indent=2))
    nd = tmp_path / "n.json"
    nd.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    for p in (arr, nd):
        d = summary(capsys, str(p))
        assert d["input"]["events_used"] == 12
        assert d["input"]["skipped_not_audit"] == 1


def test_cloud_timestamp_fallback(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    e = {
        "timestamp": "2026-10-01T10:00:00.123456Z",
        "jsonPayload": {"event": "tool.call", "message": "tool.call", "tool": "x"},
    }
    p = tmp_path / "t.json"
    p.write_text(json.dumps([e]))
    d = summary(capsys, str(p))
    assert d["from"] == "2026-10-01T10:00:00Z"


def test_stdin(monkeypatch: pytest.MonkeyPatch, log: Path, capsys: pytest.CaptureFixture[str]):
    class FakeStdin:
        buffer = io.BytesIO(log.read_bytes())

    monkeypatch.setattr("sys.stdin", FakeStdin())
    assert summary(capsys)["input"]["events_used"] == 12


def test_garbage_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    good = make_log()[0]
    nasty: list[bytes] = [
        b"\x00\xff\xfe binary \x80",
        b"not json",
        b"{" * 100000,  # deep nesting
        b'{"a":' * 10000,
        b"x" * (auditcli.MAX_LINE * 3),
        b"null",
        b"123",
        b'"str"',
        b'{"event":5,"message":5}',
        b'{"event":"tool.call","message":"tool.call","tool":{"a":1},"outcome":["x"],'
        b'"ts":"nan","user":1}',
        b'{"event":"tool.call","message":"tool.call","ts":1e999}',
        b'{"event":"tool.call","message":"tool.call","ts":true,"dur":null}',
        b'{"jsonPayload":[1],"event":"a.b"}',
        b'{"jsonPayload":{"event":"a.b","message":"other"}}',
        b"",
        good.encode(),
    ]
    p = tmp_path / "g.log"
    p.write_bytes(b"\n".join(nasty) + b"\n")
    d = summary(capsys, str(p))
    assert d["input"]["skipped_too_long"] == 2
    assert d["input"]["skipped_malformed"] >= 3
    assert d["input"]["events_used"] >= 3  # the good line plus lines with odd types


@pytest.mark.parametrize("doc", [b"[" * 100000, b"[1, 2,", b'[{"jsonPayload": 1}, 5, null]'])
def test_garbage_array(doc: bytes, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    p = tmp_path / "g.json"
    p.write_bytes(doc)
    assert summary(capsys, str(p))["input"]["events_used"] == 0


def test_forged_values_are_neutralised(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    evil = "\x1b[31mRED\x1b]0;title\x07\x1b[2J\r\nfake: line‮\x00" + "z" * 500
    forged = {
        "event": "tool.call",
        "message": "tool.call",
        "tool": evil,
        "outcome": "error",
        "code": evil,
        "dur": evil,
        "user": evil,
        "ts": time.time(),
    }
    forged2 = {"event": "auth.sign_in", "message": "auth.sign_in", "outcome": evil, "ip": evil}
    p = tmp_path / "f.log"
    p.write_text(json.dumps(forged) + "\n" + json.dumps(forged2) + "\n")
    code, out, err = run(capsys, str(p))
    assert code == 0
    for text in (out, err):
        for bad in ("\x1b", "\r", "\x00", "‮"):
            assert bad not in text
        assert "title" not in text  # the whole OSC sequence is removed
    assert max(len(line) for line in out.splitlines()) < 300
    assert "RED" in out  # the printable remainder is still shown
    _, jout, _ = run(capsys, "--json", str(p))
    assert "\x1b" not in jout


def test_many_distinct_keys_are_capped(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    lines = [
        json.dumps({"event": "tool.call", "message": "tool.call", "tool": f"t{i}"})
        for i in range(auditcli.MAX_KEYS + 50)
    ]
    p = tmp_path / "m.log"
    p.write_text("\n".join(lines))
    d = summary(capsys, str(p))
    assert len(d["tools"]) == auditcli.MAX_KEYS + 1
    assert d["tools"][auditcli.OTHER]["calls"] == 50


def test_missing_key_is_a_clear_error(
    log: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.delenv("PSEUDONYM_KEY")
    code, out, err = run(capsys, "--user", ALICE, str(log))
    assert code == 1 and out == ""
    assert "no pseudonym key" in err and "PSEUDONYM_KEY" in err
    # a summary without a filter needs no key
    assert run(capsys, str(log))[0] == 0


def test_bad_keys_do_not_echo(
    log: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    secret = "s3cr3t-not-base64!!"
    monkeypatch.setenv("PSEUDONYM_KEY", secret)
    code, out, err = run(capsys, "--user", ALICE, str(log))
    assert code == 1 and secret not in out + err
    short = base64.b64encode(b"short-key-0123456").decode()
    monkeypatch.setenv("PSEUDONYM_KEY", short)
    code, out, err = run(capsys, "pseudonym", "user", ALICE)
    assert code == 1 and short not in out + err and "at least 32" in err


def test_key_file_and_key_never_printed(
    log: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
):
    monkeypatch.delenv("PSEUDONYM_KEY")
    kf = tmp_path / "key"
    kf.write_text(KEY_B64 + "\n")
    code, out, err = run(capsys, "--key-file", str(kf), "--user", ALICE, str(log))
    assert code == 0 and KEY_B64 not in out + err
    code, out, err = run(capsys, "--key-file", str(tmp_path / "nokey"), "--user", ALICE, str(log))
    assert code == 1 and KEY_B64 not in err
    # the key cannot be passed as a value
    with pytest.raises(SystemExit):
        main(["audit", "--key", KEY_B64, str(log)])
    capsys.readouterr()


def test_pseudonym_command(capsys: pytest.CaptureFixture[str]):
    cases = {
        "user": (ALICE, user_id(ALICE)[:14]),
        "client": ("cid", audit.pseudonym("c", "cid", KEY)),
        "account": ("acc", audit.pseudonym("a", "acc", KEY)),
        "grant": ("g1", audit.pseudonym("g", "g1", KEY)),
        "identity": ("i1", audit.pseudonym("i", "i1", KEY)),
        "approval": ("p1", audit.pseudonym("p", "p1", KEY)),
        "ip": ("203.0.113.55", audit.pseudonym("n", "203.0.113.0/24", KEY)),
    }
    for kind, (value, expected) in cases.items():
        code, out, _ = run(capsys, "pseudonym", kind, value)
        assert code == 0 and out.strip() == expected, kind
    assert run(capsys, "pseudonym", "user", "not an address")[0] == 1
    assert run(capsys, "pseudonym", "ip", "nope")[0] == 1


def test_local_key(
    log: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    state = tmp_path / "state"
    monkeypatch.setattr("platformdirs.user_state_dir", lambda *a, **k: str(state))  # pyright: ignore[reportUnknownLambdaType]
    code, _, err = run(capsys, "pseudonym", "account", "x", "--local")
    assert code == 1 and "local audit key" in err
    key = audit.local_key(state)
    code, out, _ = run(capsys, "pseudonym", "account", "x", "--local")
    assert code == 0 and out.strip() == audit.pseudonym("a", "x", key)
    code, _, err = run(capsys, "--local", "--user", ALICE, str(log))
    assert code == 1 and "local mode has no users" in err


def test_missing_input_file(capsys: pytest.CaptureFixture[str]):
    code, _, err = run(capsys, "/nonexistent/\x1b[31mfile")
    assert code == 1 and "\x1b" not in err
