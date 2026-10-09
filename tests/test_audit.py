"""The audit pipeline: schema allow-list, pseudonyms, hostile values, output streams."""

from __future__ import annotations

import io
import json
import logging
import re
import subprocess
import sys
from typing import Any

import pytest

from universal_email_mcp import audit
from universal_email_mcp.audit import EVENTS, FIELDS, AuditSchemaError

LOGGER = audit.LOGGER_NAME

HOSTILE_TEXT = [
    "alice@example.org",
    "Subject: Quarterly report",
    "folder/Kunden Müller",
    "http://169.254.169.254/",
    "x" * 200,
    "<script>alert(1)</script>",
    "line\nbreak",
    "",
]
USER = "u_" + "ab" * 16
SECRETS = ("alice", "example.org", "Quarterly", "Kunden", "169.254", "script", "xxxxxxxx")


def sample_value(kind: str) -> Any:
    return {
        "user": USER,
        "ref:c": "https://client.example/meta.json",
        "ref:a": "Private Name",
        "ref:g": "g_0123456789abcdef",
        "ref:i": "i_0123456789abcdef",
        "ref:p": "a_0123456789abcdef",
        "ip": "203.0.113.77",
        "tok": "ok",
        "words": "mail.read mail.send",
        "int": 3,
        "bool": True,
        "counts": {"known": 1, "new": 2},
    }[kind]


def hostile_values(kind: str) -> list[Any]:
    if kind in ("tok", "words"):
        return HOSTILE_TEXT[:-1] + [None, 5, ["a"], {"a": 1}]
    if kind == "int":
        return ["7", -1, 1.5, True, "alice@example.org"]
    if kind == "bool":
        return ["yes", 1, "alice@example.org"]
    if kind == "counts":
        return [{"alice@example.org": 1}, {"ok": "alice@example.org"}, {"ok": -1}, "x"]
    return []


def lines(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == LOGGER]


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.INFO, logger=LOGGER)
    return caplog


# ---------------------------------------------------------------- shape


def test_every_event_has_the_stable_shape(logs: pytest.LogCaptureFixture):
    audit.configure(instance="rev-7", log_ip=True)
    for name, spec in EVENTS.items():
        fields = {f: sample_value(FIELDS[f]) for f in spec.fields | audit.COMMON}
        fields["outcome"] = "ok"
        audit.event(name, **fields)
    got = lines(logs)
    assert [e["event"] for e in got] == list(EVENTS)
    for e in got:
        assert e["message"] == e["event"]
        assert e["severity"] in ("INFO", "WARNING", "ERROR")
        assert isinstance(e["ts"], float)
        assert e["instance"] == "rev-7"
        assert set(e) <= {"event", "message", "severity", "ts", "instance", "request_id"} | (
            set(FIELDS)
        )
        blob = json.dumps(e)
        assert "Private Name" not in blob and "client.example" not in blob
        assert "203.0.113" not in blob
        assert USER not in blob  # only the short form
        if "user" in e:
            assert e["user"] == USER[:14]


def test_every_field_kind_is_used_and_valid():
    kinds = {"user", "ref:c", "ref:a", "ref:g", "ref:i", "ref:p", "ip", "tok", "words", "int",
             "bool", "counts"}  # fmt: skip
    assert set(FIELDS.values()) == kinds
    for spec in EVENTS.values():
        assert spec.fields <= set(FIELDS), spec.fields - set(FIELDS)


def test_severity_follows_the_outcome(logs: pytest.LogCaptureFixture):
    audit.event("auth.sign_in", outcome="ok", user=USER)
    audit.event("auth.sign_in", outcome="bad_credentials", user=USER)
    audit.event("send.failed", code="SMTP_REJECTED")
    audit.event("auth.csrf_failed", area="portal")
    got = lines(logs)
    assert [e["severity"] for e in got] == ["INFO", "WARNING", "ERROR", "WARNING"]
    assert [r.levelno for r in logs.records if r.name == LOGGER] == [
        logging.INFO, logging.WARNING, logging.ERROR, logging.WARNING,
    ]  # fmt: skip


# ---------------------------------------------------------------- allow-list


@pytest.mark.parametrize("name", list(EVENTS))
def test_hostile_values_never_reach_the_log_in_any_event(name: str, logs: pytest.LogCaptureFixture):
    """Production behaviour (not strict): bad values become "invalid" or vanish."""
    audit.configure(strict=False, log_ip=True)
    spec = EVENTS[name]
    for field in sorted((spec.fields | audit.COMMON) - {"ip"}):
        for bad in hostile_values(FIELDS[field]):
            audit.event(name, **{field: bad})
    # fields an event does not allow, with hostile content, are dropped
    audit.event(name, subject="Quarterly report", to="alice@example.org", body="x" * 500)
    audit.event(name, ip="alice@example.org", user="alice@example.org", client="alice@example.org")
    blob = "\n".join(r.getMessage() for r in logs.records if r.name == LOGGER)
    for secret in SECRETS:
        assert secret not in blob, (name, secret)
    for e in lines(logs):
        assert "subject" not in e and "to" not in e and "body" not in e


def test_strict_mode_raises_on_anything_outside_the_schema():
    with pytest.raises(AuditSchemaError):
        audit.event("no.such.event")
    with pytest.raises(AuditSchemaError):
        audit.event("tool.call", subject="x")
    with pytest.raises(AuditSchemaError):
        audit.event("tool.call", tool="alice@example.org")
    with pytest.raises(AuditSchemaError):
        audit.event("tool.call", succeeded="3")
    with pytest.raises(AuditSchemaError):
        audit.event("tool.call", user="alice@example.org")


def test_unknown_event_is_reported_not_passed_through(logs: pytest.LogCaptureFixture):
    audit.configure(strict=False)
    audit.event("alice@example.org", user=USER, tool="x")
    (e,) = lines(logs)
    assert e["event"] == "audit.invalid" and e["reason"] == "unknown_event"
    assert "alice" not in json.dumps(e) and "user" not in e


def test_only_known_values_are_logged_for_free_form_looking_fields(
    logs: pytest.LogCaptureFixture,
):
    audit.event("portal.account_permissions", permissions="read send", account="Name")
    audit.event("send.requested", recipients={"new": 1, "known": 0}, size="<10k", mode="confirm")
    got = lines(logs)
    assert got[0]["permissions"] == "read send"
    assert got[1]["recipients"] == {"known": 0, "new": 1}


# ---------------------------------------------------------------- pseudonyms


def test_pseudonyms_are_keyed_stable_and_not_the_raw_id(logs: pytest.LogCaptureFixture):
    audit.configure(key=b"k" * 32)
    audit.event("auth.consent", outcome="approved", client="https://c.example/a.json", grant="g_1")
    audit.event("auth.consent", outcome="approved", client="https://c.example/a.json", grant="g_1")
    audit.configure(key=b"other-key-other-key-other-key!!")
    audit.event("auth.consent", outcome="approved", client="https://c.example/a.json", grant="g_1")
    a, b, c = lines(logs)
    assert a["client"] == b["client"] != c["client"]
    assert re.fullmatch(r"c_[0-9a-f]{12}", a["client"])
    assert re.fullmatch(r"g_[0-9a-f]{12}", a["grant"])
    assert a["client"] != a["grant"]
    assert "c.example" not in json.dumps(a)


def test_kinds_do_not_share_pseudonyms(logs: pytest.LogCaptureFixture):
    audit.event("tool.call", client="same", account="same", grant="same", user=USER)
    (e,) = lines(logs)
    assert len({e["client"][2:], e["account"][2:], e["grant"][2:]}) == 3


def test_ip_is_off_by_default_and_only_a_network_pseudonym_when_on(
    logs: pytest.LogCaptureFixture,
):
    audit.event("ratelimit.hit", scope="signin_ip", ip="203.0.113.5")
    audit.configure(log_ip=True)
    audit.event("ratelimit.hit", scope="signin_ip", ip="203.0.113.5")
    audit.event("ratelimit.hit", scope="signin_ip", ip="203.0.113.99")
    audit.event("ratelimit.hit", scope="signin_ip", ip="2001:db8:1:2:3:4:5:6")
    audit.event("ratelimit.hit", scope="signin_ip", ip="not an ip")
    off, a, b, v6, junk = lines(logs)
    assert "ip" not in off and "ip" not in junk
    assert a["ip"] == b["ip"]  # same /24
    assert re.fullmatch(r"n_[0-9a-f]{12}", v6["ip"])
    assert "203.0.113" not in json.dumps(lines(logs)) and "2001" not in json.dumps(lines(logs))


def test_local_key_is_created_once_with_private_permissions(tmp_path: Any):
    k1 = audit.local_key(tmp_path)
    k2 = audit.local_key(tmp_path)
    assert k1 == k2 and len(k1) == 32
    assert ((tmp_path / "audit.key").stat().st_mode & 0o777) == 0o600


def test_local_key_falls_back_to_a_throwaway_key(tmp_path: Any):
    blocked = tmp_path / "file"
    blocked.write_text("x")
    assert len(audit.local_key(blocked / "sub")) == 32  # cannot create the directory


def test_the_key_needs_some_length():
    with pytest.raises(ValueError):
        audit.configure(key=b"short")


# ---------------------------------------------------------------- output streams


def test_setup_writes_one_json_line_per_event_to_the_given_stream():
    stream = io.StringIO()
    log = logging.getLogger(LOGGER)
    saved = (list(log.handlers), log.propagate, log.level)
    try:
        audit.setup(stream)
        audit.setup(stream)  # idempotent: still one handler
        audit.event("auth.sign_in", outcome="bad_credentials", user=USER)
        out = stream.getvalue().splitlines()
        assert len(out) == 1
        e = json.loads(out[0])
        assert e["severity"] == "WARNING" and e["event"] == "auth.sign_in"
    finally:
        log.handlers[:] = saved[0]
        log.propagate, level = saved[1], saved[2]
        log.setLevel(level)


def run_python(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60, check=False
    )


def test_default_target_is_stderr_never_stdout():
    p = run_python(
        "from universal_email_mcp import audit\n"
        "audit.setup()\n"
        "audit.event('auth.csrf_failed', area='portal')\n"
    )
    assert p.returncode == 0, p.stderr
    assert p.stdout == ""
    assert json.loads(p.stderr)["event"] == "auth.csrf_failed"


def test_serve_mode_writes_to_stdout_with_severity():
    p = run_python(
        "import sys\n"
        "from universal_email_mcp import audit\n"
        "audit.setup(sys.stdout)\n"
        "audit.event('send.failed', code='X')\n"
    )
    assert p.returncode == 0, p.stderr
    assert p.stderr == ""
    assert json.loads(p.stdout)["severity"] == "ERROR"


def test_pseudonyms_are_stable_across_processes_with_a_persisted_key(tmp_path: Any):
    code = (
        "import sys\n"
        "from universal_email_mcp import audit\n"
        f"audit.configure(key=audit.local_key({str(tmp_path)!r}))\n"
        "audit.setup(sys.stdout)\n"
        "audit.event('tool.call', account='Work', user=None)\n"
    )
    a, b = run_python(code), run_python(code)
    assert json.loads(a.stdout)["account"] == json.loads(b.stdout)["account"]
