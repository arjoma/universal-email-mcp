"""``universal-email-mcp serve``: startup refusals and a real process."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import signal
import socket
import sys
from pathlib import Path

import httpx2
import pytest

from universal_email_mcp.cli import main

CONFIG = (
    '[[accounts]]\nname = "Work"\nusername = "u"\npassword_env = "UEM_TEST_UNSET_PASSWORD"\n'
    '[accounts.imap]\nhost = "127.0.0.1"\nport = 1\n'
)


def test_serve_refuses_without_token_or_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG)
    monkeypatch.delenv("UEM_DEV_TOKEN", raising=False)
    monkeypatch.setenv("PUBLIC_URL", "https://mcp.example.com")
    assert main(["serve", "--config", str(cfg)]) == 1
    err = capsys.readouterr().err
    assert "UEM_DEV_TOKEN" in err and "--insecure-local" in err


def test_serve_insecure_local_refuses_public_bind(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG)
    monkeypatch.delenv("UEM_DEV_TOKEN", raising=False)
    assert main(["serve", "--config", str(cfg), "--insecure-local", "--host", "0.0.0.0"]) == 1
    assert "loopback" in capsys.readouterr().err


def test_serve_requires_a_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("UEM_DEV_TOKEN", "t" * 40)
    assert main(["serve", "--config", str(tmp_path / "missing.toml")]) == 1
    assert "CONFIG_INVALID" in capsys.readouterr().err


async def test_serve_process_serves_and_shuts_down_gracefully(tmp_path: Path):
    """JSON logs on stdout, /health, the token guard, and graceful SIGTERM."""
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    token = secrets.token_urlsafe(32)
    env = {k: v for k, v in os.environ.items() if k != "UEM_TEST_UNSET_PASSWORD"}
    env |= {"UEM_DEV_TOKEN": token, "ALLOWED_HOSTS": "127.0.0.1", "PORT": str(port)}
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "universal_email_mcp",
        "serve",
        "--config",
        str(cfg),
        "--host",
        "127.0.0.1",
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        async with httpx2.AsyncClient() as http:
            for _ in range(300):
                try:
                    if (await http.get(f"http://127.0.0.1:{port}/health")).status_code == 200:
                        break
                except httpx2.TransportError:
                    pass
                await asyncio.sleep(0.1)
            else:
                pytest.fail("serve did not come up")
            r = await http.post(f"http://127.0.0.1:{port}/mcp", json={})
            assert r.status_code == 401
        proc.send_signal(signal.SIGTERM)
        out, _err = await asyncio.wait_for(proc.communicate(), 20)
        # uvicorn re-raises the captured SIGTERM after a graceful stop (exit status 143)
        assert proc.returncode in (0, -signal.SIGTERM)
        lines = [json.loads(line) for line in out.decode().splitlines() if line.strip()]
        assert lines and all("severity" in x and "message" in x for x in lines)
        assert any(x.get("event") == "http_request" and x["status"] == 401 for x in lines)
        assert any("Application shutdown complete" in x["message"] for x in lines)
        assert token not in out.decode()
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()


async def test_serve_oauth_mode_process(tmp_path: Path):
    """Without dev flags ``serve`` is the OAuth server: no TOML config needed, metadata and
    a store-backed /ready, no secrets or tokens in the logs."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UEM_", "STORE_"))}
    env |= {
        "STORE_BACKEND": "memory",
        "PUBLIC_URL": f"http://127.0.0.1:{port}",
        "LOGIN_DOMAINS": "example.org=imap.example.org",
        "PORT": str(port),
    }
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "universal_email_mcp", "serve", "--host", "127.0.0.1",
        env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )  # fmt: skip
    base = f"http://127.0.0.1:{port}"
    try:
        async with httpx2.AsyncClient() as http:
            for _ in range(300):
                try:
                    if (await http.get(f"{base}/health")).status_code == 200:
                        break
                except httpx2.TransportError:
                    pass
                await asyncio.sleep(0.1)
            else:
                pytest.fail("serve did not come up")
            ready = (await http.get(f"{base}/ready")).json()
            assert ready["checks"] == {"config": True, "store": True}
            meta = (await http.get(f"{base}/.well-known/oauth-authorization-server")).json()
            assert meta["issuer"] == base and meta["token_endpoint"] == f"{base}/token"
            r = await http.post(f"{base}/mcp", json={})
            assert r.status_code == 401 and "resource_metadata" in r.headers["www-authenticate"]
        proc.send_signal(signal.SIGTERM)
        out, _err = await asyncio.wait_for(proc.communicate(), 20)
        assert "memory without STORE_KEYS" in out.decode()
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()


def test_serve_oauth_mode_refuses_incomplete_environment(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    for var in ("UEM_DEV_TOKEN", "STORE_BACKEND", "LOGIN_DOMAINS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PUBLIC_URL", "https://mcp.example.com")
    monkeypatch.setenv("STORE_BACKEND", "memory")
    assert main(["serve"]) == 1
    assert "LOGIN_DOMAINS" in capsys.readouterr().err


def test_serve_oauth_mode_refuses_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    """--config would be silently ignored in OAuth mode: say so instead."""
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG)
    for var in ("UEM_DEV_TOKEN", "STORE_BACKEND", "LOGIN_DOMAINS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PUBLIC_URL", "https://mcp.example.com")
    monkeypatch.setenv("STORE_BACKEND", "memory")
    assert main(["serve", "--config", str(cfg)]) == 1
    err = capsys.readouterr().err
    assert "--config" in err and "OAuth mode" in err


# ---------------------------------------------------------------- admin rotate-keys


KEY1, KEY2 = bytes(range(32)), bytes(range(1, 33))


def _rotation_store(damaged: bool):
    """A memory store holding two accounts sealed with k1; the ring now has k2 active."""
    from datetime import UTC, datetime

    from universal_email_mcp.store import KeyRing, MailAccount, MemoryBackend, Store
    from universal_email_mcp.store.backend import Op

    backend = MemoryBackend()
    old = Store(backend, KeyRing({"k1": KEY1}))

    async def fill() -> None:
        for rid in ("a1", "a2"):
            await old.create(
                MailAccount(
                    id=rid, user_id="u_1", name="Work", host="imap.example.org", port=993,
                    username="alice@example.org", password="PW-SECRET-1",
                    created_at=datetime(2026, 10, 1, tzinfo=UTC),
                )
            )  # fmt: skip
        if damaged:
            doc = await backend.get("accounts", "a2")
            assert doc is not None
            broken = {**doc, "_sealed": doc["_sealed"][:-6] + "AAAAAA"}
            await backend.commit([Op("replace", "accounts", "a2", broken, doc["_v"])])

    asyncio.run(fill())
    return Store(backend, KeyRing({"k1": KEY1, "k2": KEY2}))


def _admin_env(monkeypatch: pytest.MonkeyPatch, store) -> None:
    import universal_email_mcp.oauth.app as oauth_app

    for var in ("UEM_DEV_TOKEN", "STORE_KEYS", "STORE_KEYS_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PUBLIC_URL", "https://mcp.example.com")
    monkeypatch.setenv("STORE_BACKEND", "memory")
    monkeypatch.setenv("LOGIN_DOMAINS", "example.org=imap.example.org")
    monkeypatch.setattr(oauth_app, "make_store", lambda _op: store)


def test_admin_rotate_keys_dry_run_then_real(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    store = _rotation_store(damaged=False)
    _admin_env(monkeypatch, store)
    assert main(["admin", "rotate-keys", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "accounts: 2 would be re-sealed" in out
    doc = asyncio.run(store.backend.get("accounts", "a1"))
    assert doc is not None and doc["_sealed"].startswith("e1.k1.")  # dry run wrote nothing
    assert main(["admin", "rotate-keys"]) == 0
    assert "accounts: 2 re-sealed" in capsys.readouterr().out
    assert main(["admin", "rotate-keys"]) == 0
    assert "accounts: 0 re-sealed" in capsys.readouterr().out


def test_admin_rotate_keys_reports_unreadable_records_without_content(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    store = _rotation_store(damaged=True)
    _admin_env(monkeypatch, store)
    assert main(["admin", "rotate-keys"]) == 3
    cap = capsys.readouterr()
    assert "accounts: 1 re-sealed" in cap.out and "accounts: 1 UNREADABLE" in cap.out
    for text in (cap.out, cap.err):
        assert "PW-SECRET-1" not in text and "a2" not in text and KEY1.hex() not in text


def test_admin_without_a_command_prints_usage(capsys: pytest.CaptureFixture[str]):
    assert main(["admin"]) == 2
    assert "rotate-keys" in capsys.readouterr().err
