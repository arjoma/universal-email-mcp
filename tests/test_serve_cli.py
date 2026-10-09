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
