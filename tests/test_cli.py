import os
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from universal_email_mcp.cli import main


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]):
    assert main([]) == 2
    assert "probe" in capsys.readouterr().err


def test_version(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "universal-email-mcp" in capsys.readouterr().out


def test_local_without_config_fails_cleanly(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["local", "--config", str(tmp_path / "missing.toml")]) == 1
    assert "CONFIG_INVALID" in capsys.readouterr().err


async def test_local_serves_mcp_over_stdio(tmp_path: Path):
    cfg = tmp_path / "c.toml"
    cfg.write_text(
        '[[accounts]]\nname = "Work"\nserver = "imap.example.com"\nusername = "u"\n'
        'password_env = "UEM_TEST_UNSET_PASSWORD"\n'
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "universal_email_mcp", "local", "--config", str(cfg)],
        env={k: v for k, v in os.environ.items() if k != "UEM_TEST_UNSET_PASSWORD"},
    )
    async with Client(params) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert {"find_messages", "list_folders", "get_message", "find_contacts"} <= names
        r = await c.call_tool("account_info", {})
        assert r.is_error and r.structured_content is not None
        assert r.structured_content["problems"][0]["code"] == "CREDENTIAL_MISSING"


def test_probe_requires_target(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit):
        main(["probe"])


def test_probe_host_requires_user(capsys: pytest.CaptureFixture[str]):
    assert main(["probe", "--host", "mail.example.com"]) == 1
    assert "--user is required" in capsys.readouterr().err


def test_probe_without_password_fails_cleanly(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("UEM_PASSWORD", raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["probe", "--server", "united-domains", "--user", "u", "--json"]) == 1
    assert '"code": "CREDENTIAL_MISSING"' in capsys.readouterr().err


def test_probe_unknown_account(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    cfg = tmp_path / "c.toml"
    cfg.write_text('[[accounts]]\nname = "a"\nserver = "x.example.com"\nusername = "u"\n')
    assert main(["probe", "--account", "nope", "--config", str(cfg)]) == 1
    err = capsys.readouterr().err
    assert "CONFIG_INVALID" in err and "Known accounts: a" in err
    assert f"config: {cfg} (accounts: a)" in err


def test_local_reports_the_loaded_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    """--config wins over UEM_CONFIG, and stderr names the file that was loaded."""
    cfg = tmp_path / "sandbox.toml"
    cfg.write_text('[[accounts]]\nname = "Sandbox"\nserver = "x.example.com"\nusername = "u"\n')
    monkeypatch.setenv("UEM_CONFIG", str(tmp_path / "real.toml"))
    served: list[object] = []
    monkeypatch.setattr("universal_email_mcp.server.local.run_local", served.append)
    assert main(["local", "--config", str(cfg)]) == 0
    assert len(served) == 1
    captured = capsys.readouterr()
    assert f"config: {cfg} (accounts: Sandbox)" in captured.err and not captured.out


def test_probe_public_only_blocks_loopback(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("UEM_PASSWORD", "x")
    args = ["probe", "--host", "127.0.0.1", "--user", "u", "--public-only", "--port", "1"]
    assert main(args) == 1
    assert "ADDRESS_NOT_ALLOWED" in capsys.readouterr().err
