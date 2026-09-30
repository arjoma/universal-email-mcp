from pathlib import Path

import pytest

from universal_email_mcp.cli import main


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]):
    assert main([]) == 2
    assert "probe" in capsys.readouterr().err


def test_version(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "universal-email-mcp" in capsys.readouterr().out


def test_local_is_a_stub(capsys: pytest.CaptureFixture[str]):
    assert main(["local"]) == 2
    assert "not implemented" in capsys.readouterr().err


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


def test_probe_public_only_blocks_loopback(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("UEM_PASSWORD", "x")
    args = ["probe", "--host", "127.0.0.1", "--user", "u", "--public-only", "--port", "1"]
    assert main(args) == 1
    assert "ADDRESS_NOT_ALLOWED" in capsys.readouterr().err
