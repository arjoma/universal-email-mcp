"""Static checks of the deployment files in ``deploy/gcp`` (no cloud calls)."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
GCP = ROOT / "deploy" / "gcp"

RENDER_ENV = {
    "SERVICE": "uem",
    "IMAGE": "europe-docker.pkg.dev/p/r/uem@sha256:" + "0" * 64,
    "RUNTIME_SA": "uem-runtime@p.iam.gserviceaccount.com",
    "PROJECT_ID": "p",
    "PUBLIC_URL": "https://mail.example.org",
    "CONTENT_ORIGIN": "https://content.example.org",
    "LOGIN_DOMAINS": "example.org=imap.example.org",
    "MAIL_SERVERS": "imap.example.org,imap2.example.org",
}


def _render(**extra: str) -> str:
    env = {**os.environ, **RENDER_ENV, **extra}
    done = subprocess.run(
        [str(GCP / "render.sh")], env=env, capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    return done.stdout


@pytest.fixture(scope="module")
def service() -> dict[str, Any]:
    return yaml.safe_load(_render())


def _container(service: dict[str, Any]) -> dict[str, Any]:
    return service["spec"]["template"]["spec"]["containers"][0]


def test_service_yaml_shape(service: dict[str, Any]) -> None:
    template = service["spec"]["template"]
    assert service["kind"] == "Service"
    assert template["metadata"]["annotations"]["run.googleapis.com/execution-environment"] == "gen2"
    assert template["spec"]["serviceAccountName"] == RENDER_ENV["RUNTIME_SA"]
    c = _container(service)
    assert c["image"] == RENDER_ENV["IMAGE"]
    assert c["startupProbe"]["httpGet"]["path"] == "/ready"
    assert c["livenessProbe"]["httpGet"]["path"] == "/health"
    assert template["spec"]["timeoutSeconds"] >= 300


def test_service_secrets_are_references(service: dict[str, Any]) -> None:
    env = {e["name"]: e for e in _container(service)["env"]}
    for name in ("STORE_KEYS", "PSEUDONYM_KEY"):
        assert "value" not in env[name]
        assert env[name]["valueFrom"]["secretKeyRef"]["key"] == "latest"
    assert "UEM_DEV_TOKEN" not in env
    assert env["STORE_BACKEND"]["value"] == "firestore"


def test_service_env_is_documented(service: dict[str, Any]) -> None:
    doc = (ROOT / "docs" / "operator-env.md").read_text()
    for e in _container(service)["env"]:
        assert f"`{e['name']}`" in doc, f"{e['name']} is not in docs/operator-env.md"


def test_render_rejects_missing_values() -> None:
    env = {k: v for k, v in os.environ.items() if k not in RENDER_ENV}
    done = subprocess.run([str(GCP / "render.sh")], env=env, capture_output=True, check=False)
    assert done.returncode != 0


def test_render_leaves_no_placeholder() -> None:
    assert re.search(r"__[A-Z_]+__", _render()) is None


def test_cloudbuild_yaml() -> None:
    build = yaml.safe_load((GCP / "cloudbuild.yaml").read_text())
    assert [s["id"] for s in build["steps"]] == ["build-push", "deploy"]
    assert all(k.startswith("_") for k in build["substitutions"])
    assert build["options"]["logging"] == "CLOUD_LOGGING_ONLY"
    assert build["substitutions"]["_EXTRAS"] == "gcp"


@pytest.mark.parametrize("script", sorted(p.name for p in GCP.glob("*.sh")))
def test_shell_syntax(script: str) -> None:
    done = subprocess.run(["bash", "-n", str(GCP / script)], capture_output=True, check=False)
    assert done.returncode == 0, done.stderr


def test_bootstrap_dry_run_matches_docs() -> None:
    env = {**os.environ, "PROJECT_ID": "p", "REGION": "r", "DRY_RUN": "1"}
    done = subprocess.run(
        [str(GCP / "bootstrap.sh")], env=env, capture_output=True, text=True, check=True
    )
    docs = (ROOT / "docs" / "stored-data.md").read_text()
    match = re.search(r"for c in ([a-z_ ]+); do", docs)
    assert match
    for c in match.group(1).split():
        assert f"--collection-group {c} " in done.stdout
    # Least privilege: no primitive roles, secret access only on the two secrets.
    assert "roles/owner" not in done.stdout
    assert "roles/editor" not in done.stdout
    accessor = [ln for ln in done.stdout.splitlines() if "secretAccessor" in ln]
    assert len(accessor) == 2
    assert all("secrets add-iam-policy-binding" in ln for ln in accessor)


def test_deploy_files_are_vendor_neutral() -> None:
    allowed = (
        "localhost",
        "example.org",
        "example.com",
        "google.com",
        "googleapis.com",
        "github.com",
    )
    for f in [*GCP.iterdir(), ROOT / "docs" / "deploy-gcp.md"]:
        text = f.read_text()
        for host in re.findall(r"https?://([a-z0-9.-]+)", text):
            assert host.endswith(allowed), f"{f.name}: {host}"
