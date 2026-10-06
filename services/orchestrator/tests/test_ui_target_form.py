"""UI for defining managed targets in-app."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import CURRENT_SCHEMA_VERSION, AppConfig
from shift_left.main import app
from shift_left.review.service import ReviewService
from shift_left.triage.service import AntaresTriageService
from tests.test_phase3_hardening import FakeGit


def _minimal_config_yaml() -> dict:
    return {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "orchestrator": {"host": "127.0.0.1"},
        "ui": {"enabled": True, "require_loopback_client": False},
        "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False, "gguf_glob": "*.gguf"}},
        "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        "gate": {"check_repo": "shiftleft-admin/sample-firewall", "protected_branch": "main"},
        "managed_targets": {"targets": [], "applied_revisions": []},
    }


@pytest.fixture
def target_form_client(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_file = config_dir / "shift-left.yaml"
    config_file.write_text(yaml.safe_dump(_minimal_config_yaml()))

    monkeypatch.setenv("SHIFT_LEFT_CONFIG", str(config_file))

    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            **(_minimal_config_yaml()),
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
        }
    )
    service = ReviewService(config)
    fake_git = FakeGit()
    service._git = fake_git
    service._approval_service._git = fake_git
    service._gate_service._git = fake_git
    service._changes._git = fake_git
    service._forgejo_embed._git = fake_git
    service._changes._forgejo = service._forgejo_embed
    service._targets._git = fake_git

    async def list_repo_tree_paths(owner, repo, ref):
        return ["terraform/main.tf", "README.md"]

    fake_git.list_repo_tree_paths = list_repo_tree_paths
    service.target_writes._store._path = config_file
    service.settings._store._path = config_file

    app.state.config = config
    app.state.review_service = service
    app.state.triage_service = AntaresTriageService(config)
    app.state.token_store = service.token_store

    client = TestClient(app)
    _, admin_token = mint_api_token(
        service.token_store,
        label="admin",
        actor="admin",
        capabilities=[TokenCapability.ADMIN],
    )
    _, viewer_token = mint_api_token(
        service.token_store,
        label="viewer",
        actor="viewer",
        capabilities=[TokenCapability.REVIEW],
    )
    return client, service, config_file, admin_token, viewer_token


def test_target_new_form_requires_admin(target_form_client) -> None:
    client, _, _, _, viewer_token = target_form_client
    client.cookies.set(TOKEN_COOKIE_NAME, viewer_token)
    response = client.get("/ui/targets/new")
    assert response.status_code == 403


def test_target_new_form_loads_for_admin(target_form_client) -> None:
    client, _, _, admin_token, _ = target_form_client
    client.cookies.set(TOKEN_COOKIE_NAME, admin_token)
    response = client.get("/ui/targets/new")
    assert response.status_code == 200
    assert "Define managed target" in response.text
    assert 'name="display_name"' in response.text


def test_create_target_via_ui_persists_and_shows_on_overview(target_form_client) -> None:
    client, service, config_file, admin_token, _ = target_form_client
    client.cookies.set(TOKEN_COOKIE_NAME, admin_token)

    response = client.post(
        "/ui/targets/new",
        data={
            "display_name": "edge-fw-01",
            "target_type": "cisco_secure_firewall",
            "repo": "shiftleft-admin/sample-firewall",
            "branch": "main",
            "config_paths": "terraform/**",
            "environment": "production",
            "criticality": "high",
            "owner": "netsecops",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/targets/edge-fw-01?notice=target-created"

    on_disk = yaml.safe_load(config_file.read_text())
    assert len(on_disk["managed_targets"]["targets"]) == 1
    assert on_disk["managed_targets"]["targets"][0]["id"] == "edge-fw-01"

    assert len(service._config.managed_targets.targets) == 1
    overview = client.get("/ui/targets")
    assert overview.status_code == 200
    assert "edge-fw-01" in overview.text


def test_create_target_rejects_non_admin(target_form_client) -> None:
    client, _, _, _, viewer_token = target_form_client
    client.cookies.set(TOKEN_COOKIE_NAME, viewer_token)
    response = client.post(
        "/ui/targets/new",
        data={
            "display_name": "edge-fw-01",
            "target_type": "generic_terraform",
            "repo": "o/r",
            "branch": "main",
            "config_paths": "terraform/**",
        },
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_create_target_shows_validation_error(target_form_client) -> None:
    client, _, _, admin_token, _ = target_form_client
    client.cookies.set(TOKEN_COOKIE_NAME, admin_token)
    response = client.post(
        "/ui/targets/new",
        data={
            "display_name": "edge-fw-01",
            "target_type": "generic_terraform",
            "repo": "bad-repo",
            "branch": "main",
            "config_paths": "terraform/**",
        },
    )
    assert response.status_code == 400
    assert "owner/name" in response.text.lower() or "Repository" in response.text


def test_targets_new_route_egress_blocked(target_form_client) -> None:
    client, _, _, admin_token, _ = target_form_client
    client.cookies.set(TOKEN_COOKIE_NAME, admin_token)
    attempts: list[tuple] = []

    def tracking_connect(address, timeout=None, source_address=None):
        host = address[0] if isinstance(address, tuple) else str(address)
        if host not in {"127.0.0.1", "localhost", "::1"}:
            attempts.append(address)
        raise OSError("blocked in test")

    with patch("socket.create_connection", side_effect=tracking_connect):
        with patch(
            "shift_left.api.ui_support.run_egress_probe",
            return_value=type("R", (), {"ok": True, "message": "blocked"})(),
        ):
            from shift_left.sovereignty.network import EgressGuard

            with EgressGuard(allowed_hosts=frozenset({"127.0.0.1", "localhost", "::1"})):
                response = client.get("/ui/targets/new")
                assert response.status_code == 200
    assert attempts == []


def test_create_target_rejects_zero_file_glob(target_form_client) -> None:
    client, _, _, admin_token, _ = target_form_client
    client.cookies.set(TOKEN_COOKIE_NAME, admin_token)
    response = client.post(
        "/ui/targets/new",
        data={
            "display_name": "edge-fw-01",
            "target_type": "generic_terraform",
            "repo": "shiftleft-admin/sample-firewall",
            "branch": "main",
            "config_paths": "nonexistent/**",
        },
    )
    assert response.status_code == 400
    assert "matches no files" in response.text


def test_create_target_rejects_overlapping_paths(target_form_client) -> None:
    client, _, config_file, admin_token, _ = target_form_client
    client.cookies.set(TOKEN_COOKIE_NAME, admin_token)
    first = client.post(
        "/ui/targets/new",
        data={
            "display_name": "edge-fw-01",
            "target_type": "generic_terraform",
            "repo": "shiftleft-admin/sample-firewall",
            "branch": "main",
            "config_paths": "terraform/**",
        },
        follow_redirects=False,
    )
    assert first.status_code == 303

    overlap = client.post(
        "/ui/targets/new",
        data={
            "display_name": "edge-fw-02",
            "target_type": "generic_terraform",
            "repo": "shiftleft-admin/sample-firewall",
            "branch": "main",
            "config_paths": "terraform/*.tf",
        },
    )
    assert overlap.status_code == 400
    assert "ambiguous" in overlap.text.lower() or "overlap" in overlap.text.lower()
