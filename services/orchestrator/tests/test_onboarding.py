"""Onboarding CLI — unit tests (no full Docker bootstrap in CI)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from shift_left.config import AppConfig
from shift_left.system.prerequisites import (
    OverallSystemState,
    PrerequisiteChecker,
    PrerequisiteCriticality,
    compute_overall_state,
)
from shift_left_cli.compose_util import ComposeCli, detect_compose
from shift_left_cli.configure import generate_config, generate_env
from shift_left_cli.repos import import_config_repo
from shift_left_cli.state import load_state, mark_phase, phase_complete


def test_phase_resume_is_idempotent(tmp_path: Path) -> None:
    assert not phase_complete(tmp_path, "preflight")
    mark_phase(tmp_path, "preflight")
    assert phase_complete(tmp_path, "preflight")
    state = load_state(tmp_path)
    assert "preflight" in state["completed_phases"]


def test_configure_replaces_config_directory(tmp_path: Path) -> None:
    example = tmp_path / "config" / "shift-left.example.yaml"
    example.parent.mkdir(parents=True)
    example.write_text("models:\n  foundation_sec: {}\n")
    mistaken = tmp_path / "config" / "shift-left.yaml"
    mistaken.mkdir()
    dest = generate_config(tmp_path, platform={"model_hosting": "host-native-macos"})
    assert dest.is_file()
    assert not mistaken.is_dir()


def test_configure_defaults_q4_and_skips_antares(tmp_path: Path) -> None:
    saved_env = os.environ.copy()
    example = tmp_path / "config" / "shift-left.example.yaml"
    example.parent.mkdir(parents=True)
    example.write_text(
        yaml.safe_dump(
            {
                "models": {"foundation_sec": {"use_low_memory": False}, "antares": {}},
                "antares_triage": {},
                "routing": {"config_globs": ["**/*.tf"]},
            }
        )
    )
    try:
        generate_env(tmp_path, platform={"model_hosting": "compose-linux"})
        generate_config(tmp_path, platform={"model_hosting": "compose-linux"})
    finally:
        os.environ.clear()
        os.environ.update(saved_env)
    raw = yaml.safe_load((tmp_path / "config" / "shift-left.yaml").read_text())
    assert raw["models"]["foundation_sec"]["use_low_memory"] is True
    assert raw["models"]["antares"]["installed"] is False
    assert raw["antares_triage"]["installed"] is False
    env = (tmp_path / ".env").read_text()
    assert "SHIFT_LEFT_MODEL_HOSTING=compose-linux" in env
    assert "POSTGRES_PASSWORD=" in env
    assert "FORGEJO_TOKEN=" in env


def test_import_config_reports_skipped_globs(tmp_path: Path) -> None:
    cfg = tmp_path / "config" / "shift-left.yaml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(yaml.safe_dump({"routing": {"config_globs": ["**/*.tf"]}}))
    src = tmp_path / "src"
    src.mkdir()
    tf_dir = src / "terraform"
    tf_dir.mkdir()
    (tf_dir / "main.tf").write_text('resource "x" "y" {}')
    (src / "README.md").write_text("docs")
    report = import_config_repo(tmp_path, src)
    assert report["matched"] == ["terraform/main.tf"]
    assert report["skipped"] == ["README.md"]


@pytest.mark.asyncio
async def test_antares_not_installed_yields_healthy() -> None:
    config = AppConfig.model_validate(
        {
            "models": {
                "antares": {"enabled": False, "installed": False},
                "foundation_sec": {"enabled": True, "service_url": "http://127.0.0.1:8091"},
            },
            "antares_triage": {"installed": False},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://127.0.0.1:3000"}},
        }
    )
    checker = PrerequisiteChecker(config=config, git=MagicMock(), reference=MagicMock())
    server = await checker._check_antares_server("host-native")
    weights = await checker._check_antares_weights("host-native")
    assert server.ok is True
    assert server.status == "not_installed"
    assert weights.ok is True
    assert weights.status == "not_installed"
    checks = [
        type(
            "C",
            (),
            {
                "criticality": PrerequisiteCriticality.CRITICAL,
                "ok": True,
                "status": "ok",
                "skipped_reason": None,
            },
        )(),
        server,
        weights,
    ]
    assert compute_overall_state(checks) == OverallSystemState.HEALTHY


def test_compose_detection_prefers_compose_subcommand(tmp_path: Path) -> None:
    with patch("shift_left_cli.compose_util._probe") as probe:
        probe.side_effect = lambda prefix, root: prefix == ("docker", "compose")
        cli = detect_compose(tmp_path)
    assert cli.form == "docker compose"
    assert cli.cmd("ps") == ["docker", "compose", "ps"]


def test_compose_detection_falls_back_to_docker_compose(tmp_path: Path) -> None:
    with patch("shift_left_cli.compose_util._probe") as probe:
        probe.side_effect = lambda prefix, root: prefix == ("docker-compose",)
        cli = detect_compose(tmp_path)
    assert cli.form == "docker-compose"
    assert cli.cmd("up") == ["docker-compose", "up"]


def test_docker_daemon_hint_for_colima() -> None:
    from shift_left_cli.preflight import _docker_start_hint

    hint = _docker_start_hint("dial unix /Users/me/.colima/default/docker.sock: connect: no such file")
    assert "colima start" in hint


def test_model_staging_detects_q4_gguf(tmp_path: Path) -> None:
    from shift_left_cli.models_check import inspect_model_staging, print_model_staging_report
    from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_Q4_K_M

    status = inspect_model_staging(tmp_path)
    assert status.needs_foundation_sec_download

    dest = tmp_path / VERIFIED_FOUNDATION_SEC_Q4_K_M["local_path_default"]
    dest.mkdir(parents=True)
    (dest / VERIFIED_FOUNDATION_SEC_Q4_K_M["gguf_filename"]).write_bytes(b"x" * 128)
    status = inspect_model_staging(tmp_path)
    assert status.foundation_sec_q4_path is not None
    assert status.foundation_sec_ready
    assert status.use_low_memory
    assert not status.needs_foundation_sec_download
    print_model_staging_report(tmp_path, status)


def test_model_staging_repairs_nested_models_dir(tmp_path: Path) -> None:
    from shift_left_cli.models_check import inspect_model_staging
    from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_Q8_0

    nested = tmp_path / "models" / "models" / "foundation-sec-q8_0"
    nested.mkdir(parents=True)
    (nested / VERIFIED_FOUNDATION_SEC_Q8_0["gguf_filename"]).write_bytes(b"x" * 128)

    status = inspect_model_staging(tmp_path)
    assert status.repair_actions
    assert status.foundation_sec_q8_path is not None
    assert not status.use_low_memory
    assert not status.needs_foundation_sec_download


def test_stack_waits_on_localhost_for_forgejo(monkeypatch: pytest.MonkeyPatch) -> None:
    from shift_left_cli import stack

    monkeypatch.setenv("FORGEJO_PORT", "3001")
    host, port = stack.service_host_port("forgejo")
    assert host == "127.0.0.1"
    assert port == 3001


def test_forgejo_app_ini_headless_install(tmp_path: Path) -> None:
    from shift_left_cli.forgejo_config import ensure_forgejo_app_config

    env = tmp_path / ".env"
    env.write_text("POSTGRES_PASSWORD=test-db-pass\nFORGEJO_ROOT_URL=http://localhost:3000\n")
    changed = ensure_forgejo_app_config(tmp_path)
    assert changed is True
    ini = (tmp_path / "data" / "forgejo" / "custom" / "conf" / "app.ini").read_text()
    assert "INSTALL_LOCK = true" in ini
    assert "PASSWD = test-db-pass" in ini
    assert "ROOT = /var/lib/gitea/git/repositories" in ini
    assert (tmp_path / ".env").read_text().count("FORGEJO_SECRET_KEY=") == 1
    assert ensure_forgejo_app_config(tmp_path) is False


def test_ensure_access_token_replaces_duplicate_name(monkeypatch: pytest.MonkeyPatch) -> None:
    from shift_left_cli import forgejo_bootstrap as fb

    calls: list[str] = []

    def fake_create(root, compose, username):  # noqa: ANN001
        calls.append("create")
        if len(calls) == 1:
            raise fb.ForgejoBootstrapError("access token name has been used already")
        return "new-token-value"

    monkeypatch.setattr(fb, "_token_valid", lambda token: False)
    monkeypatch.setattr(fb, "_delete_access_token_by_name", lambda *args: calls.append("delete"))
    monkeypatch.setattr(fb, "_create_access_token", fake_create)

    token = fb._ensure_access_token(Path("/tmp"), None, "shiftleft-admin", "pw")
    assert token == "new-token-value"
    assert calls == ["create", "delete", "create"]


def test_forgejo_bootstrap_idempotent_read_secret(tmp_path: Path) -> None:
    from shift_left_cli.forgejo_bootstrap import _read_bootstrap_secret, _persist_bootstrap_secrets

    _persist_bootstrap_secrets(tmp_path, {"forgejo_token": "abc", "forgejo_admin_password": "pw"})
    assert _read_bootstrap_secret(tmp_path, "forgejo_token") == "abc"


def test_install_antares_enables_triage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from shift_left_cli import install_antares as installer

    cfg = tmp_path / "config" / "shift-left.yaml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(
        yaml.safe_dump(
            {
                "models": {"antares": {"enabled": False, "installed": False}},
                "antares_triage": {"enabled": False, "installed": False},
            }
        )
    )
    monkeypatch.setattr(installer, "_token_present", lambda: True)
    monkeypatch.setattr("shift_left_cli.script_util.run_bash_script", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "shift_left_cli.model_packages.ensure_antares_server_package",
        lambda root: None,
    )
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "download-antares-model.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    installer.install_antares(tmp_path)

    raw = yaml.safe_load(cfg.read_text())
    assert raw["models"]["antares"]["enabled"] is True
    assert raw["models"]["antares"]["installed"] is True
    assert raw["antares_triage"]["enabled"] is True
    assert raw["antares_triage"]["installed"] is True


def test_sample_repo_branch_payload_structure() -> None:
    from shift_left_cli.forgejo_bootstrap import RUNNER_LABEL
    from shift_left_cli.sample_repo import PREFERRED_SAMPLE_OWNER, SAMPLE_REPO_NAME

    assert RUNNER_LABEL == "self-hosted"
    assert PREFERRED_SAMPLE_OWNER == "shift-left"
    assert SAMPLE_REPO_NAME == "sample-firewall"


def test_resolve_sample_owner_uses_existing_admin_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from shift_left_cli import sample_repo as sr

    monkeypatch.setattr(sr, "_repo_exists", lambda base, token, owner, name: owner == "shiftleft-admin")
    monkeypatch.setattr(sr, "_authenticated_login", lambda base, token: "shiftleft-admin")
    monkeypatch.setattr(sr, "_org_exists", lambda base, token, org: False)
    monkeypatch.setattr(sr, "_create_org", lambda base, token, org: False)

    owner = sr._resolve_sample_owner("http://localhost:3000", "token", tmp_path)
    assert owner == "shiftleft-admin"
