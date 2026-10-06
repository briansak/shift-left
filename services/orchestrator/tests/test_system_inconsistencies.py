"""Regression tests for System page state consistency fixes."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from shift_left.config import AppConfig
from shift_left.system.models_inventory import foundation_sec_inventory
from shift_left.system.prerequisites import PrerequisiteChecker, PrerequisiteCriticality
from shift_left.system.services import ServiceLifecycleManager
from shift_left.ui.system_view import build_lifecycle_feedback, build_merged_health_rows
from tests.test_prerequisites_health import _check


def test_lifecycle_feedback_start_all_with_steps() -> None:
    fb = build_lifecycle_feedback(
        {
            "notice": "start-all",
            "outcome": "chain_stopped",
            "failed": "forgejo",
            "phase": "verification",
            "started": "postgres",
            "skipped": "foundation-sec-server",
            "error": "not ready",
            "steps": "postgres:verified_healthy;forgejo:verification_timeout;foundation-sec-server:skipped",
        }
    )
    assert fb is not None
    assert fb.code == "chain_stopped"
    assert fb.tone == "danger"
    assert fb.started_services == ("postgres",)
    assert fb.error == "not ready"
    assert len(fb.steps) == 3


def test_lifecycle_feedback_service_action() -> None:
    fb = build_lifecycle_feedback(
        {
            "notice": "service-action",
            "outcome": "command_failed",
            "service": "forgejo",
            "action": "start",
            "phase": "command",
            "error": "compose exit 1",
            "steps": "forgejo:command_failed",
        }
    )
    assert fb is not None
    assert fb.tone == "danger"
    assert fb.failed_service == "forgejo"


def test_merged_rows_skip_stopped_when_prerequisite_ok() -> None:
    checks = [
        {
            "id": "postgres",
            "name": "Postgres (Forgejo database)",
            "ok": True,
            "_group": "critical",
            "duration_ms": 1,
        },
    ]
    services = [
        {
            "service": "postgres",
            "display_name": "Forgejo Postgres",
            "running": False,
            "start_feasibility": "start",
            "actions_available": ["start"],
        },
    ]
    rows = build_merged_health_rows(checks, services, can_admin=False)
    assert not any(row.row_id == "service-postgres" for row in rows)


def test_compose_service_running_from_ps() -> None:
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "findings_store": {"sqlite_path": ":memory:"},
            "audit": {"sqlite_path": ":memory:"},
            "auth": {"sqlite_path": ":memory:"},
        }
    )
    lifecycle = ServiceLifecycleManager(config=config, audit=object())  # type: ignore[arg-type]
    with patch.object(lifecycle, "docker_control_available", return_value=True):
        with patch.object(
            lifecycle,
            "_compose_running_services",
            return_value={"postgres", "forgejo"},
        ):
            import asyncio

            status = asyncio.run(lifecycle.status("postgres"))
    assert status["running"] is True


def test_groups_failing_omits_passing_code_handlers() -> None:
    checks = [
        _check("code_handlers", criticality=PrerequisiteCriticality.DEGRADED_CODE, ok=True),
        _check(
            "foundation_sec_server",
            criticality=PrerequisiteCriticality.DEGRADED_CONFIG,
            ok=False,
            status="failed",
        ),
    ]
    checker = PrerequisiteChecker(
        config=AppConfig.model_validate(
            {
                "orchestrator": {"host": "127.0.0.1"},
                "findings_store": {"sqlite_path": ":memory:"},
                "audit": {"sqlite_path": ":memory:"},
                "auth": {"sqlite_path": ":memory:"},
            }
        ),
        git=object(),  # type: ignore[arg-type]
        reference=object(),  # type: ignore[arg-type]
    )
    failing = checker._group_checks_failing(checks)
    assert failing["degraded_code"] == []
    assert len(failing["degraded_config"]) == 1


def test_inventory_marks_runtime_staged_when_server_loaded(tmp_path) -> None:
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "findings_store": {"sqlite_path": str(tmp_path / "f.db")},
            "audit": {"sqlite_path": str(tmp_path / "a.db")},
            "auth": {"sqlite_path": str(tmp_path / "auth.db")},
            "models": {"foundation_sec": {"use_low_memory": False}},
        }
    )
    inv = foundation_sec_inventory(
        config,
        prereq_checks=[
            {
                "id": "foundation_sec_server",
                "ok": True,
                "details": {"runtime": {"gguf_file": "foundation-sec.gguf", "loaded": True}},
            },
        ],
    )
    assert inv["q8_0_staged"] is True
    assert inv["active_profile_staged"] is True
    assert inv["staging_verified_via"] == "runtime_health"


@pytest.mark.asyncio
async def test_antares_server_fails_when_weights_missing(tmp_path, monkeypatch) -> None:
    (tmp_path / "models" / "1b").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SHIFT_LEFT_REPO_ROOT", str(tmp_path))
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "findings_store": {"sqlite_path": str(tmp_path / "f.db")},
            "audit": {"sqlite_path": str(tmp_path / "a.db")},
            "auth": {"sqlite_path": str(tmp_path / "auth.db")},
            "models": {"antares": {"installed": True, "local_path": "models/1b"}},
            "antares_triage": {"installed": True},
        }
    )
    checker = PrerequisiteChecker(
        config=config,
        git=object(),  # type: ignore[arg-type]
        reference=object(),  # type: ignore[arg-type]
    )

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"status": "ok", "loaded": False, "model_path": str(tmp_path / "models/1b")}

    with patch("shift_left.config.resolve_repo_root", return_value=tmp_path):
        with patch("httpx.AsyncClient.get", return_value=FakeResponse()):
            server = await checker._check_antares_server("host-native")
    assert server.ok is False
    assert server.status == "advisory_failed"
    assert "1b" in server.remediation or "1b" in server.error
