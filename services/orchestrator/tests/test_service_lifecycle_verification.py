"""Verified service start with dependency ordering."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from shift_left.config import AppConfig, CURRENT_SCHEMA_VERSION
from shift_left.main import app
from shift_left.review.service import ReviewService
from shift_left.system.prerequisites import PrerequisiteCheck, PrerequisiteCriticality
from shift_left.system.services import ServiceLifecycleManager
from tests.test_phase3_hardening import FakeGit


def _check(
    check_id: str,
    *,
    ok: bool,
    error: str | None = None,
    affected_capability: str | None = None,
) -> PrerequisiteCheck:
    return PrerequisiteCheck(
        id=check_id,
        name=check_id,
        criticality=PrerequisiteCriticality.CRITICAL,
        ok=ok,
        status="ok" if ok else "failed",
        error=error,
        affected_capability=affected_capability,
    )


@pytest.fixture
def lifecycle_service(tmp_path, monkeypatch):
    db = tmp_path / "shift-left.db"
    cfg_path = tmp_path / "shift-left.yaml"
    cfg_path.write_text(
        f"""schema_version: {CURRENT_SCHEMA_VERSION}
orchestration: {{}}
orchestrator:
  host: 127.0.0.1
ui:
  enabled: true
  require_loopback_client: false
findings_store:
  sqlite_path: {db}
audit:
  sqlite_path: {db}
auth:
  sqlite_path: {db}
models:
  antares:
    enabled: false
  foundation_sec:
    enabled: false
git:
  backend: bundled-forgejo
rbac:
  allow_self_approval: false
"""
    )
    monkeypatch.setenv("SHIFT_LEFT_CONFIG", str(cfg_path))
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": True, "require_loopback_client": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo"},
            "rbac": {"allow_self_approval": False},
        }
    )
    service = ReviewService(config)
    fake_git = FakeGit()
    service._git = fake_git
    service.system_status._git = fake_git
    app.state.config = config
    app.state.review_service = service
    return service


def test_start_blocked_when_postgres_unhealthy(lifecycle_service) -> None:
    lifecycle = lifecycle_service.service_lifecycle

    async def fake_verify(check_id: str, *, topology: str | None = None):
        if check_id == "postgres":
            return _check("postgres", ok=False, error="connection refused", affected_capability="git hosting")
        return _check(check_id, ok=True)

    with patch.object(lifecycle_service.system_status._prerequisites, "verify_check", side_effect=fake_verify):
        with patch.object(lifecycle, "docker_control_available", return_value=True):
            assessment = asyncio.run(lifecycle.assess_start("forgejo"))
            assert assessment["blocking_dependencies"][0]["service"] == "postgres"
            with pytest.raises(ValueError, match="dependency postgres is unhealthy"):
                asyncio.run(lifecycle.run_action(service="forgejo", action="start", actor="admin"))


def test_start_all_stops_when_postgres_verification_fails(lifecycle_service) -> None:
    lifecycle = lifecycle_service.service_lifecycle
    started: list[str] = []

    async def fake_run_action(*, service, action, actor, skip_dependency_check=False, skip_verification=False):
        started.append(service)
        if service == "postgres":
            return {
                "outcome": "verification_timeout",
                "command_outcome": "ok",
                "verification_outcome": "verification_timeout",
                "detail": "timeout",
                "verification": {"outcome": "verification_timeout"},
            }
        raise AssertionError(f"should not start downstream {service}")

    with patch.object(lifecycle, "run_action", side_effect=fake_run_action):
        with patch.object(lifecycle, "docker_control_available", return_value=True):
            result = asyncio.run(
                lifecycle.start_all_prerequisites(actor="admin", include_degraded=False)
            )

    assert started == ["postgres"]
    assert result["outcome"] == "chain_stopped"
    assert result["failed_service"] == "postgres"
    assert result["failed_phase"] == "verification"


def test_start_all_runs_dependency_order(lifecycle_service) -> None:
    lifecycle = lifecycle_service.service_lifecycle
    started: list[str] = []

    async def fake_run_action(*, service, action, actor, skip_dependency_check=False, skip_verification=False):
        started.append(service)
        return {
            "outcome": "verified_healthy",
            "command_outcome": "ok",
            "verification_outcome": "verified_healthy",
            "detail": "ok",
            "verification": {"outcome": "verified_healthy"},
        }

    with patch.object(lifecycle, "run_action", side_effect=fake_run_action):
        with patch.object(lifecycle, "docker_control_available", return_value=True):
            result = asyncio.run(
                lifecycle.start_all_prerequisites(actor="admin", include_degraded=False)
            )

    assert started == ["postgres", "forgejo", "forgejo-runner"]
    assert result["outcome"] == "chain_complete"


def test_start_all_skips_detect_only_degraded_services(lifecycle_service) -> None:
    lifecycle = lifecycle_service.service_lifecycle
    # The recovery chain only includes Foundation-Sec when the model is enabled.
    lifecycle._config.models.foundation_sec.enabled = True
    started: list[str] = []

    async def fake_run_action(*, service, action, actor, skip_dependency_check=False, skip_verification=False):
        started.append(service)
        return {
            "outcome": "verified_healthy",
            "command_outcome": "ok",
            "verification_outcome": "verified_healthy",
            "detail": "ok",
            "verification": {"outcome": "verified_healthy"},
        }

    with patch.object(lifecycle, "run_action", side_effect=fake_run_action):
        with patch.object(lifecycle, "docker_control_available", return_value=True):
            with patch.object(
                lifecycle,
                "start_feasibility",
                side_effect=lambda service: (
                    {"feasibility": "detect_only", "note": "host-native"}
                    if service == "foundation-sec-server"
                    else {"feasibility": "start", "note": "compose"}
                ),
            ):
                result = asyncio.run(
                    lifecycle.start_all_prerequisites(actor="admin", include_degraded=True)
                )

    assert started == ["postgres", "forgejo", "forgejo-runner"]
    assert result["outcome"] == "chain_complete"
    assert result["skipped_services"] == ["foundation-sec-server"]


def test_verification_timeout_not_reported_as_success(lifecycle_service) -> None:
    lifecycle = lifecycle_service.service_lifecycle
    poll_calls = 0

    async def always_unhealthy(check_id: str, *, topology: str | None = None):
        nonlocal poll_calls
        poll_calls += 1
        return _check(check_id, ok=False, error="not ready")

    with patch.object(lifecycle, "docker_control_available", return_value=True):
        with patch.object(lifecycle_service.system_status._prerequisites, "verify_check", side_effect=always_unhealthy):
            with patch.object(lifecycle, "_dispatch_command", return_value=("ok", "started")):
                with patch("shift_left.system.services.readiness_timeout", return_value=0.05):
                    with patch("asyncio.sleep", new_callable=AsyncMock):
                        result = asyncio.run(
                            lifecycle.run_action(
                                service="postgres",
                                action="start",
                                actor="admin",
                                skip_dependency_check=True,
                            )
                        )

    assert result["command_outcome"] == "ok"
    assert result["outcome"] == "verification_timeout"
    assert result["verification_outcome"] == "verification_timeout"
    assert poll_calls >= 1


def test_audit_distinguishes_command_from_verified(lifecycle_service) -> None:
    lifecycle = lifecycle_service.service_lifecycle

    async def healthy_postgres(check_id: str, *, topology: str | None = None):
        return _check(check_id, ok=True)

    with patch.object(lifecycle, "docker_control_available", return_value=True):
        with patch.object(lifecycle_service.system_status._prerequisites, "verify_check", side_effect=healthy_postgres):
            with patch.object(lifecycle, "_dispatch_command", return_value=("ok", "started")):
                with patch("shift_left.system.services.readiness_timeout", return_value=5.0):
                    asyncio.run(
                        lifecycle.run_action(
                            service="postgres",
                            action="start",
                            actor="admin",
                            skip_dependency_check=True,
                        )
                    )

    events = lifecycle_service.audit.list_events(subject_prefix="postgres/start", limit=10)
    actions = [event.action for event in events]
    assert "service.lifecycle.command" in actions
    assert "service.lifecycle.verified" in actions
    verified = next(event for event in events if event.action == "service.lifecycle.verified")
    assert verified.details["command_outcome"] == "ok"
    assert verified.details["verification_outcome"] == "verified_healthy"


def test_readiness_polling_does_not_invoke_inference(lifecycle_service) -> None:
    lifecycle = lifecycle_service.service_lifecycle
    analyze_calls: list[str] = []

    async def fake_verify(check_id: str, *, topology: str | None = None):
        if check_id == "foundation_sec_server":
            return _check(check_id, ok=True)
        return _check(check_id, ok=True)

    async def blocked_analyze(*args, **kwargs):
        analyze_calls.append("analyze")
        raise AssertionError("analyze must not run during readiness poll")

    foundation = lifecycle_service.system_status._prerequisites._foundation_client
    if foundation is not None:
        foundation.analyze = blocked_analyze

    with patch.object(lifecycle, "topology", return_value="host-native"):
        with patch.object(lifecycle_service.system_status._prerequisites, "verify_check", side_effect=fake_verify):
            with patch.object(lifecycle, "_dispatch_command", return_value=("ok", "started")):
                with patch("shift_left.system.services.readiness_timeout", return_value=5.0):
                    result = asyncio.run(
                        lifecycle.run_action(
                            service="foundation-sec-server",
                            action="start",
                            actor="admin",
                            skip_dependency_check=True,
                        )
                    )

    assert analyze_calls == []
    assert result["verification_outcome"] == "verified_healthy"


def test_orchestrator_is_detect_only(lifecycle_service) -> None:
    lifecycle = lifecycle_service.service_lifecycle
    feasibility = lifecycle.start_feasibility("orchestrator")
    assert feasibility["feasibility"] == "detect_only"
    with pytest.raises(ValueError, match="Cannot restart orchestrator"):
        asyncio.run(lifecycle.run_action(service="orchestrator", action="restart", actor="admin"))


def test_host_native_model_supervised_when_orchestrator_on_host(lifecycle_service) -> None:
    from unittest.mock import MagicMock

    lifecycle = lifecycle_service.service_lifecycle
    mock_report = MagicMock()
    mock_report.model_hosting = "host-native-macos"
    mock_report.orchestrator_in_container = False
    with patch.object(lifecycle, "topology_report", return_value=mock_report):
        antares = lifecycle.start_feasibility("antares-server")
        assert antares["feasibility"] == "start"
        assert "./shift-left" in antares["note"]
        assert antares["control_mode"] == "supervised-host-native"


def test_dependency_graph_documents_chain() -> None:
    graph = ServiceLifecycleManager(
        config=AppConfig.model_validate({"orchestrator": {"host": "127.0.0.1"}}),
        audit=AsyncMock(),
    ).dependency_graph()
    assert graph["edges"]["forgejo"] == ["postgres"]
    assert graph["edges"]["forgejo-runner"] == ["postgres", "forgejo"]
    assert graph["critical_pipeline_chain"] == ["postgres", "forgejo", "forgejo-runner"]
