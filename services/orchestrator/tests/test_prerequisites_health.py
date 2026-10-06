"""Prerequisite-based system health — criticality, functional checks, timeouts."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import AppConfig
from shift_left.main import app
from shift_left.review.service import ReviewService
from shift_left.system.prerequisites import (
    OverallSystemState,
    PrerequisiteCheck,
    PrerequisiteChecker,
    PrerequisiteCriticality,
    compute_overall_state,
)
from shift_left.triage.service import AntaresTriageService
from tests.test_phase3_hardening import FakeGit


def _check(
    check_id: str,
    *,
    criticality: PrerequisiteCriticality,
    ok: bool,
    status: str = "ok",
    error: str | None = None,
    depends_on: str | None = None,
    skipped_reason: str | None = None,
) -> PrerequisiteCheck:
    return PrerequisiteCheck(
        id=check_id,
        name=check_id,
        criticality=criticality,
        ok=ok,
        status=status,
        error=error,
        depends_on=depends_on,
        skipped_reason=skipped_reason,
        affected_capability="test-capability",
    )


def test_postgres_failure_yields_failed_and_skips_forgejo() -> None:
    checks = [
        _check("postgres", criticality=PrerequisiteCriticality.CRITICAL, ok=False, status="failed"),
        _check(
            "forgejo",
            criticality=PrerequisiteCriticality.CRITICAL,
            ok=False,
            status="skipped",
            skipped_reason="postgres_unavailable",
            depends_on="postgres",
        ),
    ]
    assert compute_overall_state(checks) == OverallSystemState.FAILED


def test_foundation_sec_failure_is_degraded_not_failed() -> None:
    checks = [
        _check("postgres", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
        _check(
            "foundation_sec_server",
            criticality=PrerequisiteCriticality.DEGRADED_CONFIG,
            ok=False,
            status="failed",
            error="unreachable",
        ),
    ]
    assert compute_overall_state(checks) == OverallSystemState.DEGRADED


def test_antares_advisory_failure_does_not_degrade() -> None:
    checks = [
        _check("postgres", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
        _check(
            "antares_server",
            criticality=PrerequisiteCriticality.ADVISORY,
            ok=False,
            status="advisory_failed",
        ),
    ]
    assert compute_overall_state(checks) == OverallSystemState.HEALTHY


@pytest.fixture
def prereq_client(tmp_path):
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": True, "require_loopback_client": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {
                "antares": {"enabled": False},
                "foundation_sec": {"enabled": True, "service_url": "http://127.0.0.1:8091"},
            },
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    service = ReviewService(config)
    fake_git = FakeGit()
    service._git = fake_git
    service.system_status._git = fake_git
    app.state.config = config
    app.state.review_service = service
    app.state.triage_service = AntaresTriageService(config)
    app.state.token_store = service.token_store
    client = TestClient(app)
    _, admin = mint_api_token(
        service.token_store,
        label="admin",
        actor="admin",
        capabilities=[TokenCapability.ADMIN],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, admin)
    return client, service, admin


@pytest.mark.asyncio
async def test_invalid_forgejo_token_critical(prereq_client) -> None:
    _, service, admin = prereq_client
    checker = service.system_status._prerequisites

    async def fake_run(topology: str):
        return [
            _check("postgres", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
            _check("forgejo", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
            _check(
                "forgejo_token",
                criticality=PrerequisiteCriticality.CRITICAL,
                ok=False,
                status="failed",
                error="FORGEJO_TOKEN rejected (HTTP 401).",
            ),
        ]

    with patch.object(checker, "_run_all_checks", side_effect=fake_run):
        report = await checker.build_report(force_refresh=True)
    assert report["overall_state"] == "failed"
    token = next(item for item in report["checks"] if item["id"] == "forgejo_token")
    assert "401" in (token.get("error") or "")


@pytest.mark.asyncio
async def test_offline_runner_detected(prereq_client) -> None:
    _, service, _ = prereq_client
    checker = service.system_status._prerequisites

    async def fake_run(topology: str):
        return [
            _check(
                "forgejo_runner",
                criticality=PrerequisiteCriticality.CRITICAL,
                ok=False,
                status="failed",
                error="Runner 'shift-left-runner' is offline",
            ),
        ]

    with patch.object(checker, "_run_all_checks", side_effect=fake_run):
        report = await checker.build_report(force_refresh=True)
    assert report["overall_state"] == "failed"


@pytest.mark.asyncio
async def test_runner_label_mismatch_detected(prereq_client) -> None:
    _, service, _ = prereq_client
    checker = service.system_status._prerequisites

    async def fake_run(topology: str):
        return [
            _check(
                "forgejo_runner",
                criticality=PrerequisiteCriticality.CRITICAL,
                ok=False,
                status="failed",
                error="Runner labels ['linux'] do not include workflow target 'self-hosted'",
            ),
        ]

    with patch.object(checker, "_run_all_checks", side_effect=fake_run):
        report = await checker.build_report(force_refresh=True)
    runner = report["checks"][0]
    assert "self-hosted" in runner["error"]


@pytest.mark.asyncio
async def test_sha256_mismatch_degraded_config(prereq_client) -> None:
    _, service, _ = prereq_client
    checker = service.system_status._prerequisites

    async def fake_run(topology: str):
        return [
            _check(
                "foundation_sec_weights",
                criticality=PrerequisiteCriticality.DEGRADED_CONFIG,
                ok=False,
                status="failed",
                error="SHA256 mismatch",
            ),
        ]

    with patch.object(checker, "_run_all_checks", side_effect=fake_run):
        report = await checker.build_report(force_refresh=True)
    assert report["overall_state"] == "degraded"


@pytest.mark.asyncio
async def test_unexpected_quant_degraded(prereq_client) -> None:
    _, service, _ = prereq_client
    checker = service.system_status._prerequisites

    async def fake_run(topology: str):
        return [
            _check(
                "foundation_sec_server",
                criticality=PrerequisiteCriticality.DEGRADED_CONFIG,
                ok=False,
                status="failed",
                error="Model server quant mismatch: running 'low-memory', configured 'default'.",
            ),
        ]

    with patch.object(checker, "_run_all_checks", side_effect=fake_run):
        report = await checker.build_report(force_refresh=True)
    assert report["overall_state"] == "degraded"


@pytest.mark.asyncio
async def test_health_checks_do_not_load_models(prereq_client) -> None:
    _, service, _ = prereq_client
    client_mock = service._foundation_sec
    assert client_mock is not None
    client_mock.health = AsyncMock(return_value={"status": "ok", "quant": "default", "loaded": False})
    analyze = AsyncMock()
    client_mock.analyze_hunks = analyze

    checker = PrerequisiteChecker(
        config=service._config,
        git=service._git,
        reference=service._reference,
        foundation_client=client_mock,
    )
    await checker._check_foundation_sec_server("host-native")
    client_mock.health.assert_awaited_once()
    analyze.assert_not_called()


@pytest.mark.asyncio
async def test_hung_check_times_out(prereq_client) -> None:
    _, service, _ = prereq_client
    checker = service.system_status._prerequisites

    async def slow_postgres():
        await asyncio.sleep(1.0)
        return _check("postgres", criticality=PrerequisiteCriticality.CRITICAL, ok=True)

    result = await checker._timed("postgres", slow_postgres, timeout=0.05)
    assert result.status == "timed_out"
    assert "timed out" in (result.error or "").lower()


def test_prerequisites_api_endpoint(prereq_client) -> None:
    client, service, admin = prereq_client
    mock_report = {
        "overall_state": "healthy",
        "checks": [],
        "groups": {key.value: [] for key in PrerequisiteCriticality},
        "summary": "ok",
        "affected_capabilities": [],
        "ready": True,
        "topology": "host-native",
        "report_generated_at": "2026-01-01T00:00:00+00:00",
        "cache": {"hit": False, "ttl_seconds": 30, "cached_at": "2026-01-01T00:00:00+00:00"},
        "derived_prerequisites": [],
        "consolidated_with": [],
    }
    with patch.object(service.system_status._prerequisites, "build_report", AsyncMock(return_value=mock_report)):
        response = client.get(
            "/api/v1/system/prerequisites?refresh=true",
            headers={"Authorization": f"Bearer {admin}"},
        )
    assert response.status_code == 200
