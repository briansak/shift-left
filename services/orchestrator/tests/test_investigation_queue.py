"""Investigation queue, launch, runner, cancel, and re-run contracts."""

from __future__ import annotations

import asyncio
import os
import subprocess
import threading
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from shift_left.antares.localization import TriageQueryPayload
from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import AppConfig
from shift_left.investigations.cancel_registry import InvestigationCancelRegistry
from shift_left.investigations.launch import LaunchRejectedError, LaunchRequest, launch_investigation
from shift_left.investigations.lifecycle import LifecycleRejectedError, cancel_investigation, rerun_investigation
from shift_left.investigations.runner import InvestigationQueueRunner
from shift_left.investigations.schema import InvestigationState
from shift_left.investigations.store import InvestigationStore
from shift_left.main import app
from shift_left.models.database import AuditStore
from shift_left.models.schema import RankedFileCandidate, utc_now
from shift_left.review.service import ReviewService
from shift_left.triage.service import AntaresTriageService


def _base_config(tmp_path: Path, **overrides: object) -> AppConfig:
    db = tmp_path / "shift-left.db"
    inv_db = tmp_path / "investigations.db"
    payload = {
        "schema_version": 11,
        "orchestrator": {"host": "127.0.0.1"},
        "ui": {"enabled": True, "require_loopback_client": False},
        "findings_store": {"sqlite_path": str(db)},
        "audit": {"sqlite_path": str(db)},
        "auth": {"sqlite_path": str(db)},
        "investigations": {
            "sqlite_path": str(inv_db),
            "queue_depth_cap": 2,
            "queue_wait_timeout_minutes": 15,
        },
        "models": {
            "antares": {"enabled": False, "service_url": "http://127.0.0.1:18090"},
            "foundation_sec": {"enabled": False},
        },
        "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        "antares_triage": {"enabled": True, "repos_checkout_dir": str(tmp_path / "repos")},
        "reference_data": {"cache_dir": str(tmp_path / "reference")},
    }
    payload.update(overrides)
    return AppConfig.model_validate(payload)


def _init_git_repo(path: Path, *, files: dict[str, str] | None = None) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=path, check=True)
    for rel, content in (files or {"app/db.py": 'cursor.execute(f"SELECT {x}")'}).items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, check=True)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
    return sha


@pytest.fixture
def queue_env(tmp_path):
    config = _base_config(tmp_path)
    checkout_root = tmp_path / "repos" / "demo" / "app"
    head_sha = _init_git_repo(checkout_root)
    service = ReviewService(config)
    audit = service.audit
    store = InvestigationStore(str(tmp_path / "investigations.db"), audit=audit)
    triage = AntaresTriageService(config, audit=audit)
    cancel_registry = InvestigationCancelRegistry()
    runner = InvestigationQueueRunner(
        config=config,
        store=store,
        triage=triage,
        audit=audit,
        cancel_registry=cancel_registry,
        audit_callback_tokens=type("T", (), {"issue": lambda self: "slat_test"})(),
        poll_interval_seconds=0.05,
    )
    return config, store, triage, cancel_registry, runner, checkout_root, head_sha, service


def _mint(service: ReviewService, *, capabilities: list[TokenCapability]) -> str:
    _, token = mint_api_token(
        service.token_store,
        label="queue-test",
        actor="operator",
        capabilities=capabilities,
    )
    return token


@pytest.mark.asyncio
async def test_launch_rejected_without_checkout(queue_env) -> None:
    config, store, triage, *_ = queue_env
    with pytest.raises(LaunchRejectedError, match="no local checkout"):
        await launch_investigation(
            config=config,
            store=store,
            triage=triage,
            actor="operator",
            request=LaunchRequest(repo="missing/repo", ref="main", task_cwe="CWE-843"),
            require_server_available=False,
        )


@pytest.mark.asyncio
async def test_launch_rejected_unresolvable_ref(queue_env) -> None:
    config, store, triage, *_ = queue_env
    with pytest.raises(LaunchRejectedError, match="does not resolve"):
        await launch_investigation(
            config=config,
            store=store,
            triage=triage,
            actor="operator",
            request=LaunchRequest(repo="demo/app", ref="not-a-ref", task_cwe="CWE-843"),
            require_server_available=False,
        )


@pytest.mark.asyncio
async def test_launch_rejected_missing_cwe(queue_env) -> None:
    config, store, triage, *_ = queue_env
    with pytest.raises(LaunchRejectedError, match="task_cwe is required"):
        await launch_investigation(
            config=config,
            store=store,
            triage=triage,
            actor="operator",
            request=LaunchRequest(repo="demo/app", ref="main"),
            require_server_available=False,
        )


@pytest.mark.asyncio
async def test_launch_rejected_queue_depth_cap(queue_env) -> None:
    config, store, triage, _, _, _, head_sha, _ = queue_env
    for _ in range(2):
        store.create_investigation(
            repo="demo/app",
            requested_ref="main",
            resolved_commit_sha=head_sha,
            task_cwe="CWE-843",
            actor="operator",
            model_variant="fdtn-ai/antares-1b",
        )
    with pytest.raises(LaunchRejectedError, match="cannot accept"):
        await launch_investigation(
            config=config,
            store=store,
            triage=triage,
            actor="operator",
            request=LaunchRequest(repo="demo/app", ref="main", task_cwe="CWE-843"),
            require_server_available=False,
        )


@pytest.mark.asyncio
async def test_launch_rejected_server_unavailable(queue_env) -> None:
    config, store, triage, *_ = queue_env
    with patch.object(triage._client, "health", AsyncMock(side_effect=RuntimeError("down"))):
        with pytest.raises(LaunchRejectedError, match="antares-server is unavailable"):
            await launch_investigation(
                config=config,
                store=store,
                triage=triage,
                actor="operator",
                request=LaunchRequest(repo="demo/app", ref="main", task_cwe="CWE-843"),
                require_server_available=True,
            )


@pytest.mark.asyncio
async def test_launch_rejected_variant_below_minimum(queue_env) -> None:
    config, store, triage, *_ = queue_env
    config.antares_triage.model_variant = "fdtn-ai/antares-350m"
    with pytest.raises(LaunchRejectedError, match="below the minimum"):
        await launch_investigation(
            config=config,
            store=store,
            triage=triage,
            actor="operator",
            request=LaunchRequest(repo="demo/app", ref="main", task_cwe="CWE-843"),
            require_server_available=False,
        )


@pytest.mark.asyncio
async def test_cve_resolution_fails_closed_without_network(queue_env, tmp_path) -> None:
    config, store, triage, *_ = queue_env
    cache = tmp_path / "reference" / "cve"
    cache.mkdir(parents=True)
    with pytest.raises(LaunchRejectedError, match="not present in local reference cache"):
        await launch_investigation(
            config=config,
            store=store,
            triage=triage,
            actor="operator",
            request=LaunchRequest(
                repo="demo/app",
                ref="main",
                advisory_cve="CVE-2099-0001",
            ),
            require_server_available=False,
        )


def test_fifo_claim_order(queue_env) -> None:
    _, store, _, _, _, _, head_sha, _ = queue_env
    first = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    second = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-89",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    third = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-798",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    claimed = [store.claim_next_queued("runner-a").investigation_id for _ in range(3)]
    assert claimed == [first, second, third]


def test_claim_prevents_double_execution(queue_env) -> None:
    _, store, _, _, _, _, head_sha, _ = queue_env
    store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    )
    results: list[str | None] = []

    def claim() -> None:
        claimed = store.claim_next_queued("runner-parallel")
        results.append(claimed.investigation_id if claimed else None)

    threads = [threading.Thread(target=claim) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(None) == 3
    assert len({item for item in results if item}) == 1


@pytest.mark.asyncio
async def test_queue_wait_timeout_fails_queued_investigation(queue_env) -> None:
    config, store, _, _, runner, _, head_sha, _ = queue_env
    config.investigations.queue_wait_timeout_minutes = 0
    inv_id = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    store.set_queue_waiting(inv_id, reason="Waiting for antares-server")
    old = utc_now() - timedelta(minutes=1)
    with store._engine.connect() as conn:  # noqa: SLF001
        conn.exec_driver_sql(
            "UPDATE investigations SET queued_waiting_since = ? WHERE investigation_id = ?",
            (old.isoformat(), inv_id),
        )
        conn.commit()
    await runner._apply_queue_wait_timeouts()
    record = store.get(inv_id)
    assert record is not None
    assert record.state == InvestigationState.FAILED
    assert record.outcome_reason == "antares-server unavailable"


def test_restart_reaps_running_and_retains_trace(queue_env) -> None:
    _, store, _, _, _, _, head_sha, _ = queue_env
    inv_id = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.append_trace_turn(
        inv_id,
        turn_index=0,
        command="grep token app.py",
        exit_status=0,
        output_truncated="ok",
    )
    reaped = store.reap_orphaned_running()
    assert inv_id in reaped
    record = store.get(inv_id, include_children=True)
    assert record is not None
    assert record.state == InvestigationState.FAILED
    assert record.outcome_reason == "orchestrator restarted during execution"
    assert len(record.trace_turns) == 1


@pytest.mark.asyncio
async def test_cancel_from_running_records_turn(queue_env) -> None:
    _, store, triage, cancel_registry, _, _, head_sha, _ = queue_env
    inv_id = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    cancel_registry.register(inv_id)
    with patch.object(triage._client, "cancel_investigation", AsyncMock()):
        record = await cancel_investigation(
            store=store,
            triage=triage,
            cancel_registry=cancel_registry,
            investigation_id=inv_id,
            actor="operator",
        )
    assert record.state == InvestigationState.CANCELLED
    trace = store.get(inv_id, include_children=True)
    assert trace is not None
    assert len(trace.trace_turns) == 1
    from shift_left.investigations.trace_markers import (
        CANCELLATION_MARKER_COMMAND,
        CANCELLATION_MARKER_EXIT_STATUS,
        CANCELLATION_MARKER_OUTPUT,
    )

    assert trace.trace_turns[0].command == CANCELLATION_MARKER_COMMAND
    assert trace.trace_turns[0].exit_status == CANCELLATION_MARKER_EXIT_STATUS
    assert trace.trace_turns[0].output_truncated == CANCELLATION_MARKER_OUTPUT


@pytest.mark.asyncio
async def test_cancel_illegal_from_terminal(queue_env) -> None:
    _, store, triage, cancel_registry, _, _, head_sha, _ = queue_env
    inv_id = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.transition_state(inv_id, InvestigationState.COMPLETED, actor="operator")
    with pytest.raises(LifecycleRejectedError):
        await cancel_investigation(
            store=store,
            triage=triage,
            cancel_registry=cancel_registry,
            investigation_id=inv_id,
            actor="operator",
        )


@pytest.mark.asyncio
async def test_rerun_creates_new_id_and_leaves_original(queue_env) -> None:
    config, store, triage, _, _, checkout_root, head_sha, _ = queue_env
    original = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    )
    store.transition_state(original.investigation_id, InvestigationState.RUNNING, actor="operator")
    store.transition_state(original.investigation_id, InvestigationState.COMPLETED, actor="operator")
    subprocess.run(["git", "commit", "--allow-empty", "-m", "advance"], cwd=checkout_root, check=True)
    new_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout_root, text=True).strip()
    with patch.object(triage._client, "health", AsyncMock(return_value={"status": "ok"})):
        rerun = await rerun_investigation(
            config=config,
            store=store,
            triage=triage,
            investigation_id=original.investigation_id,
            actor="operator",
        )
    assert rerun.investigation_id != original.investigation_id
    assert rerun.originating_investigation_id == original.investigation_id
    assert rerun.resolved_commit_sha == new_sha
    untouched = store.get(original.investigation_id)
    assert untouched is not None
    assert untouched.state == InvestigationState.COMPLETED
    assert untouched.resolved_commit_sha == head_sha


def test_completed_no_files_via_runner_finalize(queue_env) -> None:
    _, store, _, _, runner, _, head_sha, _ = queue_env
    inv_id = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-401",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    from shift_left.analysis.result import completed_no_findings
    from shift_left.models.schema import TargetKind

    payload = TriageQueryPayload(
        outcome="completed_no_files",
        exploration_trace="",
        turn_count=2,
        ranked_files=[],
    )
    runner._finalize_from_result(inv_id, completed_no_findings(TargetKind.CODE), payload)
    record = store.get(inv_id)
    assert record is not None
    assert record.state == InvestigationState.COMPLETED_NO_FILES
    assert record.outcome_reason == "submit_no_vulnerability_found"


def test_session_without_triage_rejected_on_launch_cancel_rerun(tmp_path) -> None:
    config = _base_config(tmp_path)
    service = ReviewService(config)
    store = InvestigationStore(str(tmp_path / "investigations.db"), audit=service.audit)
    app.state.config = config
    app.state.review_service = service
    app.state.investigation_store = store
    app.state.triage_service = AntaresTriageService(config)
    app.state.token_store = service.token_store
    app.state.investigation_cancel_registry = InvestigationCancelRegistry()
    token = _mint(service, capabilities=[TokenCapability.REVIEW])
    client = TestClient(app)
    client.cookies.set(TOKEN_COOKIE_NAME, token)
    launch = client.post(
        "/api/v1/investigations",
        json={"repo": "demo/app", "ref": "main", "task_cwe": "CWE-843"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert launch.status_code == 403
    inv_id = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha="abc",
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    cancel = client.post(f"/api/v1/investigations/{inv_id}/cancel")
    assert cancel.status_code == 403
    rerun = client.post(f"/api/v1/investigations/{inv_id}/rerun")
    assert rerun.status_code == 403


@pytest.mark.asyncio
async def test_runner_end_to_end_with_scripted_antares_response(queue_env) -> None:
    """Orchestrator path: pinned worktree + mocked scripted Antares payload."""
    from shift_left.analysis.result import completed_no_findings
    from shift_left.models.schema import TargetKind

    _, store, triage, _, runner, _, head_sha, _ = queue_env
    inv_id = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha=head_sha,
        task_cwe="CWE-89",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    store.claim_next_queued("e2e-runner")
    payload = TriageQueryPayload(
        outcome="completed_with_files",
        exploration_trace="scripted",
        turn_count=2,
        ranked_files=[RankedFileCandidate(path="app/db.py", rank=1)],
    )

    async def fake_run(**kwargs):
        return completed_no_findings(TargetKind.CODE), payload

    with patch.object(runner, "_run_antares", side_effect=fake_run):
        await asyncio.to_thread(runner._execute_investigation, inv_id)
    record = store.get(inv_id, include_children=True)
    assert record is not None
    assert record.state == InvestigationState.COMPLETED
    assert record.candidates and record.candidates[0].file_path == "app/db.py"
