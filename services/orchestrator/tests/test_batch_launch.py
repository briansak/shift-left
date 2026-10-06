"""Batch investigation launch, queue interaction, and cancel."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from shift_left.investigations.batch_launch import (
    BatchLaunchRequest,
    _top25_cwe_rows,
    launch_investigation_batch,
    top25_cwes_for_languages,
)
from shift_left.profiler.profile import sort_batch_cwes
from shift_left.investigations.batch_lifecycle import cancel_investigation_batch
from shift_left.investigations.cancel_registry import InvestigationCancelRegistry
from shift_left.investigations.launch import LaunchRejectedError
from shift_left.investigations.schema import InvestigationState
from shift_left.investigations.store import InvestigationStore
from shift_left.triage.service import AntaresTriageService
from shift_left.review.service import ReviewService
from shift_left.config import AppConfig


def _base_config(tmp_path: Path, **overrides: object) -> AppConfig:
    db = tmp_path / "shift-left.db"
    payload = {
        "schema_version": 11,
        "orchestrator": {"host": "127.0.0.1"},
        "findings_store": {"sqlite_path": str(db)},
        "audit": {"sqlite_path": str(db)},
        "auth": {"sqlite_path": str(db)},
        "investigations": {
            "sqlite_path": str(tmp_path / "investigations.db"),
            "queue_depth_cap": 3,
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


def _init_git_repo(path: Path, files: dict[str, str]) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=path, check=True)
    for rel, content in files.items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, check=True)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


@pytest.fixture
def batch_env(tmp_path):
    config = _base_config(tmp_path)
    checkout = tmp_path / "repos" / "demo" / "app"
    _init_git_repo(
        checkout,
        {
            "requirements.txt": "sqlalchemy\n",
            "app/db.py": 'import sqlalchemy\nsql = f"SELECT {x}"\n',
        },
    )
    service = ReviewService(config)
    store = InvestigationStore(str(tmp_path / "investigations.db"), audit=service.audit)
    triage = AntaresTriageService(config, audit=service.audit)
    cancel_registry = InvestigationCancelRegistry()
    return config, store, triage, cancel_registry


@pytest.mark.asyncio
async def test_profiled_batch_creates_independent_investigations(batch_env) -> None:
    config, store, triage, _ = batch_env
    result = await launch_investigation_batch(
        config=config,
        store=store,
        triage=triage,
        actor="operator",
        request=BatchLaunchRequest(repo="demo/app", ref="main", source="profiled"),
        require_server_available=False,
    )
    assert result.batch.source == "profiled"
    assert len(result.investigation_ids) >= 1
    for inv_id in result.investigation_ids:
        record = store.get(inv_id)
        assert record is not None
        assert record.batch_id == result.batch.batch_id
        assert record.terminal_call_budget == 15


@pytest.mark.asyncio
async def test_batch_rejected_when_queue_cap_exceeded(batch_env) -> None:
    config, store, triage, _ = batch_env
    for _ in range(3):
        store.create_investigation(
            repo="demo/app",
            requested_ref="main",
            resolved_commit_sha="abc",
            task_cwe="CWE-843",
            actor="operator",
            model_variant="fdtn-ai/antares-1b",
        )
    with pytest.raises(LaunchRejectedError, match="cannot accept"):
        await launch_investigation_batch(
            config=config,
            store=store,
            triage=triage,
            actor="operator",
            request=BatchLaunchRequest(
                repo="demo/app",
                ref="main",
                source="custom",
                custom_cwes=("CWE-843", "CWE-89"),
                confirmed_large_batch=False,
            ),
            require_server_available=False,
        )


@pytest.mark.asyncio
async def test_custom_batch_requires_confirmation_above_ten(batch_env) -> None:
    from shift_left.cwe.localization_candidates import localization_candidate_entries

    config, store, triage, _ = batch_env
    cwes = tuple(str(entry["id"]) for entry in localization_candidate_entries()[:11])
    with pytest.raises(LaunchRejectedError, match="confirm"):
        await launch_investigation_batch(
            config=config,
            store=store,
            triage=triage,
            actor="operator",
            request=BatchLaunchRequest(
                repo="demo/app",
                ref="main",
                source="custom",
                custom_cwes=cwes,
                confirmed_large_batch=False,
            ),
            require_server_available=False,
        )


@pytest.mark.asyncio
async def test_batch_cancel_cancels_queued_children(batch_env) -> None:
    config, store, triage, cancel_registry = batch_env
    result = await launch_investigation_batch(
        config=config,
        store=store,
        triage=triage,
        actor="operator",
        request=BatchLaunchRequest(repo="demo/app", ref="main", source="profiled"),
        require_server_available=False,
    )
    await cancel_investigation_batch(
        store=store,
        triage=triage,
        cancel_registry=cancel_registry,
        batch_id=result.batch.batch_id,
        actor="operator",
    )
    for inv_id in result.investigation_ids:
        record = store.get(inv_id)
        assert record is not None
        assert record.state == InvestigationState.CANCELLED


def test_top25_filter_reports_survivors() -> None:
    survivors = top25_cwes_for_languages({"Python"})
    assert survivors
    assert all(entry.get("in_cwe_top_25") for entry in survivors)


def test_top25_rows_assign_profiler_tiers_and_language_only_fallback() -> None:
    rows, count = _top25_cwe_rows(
        {"Python"},
        {
            "suggestions": [
                {"cwe_id": "CWE-89", "relevance_tier": "direct"},
                {"cwe_id": "CWE-502", "relevance_tier": "indirect"},
            ]
        },
    )
    assert count == 10
    tier_by_cwe = {cwe_id: tier for cwe_id, tier, _tract in rows}
    assert tier_by_cwe["CWE-89"] == "direct"
    assert tier_by_cwe["CWE-502"] == "indirect"
    assert tier_by_cwe["CWE-190"] == "language-only"


def test_top25_sort_uses_top25_rank_after_tier_and_tractability() -> None:
    rows = sort_batch_cwes(
        [
            ("CWE-306", "language-only", "unrated"),
            ("CWE-79", "language-only", "unrated"),
        ]
    )
    assert [row[0] for row in rows] == ["CWE-79", "CWE-306"]


def test_top25_filter_honors_language_agnostic_for_python_repo() -> None:
    survivors = top25_cwes_for_languages({"Python"})
    ids = {str(entry["id"]) for entry in survivors}
    assert len(survivors) == 10
    assert "CWE-89" in ids
    assert "CWE-502" in ids


def test_top25_python_filter_yields_ten_without_confirmation_threshold() -> None:
    survivors = top25_cwes_for_languages({"Python"})
    assert len(survivors) == 10
    from shift_left.investigations.batch_constants import BATCH_CONFIRM_THRESHOLD

    assert len(survivors) <= BATCH_CONFIRM_THRESHOLD


@pytest.mark.asyncio
async def test_batch_enqueue_order_prefers_direct_evidence(batch_env) -> None:
    config, store, triage, _ = batch_env
    result = await launch_investigation_batch(
        config=config,
        store=store,
        triage=triage,
        actor="operator",
        request=BatchLaunchRequest(repo="demo/app", ref="main", source="profiled"),
        require_server_available=False,
    )
    queued = store.list_queued_fifo()
    batch_queued = [row for row in queued if row.batch_id == result.batch.batch_id]
    tiers = [row.profile_evidence_tier for row in batch_queued]
    assert tiers == sorted(tiers, key=lambda tier: {"direct": 0, "indirect": 1, "language-only": 2}.get(tier or "language-only", 9))


@pytest.mark.asyncio
async def test_preview_deselects_language_only_members(batch_env) -> None:
    from shift_left.investigations.batch_launch import preview_investigation_batch

    config, store, triage, _ = batch_env
    preview = await preview_investigation_batch(
        config=config,
        store=store,
        triage=triage,
        request=BatchLaunchRequest(repo="demo/app", ref="main", source="top25"),
    )
    assert preview.members
    language_only = [row for row in preview.members if row.evidence_tier == "language-only"]
    evidenced = [row for row in preview.members if row.evidence_tier != "language-only"]
    assert language_only
    assert all(not row.selected_by_default for row in language_only)
    assert evidenced
    assert all(row.selected_by_default for row in evidenced)
    assert preview.selected_count == len(evidenced)
    assert preview.estimated_wall_clock_seconds == preview.selected_count * 62
    assert preview.queue_depth_cap == 3
    assert any(row.top25_rank for row in preview.members)
    assert any(row.name for row in preview.members)


@pytest.mark.asyncio
async def test_launch_respects_selected_cwes_from_preview(batch_env) -> None:
    from shift_left.investigations.batch_launch import preview_investigation_batch

    config, store, triage, _ = batch_env
    preview = await preview_investigation_batch(
        config=config,
        store=store,
        triage=triage,
        request=BatchLaunchRequest(repo="demo/app", ref="main", source="top25"),
    )
    chosen = next(row.cwe_id for row in preview.members if row.selected_by_default)
    result = await launch_investigation_batch(
        config=config,
        store=store,
        triage=triage,
        actor="operator",
        request=BatchLaunchRequest(
            repo="demo/app",
            ref="main",
            source="top25",
            selected_cwes=(chosen,),
        ),
        require_server_available=False,
    )
    assert result.investigation_ids
    assert len(result.investigation_ids) == 1
    record = store.get(result.investigation_ids[0])
    assert record is not None
    assert record.task_cwe == chosen
    assert record.exclude_test_paths is True
    assert record.snapshot_scope == "full"
