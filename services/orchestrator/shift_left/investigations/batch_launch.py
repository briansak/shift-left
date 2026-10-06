"""Batch investigation launch — independent investigations per CWE."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from shift_left.config import AppConfig
from shift_left.cwe.localization_candidates import (
    localization_candidate_by_id,
    localization_candidate_entries,
)
from shift_left.investigations.batch_constants import (
    MEDIAN_INVESTIGATION_SECONDS,
)
from shift_left.investigations.batch_schema import BatchSource, InvestigationBatchRecord
import tempfile

from shift_left.investigations.git_checkout import (
    GitCheckoutError,
    estimate_launch_snapshot_bytes,
    materialize_worktree_at_sha,
    remove_worktree,
    resolve_ref_to_sha,
)
from shift_left.investigations.launch import LaunchRejectedError, ensure_queue_capacity
from shift_left.investigations.preflight import (
    check_antares_server_available,
    minimum_variant_message,
    variant_below_minimum,
)
from shift_left.investigations.store import InvestigationStore
from shift_left.investigations.suitability import normalize_task_cwe
from shift_left.profiler.profile import (
    load_top25_ranks,
    profiler_tier_by_cwe,
    profile_repository,
    sort_batch_cwes,
)
from shift_left.triage.service import AntaresTriageService
from shift_left.ui.cwe_dictionary import normalize_cwe_id
from shift_left.models.schema import utc_now


@dataclass(frozen=True)
class BatchLaunchRequest:
    repo: str
    ref: str
    source: BatchSource
    custom_cwes: tuple[str, ...] = ()
    selected_cwes: tuple[str, ...] | None = None
    confirmed_large_batch: bool = False
    exclude_test_paths: bool = True
    snapshot_scope: str = "full"
    snapshot_base_ref: str = "main"


@dataclass(frozen=True)
class BatchLaunchResult:
    batch: InvestigationBatchRecord
    investigation_ids: tuple[str, ...]
    estimated_wall_clock_seconds: int
    top25_survivor_count: int | None = None
    snapshot_bytes: int = 0


@dataclass(frozen=True)
class BatchMemberPreview:
    cwe_id: str
    name: str
    evidence_tier: str
    tractability: str
    top25_rank: int | None
    selected_by_default: bool


@dataclass(frozen=True)
class BatchPreviewResult:
    members: tuple[BatchMemberPreview, ...]
    snapshot_bytes: int
    snapshot_scope: str
    commit_sha: str
    top25_survivor_count: int | None
    queue_depth: int
    queue_depth_cap: int
    estimated_wall_clock_seconds: int
    selected_count: int


def _load_top25_ids() -> frozenset[str]:
    from shift_left.config import resolve_repo_root

    path = resolve_repo_root() / "data" / "cwe" / "cwe-top-25-2024.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return frozenset(normalize_cwe_id(entry["id"]) for entry in payload.get("entries", []))


def top25_cwes_for_languages(languages: set[str]) -> list[dict[str, Any]]:
    """Top 25 Base/Variant entries matching repo languages (picker-aligned filter)."""
    top25 = _load_top25_ids()
    survivors: list[dict[str, Any]] = []
    for entry in localization_candidate_entries():
        cwe_id = normalize_cwe_id(str(entry.get("id") or ""))
        if cwe_id not in top25:
            continue
        applicable = {str(lang) for lang in (entry.get("applicable_languages") or [])}
        if not applicable:
            continue
        if "Not Language-Specific" in applicable:
            survivors.append(entry)
            continue
        if languages and (applicable & languages):
            survivors.append(entry)
    survivors.sort(key=lambda item: str(item.get("id")))
    return survivors


def _profiled_cwe_rows(profile_snapshot: dict[str, Any]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for item in profile_snapshot.get("suggestions", []):
        cwe_id = normalize_cwe_id(str(item.get("cwe_id") or ""))
        rows.append(
            (
                cwe_id,
                str(item.get("relevance_tier") or "language-only"),
                str(item.get("tractability") or "unrated"),
            )
        )
    return rows


def _custom_cwe_rows(custom_cwes: tuple[str, ...]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for raw in custom_cwes:
        cwe_id = normalize_task_cwe(raw)
        entry = localization_candidate_by_id(cwe_id)
        if entry is None:
            raise LaunchRejectedError(f"{cwe_id} is not in the localization candidate catalog")
        rows.append(
            (
                cwe_id,
                "none",
                str(entry.get("tractability") or "unrated"),
            )
        )
    return rows


def _top25_cwe_rows(
    languages: set[str],
    profile_snapshot: dict[str, Any],
) -> tuple[list[tuple[str, str, str]], int]:
    survivors = top25_cwes_for_languages(languages)
    tier_by_cwe = profiler_tier_by_cwe(profile_snapshot)
    rows = [
        (
            normalize_cwe_id(str(entry.get("id") or "")),
            tier_by_cwe.get(
                normalize_cwe_id(str(entry.get("id") or "")),
                "language-only",
            ),
            str(entry.get("tractability") or "unrated"),
        )
        for entry in survivors
    ]
    return rows, len(survivors)


def _member_previews(cwe_rows: list[tuple[str, str, str]]) -> list[BatchMemberPreview]:
    ranks = load_top25_ranks()
    members: list[BatchMemberPreview] = []
    for cwe_id, evidence_tier, tractability in sort_batch_cwes(cwe_rows):
        entry = localization_candidate_by_id(cwe_id)
        name = str((entry or {}).get("name") or (entry or {}).get("short_description") or "")
        tier = evidence_tier or "none"
        members.append(
            BatchMemberPreview(
                cwe_id=cwe_id,
                name=name,
                evidence_tier=tier,
                tractability=tractability or "unrated",
                top25_rank=ranks.get(cwe_id),
                selected_by_default=tier != "language-only",
            )
        )
    return members


def _filter_selected_rows(
    cwe_rows: list[tuple[str, str, str]],
    selected_cwes: tuple[str, ...] | None,
) -> list[tuple[str, str, str]]:
    if selected_cwes is None:
        return cwe_rows
    selected = {normalize_task_cwe(item) for item in selected_cwes if item.strip()}
    if not selected:
        raise LaunchRejectedError("Select at least one CWE before launching the batch.")
    known = {row[0] for row in cwe_rows}
    unknown = sorted(selected - known)
    if unknown:
        raise LaunchRejectedError(
            "Selected CWE(s) are not in the resolved batch: " + ", ".join(unknown)
        )
    return [row for row in cwe_rows if row[0] in selected]


def _resolve_cwe_rows_for_source(
    *,
    source: BatchSource,
    custom_cwes: tuple[str, ...],
    checkout: Path,
    commit_sha: str,
) -> tuple[list[tuple[str, str, str]], dict[str, Any], int | None]:
    profile_snapshot: dict[str, Any] = {}
    top25_survivor_count: int | None = None
    if source == "profiled":
        worktree = Path(tempfile.mkdtemp(prefix="batch-profile-"))
        try:
            try:
                materialize_worktree_at_sha(checkout, commit_sha, worktree)
            except GitCheckoutError as exc:
                raise LaunchRejectedError(str(exc)) from exc
            profile = profile_repository(worktree)
            profile_snapshot = profile.to_snapshot()
            cwe_rows = _profiled_cwe_rows(profile_snapshot)
        finally:
            remove_worktree(checkout, worktree)
        if not cwe_rows:
            raise LaunchRejectedError(
                "Repository profile yielded no CWE suggestions with direct or indirect evidence. "
                "Try Top 25 or custom selection."
            )
        return cwe_rows, profile_snapshot, None
    if source == "top25":
        worktree = Path(tempfile.mkdtemp(prefix="batch-profile-"))
        try:
            try:
                materialize_worktree_at_sha(checkout, commit_sha, worktree)
            except GitCheckoutError as exc:
                raise LaunchRejectedError(str(exc)) from exc
            profile = profile_repository(worktree)
            profile_snapshot = profile.to_snapshot()
            languages = set(profile.languages)
        finally:
            remove_worktree(checkout, worktree)
        cwe_rows, top25_survivor_count = _top25_cwe_rows(languages, profile_snapshot)
        if not cwe_rows:
            raise LaunchRejectedError(
                "No CWE Top 25 entries survive Base/Variant and language filtering for this repo."
            )
        return cwe_rows, profile_snapshot, top25_survivor_count
    if source == "custom":
        if not custom_cwes:
            raise LaunchRejectedError("Select at least one CWE from the catalog for a custom batch.")
        return _custom_cwe_rows(custom_cwes), {}, None
    raise LaunchRejectedError(f"Unknown batch source: {source!r}")


def _prepare_batch_resolution(
    *,
    config: AppConfig,
    triage: AntaresTriageService,
    request: BatchLaunchRequest,
) -> tuple[Path, str, int, list[tuple[str, str, str]], dict[str, Any], int | None]:
    checkout = triage.checkout_path(request.repo)
    if not checkout.is_dir():
        raise LaunchRejectedError(
            f"Repo {request.repo!r} has no local checkout at {checkout}. "
            "Maintain a checkout under repos_checkout_dir before launching."
        )
    try:
        commit_sha = resolve_ref_to_sha(checkout, request.ref)
    except GitCheckoutError as exc:
        raise LaunchRejectedError(str(exc)) from exc
    try:
        snapshot_bytes, _paths = estimate_launch_snapshot_bytes(
            checkout,
            commit_sha,
            snapshot_scope=request.snapshot_scope or "full",
            base_ref=request.snapshot_base_ref or "main",
        )
    except GitCheckoutError as exc:
        raise LaunchRejectedError(str(exc)) from exc
    cwe_rows, profile_snapshot, top25_survivor_count = _resolve_cwe_rows_for_source(
        source=request.source,
        custom_cwes=request.custom_cwes,
        checkout=checkout,
        commit_sha=commit_sha,
    )
    return checkout, commit_sha, snapshot_bytes, cwe_rows, profile_snapshot, top25_survivor_count


async def preview_investigation_batch(
    *,
    config: AppConfig,
    store: InvestigationStore,
    triage: AntaresTriageService,
    request: BatchLaunchRequest,
) -> BatchPreviewResult:
    if request.source == "custom" and not tuple(cwe.strip() for cwe in request.custom_cwes if cwe.strip()):
        raise LaunchRejectedError("Select at least one CWE from the catalog for a custom batch.")
    _, commit_sha, snapshot_bytes, cwe_rows, _snapshot, top25_survivor_count = (
        _prepare_batch_resolution(config=config, triage=triage, request=request)
    )
    members = _member_previews(cwe_rows)
    if request.selected_cwes is not None:
        selected = {normalize_task_cwe(item) for item in request.selected_cwes if item.strip()}
        members = [
            BatchMemberPreview(
                cwe_id=member.cwe_id,
                name=member.name,
                evidence_tier=member.evidence_tier,
                tractability=member.tractability,
                top25_rank=member.top25_rank,
                selected_by_default=member.cwe_id in selected,
            )
            for member in members
        ]
    selected_count = sum(1 for member in members if member.selected_by_default)
    return BatchPreviewResult(
        members=tuple(members),
        snapshot_bytes=snapshot_bytes,
        snapshot_scope=request.snapshot_scope or "full",
        commit_sha=commit_sha,
        top25_survivor_count=top25_survivor_count,
        queue_depth=store.count_queued(),
        queue_depth_cap=config.investigations.queue_depth_cap,
        estimated_wall_clock_seconds=selected_count * MEDIAN_INVESTIGATION_SECONDS,
        selected_count=selected_count,
    )


async def launch_investigation_batch(
    *,
    config: AppConfig,
    store: InvestigationStore,
    triage: AntaresTriageService,
    actor: str,
    request: BatchLaunchRequest,
    require_server_available: bool = True,
) -> BatchLaunchResult:
    if not config.antares_triage.enabled:
        raise LaunchRejectedError("Antares triage is disabled in configuration")

    if request.source == "custom" and not tuple(cwe.strip() for cwe in request.custom_cwes if cwe.strip()):
        raise LaunchRejectedError("Select at least one CWE from the catalog for a custom batch.")

    if variant_below_minimum(config):
        raise LaunchRejectedError(minimum_variant_message(config))

    if require_server_available and not await check_antares_server_available(triage._client):
        raise LaunchRejectedError(
            "antares-server is unavailable — install or start it from System before launching"
        )

    _checkout, commit_sha, snapshot_bytes, cwe_rows, profile_snapshot, top25_survivor_count = (
        _prepare_batch_resolution(config=config, triage=triage, request=request)
    )
    cwe_rows = _filter_selected_rows(cwe_rows, request.selected_cwes)

    if len(cwe_rows) > config.investigations.batch.size_cap:
        raise LaunchRejectedError(
            f"Batch size {len(cwe_rows)} exceeds the recommended cap of "
            f"{config.investigations.batch.size_cap}. "
            "Narrow scope with the profiler or custom selection."
        )

    if len(cwe_rows) > config.investigations.batch.confirm_threshold and not request.confirmed_large_batch:
        raise LaunchRejectedError(
            f"Batch has {len(cwe_rows)} investigations — confirm to proceed "
            f"(estimated ~{len(cwe_rows) * MEDIAN_INVESTIGATION_SECONDS // 60} min sequential)."
        )

    ensure_queue_capacity(store, config, additional=len(cwe_rows))

    sorted_rows = sort_batch_cwes(cwe_rows)
    agent_cfg = config.models.antares.agent
    base_time = utc_now()
    investigation_ids: list[str] = []
    child_meta: list[tuple[str, str, str, int]] = []
    snapshot_scope = request.snapshot_scope or "full"
    snapshot_base_ref = request.snapshot_base_ref or "main"

    for sort_order, (cwe_id, evidence_tier, tractability) in enumerate(sorted_rows):
        entry = localization_candidate_by_id(cwe_id)
        description = str(entry.get("short_description") or "") if entry else None
        created_at = base_time + timedelta(microseconds=sort_order)
        record = store.create_investigation(
            repo=request.repo.strip(),
            requested_ref=request.ref.strip(),
            resolved_commit_sha=commit_sha,
            task_cwe=cwe_id,
            task_cwe_description=description,
            actor=actor.strip(),
            model_variant=config.antares_triage.model_variant,
            terminal_call_budget=agent_cfg.max_terminal_calls or 15,
            snapshot_bytes=snapshot_bytes,
            created_at=created_at,
            batch_sort_order=sort_order,
            profile_evidence_tier=evidence_tier,
            exclude_test_paths=request.exclude_test_paths,
            snapshot_scope=snapshot_scope,
            snapshot_base_ref=snapshot_base_ref,
        )
        investigation_ids.append(record.investigation_id)
        child_meta.append((record.investigation_id, cwe_id, evidence_tier, sort_order))

    batch = store.create_batch(
        source=request.source,
        repo=request.repo.strip(),
        requested_ref=request.ref.strip(),
        resolved_commit_sha=commit_sha,
        actor=actor.strip(),
        profile_snapshot=profile_snapshot,
        top25_survivor_count=top25_survivor_count,
        children=child_meta,
    )

    return BatchLaunchResult(
        batch=batch,
        investigation_ids=tuple(investigation_ids),
        estimated_wall_clock_seconds=len(investigation_ids) * MEDIAN_INVESTIGATION_SECONDS,
        top25_survivor_count=top25_survivor_count,
        snapshot_bytes=snapshot_bytes,
    )
