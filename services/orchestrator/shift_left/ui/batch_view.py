"""Batch investigation presentation — grouped by CWE, not merged findings."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from shift_left.investigations.batch_constants import (
    BATCH_CONFIRM_THRESHOLD,
    BATCH_SIZE_CAP,
    BENCHMARK_MEAN_PRECISION,
    BENCHMARK_NOTE,
    BENCHMARK_P_AT_1,
    MEDIAN_INVESTIGATION_SECONDS,
)
from shift_left.investigations.batch_schema import BatchChildRecord, BatchState, InvestigationBatchRecord
from shift_left.investigations.schema import InvestigationRecord, InvestigationState
from shift_left.investigations.store import InvestigationStore
from shift_left.ui.investigation_view import investigation_state_pill_class, short_sha


@dataclass(frozen=True)
class BatchChildView:
    investigation_id: str
    task_cwe: str
    state: InvestigationState
    state_pill_class: str
    tractability: str
    evidence_tier: str
    no_repo_evidence: bool
    candidates_without_evidence_basis: bool
    candidate_count: int
    candidates: tuple[str, ...]
    detail_href: str


@dataclass(frozen=True)
class InvestigationBatchView:
    batch_id: str
    source: str
    repo_ref_label: str
    short_sha: str
    state: BatchState
    state_pill_class: str
    child_count: int
    estimated_wall_clock_label: str
    benchmark_precision_label: str
    benchmark_p_at_1_label: str
    benchmark_note: str
    top25_survivor_count: int | None
    scope_rationale: str
    total_candidate_count: int
    false_positive_framing: str
    children: tuple[BatchChildView, ...]
    can_cancel: bool
    created_at_label: str


def _format_timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _scope_rationale(batch: InvestigationBatchRecord) -> str:
    if batch.source == "profiled":
        return (
            "Profiled batch (narrower) — one investigation per CWE with direct or indirect "
            "profiler evidence only. Top 25 members without a surface mapping are excluded. "
            "Each run has its own 15-call budget."
        )
    if batch.source == "top25":
        count = batch.top25_survivor_count
        return (
            f"Top 25 batch — {count} CWE(s) survive Base/Variant and language filtering. "
            "Profiler evidence sets each member's tier (direct, indirect, or language-only); "
            "language-only rows had no mapped surface evidence in this repo."
        )
    return (
        "Custom batch — operator-selected CWEs from the localization catalog. "
        "Each CWE is an independent investigation."
    )


def _vloc_rationale() -> str:
    return (
        "Full-catalog or VLoc Bench 147 sweeps are not offered: at ~62s median per "
        "investigation, 147 sequential runs is ~2.5 hours, and most would target weakness "
        "classes with no evidence in this repo. VLoc's 147 is benchmark coverage across "
        "290 repositories, not per-repo scope."
    )


def build_batch_launch_notice() -> str:
    return _vloc_rationale()


def _false_positive_framing(total_candidates: int) -> str:
    return (
        f"{total_candidates} candidate file(s) across this batch. "
        "Only CWEs with direct or indirect profiler evidence have repository basis for localization. "
        "Candidates from language-only members have no mapped surface evidence tying this repo to "
        "that weakness class — treat them as ungrounded for the class, not merely unconfirmed."
    )


def build_batch_confirm_message(
    count: int,
    *,
    confirm_threshold: int = BATCH_CONFIRM_THRESHOLD,
    size_cap: int = BATCH_SIZE_CAP,
) -> str | None:
    if count <= confirm_threshold:
        return None
    minutes = (count * MEDIAN_INVESTIGATION_SECONDS) // 60
    return (
        f"This batch queues {count} independent investigations "
        f"(estimated ~{minutes} min sequential at {MEDIAN_INVESTIGATION_SECONDS}s median each). "
        f"Cap is {size_cap}."
    )


def build_investigation_batch_view(
    store: InvestigationStore,
    batch: InvestigationBatchRecord,
) -> InvestigationBatchView:
    store.refresh_batch_state(batch.batch_id)
    batch = store.get_batch(batch.batch_id) or batch
    children_meta = store.list_batch_children(batch.batch_id)
    child_views: list[BatchChildView] = []
    for meta in children_meta:
        record = store.get(meta.investigation_id, include_children=True)
        if record is None:
            continue
        child_views.append(_child_view(record, meta))
    minutes = (len(child_views) * MEDIAN_INVESTIGATION_SECONDS) // 60
    total_candidates = sum(child.candidate_count for child in child_views)
    active = batch.state == BatchState.ACTIVE and any(
        child.state in {InvestigationState.QUEUED, InvestigationState.RUNNING}
        for child in child_views
    )
    return InvestigationBatchView(
        batch_id=batch.batch_id,
        source=batch.source,
        repo_ref_label=f"{batch.repo} @ {batch.requested_ref}",
        short_sha=short_sha(batch.resolved_commit_sha),
        state=batch.state if not active else BatchState.ACTIVE,
        state_pill_class=_batch_state_pill(batch.state if not active else BatchState.ACTIVE),
        child_count=len(child_views),
        estimated_wall_clock_label=f"~{minutes} min sequential ({MEDIAN_INVESTIGATION_SECONDS}s median each)",
        benchmark_precision_label=f"{BENCHMARK_MEAN_PRECISION:.3f}",
        benchmark_p_at_1_label=f"{BENCHMARK_P_AT_1:.3f}",
        benchmark_note=BENCHMARK_NOTE,
        top25_survivor_count=batch.top25_survivor_count,
        scope_rationale=_scope_rationale(batch),
        total_candidate_count=total_candidates,
        false_positive_framing=_false_positive_framing(total_candidates),
        children=tuple(child_views),
        can_cancel=batch.state == BatchState.ACTIVE and active,
        created_at_label=_format_timestamp(batch.created_at),
    )


def _batch_state_pill(state: BatchState) -> str:
    if state == BatchState.ACTIVE:
        return "status-pill--info"
    if state == BatchState.COMPLETED:
        return "status-pill--ok"
    return "status-pill--muted"


def _child_view(record: InvestigationRecord, meta: BatchChildRecord) -> BatchChildView:
    tier = meta.profile_evidence_tier or "none"
    paths = tuple(candidate.file_path for candidate in record.candidates)
    return BatchChildView(
        investigation_id=record.investigation_id,
        task_cwe=record.task_cwe,
        state=record.state,
        state_pill_class=investigation_state_pill_class(record.state),
        tractability=meta.tractability,
        evidence_tier=tier,
        no_repo_evidence=tier == "language-only" and not record.candidates,
        candidates_without_evidence_basis=tier == "language-only" and bool(record.candidates),
        candidate_count=len(record.candidates),
        candidates=paths,
        detail_href=f"/ui/investigations/{record.investigation_id}",
    )
