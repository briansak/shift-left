"""Investigation list, detail, and launch form presentation."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from shift_left.antares.client import PUBLISHED_FILE_F1
from shift_left.config import AppConfig
from shift_left.cwe.localization_candidates import localization_candidate_entries
from shift_left.investigations.batch_constants import MEDIAN_INVESTIGATION_SECONDS
from shift_left.investigations.batch_launch import BatchPreviewResult
from shift_left.profiler.profile import load_top25_ranks
from shift_left.investigations.schema import (
    AuditTraceReconciliation,
    CandidateDisposition,
    CandidateRecord,
    InvestigationRecord,
    InvestigationState,
    TraceRecord,
)
from shift_left.investigations.stale import is_investigation_stale
from shift_left.investigations.preflight import LaunchPreflight
from shift_left.investigations.store import InvestigationStore
from shift_left.investigations.suitability import STRONG_CWES, WEAK_CWES
from shift_left.models.database import AuditStore
from shift_left.ui.config_redaction import redact_display_text

if TYPE_CHECKING:
    from shift_left.investigations.runner import InvestigationQueueRunner

DEFAULT_PAGE_SIZE = 25
INVESTIGATION_POLL_INTERVAL_MS = 5000


@dataclass(frozen=True)
class InvestigationRunnerStatusView:
    worker_alive: bool
    worker_label: str
    status_pill_class: str
    current_investigation_id: str | None
    current_investigation_short: str | None
    current_elapsed_label: str | None
    queue_depth: int
    health_gate_reason: str | None
    show_warn: bool
    warn_message: str | None
    system_href: str


@dataclass(frozen=True)
class InvestigationListSummary:
    total: int
    by_state: dict[str, int]
    open_disposition_total: int


@dataclass(frozen=True)
class InvestigationListRow:
    investigation_id: str
    repo_ref_label: str
    short_sha: str
    task_cwe: str
    state: InvestigationState
    state_pill_class: str
    candidate_count: int
    terminal_calls_label: str
    duration_label: str
    actor: str
    created_at_label: str
    is_stale: bool
    detail_href: str
    queue_status_label: str | None
    waiting_reason: str | None
    open_disposition_count: int
    can_cancel: bool
    can_rerun: bool
    batch_href: str | None = None


@dataclass(frozen=True)
class LaunchCatalogRow:
    cwe_id: str
    name: str
    tractability: str
    top25_rank: int | None
    selected: bool = False


@dataclass(frozen=True)
class LaunchPreviewMemberView:
    cwe_id: str
    name: str
    evidence_tier: str
    tractability: str
    top25_rank: int | None
    selected: bool


@dataclass(frozen=True)
class InvestigationLaunchFormView:
    can_submit: bool
    disabled_reason: str | None
    strong_cwes: tuple[str, ...]
    weak_cwes: tuple[str, ...]
    snapshot_warn_mb: int = 10
    error: str | None = None
    notice: str | None = None
    default_task_cwe: str = ""
    default_task_cwe_description: str = ""
    launch_prefill: bool = False
    source: str = "single"
    snapshot_scope: str = "full"
    snapshot_base_ref: str = "main"
    repo: str = ""
    ref: str = ""
    exclude_test_paths: bool = True
    queue_depth: int = 0
    queue_depth_cap: int = 10
    snapshot_bytes: int | None = None
    snapshot_bytes_label: str | None = None
    estimated_wall_clock_seconds: int = 0
    estimated_wall_clock_label: str | None = None
    median_investigation_seconds: int = MEDIAN_INVESTIGATION_SECONDS
    preview_members: tuple[LaunchPreviewMemberView, ...] = ()
    catalog: tuple[LaunchCatalogRow, ...] = ()
    catalog_json: str = "[]"
    previewed: bool = False
    confirm_threshold: int = 10
    selected_count: int = 0


@dataclass(frozen=True)
class InvestigationListView:
    summary: InvestigationListSummary
    rows: tuple[InvestigationListRow, ...]
    page: int
    page_size: int
    total_pages: int
    antares_available: bool
    empty: bool
    launch_form: InvestigationLaunchFormView
    runner_status: InvestigationRunnerStatusView
    auto_refresh: bool
    poll_interval_ms: int
    batch_launch_notice: str


@dataclass(frozen=True)
class InvestigationCandidateRowView:
    submission_rank: int
    file_path: str
    disposition: CandidateDisposition
    disposition_actor: str | None
    disposition_at_label: str
    note_display: str
    has_note: bool


@dataclass(frozen=True)
class InvestigationTraceTurnView:
    turn_index: int
    command: str
    exit_status: int
    output_truncated: str
    charged: bool = True
    duplicate_of_turn: int | None = None


@dataclass(frozen=True)
class InvestigationDetailView:
    investigation_id: str
    repo_ref_label: str
    short_sha: str
    task_cwe: str
    state: InvestigationState
    state_pill_class: str
    model_variant: str
    published_file_f1: float | None
    duration_label: str
    terminal_calls_label: str
    is_stale: bool
    candidates: tuple[InvestigationCandidateRowView, ...]
    open_disposition_count: int
    trace_turn_count: int
    show_trace_drawer: bool
    trace_fetch_href: str
    reconciliation: AuditTraceReconciliation | None
    show_no_files_message: bool
    no_files_message: str
    show_candidate_table: bool
    trace_href: str
    can_cancel: bool
    can_rerun: bool
    can_edit_disposition: bool
    waiting_reason: str | None
    is_running: bool
    auto_refresh: bool
    poll_interval_ms: int


def short_sha(commit_sha: str) -> str:
    text = (commit_sha or "").strip()
    return text[:7] if text else "—"


def _ordinal(position: int) -> str:
    if 10 <= position % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(position % 10, "th")
    return f"{position}{suffix}"


def _queue_status_label(record: InvestigationRecord, store: InvestigationStore) -> str | None:
    if record.state == InvestigationState.QUEUED:
        position = store.queue_position(record.investigation_id)
        if position is not None:
            return f"{_ordinal(position)} in queue"
    if record.state == InvestigationState.RUNNING:
        return f"{record.terminal_calls_used}/{record.terminal_call_budget} terminal calls"
    return None


def _can_cancel(state: InvestigationState) -> bool:
    return state in {InvestigationState.QUEUED, InvestigationState.RUNNING}


def has_active_investigations(store: InvestigationStore) -> bool:
    counts = store.count_by_state()
    return counts.get(InvestigationState.QUEUED.value, 0) + counts.get(
        InvestigationState.RUNNING.value, 0
    ) > 0


def build_runner_status_view(
    runner: InvestigationQueueRunner | None,
    store: InvestigationStore,
    *,
    now: datetime | None = None,
) -> InvestigationRunnerStatusView:
    queue_depth = store.count_queued()
    alive = runner is not None and runner.is_alive()
    health_gate_reason = runner.health_gate_reason if runner is not None else None
    current_id = runner.current_investigation_id if runner is not None else None
    started_at = runner.current_started_at if runner is not None else None

    show_warn = not alive and queue_depth > 0
    warn_message: str | None = None
    if show_warn:
        warn_message = (
            "Investigation queue runner is not running — queued work will not drain. "
            "Check orchestrator startup and Antares on System."
        )

    elapsed: str | None = None
    if current_id and started_at is not None:
        elapsed = _format_duration(started_at, now)

    if alive:
        worker_label = "alive"
        pill = "status-pill--healthy"
    else:
        worker_label = "dead"
        pill = "status-pill--danger" if show_warn else "status-pill--muted"

    return InvestigationRunnerStatusView(
        worker_alive=alive,
        worker_label=worker_label,
        status_pill_class=pill,
        current_investigation_id=current_id,
        current_investigation_short=short_sha(current_id) if current_id else None,
        current_elapsed_label=elapsed,
        queue_depth=queue_depth,
        health_gate_reason=health_gate_reason,
        show_warn=show_warn,
        warn_message=warn_message,
        system_href="/ui/system",
    )


def _can_rerun(state: InvestigationState) -> bool:
    return state in {
        InvestigationState.COMPLETED,
        InvestigationState.COMPLETED_NO_FILES,
        InvestigationState.FAILED,
        InvestigationState.CANCELLED,
    }


def format_snapshot_bytes(byte_count: int) -> str:
    if byte_count < 1024:
        return f"{byte_count} B"
    if byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.1f} KB"
    return f"{byte_count / (1024 * 1024):.1f} MB"


def format_wall_clock(member_count: int, *, median_seconds: int = MEDIAN_INVESTIGATION_SECONDS) -> str:
    if member_count <= 0:
        return "—"
    total = member_count * median_seconds
    if total < 60:
        return f"~{total}s sequential ({median_seconds}s median × {member_count})"
    minutes = total // 60
    return f"~{minutes} min sequential ({median_seconds}s median × {member_count})"


def _catalog_rows(selected: set[str] | None = None) -> tuple[LaunchCatalogRow, ...]:
    ranks = load_top25_ranks()
    chosen = {item.strip() for item in (selected or set()) if item.strip()}
    rows: list[LaunchCatalogRow] = []
    for entry in localization_candidate_entries():
        cwe_id = str(entry.get("id") or "")
        if not cwe_id:
            continue
        rows.append(
            LaunchCatalogRow(
                cwe_id=cwe_id,
                name=str(entry.get("name") or ""),
                tractability=str(entry.get("tractability") or "unrated"),
                top25_rank=ranks.get(cwe_id),
                selected=cwe_id in chosen,
            )
        )
    rows.sort(key=lambda row: (row.top25_rank is None, row.top25_rank or 999, row.cwe_id))
    return tuple(rows)


def _catalog_json(rows: tuple[LaunchCatalogRow, ...]) -> str:
    return json.dumps(
        [
            {
                "id": row.cwe_id,
                "name": row.name,
                "tractability": row.tractability,
                "top25_rank": row.top25_rank,
            }
            for row in rows
        ]
    )


def build_launch_form_view(
    preflight: LaunchPreflight,
    *,
    error: str | None = None,
    notice: str | None = None,
    default_task_cwe: str = "",
    default_task_cwe_description: str = "",
    source: str = "single",
    snapshot_scope: str = "full",
    snapshot_base_ref: str = "main",
    repo: str = "",
    ref: str = "",
    exclude_test_paths: bool = True,
    queue_depth: int = 0,
    queue_depth_cap: int = 10,
    preview: BatchPreviewResult | None = None,
    selected_catalog_cwes: tuple[str, ...] = (),
) -> InvestigationLaunchFormView:
    normalized_cwe = default_task_cwe.strip()
    normalized_description = default_task_cwe_description.strip()
    catalog = _catalog_rows(set(selected_catalog_cwes))
    members: tuple[LaunchPreviewMemberView, ...] = ()
    snapshot_bytes: int | None = None
    selected_count = 1 if (source or "single") == "single" else len(selected_catalog_cwes)
    if preview is not None:
        members = tuple(
            LaunchPreviewMemberView(
                cwe_id=item.cwe_id,
                name=item.name,
                evidence_tier=item.evidence_tier,
                tractability=item.tractability,
                top25_rank=item.top25_rank,
                selected=item.selected_by_default,
            )
            for item in preview.members
        )
        snapshot_bytes = preview.snapshot_bytes
        selected_count = preview.selected_count
        queue_depth = preview.queue_depth
        queue_depth_cap = preview.queue_depth_cap
    return InvestigationLaunchFormView(
        can_submit=preflight.can_submit,
        disabled_reason=preflight.disabled_reason,
        strong_cwes=tuple(sorted(STRONG_CWES)),
        weak_cwes=tuple(sorted(WEAK_CWES)),
        error=error,
        notice=notice,
        default_task_cwe=normalized_cwe,
        default_task_cwe_description=normalized_description,
        launch_prefill=bool(
            normalized_cwe or normalized_description or repo or preview is not None or source != "single"
        ),
        source=source or "single",
        snapshot_scope=snapshot_scope or "full",
        snapshot_base_ref=snapshot_base_ref or "main",
        repo=repo.strip(),
        ref=ref.strip(),
        exclude_test_paths=exclude_test_paths,
        queue_depth=queue_depth,
        queue_depth_cap=queue_depth_cap,
        snapshot_bytes=snapshot_bytes,
        snapshot_bytes_label=None if snapshot_bytes is None else format_snapshot_bytes(snapshot_bytes),
        estimated_wall_clock_seconds=selected_count * MEDIAN_INVESTIGATION_SECONDS,
        estimated_wall_clock_label=format_wall_clock(selected_count),
        median_investigation_seconds=MEDIAN_INVESTIGATION_SECONDS,
        preview_members=members,
        catalog=catalog,
        catalog_json=_catalog_json(catalog),
        previewed=preview is not None,
        selected_count=selected_count,
    )


def investigation_state_pill_class(state: InvestigationState) -> str:
    if state in {InvestigationState.QUEUED, InvestigationState.RUNNING}:
        return "status-pill--accent"
    if state == InvestigationState.COMPLETED:
        return "status-pill--healthy"
    if state in {InvestigationState.COMPLETED_NO_FILES, InvestigationState.CANCELLED}:
        return "status-pill--muted"
    if state == InvestigationState.FAILED:
        return "status-pill--danger"
    return "status-pill--muted"


def _candidate_row_view(candidate: CandidateRecord) -> InvestigationCandidateRowView:
    note = candidate.disposition_note or ""
    redacted = redact_display_text(note, path=candidate.file_path) if note else ""
    return InvestigationCandidateRowView(
        submission_rank=candidate.submission_rank,
        file_path=candidate.file_path,
        disposition=candidate.disposition,
        disposition_actor=candidate.disposition_actor,
        disposition_at_label=_format_timestamp(candidate.disposition_at),
        note_display=redacted,
        has_note=bool(note),
    )


def _format_timestamp(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.astimezone().strftime("%Y-%m-%d %H:%M UTC")


def _format_duration(started_at: datetime | None, finished_at: datetime | None) -> str:
    if started_at is None:
        return "—"
    end = finished_at or datetime.now(tz=started_at.tzinfo)
    seconds = max(0, int((end - started_at).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    minutes, rem = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {rem}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def resolve_checkout_head_sha(repos_checkout_dir: str, repo: str) -> str | None:
    parts = repo.split("/", 1)
    if len(parts) != 2:
        return None
    checkout = Path(repos_checkout_dir) / parts[0] / parts[1]
    if not checkout.is_dir():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    sha = result.stdout.strip()
    return sha or None


def _head_cache(
    repos_checkout_dir: str,
    repos: set[str],
) -> dict[str, str | None]:
    return {repo: resolve_checkout_head_sha(repos_checkout_dir, repo) for repo in repos}


def _redact_trace_turn(turn: TraceRecord) -> InvestigationTraceTurnView:
    return InvestigationTraceTurnView(
        turn_index=turn.turn_index,
        command=redact_display_text(turn.command),
        exit_status=turn.exit_status,
        output_truncated=redact_display_text(turn.output_truncated),
        charged=turn.charged,
        duplicate_of_turn=turn.duplicate_of_turn,
    )


def build_investigation_list_view(
    store: InvestigationStore,
    config: AppConfig,
    *,
    runner: InvestigationQueueRunner | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    launch_form: InvestigationLaunchFormView | None = None,
) -> InvestigationListView:
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    total = store.count_investigations()
    total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * page_size
    records = store.list_investigations(offset=offset, limit=page_size)
    heads = _head_cache(
        config.antares_triage.repos_checkout_dir,
        {record.repo for record in records},
    )
    rows: list[InvestigationListRow] = []
    for record in records:
        head = heads.get(record.repo)
        rows.append(
            InvestigationListRow(
                investigation_id=record.investigation_id,
                repo_ref_label=f"{record.repo}@{record.requested_ref}",
                short_sha=short_sha(record.resolved_commit_sha),
                task_cwe=record.task_cwe,
                state=record.state,
                state_pill_class=investigation_state_pill_class(record.state),
                candidate_count=store.count_candidates(record.investigation_id),
                terminal_calls_label=f"{record.terminal_calls_used}/{record.terminal_call_budget}",
                duration_label=_format_duration(record.started_at, record.finished_at),
                actor=record.actor,
                created_at_label=_format_timestamp(record.created_at),
                is_stale=is_investigation_stale(record.resolved_commit_sha, head or ""),
                detail_href=f"/ui/investigations/{record.investigation_id}",
                queue_status_label=_queue_status_label(record, store),
                waiting_reason=record.queue_waiting_reason,
                open_disposition_count=store.open_disposition_count(record.investigation_id),
                can_cancel=_can_cancel(record.state),
                can_rerun=_can_rerun(record.state),
                batch_href=(
                    f"/ui/investigations/batches/{record.batch_id}"
                    if record.batch_id
                    else None
                ),
            )
        )
    by_state = store.count_by_state()
    summary = InvestigationListSummary(
        total=total,
        by_state=by_state,
        open_disposition_total=store.total_open_disposition_count(),
    )
    antares_available = bool(
        config.models.antares.installed or config.antares_triage.installed
    )
    default_launch = InvestigationLaunchFormView(
        can_submit=False,
        disabled_reason="Loading launch preflight…",
        strong_cwes=tuple(sorted(STRONG_CWES)),
        weak_cwes=tuple(sorted(WEAK_CWES)),
        queue_depth=store.count_queued(),
        queue_depth_cap=config.investigations.queue_depth_cap,
    )
    auto_refresh = has_active_investigations(store)
    from shift_left.ui.batch_view import build_batch_launch_notice

    return InvestigationListView(
        summary=summary,
        rows=tuple(rows),
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        antares_available=antares_available,
        empty=total == 0,
        launch_form=launch_form or default_launch,
        runner_status=build_runner_status_view(runner, store),
        auto_refresh=auto_refresh,
        poll_interval_ms=INVESTIGATION_POLL_INTERVAL_MS,
        batch_launch_notice=build_batch_launch_notice(),
    )


def build_investigation_detail_view(
    store: InvestigationStore,
    audit: AuditStore,
    config: AppConfig,
    investigation_id: str,
    *,
    can_edit_disposition: bool = False,
) -> InvestigationDetailView | None:
    record = store.get_detail(investigation_id, audit=audit, include_children=True)
    if record is None:
        return None
    head = resolve_checkout_head_sha(config.antares_triage.repos_checkout_dir, record.repo)
    published_f1 = PUBLISHED_FILE_F1.get(record.model_variant)
    f1_text = f"{published_f1:.3f}" if published_f1 is not None else "unknown"
    no_files_message = (
        "No candidate files surfaced. This does not indicate absence of the weakness — "
        f"the model's published File F1 on this task is {f1_text}."
    )
    trace_turn_count = store.count_trace_turns(investigation_id)
    is_running = record.state == InvestigationState.RUNNING
    show_no_files = record.state == InvestigationState.COMPLETED_NO_FILES
    return InvestigationDetailView(
        investigation_id=record.investigation_id,
        repo_ref_label=f"{record.repo}@{record.requested_ref}",
        short_sha=short_sha(record.resolved_commit_sha),
        task_cwe=record.task_cwe,
        state=record.state,
        state_pill_class=investigation_state_pill_class(record.state),
        model_variant=record.model_variant,
        published_file_f1=published_f1,
        duration_label=_format_duration(
            record.started_at,
            None if is_running else record.finished_at,
        ),
        terminal_calls_label=f"{record.terminal_calls_used}/{record.terminal_call_budget}",
        is_stale=is_investigation_stale(record.resolved_commit_sha, head or ""),
        candidates=tuple(_candidate_row_view(candidate) for candidate in record.candidates),
        open_disposition_count=store.open_disposition_count(investigation_id),
        trace_turn_count=trace_turn_count,
        show_trace_drawer=is_running or trace_turn_count > 0,
        trace_fetch_href=f"/ui/investigations/{record.investigation_id}/trace?fragment=1",
        reconciliation=record.audit_trace_reconciliation,
        show_no_files_message=show_no_files,
        no_files_message=no_files_message,
        show_candidate_table=not show_no_files,
        trace_href=f"/ui/investigations/{record.investigation_id}/trace",
        can_cancel=_can_cancel(record.state),
        can_rerun=_can_rerun(record.state),
        can_edit_disposition=can_edit_disposition,
        waiting_reason=record.queue_waiting_reason,
        is_running=is_running,
        auto_refresh=has_active_investigations(store),
        poll_interval_ms=INVESTIGATION_POLL_INTERVAL_MS,
    )


def build_investigation_trace_view(
    store: InvestigationStore,
    investigation_id: str,
) -> tuple[InvestigationDetailView, tuple[InvestigationTraceTurnView, ...]] | None:
    record = store.get(investigation_id, include_children=True)
    if record is None:
        return None
    trace_turns = tuple(_redact_trace_turn(turn) for turn in record.trace_turns)
    detail_stub = InvestigationDetailView(
        investigation_id=record.investigation_id,
        repo_ref_label=f"{record.repo}@{record.requested_ref}",
        short_sha=short_sha(record.resolved_commit_sha),
        task_cwe=record.task_cwe,
        state=record.state,
        state_pill_class=investigation_state_pill_class(record.state),
        model_variant=record.model_variant,
        published_file_f1=PUBLISHED_FILE_F1.get(record.model_variant),
        duration_label=_format_duration(record.started_at, record.finished_at),
        terminal_calls_label=f"{record.terminal_calls_used}/{record.terminal_call_budget}",
        is_stale=False,
        candidates=tuple(),
        open_disposition_count=0,
        trace_turn_count=len(trace_turns),
        show_trace_drawer=len(trace_turns) > 0,
        trace_fetch_href=f"/ui/investigations/{record.investigation_id}/trace?fragment=1",
        reconciliation=None,
        show_no_files_message=False,
        no_files_message="",
        show_candidate_table=False,
        trace_href=f"/ui/investigations/{record.investigation_id}/trace",
        can_cancel=False,
        can_rerun=False,
        can_edit_disposition=False,
        waiting_reason=None,
        is_running=record.state == InvestigationState.RUNNING,
        auto_refresh=False,
        poll_interval_ms=INVESTIGATION_POLL_INTERVAL_MS,
    )
    return detail_stub, trace_turns


def build_investigation_trace_fragment(
    store: InvestigationStore,
    investigation_id: str,
) -> tuple[int, tuple[InvestigationTraceTurnView, ...]] | None:
    record = store.get(investigation_id, include_children=True)
    if record is None:
        return None
    trace_turns = tuple(_redact_trace_turn(turn) for turn in record.trace_turns)
    return len(trace_turns), trace_turns


def runner_status_to_dict(status: InvestigationRunnerStatusView) -> dict[str, object]:
    return {
        "worker_alive": status.worker_alive,
        "worker_label": status.worker_label,
        "status_pill_class": status.status_pill_class,
        "current_investigation_id": status.current_investigation_id,
        "current_investigation_short": status.current_investigation_short,
        "current_elapsed_label": status.current_elapsed_label,
        "queue_depth": status.queue_depth,
        "health_gate_reason": status.health_gate_reason,
        "show_warn": status.show_warn,
        "warn_message": status.warn_message,
        "system_href": status.system_href,
    }


def _row_live_state(record: InvestigationRecord, store: InvestigationStore) -> dict[str, object]:
    queue_label = _queue_status_label(record, store)
    return {
        "investigation_id": record.investigation_id,
        "state": record.state.value,
        "state_pill_class": investigation_state_pill_class(record.state),
        "queue_or_calls_label": queue_label or (
            f"{record.terminal_calls_used}/{record.terminal_call_budget}"
        ),
        "duration_label": _format_duration(
            record.started_at,
            None if record.state == InvestigationState.RUNNING else record.finished_at,
        ),
        "waiting_reason": record.queue_waiting_reason,
    }


def build_investigation_list_live_state(
    store: InvestigationStore,
    runner: InvestigationQueueRunner | None,
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict[str, object]:
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    total = store.count_investigations()
    total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * page_size
    records = store.list_investigations(offset=offset, limit=page_size)
    counts = store.count_by_state()
    active = has_active_investigations(store)
    return {
        "active": active,
        "runner": runner_status_to_dict(build_runner_status_view(runner, store)),
        "rows": [_row_live_state(record, store) for record in records],
        "summary_active_count": counts.get(InvestigationState.QUEUED.value, 0)
        + counts.get(InvestigationState.RUNNING.value, 0),
    }


def build_investigation_detail_live_state(
    store: InvestigationStore,
    investigation_id: str,
) -> dict[str, object] | None:
    record = store.get(investigation_id)
    if record is None:
        return None
    is_running = record.state == InvestigationState.RUNNING
    active = record.state in {InvestigationState.QUEUED, InvestigationState.RUNNING}
    return {
        "active": active,
        "investigation_id": investigation_id,
        "state": record.state.value,
        "state_pill_class": investigation_state_pill_class(record.state),
        "duration_label": _format_duration(
            record.started_at,
            None if is_running else record.finished_at,
        ),
        "terminal_calls_label": (
            f"{record.terminal_calls_used}/{record.terminal_call_budget}"
        ),
        "trace_turn_count": store.count_trace_turns(investigation_id),
        "waiting_reason": record.queue_waiting_reason,
        "is_running": is_running,
    }
