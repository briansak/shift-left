"""Pydantic models for Antares investigation records."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from shift_left.models.schema import utc_now

INVESTIGATION_SOURCE_ANTARES: Literal["investigation.antares"] = "investigation.antares"


class InvestigationState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_NO_FILES = "completed_no_files"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CandidateDisposition(str, Enum):
    OPEN = "open"
    REVIEWED = "reviewed"
    NOT_ACTIONABLE = "not_actionable"


class TraceRecord(BaseModel):
    investigation_id: str
    turn_index: int = Field(ge=0)
    command: str
    exit_status: int
    output_truncated: str
    executed_at: datetime
    charged: bool = Field(
        default=True,
        description="False when the harness suppressed a byte-identical duplicate command.",
    )
    duplicate_of_turn: int | None = Field(
        default=None,
        ge=1,
        description="Original charged turn when charged is false.",
    )
    command_id: str | None = Field(
        default=None,
        description="Stable id shared by the dispatch and completion audit events.",
    )
    phase: str = Field(
        default="completed",
        description="dispatched before sandbox execute returns; completed afterward.",
    )


class CandidateRecord(BaseModel):
    investigation_id: str
    submission_rank: int = Field(ge=1, description="Display order only — not model confidence.")
    file_path: str
    disposition: CandidateDisposition = CandidateDisposition.OPEN
    disposition_actor: str | None = None
    disposition_at: datetime | None = None
    disposition_note: str | None = None


class AuditTraceReconciliation(BaseModel):
    """Compare persisted trace attempts vs sandbox command audit events."""

    trace_attempt_count: int = Field(
        ge=0,
        description="All terminal commands the model issued, including duplicate suppressions.",
    )
    sandbox_audit_attempt_count: int = Field(
        ge=0,
        description="All sandbox audit events, including duplicate suppressions.",
    )
    trace_charged_count: int = Field(
        ge=0,
        description="Trace attempts that executed in the sandbox and consumed budget.",
    )
    sandbox_audit_charged_count: int = Field(
        ge=0,
        description="Audit events for commands that executed in the sandbox.",
    )
    counts_match: bool = Field(
        description="trace_attempt_count equals sandbox_audit_attempt_count."
    )
    divergence_note: str | None = None


class InvestigationRecord(BaseModel):
    investigation_id: str
    source: Literal["investigation.antares"] = INVESTIGATION_SOURCE_ANTARES
    repo: str
    requested_ref: str
    resolved_commit_sha: str
    task_cwe: str
    task_cwe_description: str | None = None
    advisory_cve: str | None = None
    state: InvestigationState = InvestigationState.QUEUED
    model_variant: str
    model_sha256: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    terminal_calls_used: int = Field(default=0, ge=0)
    terminal_call_budget: int = Field(default=15, ge=1)
    outcome_reason: str | None = None
    actor: str
    snapshot_bytes: int = Field(default=0, ge=0)
    originating_investigation_id: str | None = Field(
        default=None,
        description="Prior investigation id when this run is a re-run.",
    )
    batch_id: str | None = Field(
        default=None,
        description="Parent batch id when launched as part of a multi-CWE batch.",
    )
    batch_sort_order: int | None = Field(
        default=None,
        ge=0,
        description="Enqueue order within a batch (lower runs first).",
    )
    profile_evidence_tier: str | None = Field(
        default=None,
        description="Profiler evidence tier at batch launch (direct, indirect, language-only, none).",
    )
    exclude_test_paths: bool = Field(
        default=True,
        description="Omit test/fixture paths from the Antares snapshot (see test-path-exclusions.json).",
    )
    snapshot_scope: str = Field(
        default="full",
        description="full checkout or pr_changed (files vs snapshot_base_ref).",
    )
    snapshot_base_ref: str | None = Field(
        default=None,
        description="Base ref for PR changed-files snapshot scope.",
    )
    queue_waiting_reason: str | None = Field(
        default=None,
        description="Why a queued investigation is not yet running (e.g. antares-server unavailable).",
    )
    queued_waiting_since: datetime | None = Field(
        default=None,
        description="When queue wait for server health began (for timeout).",
    )
    runner_claim_token: str | None = Field(
        default=None,
        description="Opaque lease token set when a runner claims this investigation.",
    )
    runner_claimed_at: datetime | None = None
    candidates: list[CandidateRecord] = Field(default_factory=list)
    trace_turns: list[TraceRecord] = Field(default_factory=list)
    open_disposition_count: int | None = Field(
        default=None,
        description="Rollup populated on list/get when candidates are not loaded.",
    )
    audit_trace_reconciliation: AuditTraceReconciliation | None = Field(
        default=None,
        description="Cross-store trace vs sandbox-audit counts; populated on detail reads.",
    )
