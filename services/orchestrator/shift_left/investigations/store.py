"""SQLite persistence for Antares investigations — not gate findings.

Schema (created via SQLAlchemy metadata on first open):

- ``investigations`` — parent record, one row per investigation_id
- ``investigation_candidates`` — ranked file paths (no confidence column)
- ``investigation_trace_turns`` — one row per command, written at dispatch and
  updated with exit status/output when execute returns

Trace command/output and candidate paths are stored **raw**; readers apply
``redact_display_text`` at presentation boundaries (see docs/secret-redaction.md).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import json

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, create_engine, delete, func, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from shift_left.investigations.batch_schema import (
    BatchChildRecord,
    BatchState,
    InvestigationBatchRecord,
)
from shift_left.investigations.schema import (
    INVESTIGATION_SOURCE_ANTARES,
    CandidateDisposition,
    CandidateRecord,
    InvestigationRecord,
    InvestigationState,
    TraceRecord,
)
from shift_left.models.database import AuditStore
from shift_left.models.schema import utc_now

_TERMINAL_STATES = frozenset(
    {
        InvestigationState.COMPLETED,
        InvestigationState.COMPLETED_NO_FILES,
        InvestigationState.FAILED,
        InvestigationState.CANCELLED,
    }
)

_ALLOWED_TRANSITIONS: dict[InvestigationState, frozenset[InvestigationState]] = {
    InvestigationState.QUEUED: frozenset(
        {InvestigationState.RUNNING, InvestigationState.CANCELLED, InvestigationState.FAILED}
    ),
    InvestigationState.RUNNING: frozenset(
        {
            InvestigationState.COMPLETED,
            InvestigationState.COMPLETED_NO_FILES,
            InvestigationState.FAILED,
            InvestigationState.CANCELLED,
        }
    ),
    InvestigationState.COMPLETED: frozenset(),
    InvestigationState.COMPLETED_NO_FILES: frozenset(),
    InvestigationState.FAILED: frozenset(),
    InvestigationState.CANCELLED: frozenset(),
}


class InvestigationBase(DeclarativeBase):
    pass


class InvestigationRow(InvestigationBase):
    __tablename__ = "investigations"
    __table_args__ = (
        Index("ix_investigations_repo", "repo"),
        Index("ix_investigations_repo_cwe", "repo", "task_cwe"),
        Index("ix_investigations_state", "state"),
        Index("ix_investigations_created_at", "created_at"),
    )

    investigation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source: Mapped[str] = mapped_column(String(64), default=INVESTIGATION_SOURCE_ANTARES)
    repo: Mapped[str] = mapped_column(String(512))
    requested_ref: Mapped[str] = mapped_column(String(256))
    resolved_commit_sha: Mapped[str] = mapped_column(String(64))
    task_cwe: Mapped[str] = mapped_column(String(32))
    task_cwe_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    advisory_cve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(32))
    model_variant: Mapped[str] = mapped_column(String(128))
    model_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terminal_calls_used: Mapped[int] = mapped_column(Integer, default=0)
    terminal_call_budget: Mapped[int] = mapped_column(Integer, default=15)
    outcome_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str] = mapped_column(String(256))
    snapshot_bytes: Mapped[int] = mapped_column(Integer, default=0)
    originating_investigation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    queue_waiting_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    queued_waiting_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    runner_claim_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    runner_claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    batch_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    batch_sort_order: Mapped[int | None] = mapped_column(Integer, nullable=True)
    profile_evidence_tier: Mapped[str | None] = mapped_column(String(32), nullable=True)
    exclude_test_paths: Mapped[int] = mapped_column(Integer, default=1)
    snapshot_scope: Mapped[str] = mapped_column(String(32), default="full")
    snapshot_base_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)


class InvestigationBatchRow(InvestigationBase):
    __tablename__ = "investigation_batches"
    __table_args__ = (Index("ix_investigation_batches_created_at", "created_at"),)

    batch_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source: Mapped[str] = mapped_column(String(32))
    repo: Mapped[str] = mapped_column(String(512))
    requested_ref: Mapped[str] = mapped_column(String(256))
    resolved_commit_sha: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(String(32))
    profile_snapshot_json: Mapped[str] = mapped_column(Text, default="{}")
    top25_survivor_count: Mapped[int | None] = mapped_column(Integer, nullable=True)


class InvestigationCandidateRow(InvestigationBase):
    __tablename__ = "investigation_candidates"
    __table_args__ = (
        Index("ix_investigation_candidates_parent", "investigation_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigations.investigation_id", ondelete="CASCADE"),
    )
    submission_rank: Mapped[int] = mapped_column(Integer)
    file_path: Mapped[str] = mapped_column(String(1024))
    disposition: Mapped[str] = mapped_column(String(32), default=CandidateDisposition.OPEN.value)
    disposition_actor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    disposition_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disposition_note: Mapped[str | None] = mapped_column(Text, nullable=True)


class InvestigationTraceRow(InvestigationBase):
    __tablename__ = "investigation_trace_turns"
    __table_args__ = (
        Index("ix_investigation_trace_parent", "investigation_id"),
        Index("ix_investigation_trace_turn", "investigation_id", "turn_index", unique=True),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigations.investigation_id", ondelete="CASCADE"),
    )
    turn_index: Mapped[int] = mapped_column(Integer)
    command: Mapped[str] = mapped_column(Text)
    exit_status: Mapped[int] = mapped_column(Integer)
    output_truncated: Mapped[str] = mapped_column(Text)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    charged: Mapped[bool] = mapped_column(Boolean, default=True)
    duplicate_of_turn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    command_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    phase: Mapped[str] = mapped_column(String(32), default="completed")


def _create_engine(sqlite_path: str):
    path = Path(sqlite_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{path}", future=True)


class InvestigationStore:
    def __init__(
        self,
        sqlite_path: str,
        *,
        retention_days: int = 90,
        audit: AuditStore | None = None,
    ) -> None:
        self._engine = _create_engine(sqlite_path)
        self._retention_days = retention_days
        self._audit = audit
        InvestigationBase.metadata.create_all(self._engine)
        self._migrate_schema()
        self._session_factory = sessionmaker(self._engine, expire_on_commit=False)

    @property
    def retention_days(self) -> int:
        return self._retention_days

    def create_investigation(
        self,
        *,
        repo: str,
        requested_ref: str,
        resolved_commit_sha: str,
        task_cwe: str,
        actor: str,
        model_variant: str,
        terminal_call_budget: int = 15,
        task_cwe_description: str | None = None,
        advisory_cve: str | None = None,
        model_sha256: str | None = None,
        snapshot_bytes: int = 0,
        investigation_id: str | None = None,
        originating_investigation_id: str | None = None,
        created_at: datetime | None = None,
        batch_id: str | None = None,
        batch_sort_order: int | None = None,
        profile_evidence_tier: str | None = None,
        exclude_test_paths: bool = True,
        snapshot_scope: str = "full",
        snapshot_base_ref: str | None = None,
    ) -> InvestigationRecord:
        inv_id = investigation_id or str(uuid4())
        now = created_at or utc_now()
        row = InvestigationRow(
            investigation_id=inv_id,
            source=INVESTIGATION_SOURCE_ANTARES,
            repo=repo.strip(),
            requested_ref=requested_ref.strip(),
            resolved_commit_sha=resolved_commit_sha.strip(),
            task_cwe=task_cwe.strip(),
            task_cwe_description=task_cwe_description,
            advisory_cve=advisory_cve,
            state=InvestigationState.QUEUED.value,
            model_variant=model_variant,
            model_sha256=model_sha256,
            created_at=now,
            terminal_call_budget=terminal_call_budget,
            actor=actor.strip(),
            snapshot_bytes=snapshot_bytes,
            originating_investigation_id=originating_investigation_id,
            batch_id=batch_id,
            batch_sort_order=batch_sort_order,
            profile_evidence_tier=profile_evidence_tier,
            exclude_test_paths=1 if exclude_test_paths else 0,
            snapshot_scope=(snapshot_scope or "full").strip() or "full",
            snapshot_base_ref=(snapshot_base_ref or "").strip() or None,
        )
        with Session(self._engine) as session:
            session.add(row)
            session.commit()
            record = self._row_to_record(row)
        self._audit_launch(
            investigation_id=inv_id,
            actor=actor,
            repo=record.repo,
            requested_ref=record.requested_ref,
            resolved_commit_sha=record.resolved_commit_sha,
            task_cwe=record.task_cwe,
            advisory_cve=record.advisory_cve,
        )
        return record

    def transition_state(
        self,
        investigation_id: str,
        to_state: InvestigationState,
        *,
        actor: str,
        reason: str | None = None,
        terminal_calls_used: int | None = None,
        snapshot_bytes: int | None = None,
        model_sha256: str | None = None,
    ) -> InvestigationRecord:
        with Session(self._engine) as session:
            row = session.get(InvestigationRow, investigation_id)
            if row is None:
                raise LookupError(f"Investigation not found: {investigation_id}")
            from_state = InvestigationState(row.state)
            allowed = _ALLOWED_TRANSITIONS.get(from_state, frozenset())
            if to_state not in allowed:
                raise ValueError(
                    f"Illegal investigation state transition: {from_state.value} -> {to_state.value}"
                )
            now = utc_now()
            row.state = to_state.value
            if to_state == InvestigationState.RUNNING and row.started_at is None:
                row.started_at = now
            if to_state in _TERMINAL_STATES:
                row.finished_at = now
            if reason is not None:
                row.outcome_reason = reason
            if terminal_calls_used is not None:
                row.terminal_calls_used = terminal_calls_used
            if snapshot_bytes is not None:
                row.snapshot_bytes = snapshot_bytes
            if model_sha256 is not None:
                row.model_sha256 = model_sha256
            if to_state == InvestigationState.RUNNING:
                row.queue_waiting_reason = None
                row.queued_waiting_since = None
            if to_state in _TERMINAL_STATES:
                row.runner_claim_token = None
                row.runner_claimed_at = None
            session.commit()
            record = self._row_to_record(row)
        self._audit_transition(
            investigation_id=investigation_id,
            actor=actor,
            repo=record.repo,
            requested_ref=record.requested_ref,
            from_state=from_state,
            to_state=to_state,
            reason=reason,
        )
        return record

    def append_trace_turn(
        self,
        investigation_id: str,
        *,
        turn_index: int,
        command: str,
        exit_status: int,
        output_truncated: str,
        executed_at: datetime | None = None,
        charged: bool = True,
        duplicate_of_turn: int | None = None,
        command_id: str | None = None,
        phase: str = "completed",
    ) -> TraceRecord:
        when = executed_at or utc_now()
        trace = TraceRecord(
            investigation_id=investigation_id,
            turn_index=turn_index,
            command=command,
            exit_status=exit_status,
            output_truncated=output_truncated,
            executed_at=when,
            charged=charged,
            duplicate_of_turn=duplicate_of_turn,
            command_id=command_id,
            phase=phase,
        )
        row = InvestigationTraceRow(
            id=str(uuid4()),
            investigation_id=investigation_id,
            turn_index=turn_index,
            command=command,
            exit_status=exit_status,
            output_truncated=output_truncated,
            executed_at=when,
            charged=charged,
            duplicate_of_turn=duplicate_of_turn,
            command_id=command_id,
            phase=phase,
        )
        with Session(self._engine) as session:
            parent = session.get(InvestigationRow, investigation_id)
            if parent is None:
                raise LookupError(f"Investigation not found: {investigation_id}")
            session.add(row)
            session.commit()
        return trace

    def complete_trace_turn(
        self,
        investigation_id: str,
        *,
        command_id: str,
        exit_status: int,
        output_truncated: str,
        charged: bool = True,
        duplicate_of_turn: int | None = None,
    ) -> bool:
        """Fill exit status and output on a dispatch row. Returns False if no row."""
        with Session(self._engine) as session:
            row = session.scalars(
                select(InvestigationTraceRow).where(
                    InvestigationTraceRow.investigation_id == investigation_id,
                    InvestigationTraceRow.command_id == command_id,
                )
            ).first()
            if row is None:
                return False
            row.exit_status = exit_status
            row.output_truncated = output_truncated
            row.charged = charged
            row.duplicate_of_turn = duplicate_of_turn
            row.phase = "completed"
            row.executed_at = utc_now()
            session.commit()
        return True

    def set_candidates(
        self,
        investigation_id: str,
        candidates: list[tuple[int, str]],
    ) -> list[CandidateRecord]:
        """Replace candidate rows once at investigation completion. Immutable afterward."""
        with Session(self._engine) as session:
            parent = session.get(InvestigationRow, investigation_id)
            if parent is None:
                raise LookupError(f"Investigation not found: {investigation_id}")
            existing = session.scalars(
                select(InvestigationCandidateRow).where(
                    InvestigationCandidateRow.investigation_id == investigation_id
                )
            ).all()
            if existing:
                raise ValueError(
                    "Candidate results are immutable once persisted; use disposition updates"
                )
            session.execute(
                delete(InvestigationCandidateRow).where(
                    InvestigationCandidateRow.investigation_id == investigation_id
                )
            )
            records: list[CandidateRecord] = []
            for submission_rank, file_path in candidates:
                row = InvestigationCandidateRow(
                    id=str(uuid4()),
                    investigation_id=investigation_id,
                    submission_rank=submission_rank,
                    file_path=file_path,
                    disposition=CandidateDisposition.OPEN.value,
                )
                session.add(row)
                records.append(self._candidate_from_row(row))
            session.commit()
        return records

    def persist_candidates_from_ranked_files(
        self,
        investigation_id: str,
        ranked_files: list[Any],
    ) -> list[CandidateRecord]:
        """Persist engine ranked files, dropping any confidence field at the boundary."""
        pairs: list[tuple[int, str]] = []
        for item in ranked_files:
            if isinstance(item, dict):
                rank = int(item["rank"])
                path = str(item["path"])
            else:
                rank = int(item.rank)
                path = str(item.path)
            pairs.append((rank, path))
        pairs.sort(key=lambda pair: pair[0])
        return self.set_candidates(investigation_id, pairs)

    def update_candidate_disposition(
        self,
        investigation_id: str,
        submission_rank: int,
        *,
        disposition: CandidateDisposition,
        actor: str,
        note: str | None = None,
    ) -> CandidateRecord:
        with Session(self._engine) as session:
            row = session.scalar(
                select(InvestigationCandidateRow).where(
                    InvestigationCandidateRow.investigation_id == investigation_id,
                    InvestigationCandidateRow.submission_rank == submission_rank,
                )
            )
            if row is None:
                raise LookupError(
                    f"Candidate rank {submission_rank} not found for investigation {investigation_id}"
                )
            from_disposition = row.disposition
            file_path = row.file_path
            row.disposition = disposition.value
            row.disposition_actor = actor
            row.disposition_at = utc_now()
            row.disposition_note = note
            session.commit()
            candidate = self._candidate_from_row(row)
        self._audit_disposition_change(
            investigation_id=investigation_id,
            file_path=file_path,
            from_disposition=from_disposition,
            to_disposition=disposition.value,
            actor=actor,
            note=note,
        )
        return candidate

    def get(
        self,
        investigation_id: str,
        *,
        include_children: bool = False,
    ) -> InvestigationRecord | None:
        with Session(self._engine) as session:
            row = session.get(InvestigationRow, investigation_id)
            if row is None:
                return None
            record = self._row_to_record(row)
            if include_children:
                record = record.model_copy(
                    update={
                        "candidates": self._load_candidates(session, investigation_id),
                        "trace_turns": self._load_trace(session, investigation_id),
                    }
                )
            record = record.model_copy(
                update={
                    "open_disposition_count": self._open_disposition_count(
                        session, investigation_id
                    ),
                }
            )
            return record

    def list_investigations(
        self,
        *,
        repo: str | None = None,
        task_cwe: str | None = None,
        state: InvestigationState | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> list[InvestigationRecord]:
        with Session(self._engine) as session:
            query = select(InvestigationRow).order_by(InvestigationRow.created_at.desc())
            if repo:
                query = query.where(InvestigationRow.repo == repo)
            if task_cwe:
                query = query.where(InvestigationRow.task_cwe == task_cwe)
            if state:
                query = query.where(InvestigationRow.state == state.value)
            query = query.offset(max(0, offset)).limit(max(1, limit))
            rows = session.scalars(query).all()
            return [
                self._row_to_record(row).model_copy(
                    update={
                        "open_disposition_count": self._open_disposition_count(
                            session, row.investigation_id
                        ),
                    }
                )
                for row in rows
            ]

    def count_by_state(self) -> dict[str, int]:
        with Session(self._engine) as session:
            rows = session.execute(
                select(InvestigationRow.state, func.count())
                .group_by(InvestigationRow.state)
            ).all()
        return {state: int(count) for state, count in rows}

    def count_investigations(
        self,
        *,
        repo: str | None = None,
        task_cwe: str | None = None,
        state: InvestigationState | None = None,
    ) -> int:
        with Session(self._engine) as session:
            query = select(func.count()).select_from(InvestigationRow)
            if repo:
                query = query.where(InvestigationRow.repo == repo)
            if task_cwe:
                query = query.where(InvestigationRow.task_cwe == task_cwe)
            if state:
                query = query.where(InvestigationRow.state == state.value)
            return int(session.scalar(query) or 0)

    def total_open_disposition_count(self) -> int:
        with Session(self._engine) as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(InvestigationCandidateRow)
                    .where(
                        InvestigationCandidateRow.disposition == CandidateDisposition.OPEN.value
                    )
                )
                or 0
            )

    def count_queued(self) -> int:
        return self.count_investigations(state=InvestigationState.QUEUED)

    def list_queued_fifo(self) -> list[InvestigationRecord]:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(InvestigationRow)
                .where(InvestigationRow.state == InvestigationState.QUEUED.value)
                .order_by(
                    InvestigationRow.created_at.asc(),
                    func.coalesce(InvestigationRow.batch_sort_order, 0).asc(),
                )
            ).all()
            return [self._row_to_record(row) for row in rows]

    def queue_position(self, investigation_id: str) -> int | None:
        with Session(self._engine) as session:
            row = session.get(InvestigationRow, investigation_id)
            if row is None or row.state != InvestigationState.QUEUED.value:
                return None
            ahead = session.scalar(
                select(func.count())
                .select_from(InvestigationRow)
                .where(
                    InvestigationRow.state == InvestigationState.QUEUED.value,
                    InvestigationRow.created_at < row.created_at,
                )
            )
            return int(ahead or 0) + 1

    def set_queue_waiting(
        self,
        investigation_id: str,
        *,
        reason: str | None,
        waiting_since: datetime | None = None,
    ) -> None:
        with Session(self._engine) as session:
            row = session.get(InvestigationRow, investigation_id)
            if row is None or row.state != InvestigationState.QUEUED.value:
                return
            row.queue_waiting_reason = reason
            if reason:
                row.queued_waiting_since = waiting_since or row.queued_waiting_since or utc_now()
            else:
                row.queued_waiting_since = None
            session.commit()

    def clear_queue_waiting(self, investigation_id: str) -> None:
        self.set_queue_waiting(investigation_id, reason=None)

    def claim_next_queued(self, runner_id: str) -> InvestigationRecord | None:
        """FIFO claim: ``BEGIN IMMEDIATE`` + conditional queued→running update.

        Only one concurrent runner receives a row; others get ``None`` or the next item.
        """
        claim_token = str(uuid4())
        now = utc_now()
        with Session(self._engine) as session:
            conn = session.connection()
            conn.execute(text("BEGIN IMMEDIATE"))
            row = session.scalar(
                select(InvestigationRow)
                .where(InvestigationRow.state == InvestigationState.QUEUED.value)
                .order_by(
                    InvestigationRow.created_at.asc(),
                    func.coalesce(InvestigationRow.batch_sort_order, 0).asc(),
                )
                .limit(1)
            )
            if row is None:
                session.commit()
                return None
            inv_id = row.investigation_id
            from_state = InvestigationState(row.state)
            row.state = InvestigationState.RUNNING.value
            row.started_at = now
            row.runner_claim_token = claim_token
            row.runner_claimed_at = now
            row.queue_waiting_reason = None
            row.queued_waiting_since = None
            session.commit()
            record = self._row_to_record(row)
        self._audit_transition(
            investigation_id=inv_id,
            actor=runner_id,
            repo=record.repo,
            requested_ref=record.requested_ref,
            from_state=from_state,
            to_state=InvestigationState.RUNNING,
            reason="runner claimed queued investigation",
        )
        return record

    def update_snapshot_bytes(self, investigation_id: str, snapshot_bytes: int) -> None:
        with Session(self._engine) as session:
            row = session.get(InvestigationRow, investigation_id)
            if row is None:
                return
            row.snapshot_bytes = max(0, snapshot_bytes)
            session.commit()

    def update_terminal_calls_used(self, investigation_id: str, count: int) -> None:
        with Session(self._engine) as session:
            row = session.get(InvestigationRow, investigation_id)
            if row is None:
                return
            row.terminal_calls_used = max(0, count)
            session.commit()

    def reap_orphaned_running(self, *, actor: str = "orchestrator") -> list[str]:
        """Fail investigations left in RUNNING after orchestrator restart.

        Constitution IV decision (claim release vs fail): **fail, do not re-queue**.

        Re-execution would duplicate sandbox work and mint a second audit trail for
        the same claim. Failing loses a partially complete investigation. We keep
        FAIL because this process has no III-style heartbeat or idempotent runner:
        releasing the claim would re-run the same investigation as a new execution
        with no merge of prior trace into a single authoritative record. The
        operator can launch a new investigation. Treat the in-flight run as mortal
        with the process.
        """
        reaped: list[str] = []
        with Session(self._engine) as session:
            rows = session.scalars(
                select(InvestigationRow).where(
                    InvestigationRow.state == InvestigationState.RUNNING.value
                )
            ).all()
            for row in rows:
                inv_id = row.investigation_id
                row.state = InvestigationState.FAILED.value
                row.finished_at = utc_now()
                row.outcome_reason = "orchestrator restarted during execution"
                row.runner_claim_token = None
                row.runner_claimed_at = None
                reaped.append(inv_id)
            session.commit()
        for inv_id in reaped:
            record = self.get(inv_id)
            if record is None:
                continue
            self._audit_transition(
                investigation_id=inv_id,
                actor=actor,
                repo=record.repo,
                requested_ref=record.requested_ref,
                from_state=InvestigationState.RUNNING,
                to_state=InvestigationState.FAILED,
                reason="orchestrator restarted during execution",
            )
        return reaped

    def count_candidates(self, investigation_id: str) -> int:
        with Session(self._engine) as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(InvestigationCandidateRow)
                    .where(InvestigationCandidateRow.investigation_id == investigation_id)
                )
                or 0
            )

    def open_disposition_count(self, investigation_id: str) -> int:
        with Session(self._engine) as session:
            return self._open_disposition_count(session, investigation_id)

    def exists(self, investigation_id: str) -> bool:
        with Session(self._engine) as session:
            return session.get(InvestigationRow, investigation_id) is not None

    def count_trace_turns(self, investigation_id: str) -> int:
        """Count all terminal attempts recorded in the trace, including duplicate suppressions."""
        with Session(self._engine) as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(InvestigationTraceRow)
                    .where(InvestigationTraceRow.investigation_id == investigation_id)
                )
                or 0
            )

    def count_trace_charged_turns(self, investigation_id: str) -> int:
        with Session(self._engine) as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(InvestigationTraceRow)
                    .where(
                        InvestigationTraceRow.investigation_id == investigation_id,
                        InvestigationTraceRow.charged.is_(True),
                    )
                )
                or 0
            )

    def get_detail(
        self,
        investigation_id: str,
        *,
        audit: AuditStore,
        include_children: bool = True,
    ) -> InvestigationRecord | None:
        from shift_left.investigations.reconciliation import reconcile_trace_audit

        record = self.get(investigation_id, include_children=include_children)
        if record is None:
            return None
        reconciliation = reconcile_trace_audit(self, audit, investigation_id)
        return record.model_copy(update={"audit_trace_reconciliation": reconciliation})

    def create_batch(
        self,
        *,
        source: str,
        repo: str,
        requested_ref: str,
        resolved_commit_sha: str,
        actor: str,
        profile_snapshot: dict[str, Any],
        top25_survivor_count: int | None,
        children: list[tuple[str, str, str, int]],
    ) -> InvestigationBatchRecord:
        batch_id = str(uuid4())
        now = utc_now()
        investigation_ids = [child[0] for child in children]
        row = InvestigationBatchRow(
            batch_id=batch_id,
            source=source,
            repo=repo.strip(),
            requested_ref=requested_ref.strip(),
            resolved_commit_sha=resolved_commit_sha.strip(),
            actor=actor.strip(),
            created_at=now,
            state=BatchState.ACTIVE.value,
            profile_snapshot_json=json.dumps(profile_snapshot),
            top25_survivor_count=top25_survivor_count,
        )
        with Session(self._engine) as session:
            session.add(row)
            for investigation_id, _cwe_id, _tier, sort_order in children:
                inv = session.get(InvestigationRow, investigation_id)
                if inv is None:
                    raise LookupError(f"Investigation not found: {investigation_id}")
                inv.batch_id = batch_id
                inv.batch_sort_order = sort_order
            session.commit()
        if self._audit is not None:
            self._audit.log(
                actor=actor,
                action="investigation.batch_launched",
                subject=f"{repo}@{requested_ref}",
                details={
                    "batch_id": batch_id,
                    "source": source,
                    "investigation_count": len(investigation_ids),
                    "investigation_ids": investigation_ids,
                },
            )
        return InvestigationBatchRecord(
            batch_id=batch_id,
            source=source,
            repo=repo.strip(),
            requested_ref=requested_ref.strip(),
            resolved_commit_sha=resolved_commit_sha.strip(),
            actor=actor.strip(),
            created_at=now,
            state=BatchState.ACTIVE,
            profile_snapshot=profile_snapshot,
            top25_survivor_count=top25_survivor_count,
            investigation_ids=investigation_ids,
        )

    def get_batch(self, batch_id: str) -> InvestigationBatchRecord | None:
        with Session(self._engine) as session:
            row = session.get(InvestigationBatchRow, batch_id)
            if row is None:
                return None
            return self._batch_from_row(row, session)

    def list_batch_children(self, batch_id: str) -> list[BatchChildRecord]:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(InvestigationRow)
                .where(InvestigationRow.batch_id == batch_id)
                .order_by(func.coalesce(InvestigationRow.batch_sort_order, 0).asc())
            ).all()
            children: list[BatchChildRecord] = []
            for row in rows:
                candidate_count = int(
                    session.scalar(
                        select(func.count())
                        .select_from(InvestigationCandidateRow)
                        .where(InvestigationCandidateRow.investigation_id == row.investigation_id)
                    )
                    or 0
                )
                tractability = "unrated"
                from shift_left.cwe.localization_candidates import localization_candidate_by_id

                catalog = localization_candidate_by_id(row.task_cwe)
                if catalog:
                    tractability = str(catalog.get("tractability") or "unrated")
                children.append(
                    BatchChildRecord(
                        batch_id=batch_id,
                        investigation_id=row.investigation_id,
                        task_cwe=row.task_cwe,
                        sort_order=int(row.batch_sort_order or 0),
                        profile_evidence_tier=str(row.profile_evidence_tier or "none"),
                        tractability=tractability,
                        candidate_count=candidate_count,
                    )
                )
            return children

    def refresh_batch_state(self, batch_id: str) -> InvestigationBatchRecord | None:
        with Session(self._engine) as session:
            batch_row = session.get(InvestigationBatchRow, batch_id)
            if batch_row is None:
                return None
            if batch_row.state != BatchState.ACTIVE.value:
                return self._batch_from_row(batch_row, session)
            rows = session.scalars(
                select(InvestigationRow).where(InvestigationRow.batch_id == batch_id)
            ).all()
            if not rows:
                return self._batch_from_row(batch_row, session)
            active = any(
                row.state in {InvestigationState.QUEUED.value, InvestigationState.RUNNING.value}
                for row in rows
            )
            if not active:
                batch_row.state = BatchState.COMPLETED.value
                session.commit()
            return self._batch_from_row(batch_row, session)

    def mark_batch_cancelled(self, batch_id: str) -> InvestigationBatchRecord | None:
        with Session(self._engine) as session:
            batch_row = session.get(InvestigationBatchRow, batch_id)
            if batch_row is None:
                return None
            batch_row.state = BatchState.CANCELLED.value
            session.commit()
            return self._batch_from_row(batch_row, session)

    def purge_expired(self, *, as_of: datetime | None = None) -> int:
        """Remove investigations older than retention window. Audit events are not purged."""
        cutoff = (as_of or utc_now()) - timedelta(days=self._retention_days)
        with Session(self._engine) as session:
            ids = session.scalars(
                select(InvestigationRow.investigation_id).where(
                    InvestigationRow.created_at < cutoff
                )
            ).all()
            if not ids:
                return 0
            session.execute(
                delete(InvestigationTraceRow).where(
                    InvestigationTraceRow.investigation_id.in_(ids)
                )
            )
            session.execute(
                delete(InvestigationCandidateRow).where(
                    InvestigationCandidateRow.investigation_id.in_(ids)
                )
            )
            session.execute(delete(InvestigationRow).where(InvestigationRow.investigation_id.in_(ids)))
            session.commit()
            return len(ids)

    def _audit_launch(
        self,
        *,
        investigation_id: str,
        actor: str,
        repo: str,
        requested_ref: str,
        resolved_commit_sha: str,
        task_cwe: str,
        advisory_cve: str | None,
    ) -> None:
        if self._audit is None:
            return
        self._audit.log(
            actor=actor,
            action="investigation.launched",
            subject=f"{repo}@{requested_ref}",
            details={
                "source": INVESTIGATION_SOURCE_ANTARES,
                "investigation_id": investigation_id,
                "repo": repo,
                "requested_ref": requested_ref,
                "resolved_commit_sha": resolved_commit_sha,
                "task_cwe": task_cwe,
                "advisory_cve": advisory_cve,
            },
        )

    def _audit_disposition_change(
        self,
        *,
        investigation_id: str,
        file_path: str,
        from_disposition: str,
        to_disposition: str,
        actor: str,
        note: str | None,
    ) -> None:
        if self._audit is None:
            return
        self._audit.log(
            actor=actor,
            action="investigation.disposition_updated",
            subject=f"investigation:{investigation_id}",
            details={
                "source": INVESTIGATION_SOURCE_ANTARES,
                "investigation_id": investigation_id,
                "file_path": file_path,
                "from_disposition": from_disposition,
                "to_disposition": to_disposition,
                "actor": actor,
                "note": note,
            },
        )

    def _audit_transition(
        self,
        *,
        investigation_id: str,
        actor: str,
        repo: str,
        requested_ref: str,
        from_state: InvestigationState | None,
        to_state: InvestigationState,
        reason: str | None,
    ) -> None:
        if self._audit is None:
            return
        self._audit.log(
            actor=actor,
            action="investigation.state_transition",
            subject=f"{repo}@{requested_ref}",
            details={
                "source": INVESTIGATION_SOURCE_ANTARES,
                "investigation_id": investigation_id,
                "from_state": from_state.value if from_state else None,
                "to_state": to_state.value,
                "reason": reason,
            },
        )

    def _migrate_schema(self) -> None:
        investigation_columns = {
            "originating_investigation_id": "TEXT",
            "queue_waiting_reason": "TEXT",
            "queued_waiting_since": "TEXT",
            "runner_claim_token": "TEXT",
            "runner_claimed_at": "TEXT",
            "batch_id": "TEXT",
            "batch_sort_order": "INTEGER",
            "profile_evidence_tier": "TEXT",
            "exclude_test_paths": "INTEGER NOT NULL DEFAULT 1",
            "snapshot_scope": "TEXT NOT NULL DEFAULT 'full'",
            "snapshot_base_ref": "TEXT",
        }
        trace_columns = {
            "charged": "INTEGER NOT NULL DEFAULT 1",
            "duplicate_of_turn": "INTEGER",
            "command_id": "TEXT",
            "phase": "TEXT NOT NULL DEFAULT 'completed'",
        }
        with self._engine.connect() as conn:
            existing = {
                row[1] for row in conn.exec_driver_sql("PRAGMA table_info(investigations)")
            }
            for name, sql_type in investigation_columns.items():
                if name not in existing:
                    conn.exec_driver_sql(
                        f"ALTER TABLE investigations ADD COLUMN {name} {sql_type}"
                    )
            trace_existing = {
                row[1]
                for row in conn.exec_driver_sql("PRAGMA table_info(investigation_trace_turns)")
            }
            for name, sql_type in trace_columns.items():
                if trace_existing and name not in trace_existing:
                    conn.exec_driver_sql(
                        f"ALTER TABLE investigation_trace_turns ADD COLUMN {name} {sql_type}"
                    )
            conn.commit()

    @staticmethod
    def _batch_from_row(row: InvestigationBatchRow, session: Session) -> InvestigationBatchRecord:
        investigation_ids = list(
            session.scalars(
                select(InvestigationRow.investigation_id)
                .where(InvestigationRow.batch_id == row.batch_id)
                .order_by(func.coalesce(InvestigationRow.batch_sort_order, 0).asc())
            ).all()
        )
        try:
            profile_snapshot = json.loads(row.profile_snapshot_json or "{}")
        except json.JSONDecodeError:
            profile_snapshot = {}
        return InvestigationBatchRecord(
            batch_id=row.batch_id,
            source=row.source,
            repo=row.repo,
            requested_ref=row.requested_ref,
            resolved_commit_sha=row.resolved_commit_sha,
            actor=row.actor,
            created_at=row.created_at,
            state=BatchState(row.state),
            profile_snapshot=profile_snapshot,
            top25_survivor_count=row.top25_survivor_count,
            investigation_ids=investigation_ids,
        )

    @staticmethod
    def _row_to_record(row: InvestigationRow) -> InvestigationRecord:
        return InvestigationRecord(
            investigation_id=row.investigation_id,
            source=INVESTIGATION_SOURCE_ANTARES,
            repo=row.repo,
            requested_ref=row.requested_ref,
            resolved_commit_sha=row.resolved_commit_sha,
            task_cwe=row.task_cwe,
            task_cwe_description=row.task_cwe_description,
            advisory_cve=row.advisory_cve,
            state=InvestigationState(row.state),
            model_variant=row.model_variant,
            model_sha256=row.model_sha256,
            created_at=row.created_at,
            started_at=row.started_at,
            finished_at=row.finished_at,
            terminal_calls_used=row.terminal_calls_used,
            terminal_call_budget=row.terminal_call_budget,
            outcome_reason=row.outcome_reason,
            actor=row.actor,
            snapshot_bytes=row.snapshot_bytes,
            originating_investigation_id=row.originating_investigation_id,
            queue_waiting_reason=row.queue_waiting_reason,
            queued_waiting_since=row.queued_waiting_since,
            runner_claim_token=row.runner_claim_token,
            runner_claimed_at=row.runner_claimed_at,
            batch_id=row.batch_id,
            batch_sort_order=row.batch_sort_order,
            profile_evidence_tier=row.profile_evidence_tier,
            exclude_test_paths=bool(getattr(row, "exclude_test_paths", 1)),
            snapshot_scope=str(getattr(row, "snapshot_scope", None) or "full"),
            snapshot_base_ref=getattr(row, "snapshot_base_ref", None),
        )

    @staticmethod
    def _candidate_from_row(row: InvestigationCandidateRow) -> CandidateRecord:
        return CandidateRecord(
            investigation_id=row.investigation_id,
            submission_rank=row.submission_rank,
            file_path=row.file_path,
            disposition=CandidateDisposition(row.disposition),
            disposition_actor=row.disposition_actor,
            disposition_at=row.disposition_at,
            disposition_note=row.disposition_note,
        )

    @staticmethod
    def _load_candidates(session: Session, investigation_id: str) -> list[CandidateRecord]:
        rows = session.scalars(
            select(InvestigationCandidateRow)
            .where(InvestigationCandidateRow.investigation_id == investigation_id)
            .order_by(InvestigationCandidateRow.submission_rank.asc())
        ).all()
        return [InvestigationStore._candidate_from_row(row) for row in rows]

    @staticmethod
    def _load_trace(session: Session, investigation_id: str) -> list[TraceRecord]:
        rows = session.scalars(
            select(InvestigationTraceRow)
            .where(InvestigationTraceRow.investigation_id == investigation_id)
            .order_by(InvestigationTraceRow.turn_index.asc())
        ).all()
        return [
            TraceRecord(
                investigation_id=row.investigation_id,
                turn_index=row.turn_index,
                command=row.command,
                exit_status=row.exit_status,
                output_truncated=row.output_truncated,
                executed_at=row.executed_at,
                charged=bool(getattr(row, "charged", True)),
                duplicate_of_turn=getattr(row, "duplicate_of_turn", None),
                command_id=getattr(row, "command_id", None),
                phase=getattr(row, "phase", None) or "completed",
            )
            for row in rows
        ]

    @staticmethod
    def _open_disposition_count(session: Session, investigation_id: str) -> int:
        return int(
            session.scalar(
                select(func.count())
                .select_from(InvestigationCandidateRow)
                .where(
                    InvestigationCandidateRow.investigation_id == investigation_id,
                    InvestigationCandidateRow.disposition == CandidateDisposition.OPEN.value,
                )
            )
            or 0
        )
