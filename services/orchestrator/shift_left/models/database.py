"""SQLite persistence: findings, audit log, approvals, policy decisions."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import DateTime, Float, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from shift_left.models.schema import (
    ApprovalRecord,
    AuditEvent,
    BlockOverrideRecord,
    Finding,
    FindingEnrichment,
    FindingSource,
    FindingStatus,
    FindingWaiverRecord,
    LineRange,
    PolicyAction,
    PolicySeverity,
    PullRequestPolicyDecision,
    Severity,
    TargetKind,
    utc_now,
)
from shift_left.ui.cwe_dictionary import model_cwe_recognition

SYSTEM_ACTOR = "system:shift-left"


class Base(DeclarativeBase):
    pass


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source: Mapped[str] = mapped_column(String(32))
    target_kind: Mapped[str] = mapped_column(String(16))
    repo: Mapped[str] = mapped_column(String(512))
    pr_ref: Mapped[str] = mapped_column(String(128))
    commit_sha: Mapped[str] = mapped_column(String(64))
    file_path: Mapped[str] = mapped_column(String(1024))
    line_range_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    handler_asserted_cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cve_refs_json: Mapped[str] = mapped_column(Text, default="[]")
    severity: Mapped[str] = mapped_column(String(16))
    policy_severity: Mapped[str] = mapped_column(String(16), default=PolicySeverity.UNCLASSIFIED.value)
    confidence: Mapped[float] = mapped_column(Float)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    trace: Mapped[str | None] = mapped_column(Text, nullable=True)
    enrichment_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default=FindingStatus.OPEN.value)
    status_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_actor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    model_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_actions_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    enrichment_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enrichment_generated_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    construct_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(64))
    subject: Mapped[str] = mapped_column(String(512))
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    protected: Mapped[str] = mapped_column(String(8), default="false")


class ApprovalRow(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    repo: Mapped[str] = mapped_column(String(512))
    pr_ref: Mapped[str] = mapped_column(String(128))
    commit_sha: Mapped[str] = mapped_column(String(64))
    approver: Mapped[str] = mapped_column(String(256))
    commit_author: Mapped[str | None] = mapped_column(String(256), nullable=True)
    approver_matches_author: Mapped[str | None] = mapped_column(String(8), nullable=True)
    separation_of_duties_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    findings_snapshot_json: Mapped[str] = mapped_column(Text)
    policy_decision: Mapped[str] = mapped_column(String(16))
    policy_decision_snapshot_json: Mapped[str] = mapped_column(Text)
    invalidated: Mapped[str] = mapped_column(String(8), default="false")
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    invalidation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked: Mapped[str] = mapped_column(String(8), default="false")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(256), nullable=True)


class BlockOverrideRow(Base):
    __tablename__ = "block_overrides"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    repo: Mapped[str] = mapped_column(String(512))
    pr_ref: Mapped[str] = mapped_column(String(128))
    commit_sha: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(256))
    justification: Mapped[str] = mapped_column(Text)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    policy_id: Mapped[str | None] = mapped_column(String(128), nullable=True)


class FindingWaiverRow(Base):
    __tablename__ = "finding_waivers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    repo: Mapped[str] = mapped_column(String(512))
    pr_ref: Mapped[str] = mapped_column(String(128))
    commit_sha: Mapped[str] = mapped_column(String(64))
    target_kind: Mapped[str] = mapped_column(String(16))
    rule_id: Mapped[str] = mapped_column(String(32))
    file_path: Mapped[str] = mapped_column(String(1024))
    line_start: Mapped[int] = mapped_column(Integer)
    construct_key: Mapped[str] = mapped_column(Text, default="")
    weakness_class: Mapped[str] = mapped_column(String(32), default="")
    finding_id: Mapped[str] = mapped_column(String(36))
    actor: Mapped[str] = mapped_column(String(256))
    reason: Mapped[str] = mapped_column(Text)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    commit_author: Mapped[str | None] = mapped_column(String(256), nullable=True)
    actor_matches_author: Mapped[str | None] = mapped_column(String(8), nullable=True)
    self_granted: Mapped[str] = mapped_column(String(8), default="false")
    granted_with_capability: Mapped[str] = mapped_column(String(32), default="approve")
    invalidated: Mapped[str] = mapped_column(String(8), default="false")
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    invalidation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class PolicyDecisionRow(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    repo: Mapped[str] = mapped_column(String(512))
    pr_ref: Mapped[str] = mapped_column(String(128))
    commit_sha: Mapped[str] = mapped_column(String(64))
    decision_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TerraformPlanRow(Base):
    __tablename__ = "terraform_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    repo: Mapped[str] = mapped_column(String(512))
    pr_ref: Mapped[str] = mapped_column(String(128))
    commit_sha: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(128))
    summary_add: Mapped[int] = mapped_column(Integer, default=0)
    summary_change: Mapped[int] = mapped_column(Integer, default=0)
    summary_destroy: Mapped[int] = mapped_column(Integer, default=0)
    output_text: Mapped[str] = mapped_column(Text)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    generated_by: Mapped[str] = mapped_column(String(256))
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    stale: Mapped[str] = mapped_column(String(8), default="false")
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def _create_engine(sqlite_path: str):
    path = Path(sqlite_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{path}", future=True)


class FindingsStore:
    def __init__(self, sqlite_path: str) -> None:
        self._engine = _create_engine(sqlite_path)
        Base.metadata.create_all(self._engine)
        self._ensure_columns()
        self._session_factory = sessionmaker(self._engine, expire_on_commit=False)

    def _ensure_columns(self) -> None:
        with self._engine.connect() as conn:
            rows = conn.exec_driver_sql("PRAGMA table_info(findings)").fetchall()
            columns = {row[1] for row in rows}
            for name, ddl in (
                ("enrichment_json", "ALTER TABLE findings ADD COLUMN enrichment_json TEXT"),
                ("status_rationale", "ALTER TABLE findings ADD COLUMN status_rationale TEXT"),
                ("status_actor", "ALTER TABLE findings ADD COLUMN status_actor TEXT"),
                ("policy_severity", "ALTER TABLE findings ADD COLUMN policy_severity TEXT"),
                ("handler_asserted_cwe", "ALTER TABLE findings ADD COLUMN handler_asserted_cwe TEXT"),
                ("model_context", "ALTER TABLE findings ADD COLUMN model_context TEXT"),
                ("recommended_actions_json", "ALTER TABLE findings ADD COLUMN recommended_actions_json TEXT"),
                ("enrichment_source", "ALTER TABLE findings ADD COLUMN enrichment_source TEXT"),
                ("enrichment_generated_at", "ALTER TABLE findings ADD COLUMN enrichment_generated_at TEXT"),
                ("construct_key", "ALTER TABLE findings ADD COLUMN construct_key TEXT"),
            ):
                if name not in columns:
                    conn.exec_driver_sql(ddl)
            conn.commit()

    def save_findings(self, findings: list[Finding]) -> None:
        with Session(self._engine) as session:
            for finding in findings:
                session.merge(self._to_row(finding))
            session.commit()

    def get(self, finding_id: str) -> Finding | None:
        with Session(self._engine) as session:
            row = session.get(FindingRow, finding_id)
            return self._from_row(row) if row else None

    def list_for_pr(self, repo: str, pr_ref: str) -> list[Finding]:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(FindingRow)
                .where(FindingRow.repo == repo, FindingRow.pr_ref == pr_ref)
                .order_by(FindingRow.created_at.desc())
            ).all()
            return [self._from_row(row) for row in rows]

    def list_filtered(
        self,
        *,
        repo: str | None = None,
        pr_ref: str | None = None,
        target_kind: str | None = None,
        policy_severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        limit: int = 500,
    ) -> list[Finding]:
        with Session(self._engine) as session:
            query = select(FindingRow).order_by(FindingRow.created_at.desc()).limit(limit)
            rows = session.scalars(query).all()
        findings = [self._from_row(row) for row in rows]
        if repo:
            findings = [item for item in findings if item.repo == repo]
        if pr_ref:
            findings = [item for item in findings if item.pr_ref == pr_ref]
        if target_kind:
            findings = [item for item in findings if item.target_kind.value == target_kind]
        if policy_severity:
            findings = [item for item in findings if item.policy_severity.value == policy_severity]
        if status:
            findings = [item for item in findings if item.status.value == status]
        if source:
            findings = [item for item in findings if item.source.value == source]
        return findings

    def list_model_only(self, *, limit: int = 500) -> list[Finding]:
        findings = self.list_filtered(limit=limit)
        return [item for item in findings if item.is_model_only]

    def update_status(
        self,
        finding_id: str,
        status: FindingStatus,
        *,
        actor: str,
        rationale: str | None = None,
    ) -> Finding | None:
        with Session(self._engine) as session:
            row = session.get(FindingRow, finding_id)
            if not row:
                return None
            row.status = status.value
            row.status_actor = actor
            row.status_rationale = rationale
            row.updated_at = utc_now()
            session.commit()
            return self._from_row(row)

    @staticmethod
    def _to_row(finding: Finding) -> FindingRow:
        line_range_json = None
        if finding.line_range:
            line_range_json = json.dumps(
                {"start": finding.line_range.start, "end": finding.line_range.end}
            )
        enrichment_json = finding.enrichment.model_dump_json() if finding.enrichment else None
        return FindingRow(
            id=finding.id,
            source=finding.source.value,
            target_kind=finding.target_kind.value,
            repo=finding.repo,
            pr_ref=finding.pr_ref,
            commit_sha=finding.commit_sha,
            file_path=finding.file_path,
            line_range_json=line_range_json,
            cwe=finding.model_asserted_cwe,
            handler_asserted_cwe=finding.handler_asserted_cwe,
            cve_refs_json=json.dumps(finding.cve_refs),
            severity=finding.model_asserted_severity.value,
            policy_severity=finding.policy_severity.value,
            confidence=finding.confidence,
            title=finding.title,
            description=finding.description,
            evidence=finding.evidence,
            trace=finding.trace,
            enrichment_json=enrichment_json,
            status=finding.status.value,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
            enrichment_source=finding.enrichment_source,
            enrichment_generated_at=(
                finding.enrichment_generated_at.isoformat()
                if finding.enrichment_generated_at
                else None
            ),
            model_context=finding.model_context,
            recommended_actions_json=json.dumps(finding.recommended_actions),
            construct_key=finding.construct_key,
        )

    @staticmethod
    def _from_row(row: FindingRow) -> Finding:
        enrichment = None
        if row.enrichment_json:
            enrichment = FindingEnrichment.model_validate_json(row.enrichment_json)
        line_range = None
        if row.line_range_json:
            data = json.loads(row.line_range_json)
            line_range = LineRange(start=data["start"], end=data["end"])
        model_cwe, model_cwe_recognized = model_cwe_recognition(row.cwe)
        return Finding(
            id=row.id,
            source=FindingSource(row.source),
            target_kind=TargetKind(row.target_kind),
            repo=row.repo,
            pr_ref=row.pr_ref,
            commit_sha=row.commit_sha,
            file_path=row.file_path,
            line_range=line_range,
            model_asserted_cwe=model_cwe,
            model_cwe_recognized=model_cwe_recognized,
            handler_asserted_cwe=getattr(row, "handler_asserted_cwe", None),
            cve_refs=json.loads(row.cve_refs_json or "[]"),
            model_asserted_severity=Severity(row.severity),
            policy_severity=PolicySeverity(
                getattr(row, "policy_severity", None) or PolicySeverity.UNCLASSIFIED.value
            ),
            confidence=row.confidence,
            title=row.title,
            description=row.description,
            evidence=row.evidence,
            trace=row.trace,
            enrichment=enrichment,
            model_context=row.model_context,
            recommended_actions=json.loads(row.recommended_actions_json or "[]"),
            enrichment_source=row.enrichment_source,
            enrichment_generated_at=(
                datetime.fromisoformat(row.enrichment_generated_at.replace("Z", "+00:00"))
                if row.enrichment_generated_at
                else None
            ),
            status=FindingStatus(row.status),
            construct_key=getattr(row, "construct_key", None) or None,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


class AuditStore:
    """Append-only audit log — no update or delete API."""

    def __init__(self, sqlite_path: str, *, retention_days: int = 365) -> None:
        self._engine = _create_engine(sqlite_path)
        self._retention_days = retention_days
        Base.metadata.create_all(self._engine)
        self._ensure_columns()

    def _ensure_columns(self) -> None:
        with self._engine.connect() as conn:
            rows = conn.exec_driver_sql("PRAGMA table_info(audit_events)").fetchall()
            columns = {row[1] for row in rows}
            if "protected" not in columns:
                conn.exec_driver_sql("ALTER TABLE audit_events ADD COLUMN protected TEXT DEFAULT 'false'")
            conn.commit()

    def append(self, event: AuditEvent, *, protected: bool = False) -> AuditEvent:
        row = AuditEventRow(
            id=event.id,
            timestamp=event.timestamp,
            actor=event.actor,
            action=event.action,
            subject=event.subject,
            details_json=json.dumps(event.details),
            protected="true" if protected else "false",
        )
        with Session(self._engine) as session:
            session.add(row)
            session.commit()
        return event

    def log(
        self,
        *,
        actor: str,
        action: str,
        subject: str,
        details: dict[str, Any] | None = None,
        protected: bool = False,
    ) -> AuditEvent:
        if not actor or not str(actor).strip():
            raise ValueError("Audit events require a non-null actor derived from identity")
        event = AuditEvent(actor=actor, action=action, subject=subject, details=details or {})
        return self.append(event, protected=protected)

    def list_events(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        subject_prefix: str | None = None,
        since: datetime | None = None,
        limit: int = 200,
    ) -> list[AuditEvent]:
        with Session(self._engine) as session:
            query = select(AuditEventRow).order_by(AuditEventRow.timestamp.desc()).limit(limit)
            rows = session.scalars(query).all()
        events = [self._from_row(row) for row in rows]
        if actor:
            events = [event for event in events if event.actor == actor]
        if action:
            events = [event for event in events if event.action == action]
        if subject_prefix:
            events = [event for event in events if event.subject.startswith(subject_prefix)]
        if since:
            events = [event for event in events if event.timestamp >= since]
        return events

    def export_all(self) -> list[dict[str, Any]]:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(AuditEventRow).order_by(AuditEventRow.timestamp.asc())
            ).all()
        return [self._from_row(row).model_dump(mode="json") for row in rows]

    def export_range(
        self,
        *,
        before: datetime,
        export_path: str | Path,
    ) -> int:
        """Write events strictly before ``before`` to ``export_path`` as JSON."""
        path = Path(export_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with Session(self._engine) as session:
            rows = session.scalars(
                select(AuditEventRow).order_by(AuditEventRow.timestamp.asc())
            ).all()
        to_export = []
        for row in rows:
            ts = row.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts < before:
                to_export.append(self._from_row(row).model_dump(mode="json"))
        payload = {
            "exported_at": utc_now().isoformat(),
            "before": before.isoformat(),
            "event_count": len(to_export),
            "events": to_export,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return len(to_export)

    def prune_before(
        self,
        *,
        before: datetime,
        export_path: str | Path,
        actor: str,
    ) -> dict[str, Any]:
        """
        Operator-initiated pruning: export affected range, then delete non-protected events.

        Writes a protected audit event recording the prune — that event is never prunable.
        """
        exported = self.export_range(before=before, export_path=export_path)

        deleted = 0
        with Session(self._engine) as session:
            rows = session.scalars(select(AuditEventRow)).all()
            for row in rows:
                if row.protected == "true":
                    continue
                ts = row.timestamp
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < before:
                    session.delete(row)
                    deleted += 1
            session.commit()

        prune_event = self.log(
            actor=actor,
            action="audit.pruned",
            subject="audit_events",
            details={
                "before": before.isoformat(),
                "deleted_count": deleted,
                "exported_count": exported,
                "export_destination": str(export_path),
            },
            protected=True,
        )
        return {
            "deleted_count": deleted,
            "exported_count": exported,
            "export_destination": str(export_path),
            "prune_event_id": prune_event.id,
        }

    @staticmethod
    def _from_row(row: AuditEventRow) -> AuditEvent:
        return AuditEvent(
            id=row.id,
            timestamp=row.timestamp,
            actor=row.actor,
            action=row.action,
            subject=row.subject,
            details=json.loads(row.details_json or "{}"),
        )


class ApprovalStore:
    def __init__(self, sqlite_path: str) -> None:
        self._engine = _create_engine(sqlite_path)
        Base.metadata.create_all(self._engine)
        self._ensure_columns()

    def _ensure_columns(self) -> None:
        with self._engine.connect() as conn:
            rows = conn.exec_driver_sql("PRAGMA table_info(approvals)").fetchall()
            columns = {row[1] for row in rows}
            for name, ddl in (
                ("commit_author", "ALTER TABLE approvals ADD COLUMN commit_author TEXT"),
                ("approver_matches_author", "ALTER TABLE approvals ADD COLUMN approver_matches_author TEXT"),
                ("separation_of_duties_result", "ALTER TABLE approvals ADD COLUMN separation_of_duties_result TEXT"),
            ):
                if name not in columns:
                    conn.exec_driver_sql(ddl)
            conn.commit()

    def grant(self, record: ApprovalRecord) -> ApprovalRecord:
        row = ApprovalRow(
            id=record.id,
            repo=record.repo,
            pr_ref=record.pr_ref,
            commit_sha=record.commit_sha,
            approver=record.approver,
            commit_author=record.commit_author,
            approver_matches_author=(
                "true" if record.approver_matches_author else "false"
                if record.approver_matches_author is not None
                else None
            ),
            separation_of_duties_result=record.separation_of_duties_result,
            approved_at=record.approved_at,
            findings_snapshot_json=json.dumps(record.findings_snapshot),
            policy_decision=record.policy_decision.value,
            policy_decision_snapshot_json=json.dumps(record.policy_decision_snapshot),
            invalidated="false",
        )
        with Session(self._engine) as session:
            session.add(row)
            session.commit()
        return record

    def revoke(self, repo: str, pr_ref: str, *, actor: str) -> int:
        count = 0
        with Session(self._engine) as session:
            rows = session.scalars(
                select(ApprovalRow).where(
                    ApprovalRow.repo == repo,
                    ApprovalRow.pr_ref == pr_ref,
                    ApprovalRow.revoked == "false",
                )
            ).all()
            for row in rows:
                row.revoked = "true"
                row.revoked_at = utc_now()
                row.revoked_by = actor
                count += 1
            session.commit()
        return count

    def invalidate_for_new_commit(
        self,
        repo: str,
        pr_ref: str,
        *,
        new_commit_sha: str,
        reason: str,
    ) -> int:
        count = 0
        with Session(self._engine) as session:
            rows = session.scalars(
                select(ApprovalRow).where(
                    ApprovalRow.repo == repo,
                    ApprovalRow.pr_ref == pr_ref,
                    ApprovalRow.invalidated == "false",
                    ApprovalRow.revoked == "false",
                )
            ).all()
            for row in rows:
                if row.commit_sha != new_commit_sha:
                    row.invalidated = "true"
                    row.invalidated_at = utc_now()
                    row.invalidation_reason = reason
                    count += 1
            session.commit()
        return count

    def active_for_commit(self, repo: str, pr_ref: str, commit_sha: str) -> ApprovalRecord | None:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(ApprovalRow)
                .where(
                    ApprovalRow.repo == repo,
                    ApprovalRow.pr_ref == pr_ref,
                    ApprovalRow.commit_sha == commit_sha,
                    ApprovalRow.invalidated == "false",
                    ApprovalRow.revoked == "false",
                )
                .order_by(ApprovalRow.approved_at.desc())
            ).all()
            if not rows:
                return None
            return self._from_row(rows[0])

    def list_for_pr(self, repo: str, pr_ref: str) -> list[ApprovalRecord]:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(ApprovalRow)
                .where(ApprovalRow.repo == repo, ApprovalRow.pr_ref == pr_ref)
                .order_by(ApprovalRow.approved_at.desc())
            ).all()
            return [self._from_row(row) for row in rows]

    @staticmethod
    def _from_row(row: ApprovalRow) -> ApprovalRecord:
        return ApprovalRecord(
            id=row.id,
            repo=row.repo,
            pr_ref=row.pr_ref,
            commit_sha=row.commit_sha,
            approver=row.approver,
            commit_author=row.commit_author,
            approver_matches_author=(
                row.approver_matches_author == "true"
                if row.approver_matches_author is not None
                else None
            ),
            separation_of_duties_result=row.separation_of_duties_result,
            approved_at=row.approved_at,
            findings_snapshot=json.loads(row.findings_snapshot_json or "[]"),
            policy_decision=PolicyAction(row.policy_decision),
            policy_decision_snapshot=json.loads(row.policy_decision_snapshot_json or "{}"),
            invalidated=row.invalidated == "true",
            invalidated_at=row.invalidated_at,
            invalidation_reason=row.invalidation_reason,
        )


class BlockOverrideStore:
    def __init__(self, sqlite_path: str) -> None:
        self._engine = _create_engine(sqlite_path)
        Base.metadata.create_all(self._engine)

    def grant(self, record: BlockOverrideRecord) -> BlockOverrideRecord:
        row = BlockOverrideRow(
            id=record.id,
            repo=record.repo,
            pr_ref=record.pr_ref,
            commit_sha=record.commit_sha,
            actor=record.actor,
            justification=record.justification,
            granted_at=record.granted_at,
            policy_id=record.policy_id,
        )
        with Session(self._engine) as session:
            session.add(row)
            session.commit()
        return record

    def active_for_commit(self, repo: str, pr_ref: str, commit_sha: str) -> BlockOverrideRecord | None:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(BlockOverrideRow)
                .where(
                    BlockOverrideRow.repo == repo,
                    BlockOverrideRow.pr_ref == pr_ref,
                    BlockOverrideRow.commit_sha == commit_sha,
                )
                .order_by(BlockOverrideRow.granted_at.desc())
            ).all()
            if not rows:
                return None
            row = rows[0]
            return BlockOverrideRecord(
                id=row.id,
                repo=row.repo,
                pr_ref=row.pr_ref,
                commit_sha=row.commit_sha,
                actor=row.actor,
                justification=row.justification,
                granted_at=row.granted_at,
                policy_id=row.policy_id,
            )


class FindingWaiverStore:
    def __init__(self, sqlite_path: str) -> None:
        self._engine = _create_engine(sqlite_path)
        Base.metadata.create_all(self._engine)
        self._ensure_columns()

    def _ensure_columns(self) -> None:
        with self._engine.connect() as conn:
            rows = conn.exec_driver_sql("PRAGMA table_info(finding_waivers)").fetchall()
            columns = {row[1] for row in rows}
            if "granted_with_capability" not in columns:
                conn.exec_driver_sql(
                    "ALTER TABLE finding_waivers ADD COLUMN granted_with_capability TEXT DEFAULT 'approve'"
                )
            if "construct_key" not in columns:
                conn.exec_driver_sql(
                    "ALTER TABLE finding_waivers ADD COLUMN construct_key TEXT DEFAULT ''"
                )
            if "weakness_class" not in columns:
                conn.exec_driver_sql(
                    "ALTER TABLE finding_waivers ADD COLUMN weakness_class TEXT DEFAULT ''"
                )
            conn.commit()

    def grant(self, record: FindingWaiverRecord) -> FindingWaiverRecord:
        row = FindingWaiverRow(
            id=record.id,
            repo=record.repo,
            pr_ref=record.pr_ref,
            commit_sha=record.commit_sha,
            target_kind=record.target_kind,
            rule_id=record.rule_id,
            file_path=record.file_path,
            line_start=record.line_start,
            construct_key=record.construct_key,
            weakness_class=record.weakness_class,
            finding_id=record.finding_id,
            actor=record.actor,
            reason=record.reason,
            granted_at=record.granted_at,
            commit_author=record.commit_author,
            actor_matches_author=(
                "true" if record.actor_matches_author else "false"
                if record.actor_matches_author is not None
                else None
            ),
            self_granted="true" if record.self_granted else "false",
            granted_with_capability=record.granted_with_capability,
            invalidated="false",
        )
        with Session(self._engine) as session:
            session.add(row)
            session.commit()
        return record

    def active_for_commit(self, repo: str, pr_ref: str, commit_sha: str) -> list[FindingWaiverRecord]:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(FindingWaiverRow)
                .where(
                    FindingWaiverRow.repo == repo,
                    FindingWaiverRow.pr_ref == pr_ref,
                    FindingWaiverRow.commit_sha == commit_sha,
                    FindingWaiverRow.invalidated == "false",
                )
                .order_by(FindingWaiverRow.granted_at.desc())
            ).all()
            return [self._from_row(row) for row in rows]

    def list_for_pr(self, repo: str, pr_ref: str) -> list[FindingWaiverRecord]:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(FindingWaiverRow)
                .where(FindingWaiverRow.repo == repo, FindingWaiverRow.pr_ref == pr_ref)
                .order_by(FindingWaiverRow.granted_at.desc())
            ).all()
            return [self._from_row(row) for row in rows]

    def invalidate_for_new_commit(
        self,
        repo: str,
        pr_ref: str,
        *,
        new_commit_sha: str,
        reason: str,
    ) -> list[FindingWaiverRecord]:
        expired: list[FindingWaiverRecord] = []
        with Session(self._engine) as session:
            rows = session.scalars(
                select(FindingWaiverRow).where(
                    FindingWaiverRow.repo == repo,
                    FindingWaiverRow.pr_ref == pr_ref,
                    FindingWaiverRow.invalidated == "false",
                )
            ).all()
            for row in rows:
                if row.commit_sha == new_commit_sha:
                    continue
                row.invalidated = "true"
                row.invalidated_at = utc_now()
                row.invalidation_reason = reason
                expired.append(self._from_row(row))
            session.commit()
        return expired

    @staticmethod
    def _from_row(row: FindingWaiverRow) -> FindingWaiverRecord:
        return FindingWaiverRecord(
            id=row.id,
            repo=row.repo,
            pr_ref=row.pr_ref,
            commit_sha=row.commit_sha,
            target_kind=row.target_kind,
            rule_id=row.rule_id,
            file_path=row.file_path,
            line_start=row.line_start,
            construct_key=getattr(row, "construct_key", None) or "",
            weakness_class=getattr(row, "weakness_class", None) or "",
            finding_id=row.finding_id,
            actor=row.actor,
            reason=row.reason,
            granted_at=row.granted_at,
            commit_author=row.commit_author,
            actor_matches_author=(
                row.actor_matches_author == "true"
                if row.actor_matches_author is not None
                else None
            ),
            self_granted=row.self_granted == "true",
            granted_with_capability=getattr(row, "granted_with_capability", None) or "approve",
            invalidated=row.invalidated == "true",
            invalidated_at=row.invalidated_at,
            invalidation_reason=row.invalidation_reason,
        )


class PolicyDecisionStore:
    def __init__(self, sqlite_path: str) -> None:
        self._engine = _create_engine(sqlite_path)
        Base.metadata.create_all(self._engine)

    def save(self, decision: PullRequestPolicyDecision) -> PullRequestPolicyDecision:
        import uuid

        row = PolicyDecisionRow(
            id=str(uuid.uuid4()),
            repo=decision.repo,
            pr_ref=decision.pr_ref,
            commit_sha=decision.commit_sha,
            decision_json=decision.model_dump_json(),
            created_at=utc_now(),
        )
        with Session(self._engine) as session:
            session.add(row)
            session.commit()
        return decision

    def latest_for_pr(self, repo: str, pr_ref: str) -> PullRequestPolicyDecision | None:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(PolicyDecisionRow)
                .where(PolicyDecisionRow.repo == repo, PolicyDecisionRow.pr_ref == pr_ref)
                .order_by(PolicyDecisionRow.created_at.desc())
            ).all()
            if not rows:
                return None
            return PullRequestPolicyDecision.model_validate_json(rows[0].decision_json)

    def for_commit(self, repo: str, pr_ref: str, commit_sha: str) -> PullRequestPolicyDecision | None:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(PolicyDecisionRow)
                .where(
                    PolicyDecisionRow.repo == repo,
                    PolicyDecisionRow.pr_ref == pr_ref,
                    PolicyDecisionRow.commit_sha == commit_sha,
                )
                .order_by(PolicyDecisionRow.created_at.desc())
            ).all()
            if not rows:
                return None
            return PullRequestPolicyDecision.model_validate_json(rows[0].decision_json)

    def list_distinct_prs(self) -> list[tuple[str, str]]:
        with Session(self._engine) as session:
            rows = session.scalars(
                select(PolicyDecisionRow.repo, PolicyDecisionRow.pr_ref)
                .distinct()
                .order_by(PolicyDecisionRow.repo, PolicyDecisionRow.pr_ref)
            ).all()
        return [(row[0], row[1]) for row in rows]


class PlanStore:
    def __init__(self, sqlite_path: str) -> None:
        self._engine = _create_engine(sqlite_path)
        Base.metadata.create_all(self._engine)

    def save(self, record) -> None:
        from shift_left.models.schema import TerraformPlanRecord

        assert isinstance(record, TerraformPlanRecord)
        row = TerraformPlanRow(
            id=record.id,
            repo=record.repo,
            pr_ref=record.pr_ref,
            commit_sha=record.commit_sha,
            target=record.target,
            summary_add=record.summary_add,
            summary_change=record.summary_change,
            summary_destroy=record.summary_destroy,
            output_text=record.output_text,
            generated_at=record.generated_at,
            generated_by=record.generated_by,
            duration_ms=record.duration_ms,
            stale="true" if record.stale else "false",
        )
        with Session(self._engine) as session:
            session.add(row)
            session.commit()

    def latest_for_pr(self, repo: str, pr_ref: str):
        from shift_left.models.schema import TerraformPlanRecord

        with Session(self._engine) as session:
            rows = session.scalars(
                select(TerraformPlanRow)
                .where(TerraformPlanRow.repo == repo, TerraformPlanRow.pr_ref == pr_ref)
                .order_by(TerraformPlanRow.generated_at.desc())
            ).all()
            if not rows:
                return None
            return self._from_row(rows[0])

    def for_commit(self, repo: str, pr_ref: str, commit_sha: str):
        with Session(self._engine) as session:
            rows = session.scalars(
                select(TerraformPlanRow)
                .where(
                    TerraformPlanRow.repo == repo,
                    TerraformPlanRow.pr_ref == pr_ref,
                    TerraformPlanRow.commit_sha == commit_sha,
                    TerraformPlanRow.stale == "false",
                )
                .order_by(TerraformPlanRow.generated_at.desc())
            ).all()
            if not rows:
                return None
            return self._from_row(rows[0])

    def latest_for_target(self, target_id: str):
        from shift_left.models.schema import TerraformPlanRecord

        pr_ref = f"TARGET-{target_id}"
        with Session(self._engine) as session:
            rows = session.scalars(
                select(TerraformPlanRow)
                .where(TerraformPlanRow.pr_ref == pr_ref, TerraformPlanRow.stale == "false")
                .order_by(TerraformPlanRow.generated_at.desc())
            ).all()
            if not rows:
                return None
            return self._from_row(rows[0])

    def invalidate_for_new_commit(self, repo: str, pr_ref: str, *, new_commit_sha: str) -> int:
        count = 0
        with Session(self._engine) as session:
            rows = session.scalars(
                select(TerraformPlanRow).where(
                    TerraformPlanRow.repo == repo,
                    TerraformPlanRow.pr_ref == pr_ref,
                    TerraformPlanRow.stale == "false",
                )
            ).all()
            for row in rows:
                if row.commit_sha != new_commit_sha:
                    row.stale = "true"
                    row.invalidated_at = utc_now()
                    count += 1
            session.commit()
        return count

    @staticmethod
    def _from_row(row: TerraformPlanRow):
        from shift_left.models.schema import TerraformPlanRecord

        return TerraformPlanRecord(
            id=row.id,
            repo=row.repo,
            pr_ref=row.pr_ref,
            commit_sha=row.commit_sha,
            target=row.target,
            summary_add=row.summary_add,
            summary_change=row.summary_change,
            summary_destroy=row.summary_destroy,
            output_text=row.output_text,
            generated_at=row.generated_at,
            generated_by=row.generated_by,
            duration_ms=row.duration_ms,
            stale=row.stale == "true",
        )
