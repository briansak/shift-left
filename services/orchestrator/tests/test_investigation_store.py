"""InvestigationStore persistence and isolation from gate/policy."""

from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from shift_left.antares.sandbox_audit import persist_sandbox_command_audit
from shift_left.investigations.audit_refs import annotate_investigation_audit_reference
from shift_left.investigations.redaction import redact_trace_record_for_display
from shift_left.investigations.reconciliation import reconcile_trace_audit
from shift_left.investigations.schema import (
    CandidateDisposition,
    InvestigationState,
    TraceRecord,
)
from shift_left.investigations.stale import is_investigation_stale
from shift_left.investigations.store import InvestigationStore
from shift_left.models.database import AuditStore
from shift_left.models.schema import RankedFileCandidate
from shift_left.ui.api_presentation import redact_audit_events_for_api


def _store(tmp_path, *, retention_days: int = 90, audit: AuditStore | None = None) -> InvestigationStore:
    return InvestigationStore(
        str(tmp_path / "investigations.db"),
        retention_days=retention_days,
        audit=audit,
    )


def _launch(store: InvestigationStore, **overrides: object) -> str:
    record = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha="abc111",
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
        **overrides,
    )
    return record.investigation_id


def test_illegal_state_transition_rejected(tmp_path) -> None:
    store = _store(tmp_path)
    inv_id = _launch(store)
    with pytest.raises(ValueError, match="Illegal investigation state transition"):
        store.transition_state(
            inv_id,
            InvestigationState.COMPLETED,
            actor="operator",
        )


def test_trace_turns_survive_simulated_crash_mid_run(tmp_path) -> None:
    store = _store(tmp_path)
    inv_id = _launch(store)
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.append_trace_turn(
        inv_id,
        turn_index=0,
        command="grep token app.py",
        exit_status=0,
        output_truncated="token=secret",
    )
    store.append_trace_turn(
        inv_id,
        turn_index=1,
        command="cat app/config.py",
        exit_status=0,
        output_truncated="password=secret",
    )
    loaded = store.get(inv_id, include_children=True)
    assert loaded is not None
    assert loaded.state == InvestigationState.RUNNING
    assert len(loaded.trace_turns) == 2
    assert loaded.trace_turns[0].command == "grep token app.py"
    assert loaded.trace_turns[1].turn_index == 1


def test_dispatch_trace_turn_survives_without_completion(tmp_path) -> None:
    store = _store(tmp_path)
    inv_id = _launch(store)
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.append_trace_turn(
        inv_id,
        turn_index=0,
        command="cat Tests/images/pillow.icns",
        exit_status=0,
        output_truncated="(dispatched; waiting for sandbox)",
        command_id="cmd-hung",
        phase="dispatched",
    )
    loaded = store.get(inv_id, include_children=True)
    assert loaded is not None
    assert len(loaded.trace_turns) == 1
    assert loaded.trace_turns[0].phase == "dispatched"
    assert loaded.trace_turns[0].command == "cat Tests/images/pillow.icns"
    assert store.complete_trace_turn(
        inv_id,
        command_id="cmd-hung",
        exit_status=0,
        output_truncated="binary",
    )
    loaded = store.get(inv_id, include_children=True)
    assert loaded is not None
    assert loaded.trace_turns[0].phase == "completed"
    assert loaded.trace_turns[0].output_truncated == "binary"


def test_reconcile_counts_dispatch_and_completion_as_one_attempt(tmp_path) -> None:
    audit_path = tmp_path / "audit.db"
    audit = AuditStore(str(audit_path), retention_days=365)
    store = InvestigationStore(str(tmp_path / "investigations.db"), audit=audit)
    inv_id = _launch(store)
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.append_trace_turn(
        inv_id,
        turn_index=0,
        command="ls",
        exit_status=0,
        output_truncated=".",
        command_id="cmd-one",
        phase="completed",
    )
    persist_sandbox_command_audit(
        audit,
        actor="operator",
        subject="example-org/example-configs@main",
        events=[
            {
                "investigation_id": inv_id,
                "command": "ls",
                "exit_code": 0,
                "output_truncated": "(dispatched; waiting for sandbox)",
                "truncated": False,
                "recorded_at": "2026-09-10T00:00:00+00:00",
                "charged": True,
                "command_id": "cmd-one",
                "phase": "dispatched",
            },
            {
                "investigation_id": inv_id,
                "command": "ls",
                "exit_code": 0,
                "output_truncated": ".",
                "truncated": False,
                "recorded_at": "2026-09-10T00:00:01+00:00",
                "charged": True,
                "command_id": "cmd-one",
                "phase": "completed",
            },
        ],
    )
    reconciliation = reconcile_trace_audit(store, audit, inv_id)
    assert reconciliation.trace_attempt_count == 1
    assert reconciliation.sandbox_audit_attempt_count == 1
    assert reconciliation.sandbox_audit_charged_count == 1
    assert reconciliation.counts_match is True


def test_completed_no_files_is_distinct_terminal_state(tmp_path) -> None:
    store = _store(tmp_path)
    inv_completed = _launch(store)
    store.transition_state(inv_completed, InvestigationState.RUNNING, actor="operator")
    store.transition_state(inv_completed, InvestigationState.COMPLETED, actor="operator")

    inv_no_files = _launch(store)
    store.transition_state(inv_no_files, InvestigationState.RUNNING, actor="operator")
    store.transition_state(
        inv_no_files,
        InvestigationState.COMPLETED_NO_FILES,
        actor="operator",
        reason="submit_no_vulnerability_found",
    )

    inv_failed = _launch(store)
    store.transition_state(inv_failed, InvestigationState.RUNNING, actor="operator")
    store.transition_state(inv_failed, InvestigationState.FAILED, actor="operator", reason="timeout")

    counts = store.count_by_state()
    assert counts[InvestigationState.COMPLETED.value] == 1
    assert counts[InvestigationState.COMPLETED_NO_FILES.value] == 1
    assert counts[InvestigationState.FAILED.value] == 1


def test_disposition_update_does_not_mutate_results(tmp_path) -> None:
    store = _store(tmp_path)
    inv_id = _launch(store)
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.set_candidates(inv_id, [(1, "src/auth.py"), (2, "src/db.py")])
    store.transition_state(inv_id, InvestigationState.COMPLETED, actor="operator")

    store.update_candidate_disposition(
        inv_id,
        1,
        disposition=CandidateDisposition.REVIEWED,
        actor="operator",
        note="looked fine",
    )

    loaded = store.get(inv_id, include_children=True)
    assert loaded is not None
    assert [(c.submission_rank, c.file_path) for c in loaded.candidates] == [
        (1, "src/auth.py"),
        (2, "src/db.py"),
    ]
    assert loaded.candidates[0].disposition == CandidateDisposition.REVIEWED
    assert loaded.open_disposition_count == 1


def test_disposition_update_records_audit(tmp_path) -> None:
    audit = AuditStore(str(tmp_path / "audit.db"))
    store = InvestigationStore(str(tmp_path / "inv.db"), audit=audit)
    inv_id = _launch(store)
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.set_candidates(inv_id, [(1, "src/auth.py")])
    store.transition_state(inv_id, InvestigationState.COMPLETED, actor="operator")

    store.update_candidate_disposition(
        inv_id,
        1,
        disposition=CandidateDisposition.NOT_ACTIONABLE,
        actor="reviewer",
        note="false positive",
    )

    events = audit.list_events(action="investigation.disposition_updated", limit=5)
    assert len(events) == 1
    details = events[0].details
    assert details["investigation_id"] == inv_id
    assert details["file_path"] == "src/auth.py"
    assert details["from_disposition"] == "open"
    assert details["to_disposition"] == "not_actionable"
    assert details["actor"] == "reviewer"
    assert details["note"] == "false positive"


def test_rerun_creates_new_id_and_leaves_prior_unchanged(tmp_path) -> None:
    store = _store(tmp_path)
    first_id = _launch(store)
    store.transition_state(first_id, InvestigationState.RUNNING, actor="operator")
    store.set_candidates(first_id, [(1, "old/path.py")])
    store.transition_state(first_id, InvestigationState.COMPLETED, actor="operator")

    second_id = _launch(store)
    assert second_id != first_id

    first = store.get(first_id, include_children=True)
    second = store.get(second_id)
    assert first is not None
    assert second is not None
    assert first.state == InvestigationState.COMPLETED
    assert second.state == InvestigationState.QUEUED
    assert first.candidates[0].file_path == "old/path.py"


def test_retention_purge_removes_children_retains_audit(tmp_path) -> None:
    audit_path = tmp_path / "audit.db"
    audit = AuditStore(str(audit_path), retention_days=365)
    store = InvestigationStore(
        str(tmp_path / "investigations.db"),
        retention_days=1,
        audit=audit,
    )
    inv_id = _launch(store)
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.append_trace_turn(
        inv_id,
        turn_index=0,
        command="ls",
        exit_status=0,
        output_truncated=".",
    )
    store.set_candidates(inv_id, [(1, "src/a.py")])
    store.transition_state(inv_id, InvestigationState.COMPLETED, actor="operator")

    old_created = utc_now_minus_days(2)
    with store._engine.connect() as conn:  # noqa: SLF001 — test backdate
        conn.exec_driver_sql(
            "UPDATE investigations SET created_at = ? WHERE investigation_id = ?",
            (old_created.isoformat(), inv_id),
        )
        conn.commit()

    removed = store.purge_expired()
    assert removed == 1
    assert store.get(inv_id) is None

    audit_events = audit.list_events(action="investigation.launched", limit=10)
    assert audit_events


def test_confidence_not_persisted_from_engine_result(tmp_path) -> None:
    store = _store(tmp_path)
    inv_id = _launch(store)
    ranked = [
        RankedFileCandidate(path="src/auth.py", rank=1, confidence=0.99),
        RankedFileCandidate(path="src/db.py", rank=2, confidence=0.42),
    ]
    store.persist_candidates_from_ranked_files(inv_id, ranked)
    loaded = store.get(inv_id, include_children=True)
    assert loaded is not None
    assert len(loaded.candidates) == 2
    assert all(not hasattr(c, "confidence") for c in loaded.candidates)
    with store._engine.connect() as conn:  # noqa: SLF001
        columns = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(investigation_candidates)")}
    assert "confidence" not in columns


def test_trace_reader_applies_redact_display_text() -> None:
    secret = "Sup3rS3cr3tC0mm"
    raw = TraceRecord(
        investigation_id="inv-1",
        turn_index=0,
        command=f"snmp-server community {secret} RW",
        exit_status=0,
        output_truncated=f"snmp-server community {secret} RW",
        executed_at=datetime.now(timezone.utc),
    )
    redacted = redact_trace_record_for_display(raw)
    assert secret not in redacted.command
    assert secret not in redacted.output_truncated
    assert "[REDACTED]" in redacted.command


def test_is_investigation_stale_when_head_differs() -> None:
    assert is_investigation_stale("abc123", "def456") is True
    assert is_investigation_stale("abc123", "abc123") is False


def test_reconcile_trace_audit_flags_divergence(tmp_path) -> None:
    audit_path = tmp_path / "audit.db"
    audit = AuditStore(str(audit_path), retention_days=365)
    store = InvestigationStore(str(tmp_path / "investigations.db"), audit=audit)
    inv_id = _launch(store)
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.append_trace_turn(
        inv_id,
        turn_index=0,
        command="ls",
        exit_status=0,
        output_truncated=".",
    )
    reconciliation = reconcile_trace_audit(store, audit, inv_id)
    assert reconciliation.trace_attempt_count == 1
    assert reconciliation.sandbox_audit_attempt_count == 0
    assert reconciliation.counts_match is False
    assert reconciliation.divergence_note is not None

    detail = store.get_detail(inv_id, audit=audit)
    assert detail is not None
    assert detail.audit_trace_reconciliation is not None
    assert detail.audit_trace_reconciliation.counts_match is False


def test_reconcile_trace_audit_counts_duplicate_suppressions(tmp_path) -> None:
    audit_path = tmp_path / "audit.db"
    audit = AuditStore(str(audit_path), retention_days=365)
    store = InvestigationStore(str(tmp_path / "investigations.db"), audit=audit)
    inv_id = _launch(store)
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.append_trace_turn(
        inv_id,
        turn_index=0,
        command="rg sql",
        exit_status=0,
        output_truncated="app/db.py",
        charged=True,
    )
    store.append_trace_turn(
        inv_id,
        turn_index=1,
        command="rg sql",
        exit_status=0,
        output_truncated="note: duplicate",
        charged=False,
        duplicate_of_turn=1,
    )
    persist_sandbox_command_audit(
        audit,
        actor="operator",
        subject="demo/app@main",
        events=[
            {
                "investigation_id": inv_id,
                "command": "rg sql",
                "exit_code": 0,
                "output_truncated": "app/db.py",
                "truncated": False,
                "recorded_at": "2026-09-10T00:00:00+00:00",
                "charged": True,
            },
            {
                "investigation_id": inv_id,
                "command": "rg sql",
                "exit_code": 0,
                "output_truncated": "note: duplicate",
                "truncated": False,
                "recorded_at": "2026-09-10T00:00:01+00:00",
                "charged": False,
                "duplicate_of_turn": 1,
            },
        ],
    )
    reconciliation = reconcile_trace_audit(store, audit, inv_id)
    assert reconciliation.trace_attempt_count == 2
    assert reconciliation.sandbox_audit_attempt_count == 2
    assert reconciliation.trace_charged_count == 1
    assert reconciliation.sandbox_audit_charged_count == 1
    assert reconciliation.counts_match is True


def test_reconcile_trace_audit_matches_when_audit_persisted(tmp_path) -> None:
    audit_path = tmp_path / "audit.db"
    audit = AuditStore(str(audit_path), retention_days=365)
    store = InvestigationStore(str(tmp_path / "investigations.db"), audit=audit)
    inv_id = _launch(store)
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.append_trace_turn(
        inv_id,
        turn_index=0,
        command="grep foo",
        exit_status=0,
        output_truncated="ok",
    )
    persist_sandbox_command_audit(
        audit,
        actor="operator",
        subject="demo/app@main",
        events=[
            {
                "investigation_id": inv_id,
                "command": "grep foo",
                "exit_code": 0,
                "output_truncated": "ok",
                "truncated": False,
                "recorded_at": "2026-09-10T00:00:00+00:00",
            }
        ],
    )
    reconciliation = reconcile_trace_audit(store, audit, inv_id)
    assert reconciliation.counts_match is True
    assert reconciliation.divergence_note is None


def test_purged_investigation_audit_reference_is_labelled(tmp_path) -> None:
    audit_path = tmp_path / "audit.db"
    audit = AuditStore(str(audit_path), retention_days=365)
    store = InvestigationStore(
        str(tmp_path / "investigations.db"),
        retention_days=1,
        audit=audit,
    )
    inv_id = _launch(store, advisory_cve="CVE-2024-0001")
    launched = audit.list_events(action="investigation.launched", limit=5)[0]

    old_created = utc_now_minus_days(2)
    with store._engine.connect() as conn:  # noqa: SLF001
        conn.exec_driver_sql(
            "UPDATE investigations SET created_at = ? WHERE investigation_id = ?",
            (old_created.isoformat(), inv_id),
        )
        conn.commit()
    store.purge_expired()
    assert store.exists(inv_id) is False

    presented = redact_audit_events_for_api([launched], investigation_store=store)[0]
    details = presented.details if hasattr(presented, "details") else presented["details"]
    assert details["investigation_reference_status"] == "purged"
    assert details["investigation_id"] == inv_id

    annotated = annotate_investigation_audit_reference(launched, store)
    assert annotated.details["investigation_reference_status"] == "purged"


def test_launch_audit_written_at_creation_with_required_fields(tmp_path) -> None:
    audit_path = tmp_path / "audit.db"
    audit = AuditStore(str(audit_path), retention_days=365)
    store = InvestigationStore(str(tmp_path / "investigations.db"), audit=audit)
    inv_id = _launch(store, advisory_cve="CVE-2024-4242")
    launched = audit.list_events(action="investigation.launched", limit=5)
    assert len(launched) == 1
    event = launched[0]
    assert event.actor == "operator"
    details = event.details
    assert details["investigation_id"] == inv_id
    assert details["repo"] == "demo/app"
    assert details["requested_ref"] == "main"
    assert details["resolved_commit_sha"] == "abc111"
    assert details["task_cwe"] == "CWE-843"
    assert details["advisory_cve"] == "CVE-2024-4242"


def test_launch_audit_survives_when_run_never_starts(tmp_path) -> None:
    audit_path = tmp_path / "audit.db"
    audit = AuditStore(str(audit_path), retention_days=365)
    store = InvestigationStore(str(tmp_path / "investigations.db"), audit=audit)
    inv_id = _launch(store)
    record = store.get(inv_id)
    assert record is not None
    assert record.state == InvestigationState.QUEUED
    launched = audit.list_events(action="investigation.launched", limit=5)
    assert any(event.details.get("investigation_id") == inv_id for event in launched)
    transitions = audit.list_events(action="investigation.state_transition", limit=5)
    assert not any(event.details.get("investigation_id") == inv_id for event in transitions)


def test_gate_and_policy_modules_do_not_import_investigation_store() -> None:
    repo_root = Path(__file__).resolve().parents[1] / "shift_left"
    targets: list[Path] = [
        repo_root / "gate",
        repo_root / "policy",
        repo_root / "handlers" / "config" / "gate_findings.py",
    ]
    forbidden_modules = (
        "shift_left.investigations",
        "shift_left.investigations.store",
    )
    violations: list[str] = []

    for target in targets:
        paths = [target] if target.is_file() else sorted(target.rglob("*.py"))
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in forbidden_modules or alias.name.endswith(
                            ".investigations.store"
                        ):
                            violations.append(f"{path}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if module in forbidden_modules or module.endswith(".investigations"):
                        violations.append(f"{path}: from {module}")
                elif isinstance(node, ast.Name) and node.id == "InvestigationStore":
                    violations.append(f"{path}: references InvestigationStore")

    assert not violations, "Gate/policy must not import investigation store:\n" + "\n".join(violations)


def utc_now_minus_days(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)
