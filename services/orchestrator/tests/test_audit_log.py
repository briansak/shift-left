"""Audit log append-only behavior and export."""

from __future__ import annotations

import pytest

from shift_left.models.database import AuditStore
from shift_left.sovereignty.network import EgressGuard


def test_audit_append_only_with_actor(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    event = store.log(actor="alice", action="finding.status_changed", subject="finding-1", details={})
    assert event.actor == "alice"
    events = store.list_events(action="finding.status_changed")
    assert len(events) == 1


def test_audit_requires_non_null_actor(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    with pytest.raises(ValueError, match="non-null actor"):
        store.log(actor="", action="test.action", subject="x", details={})


def test_finding_status_change_writes_audit_with_actor(tmp_path) -> None:
    from shift_left.config import AppConfig
    from shift_left.models.schema import (
        Finding,
        FindingSource,
        FindingStatus,
        FindingStatusUpdate,
        LineRange,
        Severity,
        TargetKind,
    )
    from shift_left.review.service import ReviewService

    db = tmp_path / "findings.db"
    config = AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": str(db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    service = ReviewService(config)
    finding = Finding(
        id="finding-test-1",
        source=FindingSource.ANTARES,
        target_kind=TargetKind.CODE,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="aaa",
        file_path="app/x.py",
        line_range=LineRange(start=1, end=1),
        model_asserted_severity=Severity.HIGH,
        confidence=0.5,
        title="T",
        description="D",
    )
    service._store.save_findings([finding])

    with pytest.raises(ValueError, match="Rationale is required"):
        service.update_finding_status(
            finding.id,
            FindingStatusUpdate(status=FindingStatus.FALSE_POSITIVE, rationale=None),
            actor="bob",
        )

    service.update_finding_status(
        finding.id,
        FindingStatusUpdate(
            status=FindingStatus.FALSE_POSITIVE,
            rationale="Confirmed safe pattern in context.",
        ),
        actor="bob",
    )
    events = service.audit.list_events(action="finding.status_changed")
    assert events
    assert events[0].actor == "bob"
    assert events[0].details.get("rationale")


def test_audit_export_with_egress_blocked(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    store.log(actor="system:shift-left", action="review.completed", subject="o/r/PR-1", details={})

    with EgressGuard(allowed_hosts=frozenset({"127.0.0.1", "localhost", "::1"})):
        exported = store.export_all()

    assert len(exported) == 1
    assert exported[0]["actor"] == "system:shift-left"
    assert exported[0]["action"] == "review.completed"


def test_prune_export_failure_aborts_before_delete(tmp_path, monkeypatch) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    store.log(actor="alice", action="test.event", subject="s", details={})

    def fail_export(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(store, "export_range", fail_export)
    from shift_left.models.schema import utc_now
    from datetime import timedelta

    with pytest.raises(OSError, match="disk full"):
        store.prune_before(
            before=utc_now() + timedelta(days=1),
            export_path=tmp_path / "export.json",
            actor="operator:cli",
        )
    assert len(store.export_all()) == 1


def test_prune_event_is_protected_and_not_deleted(tmp_path) -> None:
    from datetime import timedelta

    from shift_left.models.schema import utc_now

    store = AuditStore(str(tmp_path / "audit.db"))
    store.log(actor="alice", action="old.event", subject="s", details={})
    cutoff = utc_now() + timedelta(days=1)
    export_path = tmp_path / "export.json"
    result = store.prune_before(before=cutoff, export_path=export_path, actor="operator:cli")
    assert result["deleted_count"] == 1
    remaining = store.export_all()
    assert len(remaining) == 1
    assert remaining[0]["action"] == "audit.pruned"
    assert remaining[0]["actor"] == "operator:cli"
