"""Batch detail presentation — false-positive framing."""

from __future__ import annotations

from shift_left.investigations.batch_schema import BatchChildRecord, BatchState, InvestigationBatchRecord
from shift_left.investigations.schema import InvestigationRecord, InvestigationState
from shift_left.investigations.store import InvestigationStore
from shift_left.ui.batch_view import build_investigation_batch_view
from shift_left.models.schema import utc_now


def test_batch_view_false_positive_framing(tmp_path) -> None:
    store = InvestigationStore(str(tmp_path / "inv.db"))
    store.create_investigation(
        investigation_id="inv-89",
        repo="localdemo/celery-corpus",
        requested_ref="HEAD",
        resolved_commit_sha="abc123",
        task_cwe="CWE-89",
        actor="test",
        model_variant="fdtn-ai/antares-1b",
        profile_evidence_tier="direct",
    )
    store.create_investigation(
        investigation_id="inv-190",
        repo="localdemo/celery-corpus",
        requested_ref="HEAD",
        resolved_commit_sha="abc123",
        task_cwe="CWE-190",
        actor="test",
        model_variant="fdtn-ai/antares-1b",
        profile_evidence_tier="language-only",
    )
    batch = store.create_batch(
        source="top25",
        repo="localdemo/celery-corpus",
        requested_ref="HEAD",
        resolved_commit_sha="abc123",
        actor="test",
        profile_snapshot={},
        top25_survivor_count=2,
        children=[
            ("inv-89", "CWE-89", "direct", 0),
            ("inv-190", "CWE-190", "language-only", 1),
        ],
    )
    store.persist_candidates_from_ranked_files(
        "inv-89",
        [
            {"path": "celery/backends/database/result_filter.py", "rank": 1},
            {"path": "celery/app.py", "rank": 2},
        ],
    )
    store.persist_candidates_from_ranked_files(
        "inv-190",
        [{"path": "celery/loaders/base.py", "rank": 1}],
    )
    store.transition_state("inv-89", InvestigationState.RUNNING, actor="test")
    store.transition_state("inv-89", InvestigationState.COMPLETED, actor="test")
    store.transition_state("inv-190", InvestigationState.RUNNING, actor="test")
    store.transition_state("inv-190", InvestigationState.COMPLETED, actor="test")

    view = build_investigation_batch_view(store, batch)
    assert view.total_candidate_count == 3
    assert "3 candidate file(s)" in view.false_positive_framing
    assert "direct or indirect profiler evidence" in view.false_positive_framing

    by_cwe = {child.task_cwe: child for child in view.children}
    assert not by_cwe["CWE-89"].candidates_without_evidence_basis
    assert by_cwe["CWE-190"].candidates_without_evidence_basis
