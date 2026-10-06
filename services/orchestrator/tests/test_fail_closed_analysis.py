"""Fail-closed analysis outcomes and gate behavior."""

from __future__ import annotations

import pytest

from shift_left.analysis.result import (
    AnalysisFailureClass,
    AnalysisOutcome,
    AnalysisStage,
    TargetAnalysisResult,
    completed_no_findings,
    completed_with_findings,
    failed_analysis,
    parse_server_analysis_response,
)
from shift_left.approval.service import ApprovalService
from shift_left.config import AppConfig
from shift_left.enrichment.service import EnrichmentService
from shift_left.http.local_client import raise_local_inference_error
from shift_left.models.database import (
    ApprovalStore,
    BlockOverrideStore,
    FindingsStore,
    PolicyDecisionStore,
)
from shift_left.models.schema import (
    Finding,
    FindingSource,
    GateBlockReason,
    LineRange,
    PolicyAction,
    PullRequestPolicyDecision,
    Severity,
    TargetKind,
)
from shift_left.review.service import ReviewService
from shift_left.sovereignty.network import EgressGuard


CODE_DIFF = """diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -1,1 +1,1 @@
-old
+new
"""

ENRICHMENT_CODE_DIFF = """diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -1,1 +1,2 @@
-old
+cursor.execute("SELECT 1")
+new
"""


def _approval_service(stores) -> ApprovalService:
    config = AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": stores["path"]},
            "policy": {"allow_block_override": False},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    return ApprovalService(
        config=config,
        sqlite_path=stores["path"],
        policy_config=config.policy,
        findings_store=stores["findings"],
        policy_decisions=stores["decisions"],
        approvals=stores["approvals"],
        overrides=stores["overrides"],
        git=None,
    )


@pytest.fixture
def stores(tmp_path):
    db = tmp_path / "shift-left.db"
    path = str(db)
    return {
        "findings": FindingsStore(path),
        "decisions": PolicyDecisionStore(path),
        "approvals": ApprovalStore(path),
        "overrides": BlockOverrideStore(path),
        "path": path,
    }


def test_failed_analysis_is_not_treated_as_empty_pass() -> None:
    failed = failed_analysis(
        TargetKind.CODE,
        failure_class=AnalysisFailureClass.HTTP_ERROR,
        failure_stage=AnalysisStage.GENERATION,
        failure_message="500 from model server",
    )
    assert failed.outcome == AnalysisOutcome.FAILED
    assert failed.findings == []
    assert failed.incomplete is True


def test_parse_handler_error_is_not_inference_error() -> None:
    result = parse_server_analysis_response(
        {
            "outcome": "failed",
            "failure_class": "handler_error",
            "failure_stage": "handler_match",
            "failure_message": "match_nx_os_config_rules() missing rule_id",
            "findings": [{"title": "should be discarded on failed outcome"}],
        },
        target_kind=TargetKind.CONFIG,
        normalize_finding=lambda *_args, **_kwargs: None,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
    )
    assert result.incomplete is True
    assert result.failure_class == AnalysisFailureClass.HANDLER_ERROR
    assert result.failure_stage == AnalysisStage.HANDLER_MATCH
    assert result.failure_class != AnalysisFailureClass.INFERENCE_ERROR
    assert result.failure_stage != AnalysisStage.GENERATION
    assert result.findings == []


def test_gate_blocks_on_analysis_incomplete(stores) -> None:
    service = _approval_service(stores)
    stores["decisions"].save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            default_action=PolicyAction.FLAG,
            pr_decision=PolicyAction.PASS,
            explanation="Would pass if analysis completed.",
        )
    )
    gate = service.check_deployment_gate(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        analysis_results=[
            failed_analysis(
                TargetKind.CONFIG,
                failure_class=AnalysisFailureClass.INFERENCE_ERROR,
                failure_stage=AnalysisStage.GENERATION,
                failure_message="chunk failed",
            )
        ],
    )
    assert gate.allowed is False
    assert gate.analysis_incomplete is True
    assert gate.block_reason == GateBlockReason.ANALYSIS_INCOMPLETE


def test_gate_distinguishes_policy_block_from_analysis_incomplete(stores) -> None:
    service = _approval_service(stores)
    stores["decisions"].save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            default_action=PolicyAction.FLAG,
            pr_decision=PolicyAction.BLOCK,
            explanation="Blocked by policy.",
        )
    )
    policy_gate = service.check_deployment_gate(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        analysis_results=[completed_no_findings(TargetKind.CODE)],
    )
    assert policy_gate.block_reason == GateBlockReason.POLICY_BLOCK

    analysis_gate = service.check_deployment_gate(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        analysis_results=[
            failed_analysis(
                TargetKind.CODE,
                failure_class=AnalysisFailureClass.TIMEOUT,
                failure_stage=AnalysisStage.GENERATION,
                failure_message="timeout",
            )
        ],
    )
    assert analysis_gate.block_reason == GateBlockReason.ANALYSIS_INCOMPLETE


@pytest.mark.asyncio
async def test_code_path_handler_analysis_always_completes(
    tmp_path,
    test_runtime_egress_endpoints,
) -> None:
    allowed = test_runtime_egress_endpoints
    config = AppConfig.model_validate(
        {
            "models": {"foundation_sec": {"enabled": False}},
            "findings_store": {"sqlite_path": str(tmp_path / "findings.db")},
            "audit": {"sqlite_path": str(tmp_path / "findings.db")},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )

    with EgressGuard(allowed_endpoints=allowed):
        service = ReviewService(config)
        result = await service.review_diff(
            diff_text=ENRICHMENT_CODE_DIFF,
            repo="test/demo",
            pr_ref="PR-code-handlers",
            commit_sha="deadbeef",
        )

    assert result.findings
    assert result.findings[0].handler_asserted_cwe == "CWE-89"
    assert len(result.analysis_results) == 1
    assert result.analysis_results[0].incomplete is False


@pytest.mark.asyncio
async def test_enrichment_failure_exempt_from_gate(
    tmp_path,
    test_runtime_egress_endpoints,
) -> None:
    allowed = test_runtime_egress_endpoints
    config = AppConfig.model_validate(
        {
            "enrichment": {"enabled": True, "engine": "scripted"},
            "models": {"foundation_sec": {"enabled": False}},
            "findings_store": {"sqlite_path": str(tmp_path / "findings.db")},
            "audit": {"sqlite_path": str(tmp_path / "findings.db")},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )

    with EgressGuard(allowed_endpoints=allowed):
        service = ReviewService(config)

        def broken_summary(findings):
            raise RuntimeError("summary unavailable")

        service._model_enrichment._scripted.generate_review_summary = broken_summary  # type: ignore[method-assign]

        result = await service.review_diff(
            diff_text=ENRICHMENT_CODE_DIFF,
            repo="test/demo",
            pr_ref="PR-enrich-fail",
            commit_sha="deadbeef",
        )

    assert result.enrichment_unavailable is True
    gate = service.approvals.check_deployment_gate(
        repo="test/demo",
        pr_ref="PR-enrich-fail",
        commit_sha="deadbeef",
        analysis_results=result.analysis_results,
    )
    assert gate.analysis_incomplete is False
    assert gate.block_reason == GateBlockReason.APPROVAL_REQUIRED


def test_raise_local_inference_error_still_fail_closed() -> None:
    with pytest.raises(RuntimeError, match="does not fall back to hosted APIs"):
        raise_local_inference_error("Antares", RuntimeError("connection refused"))


@pytest.mark.asyncio
async def test_enrichment_service_scripted_engine(tmp_path, test_runtime_egress_endpoints) -> None:
    config = AppConfig.model_validate(
        {
            "enrichment": {"enabled": True, "engine": "scripted"},
            "models": {"foundation_sec": {"service_url": "http://127.0.0.1:8091"}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    from shift_left.http.local_client import LocalOnlyAsyncClient

    service = EnrichmentService(
        config,
        http=LocalOnlyAsyncClient(allowed_endpoints=test_runtime_egress_endpoints),
        allowed_endpoints=test_runtime_egress_endpoints,
    )
    finding = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="infra/main.tf",
        title="Issue",
        description="Desc",
    )
    enriched, unavailable = await service.enrich_findings([finding])
    assert unavailable is False
    assert enriched[0].model_context
    summary = await service.generate_review_summary(enriched)
    assert summary is not None
    assert summary.is_advisory is True
