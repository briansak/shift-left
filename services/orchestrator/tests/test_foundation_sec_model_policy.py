"""Model-server findings must not influence gate policy severity."""

from __future__ import annotations

from shift_left.config import PolicyConfig
from shift_left.foundation_sec.client import FoundationSecClient
from shift_left.models.schema import (
    Finding,
    FindingSource,
    Policy,
    PolicyAction,
    PolicyRule,
    PolicySeverity,
    TargetKind,
)
from shift_left.policy.engine import PolicyEngine
from shift_left.policy.severity import apply_policy_severities
from shift_left.ui.cwe_dictionary import unrecognized_model_cwe_tally


def test_foundation_sec_client_strips_handler_asserted_cwe() -> None:
    raw = {
        "file_path": "terraform/main.tf",
        "line_start": 1,
        "line_end": 10,
        "handler_asserted_cwe": "CWE-284",
        "model_asserted_cwe": "CWE-284",
        "cwe": "CWE-284",
        "severity": "high",
        "title": "Unrestricted ingress",
        "trace": "handler:TF-001",
    }
    finding = FoundationSecClient._normalize(raw, "o/r", "PR-1", "abc")
    assert finding.handler_asserted_cwe is None
    assert finding.policy_severity == PolicySeverity.UNCLASSIFIED
    assert finding.model_asserted_cwe == "CWE-284"
    assert finding.model_cwe_recognized is True


def test_foundation_sec_client_retains_unknown_model_asserted_cwe() -> None:
    raw = {
        "file_path": "terraform/main.tf",
        "line_start": 1,
        "line_end": 10,
        "model_asserted_cwe": "CWE-99999",
        "cwe": "CWE-99999",
        "severity": "high",
        "title": "Hallucinated CWE",
    }
    finding = FoundationSecClient._normalize(raw, "o/r", "PR-1", "abc")
    assert finding.model_asserted_cwe == "CWE-99999"
    assert finding.model_cwe_recognized is False
    assert finding.policy_severity == PolicySeverity.UNCLASSIFIED


def test_unrecognized_model_cwe_cannot_influence_policy_severity() -> None:
    finding = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="terraform/main.tf",
        model_asserted_cwe="CWE-99999",
        model_cwe_recognized=False,
        title="Advisory model finding",
        description="Model asserted unknown CWE",
    )
    policy = PolicyConfig(
        default_action=PolicyAction.BLOCK,
        policies=[
            Policy(
                id="block-high",
                name="block-high",
                action=PolicyAction.BLOCK,
                rules=[PolicyRule(severity_threshold=PolicySeverity.HIGH)],
            )
        ],
    )
    enriched = apply_policy_severities([finding], policy)[0]
    assert enriched.policy_severity == PolicySeverity.UNCLASSIFIED
    result = PolicyEngine(policy).evaluate(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        findings=[enriched],
    )
    assert result.pr_action != PolicyAction.BLOCK
    assert result.pr_decision.finding_decisions[0].matched_policy_id is None


def test_unrecognized_model_cwe_tally_counts_findings() -> None:
    findings = [
        Finding(
            source=FindingSource.FOUNDATION_SEC,
            target_kind=TargetKind.CONFIG,
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="abc",
            file_path="a.tf",
            model_asserted_cwe="CWE-99999",
            model_cwe_recognized=False,
            title="one",
            description="one",
        ),
        Finding(
            source=FindingSource.FOUNDATION_SEC,
            target_kind=TargetKind.CONFIG,
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="abc",
            file_path="b.tf",
            model_asserted_cwe="CWE-99999",
            model_cwe_recognized=False,
            title="two",
            description="two",
        ),
        Finding(
            source=FindingSource.FOUNDATION_SEC,
            target_kind=TargetKind.CONFIG,
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="abc",
            file_path="c.tf",
            model_asserted_cwe="CWE-284",
            model_cwe_recognized=True,
            title="recognized",
            description="recognized",
        ),
    ]
    tally = unrecognized_model_cwe_tally(findings)
    assert tally["total"] == 2
    assert tally["by_cwe_id"] == {"CWE-99999": 2}
