"""Path A policy and routing tests for deterministic Terraform gating."""

from __future__ import annotations

from pathlib import Path

from shift_left.config import AppConfig, PolicyConfig, RoutingConfig
from shift_left.models.schema import (
    Finding,
    FindingSource,
    LineRange,
    Policy,
    PolicyAction,
    PolicyAppliesTo,
    PolicyRule,
    PolicySeverity,
    Severity,
    TargetKind,
)
from shift_left.policy.engine import PolicyEngine
from shift_left.policy.severity import apply_policy_severities
from shift_left.routing.globmatch import matches_any

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / "templates" / "forgejo" / "workflows" / "shift-left-review.yml"


def _insecure_finding() -> Finding:
    finding = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="shiftleft-admin/sample-firewall",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="terraform/insecure.tf",
        line_range=LineRange(start=1, end=10),
        handler_asserted_cwe="CWE-284",
        model_asserted_cwe=None,
        model_asserted_severity=Severity.HIGH,
        confidence=1.0,
        title="Unrestricted ingress (azure)",
        description="Azure NSG rule allows unrestricted inbound source.",
        trace="handler:terraform/azure-unrestricted-ingress",
    )
    config = AppConfig.model_validate({"findings_store": {"sqlite_path": "/tmp/x.db"}})
    return apply_policy_severities([finding], config)[0]


def test_insecure_tf_policy_decision_is_block() -> None:
    finding = _insecure_finding()
    assert finding.policy_severity == PolicySeverity.HIGH
    engine = PolicyEngine(AppConfig.model_validate({"findings_store": {"sqlite_path": "/tmp/x.db"}}).policy)
    result = engine.evaluate(
        repo=finding.repo,
        pr_ref=finding.pr_ref,
        commit_sha=finding.commit_sha,
        findings=[finding],
    )
    assert result.pr_action == PolicyAction.BLOCK


def test_unclassified_never_blocks_even_with_block_policy() -> None:
    config = PolicyConfig(
        default_action=PolicyAction.BLOCK,
        rules=[
            Policy(
                id="block-all-high",
                name="Block all high",
                applies_to=PolicyAppliesTo(path_globs=["**/*"]),
                rules=[PolicyRule(severity_threshold=PolicySeverity.HIGH)],
                action=PolicyAction.BLOCK,
            )
        ],
    )
    engine = PolicyEngine(config)
    finding = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="terraform/insecure.tf",
        model_asserted_cwe="CWE-20",
        model_asserted_severity=Severity.HIGH,
        policy_severity=PolicySeverity.UNCLASSIFIED,
        confidence=0.9,
        title="Model only",
        description="No handler rule",
    )
    result = engine.evaluate(repo="o/r", pr_ref="PR-1", commit_sha="abc", findings=[finding])
    assert result.pr_action != PolicyAction.BLOCK
    assert result.pr_decision.finding_decisions[0].decision == PolicyAction.FLAG


def test_workflow_paths_ignored_by_routing() -> None:
    routing = RoutingConfig()
    assert matches_any(".forgejo/workflows/shift-left-review.yml", routing.ignore_globs)
    assert matches_any(".github/workflows/ci.yml", routing.ignore_globs)


def test_workflow_contains_template_secret_reference() -> None:
    content = WORKFLOW.read_text()
    assert "${{ secrets." in content
    assert "SHIFT_LEFT_TOKEN" in content
