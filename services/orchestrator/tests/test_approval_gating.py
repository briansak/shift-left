"""Approval gating and commit SHA binding."""

from __future__ import annotations

import pytest

from shift_left.approval.service import ApprovalService
from shift_left.config import AppConfig, PolicyConfig
from shift_left.models.database import (
    ApprovalStore,
    BlockOverrideStore,
    FindingsStore,
    PolicyDecisionStore,
)
from shift_left.models.schema import PolicyAction, PullRequestPolicyDecision


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


def _service(stores, *, allow_override: bool = False) -> ApprovalService:
    config = AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": stores["path"]},
            "policy": {"allow_block_override": allow_override},
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


def _save_block_decision(stores, commit_sha: str) -> PullRequestPolicyDecision:
    decision = PullRequestPolicyDecision(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha=commit_sha,
        default_action=PolicyAction.FLAG,
        pr_decision=PolicyAction.BLOCK,
        explanation="Blocked (advisory policy decision).",
    )
    stores["decisions"].save(decision)
    return decision


@pytest.mark.asyncio
async def test_block_decision_not_bypassable_without_override(stores) -> None:
    service = _service(stores, allow_override=False)
    _save_block_decision(stores, "commit-a")

    with pytest.raises(ValueError, match="cannot proceed"):
        await service.grant_approval(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            approver="alice",
        )


@pytest.mark.asyncio
async def test_block_decision_requires_explicit_override_when_enabled(stores) -> None:
    service = _service(stores, allow_override=True)
    _save_block_decision(stores, "commit-a")

    with pytest.raises(ValueError, match="explicit override"):
        await service.grant_approval(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            approver="alice",
        )

    await service.grant_block_override(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        actor="security-lead",
        justification="Emergency deploy with compensating controls.",
        policy_id="block-critical-code",
    )
    record = await service.grant_approval(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        approver="alice",
    )
    assert record.commit_sha == "commit-a"
    assert record.policy_decision == PolicyAction.BLOCK


@pytest.mark.asyncio
async def test_approval_invalidated_when_commit_changes(stores) -> None:
    service = _service(stores, allow_override=False)
    decision = PullRequestPolicyDecision(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        default_action=PolicyAction.FLAG,
        pr_decision=PolicyAction.FLAG,
        explanation="Flagged.",
    )
    stores["decisions"].save(decision)
    await service.grant_approval(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        approver="alice",
    )

    invalidated = service.invalidate_on_new_commit("o/r", "PR-1", new_commit_sha="commit-b")
    assert invalidated == 1

    gate_a = service.check_deployment_gate(repo="o/r", pr_ref="PR-1", commit_sha="commit-a")
    assert gate_a.approval_valid_for_commit is False

    gate_b = service.check_deployment_gate(repo="o/r", pr_ref="PR-1", commit_sha="commit-b")
    assert gate_b.allowed is False

    stores["decisions"].save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-b",
            default_action=PolicyAction.FLAG,
            pr_decision=PolicyAction.FLAG,
            explanation="New review.",
        )
    )
    await service.grant_approval(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-b",
        approver="alice",
    )
    gate_b = service.check_deployment_gate(repo="o/r", pr_ref="PR-1", commit_sha="commit-b")
    assert gate_b.allowed is True


def test_deployment_gate_requires_approval(stores) -> None:
    service = _service(stores)
    stores["decisions"].save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            default_action=PolicyAction.FLAG,
            pr_decision=PolicyAction.FLAG,
            explanation="Flagged.",
        )
    )
    gate = service.check_deployment_gate(repo="o/r", pr_ref="PR-1", commit_sha="commit-a")
    assert gate.allowed is False
    assert "approval required" in gate.reason.lower()
