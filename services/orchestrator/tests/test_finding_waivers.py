"""Per-finding waiver grant, expiry, gate effect, capability, waivability, and audit."""

from __future__ import annotations

import asyncio

import pytest

from shift_left.approval.service import ApprovalService
from shift_left.approval.waiver_service import FindingWaiverService
from shift_left.auth.context import TokenCapability
from shift_left.config import AppConfig
from shift_left.handlers.unclaimed_files import UNCLAIMED_TRACE
from shift_left.models.database import (
    ApprovalStore,
    AuditStore,
    BlockOverrideStore,
    FindingWaiverStore,
    FindingsStore,
    PolicyDecisionStore,
)
from shift_left.models.schema import (
    Finding,
    FindingPolicyDecision,
    FindingSource,
    FindingWaiverRecord,
    LineRange,
    PolicyAction,
    PolicySeverity,
    PullRequestPolicyDecision,
    TargetKind,
)
from shift_left.policy.finding_waiver import apply_waivers_to_decision
from shift_left.policy.waiver_policy import UNCLAIMED_WAIVER_REJECTION

_ACE_CONSTRUCT = "ace:outside_in:access-list outside_in extended permit ip any any"
_OBJECT_CONSTRUCT = "object:any-service"
_UNPARSED_CONSTRUCT = "unparsed:access-list outside garbage"
_FILE_CONSTRUCT = "file"


@pytest.fixture
def stores(tmp_path):
    db = tmp_path / "shift-left.db"
    audit_db = tmp_path / "audit.db"
    path = str(db)
    return {
        "findings": FindingsStore(path),
        "decisions": PolicyDecisionStore(path),
        "approvals": ApprovalStore(path),
        "overrides": BlockOverrideStore(path),
        "waivers": FindingWaiverStore(path),
        "audit": AuditStore(str(audit_db), retention_days=30),
        "path": path,
    }


def _services(stores):
    config = AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": stores["path"]},
            "audit": {"sqlite_path": str(stores["audit"]._engine.url.database)},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    waiver_service = FindingWaiverService(
        config=config,
        findings_store=stores["findings"],
        policy_decisions=stores["decisions"],
        waivers=stores["waivers"],
        audit=stores["audit"],
        git=None,
    )
    approval_service = ApprovalService(
        config=config,
        sqlite_path=stores["path"],
        policy_config=config.policy,
        findings_store=stores["findings"],
        policy_decisions=stores["decisions"],
        approvals=stores["approvals"],
        overrides=stores["overrides"],
        waivers=waiver_service,
        git=None,
    )
    return config, waiver_service, approval_service


def _block_finding(finding_id: str = "finding-1") -> Finding:
    return Finding(
        id=finding_id,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="firewall/edge.rules",
        line_range=LineRange(start=12, end=12),
        handler_asserted_cwe="CWE-284",
        policy_severity=PolicySeverity.HIGH,
        title="ASA-001 violation",
        description="Unrestricted any/any ACE",
        trace="handler:ASA-001",
        construct_key=_ACE_CONSTRUCT,
    )


def _flag_finding(finding_id: str = "finding-flag") -> Finding:
    return Finding(
        id=finding_id,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="firewall/edge.rules",
        line_range=LineRange(start=20, end=20),
        handler_asserted_cwe="CWE-284",
        policy_severity=PolicySeverity.MEDIUM,
        title="ASA-002 violation",
        description="Unconstrained service object",
        trace="handler:ASA-002",
        construct_key=_OBJECT_CONSTRUCT,
    )


def _asa007_finding(finding_id: str = "finding-asa007") -> Finding:
    return Finding(
        id=finding_id,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="firewall/edge.rules",
        line_range=LineRange(start=30, end=30),
        handler_asserted_cwe="CWE-754",
        policy_severity=PolicySeverity.HIGH,
        title="ASA-007 unparsed line",
        description="ACL line could not be parsed",
        trace="handler:ASA-007",
        construct_key=_UNPARSED_CONSTRUCT,
    )


def _hcl001_finding(finding_id: str = "finding-hcl001") -> Finding:
    return Finding(
        id=finding_id,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="terraform/main.tf",
        line_range=LineRange(start=1, end=10),
        handler_asserted_cwe="CWE-754",
        policy_severity=PolicySeverity.HIGH,
        title="HCL content could not be interpreted",
        description="python-hcl2 is not available — the gate cannot interpret this HCL/Terraform file.",
        trace="handler:HCL-001",
        construct_key=_FILE_CONSTRUCT,
    )


def _unclaimed_finding(finding_id: str = "finding-unclaimed") -> Finding:
    return Finding(
        id=finding_id,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CODE,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="misc/unclaimed.py",
        line_range=LineRange(start=1, end=1),
        handler_asserted_cwe="CWE-657",
        policy_severity=PolicySeverity.HIGH,
        title="Unclaimed path",
        description="Changed file outside claimed globs",
        trace=UNCLAIMED_TRACE,
    )


def _save_review(
    stores,
    findings: list[Finding],
    *,
    pr_decision: PolicyAction = PolicyAction.BLOCK,
) -> PullRequestPolicyDecision:
    stores["findings"].save_findings(findings)
    decision = PullRequestPolicyDecision(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        default_action=PolicyAction.FLAG,
        pr_decision=pr_decision,
        finding_decisions=[
            FindingPolicyDecision(
                finding_id=item.id,
                decision=PolicyAction.BLOCK
                if item.trace
                in {
                    "handler:ASA-001",
                    "handler:ASA-007",
                    "handler:HCL-001",
                    UNCLAIMED_TRACE,
                }
                else PolicyAction.FLAG,
                matched_policy_id="test-policy",
                matched_policy_name="Test policy",
                matched_rule_index=0,
                rule_explanation="test",
                explanation="Test.",
            )
            for item in findings
        ],
        explanation="Test review.",
    )
    stores["decisions"].save(decision)
    return decision


def _save_block_review(stores, finding: Finding) -> PullRequestPolicyDecision:
    return _save_review(stores, [finding])


def _grant(waiver_service, finding: Finding, *, capability: TokenCapability, actor: str = "alice"):
    return asyncio.run(
        waiver_service.grant_waiver(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            finding_id=finding.id,
            actor=actor,
            reason="Documented exception with ticket INC-42.",
            capability_used=capability,
        )
    )


def test_empty_waiver_reason_rejected(stores) -> None:
    _, waiver_service, _ = _services(stores)
    finding = _block_finding()
    _save_block_review(stores, finding)

    with pytest.raises(ValueError, match="non-empty reason"):
        asyncio.run(
            waiver_service.grant_waiver(
                repo="o/r",
                pr_ref="PR-1",
                commit_sha="commit-a",
                finding_id=finding.id,
                actor="alice",
                reason="   ",
                capability_used=TokenCapability.APPROVE,
            )
        )


def test_waiver_expires_on_new_commit(stores) -> None:
    _, waiver_service, _ = _services(stores)
    finding = _block_finding()
    _save_block_review(stores, finding)

    _grant(waiver_service, finding, capability=TokenCapability.APPROVE)
    assert len(waiver_service.active_for_commit("o/r", "PR-1", "commit-a")) == 1

    expired = waiver_service.invalidate_on_new_commit(
        "o/r",
        "PR-1",
        new_commit_sha="commit-b",
        actor="system:shift-left",
    )
    assert len(expired) == 1
    assert waiver_service.active_for_commit("o/r", "PR-1", "commit-a") == []


def test_waived_finding_does_not_block_gate(stores) -> None:
    _, waiver_service, approval_service = _services(stores)
    finding = _block_finding()
    decision = _save_block_review(stores, finding)

    _grant(waiver_service, finding, capability=TokenCapability.APPROVE)

    raw_gate = approval_service.check_deployment_gate(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
    )
    assert raw_gate.policy_decision != PolicyAction.BLOCK

    applied = apply_waivers_to_decision(
        decision,
        [finding],
        waiver_service.active_for_commit("o/r", "PR-1", "commit-a"),
    )
    assert applied.effective_decision.pr_decision != PolicyAction.BLOCK


def test_audit_written_on_grant_and_use(stores) -> None:
    _, waiver_service, approval_service = _services(stores)
    finding = _block_finding()
    _save_block_review(stores, finding)

    _grant(waiver_service, finding, capability=TokenCapability.APPROVE)

    grant_events = stores["audit"].list_events(action="waiver.granted", limit=10)
    assert len(grant_events) == 1
    assert grant_events[0].details["finding_id"] == finding.id
    assert grant_events[0].details["rule_id"] == "ASA-001"
    assert grant_events[0].details["line_start"] == 12
    assert grant_events[0].details["granted_with_capability"] == "approve"
    assert grant_events[0].details["required_capability"] == "approve"

    approval_service.check_deployment_gate(repo="o/r", pr_ref="PR-1", commit_sha="commit-a")
    use_events = stores["audit"].list_events(action="waiver.used", limit=10)
    assert len(use_events) == 1
    assert use_events[0].details["waiver_id"] == grant_events[0].details["waiver_id"]
    assert use_events[0].details["granted_with_capability"] == "approve"


def test_self_grant_waiver_rejected_without_rbac_flag(stores) -> None:
    config = AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": stores["path"]},
            "audit": {"sqlite_path": str(stores["audit"]._engine.url.database)},
            "rbac": {"allow_self_approval": False},
        }
    )

    class _Git:
        async def get_pull_request(self, owner, repo, pr_number):
            return {"head": {"sha": "commit-a"}}

        async def get_commit_author(self, owner, repo, commit_sha):
            return "bob"

    waiver_service = FindingWaiverService(
        config=config,
        findings_store=stores["findings"],
        policy_decisions=stores["decisions"],
        waivers=stores["waivers"],
        audit=stores["audit"],
        git=_Git(),
    )
    finding = _block_finding()
    stores["findings"].save_findings([finding])
    _save_block_review(stores, finding)

    with pytest.raises(ValueError, match="self-granted"):
        asyncio.run(
            waiver_service.grant_waiver(
                repo="o/r",
                pr_ref="PR-1",
                commit_sha="commit-a",
                finding_id=finding.id,
                actor="bob",
                reason="Attempted self waiver.",
                capability_used=TokenCapability.APPROVE,
            )
        )


def test_triage_cannot_waive_block_finding(stores) -> None:
    _, waiver_service, _ = _services(stores)
    finding = _block_finding()
    _save_block_review(stores, finding)

    with pytest.raises(ValueError, match="approve capability"):
        _grant(waiver_service, finding, capability=TokenCapability.TRIAGE)


def test_triage_can_waive_flag_finding(stores) -> None:
    _, waiver_service, _ = _services(stores)
    finding = _flag_finding()
    _save_review(stores, [finding], pr_decision=PolicyAction.FLAG)

    record = _grant(waiver_service, finding, capability=TokenCapability.TRIAGE)
    assert record.granted_with_capability == "triage"
    grant_events = stores["audit"].list_events(action="waiver.granted", limit=10)
    assert grant_events[0].details["required_capability"] == "triage"
    assert grant_events[0].details["granted_with_capability"] == "triage"


def test_approve_can_waive_block_and_flag(stores) -> None:
    _, waiver_service, _ = _services(stores)
    block = _block_finding("finding-block")
    flag = _flag_finding("finding-flag-2")
    _save_review(stores, [block, flag])

    block_record = _grant(waiver_service, block, capability=TokenCapability.APPROVE)
    flag_record = _grant(waiver_service, flag, capability=TokenCapability.APPROVE)
    assert block_record.granted_with_capability == "approve"
    assert flag_record.granted_with_capability == "approve"


def test_asa007_waiver_succeeds(stores) -> None:
    _, waiver_service, _ = _services(stores)
    finding = _asa007_finding()
    _save_block_review(stores, finding)

    record = _grant(waiver_service, finding, capability=TokenCapability.APPROVE)
    assert record.rule_id == "ASA-007"
    assert len(waiver_service.active_for_commit("o/r", "PR-1", "commit-a")) == 1


def test_hcl001_waiver_succeeds_with_approve(stores) -> None:
    _, waiver_service, _ = _services(stores)
    finding = _hcl001_finding()
    _save_block_review(stores, finding)

    record = _grant(waiver_service, finding, capability=TokenCapability.APPROVE)
    assert record.rule_id == "HCL-001"
    assert len(waiver_service.active_for_commit("o/r", "PR-1", "commit-a")) == 1


def test_hcl001_waiver_rejected_with_triage(stores) -> None:
    _, waiver_service, _ = _services(stores)
    finding = _hcl001_finding()
    _save_block_review(stores, finding)

    with pytest.raises(ValueError, match="approve capability"):
        _grant(waiver_service, finding, capability=TokenCapability.TRIAGE)


def test_hcl001_waiver_expires_on_new_commit(stores) -> None:
    _, waiver_service, _ = _services(stores)
    finding = _hcl001_finding()
    _save_block_review(stores, finding)
    _grant(waiver_service, finding, capability=TokenCapability.APPROVE)
    assert len(waiver_service.active_for_commit("o/r", "PR-1", "commit-a")) == 1

    expired = waiver_service.invalidate_on_new_commit(
        "o/r",
        "PR-1",
        new_commit_sha="commit-b",
        actor="system:shift-left",
    )
    assert len(expired) == 1
    assert waiver_service.active_for_commit("o/r", "PR-1", "commit-a") == []


def test_hcl001_unknown_registry_id_rejection_path() -> None:
    """Document pre-registry rejection: trace without rule_by_id match."""
    from shift_left.config import AppConfig
    from shift_left.policy.waiver_policy import assert_finding_waivable

    finding = _hcl001_finding()
    finding = finding.model_copy(update={"trace": "handler:not-in-registry"})
    config = AppConfig.model_validate({"findings_store": {"sqlite_path": "/tmp/x.db"}})
    with pytest.raises(ValueError, match="Unknown registry rule 'not-in-registry'"):
        assert_finding_waivable(finding, config)


def test_cli001_waiver_rejected_with_managed_target_remedy(stores) -> None:
    from shift_left.handlers.config.rules.registry import rule_by_id
    from shift_left.policy.handler_trace import handler_rule_id_from_trace
    from shift_left.policy.waiver_policy import UNDETERMINED_PLATFORM_WAIVER_REJECTION

    _, waiver_service, _ = _services(stores)
    finding = Finding(
        id="finding-cli001",
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="configs/edge.cfg",
        line_range=LineRange(start=1, end=2),
        handler_asserted_cwe="CWE-754",
        policy_severity=PolicySeverity.HIGH,
        title="Platform could not be determined",
        description="Platform could not be determined from content.",
        trace="handler:CLI-001",
        construct_key="file",
    )
    rule = rule_by_id("CLI-001")
    assert rule is not None
    assert rule.waivable is False
    assert rule.registry_status == "enforced_prematch"
    assert handler_rule_id_from_trace(finding.trace) == "CLI-001"
    _save_block_review(stores, finding)

    with pytest.raises(ValueError, match="managed_targets.targets") as raised:
        _grant(waiver_service, finding, capability=TokenCapability.APPROVE)

    message = str(raised.value)
    assert message == UNDETERMINED_PLATFORM_WAIVER_REJECTION
    assert "no registry rule_id" not in message
    assert "Unknown registry rule" not in message
    assert waiver_service.active_for_commit("o/r", "PR-1", "commit-a") == []


def test_cwe657_unclaimed_waiver_rejected_with_remedy(stores) -> None:
    _, waiver_service, _ = _services(stores)
    finding = _unclaimed_finding()
    _save_block_review(stores, finding)

    with pytest.raises(ValueError, match="cannot be waived"):
        _grant(waiver_service, finding, capability=TokenCapability.APPROVE)

    assert "config_globs" in UNCLAIMED_WAIVER_REJECTION
    assert "pr_gate_exclusion_globs" in UNCLAIMED_WAIVER_REJECTION


def test_waiver_does_not_apply_to_different_construct_same_class(stores) -> None:
    finding_a = _block_finding("finding-asa001")
    finding_b = Finding(
        id="finding-asa002",
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="firewall/edge.rules",
        line_range=LineRange(start=12, end=12),
        handler_asserted_cwe="CWE-284",
        policy_severity=PolicySeverity.MEDIUM,
        title="ASA-002 at same line",
        description="Different construct",
        trace="handler:ASA-002",
        construct_key=_OBJECT_CONSTRUCT,
    )
    decision = _save_review(stores, [finding_a, finding_b])

    waiver = FindingWaiverRecord(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        target_kind="config",
        rule_id="ASA-001",
        file_path="firewall/edge.rules",
        line_start=12,
        construct_key=_ACE_CONSTRUCT,
        weakness_class="CWE-284",
        finding_id=finding_a.id,
        actor="alice",
        reason="ASA-001 only",
        granted_with_capability="approve",
    )

    applied = apply_waivers_to_decision(decision, [finding_a, finding_b], [waiver])
    assert finding_a.id in applied.waived_finding_ids
    assert finding_b.id not in applied.waived_finding_ids
    retained_ids = {item.finding_id for item in applied.effective_decision.finding_decisions}
    assert finding_b.id in retained_ids


def test_waiver_applies_when_finding_regenerated_with_new_id(stores) -> None:
    original = _block_finding("finding-original")
    regenerated = _block_finding("finding-regenerated")
    decision = PullRequestPolicyDecision(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        default_action=PolicyAction.FLAG,
        pr_decision=PolicyAction.BLOCK,
        finding_decisions=[
            FindingPolicyDecision(
                finding_id=regenerated.id,
                decision=PolicyAction.BLOCK,
                matched_policy_id="block-uninterpretable-config",
                matched_policy_name="Block",
                matched_rule_index=0,
                rule_explanation="policy_severity>=high",
                explanation="Blocked.",
            )
        ],
        explanation="Blocked.",
    )

    waiver = FindingWaiverRecord(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        target_kind="config",
        rule_id="ASA-001",
        file_path="firewall/edge.rules",
        line_start=12,
        construct_key=_ACE_CONSTRUCT,
        weakness_class="CWE-284",
        finding_id=original.id,
        actor="alice",
        reason="Identity-key bound",
        granted_with_capability="approve",
    )

    applied = apply_waivers_to_decision(decision, [regenerated], [waiver])
    assert regenerated.id in applied.waived_finding_ids
    assert applied.effective_decision.pr_decision == PolicyAction.PASS


def test_waiver_repo_and_target_isolation(stores) -> None:
    finding_repo_a = _block_finding("finding-repo-a")
    finding_repo_b = Finding(
        id="finding-repo-b",
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="other/repo",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="firewall/edge.rules",
        line_range=LineRange(start=12, end=12),
        handler_asserted_cwe="CWE-284",
        policy_severity=PolicySeverity.HIGH,
        title="Same rule elsewhere",
        description="Different repo",
        trace="handler:ASA-001",
        construct_key=_ACE_CONSTRUCT,
    )
    finding_target_code = Finding(
        id="finding-target-code",
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CODE,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="firewall/edge.rules",
        line_range=LineRange(start=12, end=12),
        handler_asserted_cwe="CWE-284",
        policy_severity=PolicySeverity.HIGH,
        title="Same coords, code target",
        description="Different target kind",
        trace="handler:ASA-001",
        construct_key=_ACE_CONSTRUCT,
    )
    decision = PullRequestPolicyDecision(
        repo="other/repo",
        pr_ref="PR-1",
        commit_sha="commit-a",
        default_action=PolicyAction.FLAG,
        pr_decision=PolicyAction.BLOCK,
        finding_decisions=[
            FindingPolicyDecision(
                finding_id=finding_repo_b.id,
                decision=PolicyAction.BLOCK,
                matched_policy_id="p",
                matched_policy_name="P",
                matched_rule_index=0,
                rule_explanation="r",
                explanation="x",
            ),
            FindingPolicyDecision(
                finding_id=finding_target_code.id,
                decision=PolicyAction.BLOCK,
                matched_policy_id="p",
                matched_policy_name="P",
                matched_rule_index=0,
                rule_explanation="r",
                explanation="x",
            ),
        ],
        explanation="Blocked.",
    )

    waiver = FindingWaiverRecord(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        target_kind="config",
        rule_id="ASA-001",
        file_path="firewall/edge.rules",
        line_start=12,
        construct_key=_ACE_CONSTRUCT,
        weakness_class="CWE-284",
        finding_id=finding_repo_a.id,
        actor="alice",
        reason="Repo A config only",
        granted_with_capability="approve",
    )

    applied = apply_waivers_to_decision(
        decision,
        [finding_repo_b, finding_target_code],
        [waiver],
    )
    assert applied.waived_finding_ids == frozenset()
    assert applied.effective_decision.pr_decision == PolicyAction.BLOCK


def test_waiver_survives_line_shift_same_construct(stores) -> None:
    """Constitution VIII: identity is construct + class, not line_start."""
    from shift_left.handlers.config.gate_findings import findings_for_corpus_file
    from shift_left.policy.finding_waiver import finding_waiver_identity

    before = "access-list OUTSIDE_IN extended permit ip any any\n"
    after = "! unrelated nearby edit\naccess-list OUTSIDE_IN extended permit ip any any\n"
    kwargs = {
        "path": "firewall/edge.rules",
        "target_type": "cisco_secure_firewall",
        "repo": "o/r",
        "pr_ref": "PR-1",
        "commit_sha": "commit-a",
    }
    original = next(
        item
        for item in findings_for_corpus_file(content=before, **kwargs)
        if item.trace == "handler:ASA-001"
    )
    shifted = next(
        item
        for item in findings_for_corpus_file(content=after, **kwargs)
        if item.trace == "handler:ASA-001"
    )
    assert original.line_range is not None and shifted.line_range is not None
    assert original.line_range.start != shifted.line_range.start
    ident_before = finding_waiver_identity(original)
    ident_after = finding_waiver_identity(shifted)
    assert ident_before is not None and ident_after is not None
    assert ident_before.storage_key() == ident_after.storage_key()
    assert ident_before.construct_key.startswith("ace:")
    assert ident_before.weakness_class == "CWE-284"

    _, waiver_service, _ = _services(stores)
    _save_block_review(stores, original)
    grant = _grant(waiver_service, original, capability=TokenCapability.APPROVE)

    decision = PullRequestPolicyDecision(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        default_action=PolicyAction.FLAG,
        pr_decision=PolicyAction.BLOCK,
        finding_decisions=[
            FindingPolicyDecision(
                finding_id=shifted.id,
                decision=PolicyAction.BLOCK,
                matched_policy_id="block-uninterpretable-config",
                matched_policy_name="Block",
                matched_rule_index=0,
                rule_explanation="policy_severity>=high",
                explanation="Blocked.",
            )
        ],
        explanation="Blocked.",
    )
    applied = apply_waivers_to_decision(decision, [shifted], [grant])
    assert shifted.id in applied.waived_finding_ids
    assert applied.effective_decision.pr_decision == PolicyAction.PASS
    assert grant.line_start == original.line_range.start
    assert grant.line_start != shifted.line_range.start

