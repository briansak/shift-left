"""Approval gating and deployment gate checks."""

from __future__ import annotations

from shift_left.analysis.result import TargetAnalysisResult
from shift_left.approval.waiver_service import FindingWaiverService
from shift_left.config import AppConfig, PolicyConfig
from shift_left.git.protocol import GitBackend
from shift_left.models.database import ApprovalStore, BlockOverrideStore, FindingsStore, PolicyDecisionStore
from shift_left.models.schema import (
    ApprovalRecord,
    BlockOverrideRecord,
    DeploymentGateResult,
    GateBlockReason,
    PolicyAction,
    PullRequestPolicyDecision,
)
from shift_left.policy.finding_waiver import apply_waivers_to_decision

def _normalize_identity(value: str) -> str:
    return value.strip().lower()


def _split_repo_slug(repo: str) -> tuple[str, str]:
    owner, _, name = repo.partition("/")
    if not name:
        raise ValueError(f"Invalid repo slug: {repo!r}")
    return owner, name


class ApprovalService:
    def __init__(
        self,
        *,
        config: AppConfig,
        sqlite_path: str,
        policy_config: PolicyConfig,
        findings_store: FindingsStore,
        policy_decisions: PolicyDecisionStore,
        approvals: ApprovalStore,
        overrides: BlockOverrideStore,
        waivers: FindingWaiverService | None = None,
        git: GitBackend | None = None,
    ) -> None:
        self._config = config
        self._policy_config = policy_config
        self._findings = findings_store
        self._decisions = policy_decisions
        self._approvals = approvals
        self._overrides = overrides
        self._waivers = waivers
        self._git = git

    @property
    def separation_of_duties_enforced(self) -> bool:
        if self._config.rbac.allow_self_approval:
            return False
        return self._policy_config.approval.separation_of_duties_enforced

    def _gate_identity_fields(self) -> dict[str, bool]:
        rbac_flag = self._config.rbac.allow_self_approval
        sod_enforced = self.separation_of_duties_enforced
        return {
            "separation_of_duties_enforced": sod_enforced,
            "separation_of_duties_disabled": not sod_enforced,
            "rbac_allow_self_approval": rbac_flag,
        }

    async def grant_approval(
        self,
        *,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        approver: str,
    ) -> ApprovalRecord:
        if self._git is not None:
            from shift_left.git.head_sha import assert_head_sha_unchanged, pr_number_from_ref

            await assert_head_sha_unchanged(
                self._git,
                repo=repo,
                pr_number=pr_number_from_ref(pr_ref),
                rendered_sha=commit_sha,
            )

        findings = self._findings.list_for_pr(repo, pr_ref)
        decision = self._decisions.for_commit(repo, pr_ref, commit_sha)
        if decision is None:
            decision = self._decisions.latest_for_pr(repo, pr_ref)
        if decision is None:
            raise ValueError(
                "No policy decision exists for this PR/commit — run a review before granting approval."
            )
        if decision.commit_sha != commit_sha:
            raise ValueError(
                f"Policy decision is for commit {decision.commit_sha}, not {commit_sha}."
            )

        if decision.pr_decision == PolicyAction.BLOCK:
            override = self._overrides.active_for_commit(repo, pr_ref, commit_sha)
            if override is None:
                if not self._policy_config.allow_block_override:
                    raise ValueError(
                        "Block policy decision cannot proceed without approval. "
                        "No override configured (policy.allow_block_override=false)."
                    )
                raise ValueError(
                    "Block policy decision requires an explicit override record before approval. "
                    "Grant override with justification via POST /api/v1/overrides/..."
                )

        commit_author: str | None = None
        approver_matches_author: bool | None = None
        separation_result: str | None = None

        if self._git is not None:
            owner, repo_name = _split_repo_slug(repo)
            commit_author = await self._git.get_commit_author(owner, repo_name, commit_sha)

        if commit_author and approver:
            approver_matches_author = (
                _normalize_identity(approver) == _normalize_identity(commit_author)
            )

        if self._policy_config.approval.separation_of_duties_enforced:
            separation_result = "enforced"
            if approver_matches_author:
                if self._config.rbac.allow_self_approval:
                    separation_result = "rbac_self_approval_permitted"
                else:
                    separation_result = "denied_approver_equals_author"
                    raise ValueError(
                        "Separation of duties: approver cannot approve their own commit "
                        f"(author={commit_author!r}, approver={approver!r})."
                    )
            else:
                separation_result = "passed_approver_differs_from_author"
        else:
            separation_result = "rule_disabled"
            if approver_matches_author and self._config.rbac.allow_self_approval:
                separation_result = "rbac_self_approval_permitted"

        record = ApprovalRecord(
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            approver=approver,
            commit_author=commit_author,
            approver_matches_author=approver_matches_author,
            separation_of_duties_result=separation_result,
            findings_snapshot=[finding.model_dump(mode="json") for finding in findings],
            policy_decision=decision.pr_decision,
            policy_decision_snapshot=decision.model_dump(mode="json"),
        )
        return self._approvals.grant(record)

    def revoke_approval(self, repo: str, pr_ref: str, *, actor: str) -> int:
        return self._approvals.revoke(repo, pr_ref, actor=actor)

    def invalidate_on_new_commit(self, repo: str, pr_ref: str, *, new_commit_sha: str) -> int:
        return self._approvals.invalidate_for_new_commit(
            repo,
            pr_ref,
            new_commit_sha=new_commit_sha,
            reason=f"New commit {new_commit_sha} landed — approval bound to prior SHA is invalid.",
        )

    def check_deployment_gate(
        self,
        *,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        analysis_results: list[TargetAnalysisResult] | None = None,
    ) -> DeploymentGateResult:
        gate_cfg = self._config.gate
        identity = self._gate_identity_fields()
        branch_check: bool | None = None

        if analysis_results:
            incomplete = [item for item in analysis_results if item.incomplete]
            if incomplete:
                kinds = ", ".join(sorted({item.target_kind.value for item in incomplete}))
                return DeploymentGateResult(
                    allowed=False,
                    reason=(
                        f"Required model analysis incomplete for: {kinds}. "
                        "Gate blocked — this is not a policy pass or empty-findings approval."
                    ),
                    commit_sha=commit_sha,
                    policy_decision=PolicyAction.FLAG,
                    approval_present=False,
                    approval_valid_for_commit=False,
                    block_override_present=False,
                    block_reason=GateBlockReason.ANALYSIS_INCOMPLETE,
                    analysis_incomplete=True,
                    commit_status_context=gate_cfg.status_context,
                    branch_protection_gate_check_required=gate_cfg.enabled,
                    branch_protection_gate_check_configured=branch_check,
                    **identity,
                )

        decision = self._decisions.for_commit(repo, pr_ref, commit_sha)
        if decision is None:
            return DeploymentGateResult(
                allowed=False,
                reason="No policy decision for this commit — run review first.",
                commit_sha=commit_sha,
                policy_decision=PolicyAction.FLAG,
                approval_present=False,
                approval_valid_for_commit=False,
                block_override_present=False,
                block_reason=GateBlockReason.NO_POLICY_DECISION,
                commit_status_context=gate_cfg.status_context,
                branch_protection_gate_check_required=gate_cfg.enabled,
                branch_protection_gate_check_configured=branch_check,
                **identity,
            )

        findings = self._findings.list_for_pr(repo, pr_ref)
        effective_decision = decision
        if self._waivers is not None:
            active_waivers = self._waivers.active_for_commit(repo, pr_ref, commit_sha)
            waiver_result = apply_waivers_to_decision(decision, findings, active_waivers)
            effective_decision = waiver_result.effective_decision
            if waiver_result.waivers_used:
                self._waivers.log_waiver_use(
                    repo=repo,
                    pr_ref=pr_ref,
                    commit_sha=commit_sha,
                    actor="system:shift-left",
                    waivers_used=waiver_result.waivers_used,
                )

        approval = self._approvals.active_for_commit(repo, pr_ref, commit_sha)
        override = self._overrides.active_for_commit(repo, pr_ref, commit_sha)

        if effective_decision.pr_decision == PolicyAction.BLOCK:
            if not self._policy_config.allow_block_override or override is None:
                return DeploymentGateResult(
                    allowed=False,
                    reason=(
                        "Block policy decision is active and cannot be bypassed "
                        "(no override configured or granted)."
                    ),
                    commit_sha=commit_sha,
                    policy_decision=effective_decision.pr_decision,
                    approval_present=approval is not None,
                    approval_valid_for_commit=approval is not None,
                    block_override_present=override is not None,
                    block_reason=GateBlockReason.POLICY_BLOCK,
                    commit_status_context=gate_cfg.status_context,
                    branch_protection_gate_check_required=gate_cfg.enabled,
                    branch_protection_gate_check_configured=branch_check,
                    **identity,
                )

        if approval is None:
            return DeploymentGateResult(
                allowed=False,
                reason="Human approval required for deployment — none recorded for this commit SHA.",
                commit_sha=commit_sha,
                policy_decision=effective_decision.pr_decision,
                approval_present=False,
                approval_valid_for_commit=False,
                block_override_present=override is not None,
                block_reason=GateBlockReason.APPROVAL_REQUIRED,
                commit_status_context=gate_cfg.status_context,
                branch_protection_gate_check_required=gate_cfg.enabled,
                branch_protection_gate_check_configured=branch_check,
                **identity,
            )

        return DeploymentGateResult(
            allowed=True,
            reason="Approval recorded for this commit SHA and policy gate satisfied.",
            commit_sha=commit_sha,
            policy_decision=effective_decision.pr_decision,
            approval_present=True,
            approval_valid_for_commit=True,
            block_override_present=override is not None,
            block_reason=None,
            commit_status_context=gate_cfg.status_context,
            branch_protection_gate_check_required=gate_cfg.enabled,
            branch_protection_gate_check_configured=branch_check,
            **identity,
        )

    async def grant_block_override(
        self,
        *,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        actor: str,
        justification: str,
        policy_id: str | None = None,
    ) -> BlockOverrideRecord:
        if self._git is not None:
            from shift_left.git.head_sha import assert_head_sha_unchanged, pr_number_from_ref

            await assert_head_sha_unchanged(
                self._git,
                repo=repo,
                pr_number=pr_number_from_ref(pr_ref),
                rendered_sha=commit_sha,
            )
        if not self._policy_config.allow_block_override:
            raise ValueError(
                "Block override is not enabled (policy.allow_block_override=false). "
                "Block policy decisions cannot be silently bypassed."
            )
        if not justification.strip():
            raise ValueError("Block override requires explicit justification.")
        return self._overrides.grant(
            BlockOverrideRecord(
                repo=repo,
                pr_ref=pr_ref,
                commit_sha=commit_sha,
                actor=actor,
                justification=justification.strip(),
                policy_id=policy_id,
            )
        )
