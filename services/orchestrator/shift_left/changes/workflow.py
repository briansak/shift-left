"""Server-computed change workflow state — UI must not derive this client-side."""

from __future__ import annotations

from shift_left.auth.context import AuthContext, TokenCapability
from shift_left.config import AppConfig
from shift_left.git.protocol import GitBackend
from shift_left.models.database import AuditStore, PlanStore, PolicyDecisionStore
from shift_left.models.schema import (
    ChangeState,
    ChangeStateResult,
    ConfigChangeSummary,
    GateBlockReason,
    PolicyAction,
    PullRequestPolicyDecision,
)
from shift_left.approval.service import ApprovalService
from shift_left.git.forgejo_read import ForgejoEmbedService


def _pr_number_from_ref(pr_ref: str) -> int | None:
    if pr_ref.startswith("PR-"):
        suffix = pr_ref.removeprefix("PR-")
        if suffix.isdigit():
            return int(suffix)
    return None


def _split_repo_slug(repo: str) -> tuple[str, str]:
    owner, _, name = repo.partition("/")
    return owner, name


class ChangeWorkflowService:
    def __init__(
        self,
        *,
        config: AppConfig,
        policy_decisions: PolicyDecisionStore,
        plans: PlanStore,
        approvals: ApprovalService,
        audit: AuditStore,
        git: GitBackend,
        forgejo_embed: ForgejoEmbedService | None = None,
    ) -> None:
        self._config = config
        self._decisions = policy_decisions
        self._plans = plans
        self._approvals = approvals
        self._audit = audit
        self._git = git
        self._forgejo = forgejo_embed

    def audit_state_transition(
        self,
        *,
        actor: str,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        state: ChangeState,
        reason: str,
    ) -> None:
        self._audit.log(
            actor=actor,
            action="change.state_transition",
            subject=f"{repo}/{pr_ref}",
            details={
                "commit_sha": commit_sha,
                "state": state.value,
                "reason": reason,
            },
        )

    def latest_analysis_failure(
        self, repo: str, pr_ref: str, commit_sha: str
    ) -> dict[str, str | None] | None:
        """Newest analysis.failed event for this commit, if any."""
        events = self._audit.list_events(
            subject_prefix=f"{repo}/{pr_ref}",
            action="analysis.failed",
            limit=200,
        )
        for event in events:
            if event.details.get("commit_sha") != commit_sha:
                continue
            return {
                "failure_class": event.details.get("failure_class"),
                "failure_stage": event.details.get("failure_stage"),
                "failure_message": event.details.get("failure_message"),
                "target_kind": event.details.get("target_kind"),
            }
        return None

    def _validation_incomplete(self, repo: str, pr_ref: str, commit_sha: str) -> bool:
        events = self._audit.list_events(subject_prefix=f"{repo}/{pr_ref}", limit=200)
        failed_at = None
        completed_at = None
        for event in events:
            if event.details.get("commit_sha") != commit_sha:
                continue
            if event.action == "analysis.failed":
                failed_at = event.timestamp
            elif event.action == "review.completed":
                completed_at = event.timestamp
        if failed_at is None:
            return False
        if completed_at is None:
            return True
        return failed_at > completed_at

    def compute_state(
        self,
        *,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        pr_number: int | None = None,
    ) -> ChangeStateResult:
        policy_for_commit = self._decisions.for_commit(repo, pr_ref, commit_sha)
        latest_policy = self._decisions.latest_for_pr(repo, pr_ref)
        gate = self._approvals.check_deployment_gate(
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
        )
        plan = self._plans.for_commit(repo, pr_ref, commit_sha)
        stale_plan = self._plans.latest_for_pr(repo, pr_ref)
        rbac_flag = self._config.rbac.allow_self_approval

        if self._validation_incomplete(repo, pr_ref, commit_sha) or gate.analysis_incomplete:
            return self._result(
                state=ChangeState.VALIDATION_INCOMPLETE,
                reason="Required analysis did not complete for this commit.",
                next_action="Re-run validation after resolving analysis failures.",
                repo=repo,
                pr_ref=pr_ref,
                pr_number=pr_number,
                commit_sha=commit_sha,
                gate=gate,
                rbac_flag=rbac_flag,
            )

        if policy_for_commit is None:
            if latest_policy is None:
                return self._result(
                    state=ChangeState.DRAFT_OPEN,
                    reason="No validation has been recorded for this change.",
                    next_action="Run validation (review) on this pull request.",
                    repo=repo,
                    pr_ref=pr_ref,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                    gate=gate,
                    rbac_flag=rbac_flag,
                )
            if latest_policy.commit_sha != commit_sha:
                return self._result(
                    state=ChangeState.VALIDATING,
                    reason="Head commit changed — validation must run against the new SHA.",
                    next_action="Run validation for the current commit.",
                    repo=repo,
                    pr_ref=pr_ref,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                    gate=gate,
                    rbac_flag=rbac_flag,
                )
            policy_for_commit = latest_policy

        assert policy_for_commit is not None
        if policy_for_commit.commit_sha != commit_sha:
            return self._result(
                state=ChangeState.VALIDATING,
                reason="Policy decision is not bound to the current head SHA.",
                next_action="Run validation for the current commit.",
                repo=repo,
                pr_ref=pr_ref,
                pr_number=pr_number,
                commit_sha=commit_sha,
                gate=gate,
                rbac_flag=rbac_flag,
            )

        if policy_for_commit.pr_decision == PolicyAction.BLOCK and gate.block_reason in {
            GateBlockReason.POLICY_BLOCK,
            None,
        }:
            override = self._approvals._overrides.active_for_commit(repo, pr_ref, commit_sha)
            if override is None and not gate.allowed:
                return self._result(
                    state=ChangeState.BLOCKED_BY_POLICY,
                    reason=policy_for_commit.explanation or "Policy block active for this commit.",
                    next_action="Resolve findings or obtain an authorized block override, then re-validate.",
                    repo=repo,
                    pr_ref=pr_ref,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                    gate=gate,
                    rbac_flag=rbac_flag,
                )

        if not gate.allowed:
            if gate.block_reason == GateBlockReason.APPROVAL_REQUIRED:
                return self._result(
                    state=ChangeState.AWAITING_APPROVAL,
                    reason=gate.reason,
                    next_action="A different authorized reviewer must approve this commit SHA.",
                    repo=repo,
                    pr_ref=pr_ref,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                    gate=gate,
                    rbac_flag=rbac_flag,
                )
            return self._result(
                state=ChangeState.BLOCKED_BY_POLICY,
                reason=gate.reason,
                next_action="Resolve blocking conditions before approval or deployment planning.",
                repo=repo,
                pr_ref=pr_ref,
                pr_number=pr_number,
                commit_sha=commit_sha,
                gate=gate,
                rbac_flag=rbac_flag,
            )

        if plan is not None:
            return self._result(
                state=ChangeState.PLAN_GENERATED,
                reason=f"Terraform plan generated for commit {commit_sha[:7]}.",
                next_action="Review plan output; apply is not yet available in this release.",
                repo=repo,
                pr_ref=pr_ref,
                pr_number=pr_number,
                commit_sha=commit_sha,
                gate=gate,
                rbac_flag=rbac_flag,
            )

        if stale_plan is not None and stale_plan.commit_sha != commit_sha:
            return self._result(
                state=ChangeState.PLAN_STALE,
                reason=(
                    f"Plan was generated for {stale_plan.commit_sha[:7]} — "
                    f"head is now {commit_sha[:7]}."
                ),
                next_action="Generate a fresh plan after approval for the current SHA.",
                repo=repo,
                pr_ref=pr_ref,
                pr_number=pr_number,
                commit_sha=commit_sha,
                gate=gate,
                rbac_flag=rbac_flag,
            )

        return self._result(
            state=ChangeState.APPROVED,
            reason="Gate allows deployment planning for this commit SHA.",
            next_action="Generate a Terraform plan (requires deploy capability).",
            repo=repo,
            pr_ref=pr_ref,
            pr_number=pr_number,
            commit_sha=commit_sha,
            gate=gate,
            rbac_flag=rbac_flag,
        )

    @staticmethod
    def _result(
        *,
        state: ChangeState,
        reason: str,
        next_action: str,
        repo: str,
        pr_ref: str,
        pr_number: int | None,
        commit_sha: str,
        gate,
        rbac_flag: bool,
    ) -> ChangeStateResult:
        return ChangeStateResult(
            state=state,
            reason=reason,
            next_action=next_action,
            repo=repo,
            pr_ref=pr_ref,
            pr_number=pr_number,
            commit_sha=commit_sha,
            gate_allowed=gate.allowed,
            rbac_allow_self_approval=rbac_flag,
        )

    def viewer_action(
        self,
        *,
        state: ChangeState,
        auth: AuthContext | None,
        commit_author: str | None,
    ) -> str | None:
        if auth is None:
            return None
        sod_block = (
            self._approvals.separation_of_duties_enforced
            and commit_author
            and auth.actor.strip().lower() == commit_author.strip().lower()
        )
        if state in {ChangeState.DRAFT_OPEN, ChangeState.VALIDATING} and auth.has_capability(
            TokenCapability.REVIEW
        ):
            return "Run validation"
        if state == ChangeState.AWAITING_APPROVAL and auth.has_capability(TokenCapability.APPROVE):
            if sod_block:
                return None
            return "Approve"
        if state in {ChangeState.APPROVED, ChangeState.PLAN_STALE} and auth.has_capability(
            TokenCapability.DEPLOY
        ):
            return "Generate plan"
        if state == ChangeState.BLOCKED_BY_POLICY and auth.has_capability(
            TokenCapability.OVERRIDE
        ) and self._config.policy.allow_block_override:
            return "Request override"
        return None

    def _configured_repos(self) -> list[str]:
        repos: list[str] = []
        if self._config.gate.check_repo:
            repos.append(self._config.gate.check_repo)
        for repo, _pr_ref in self._decisions.list_distinct_prs():
            if repo not in repos:
                repos.append(repo)
        return repos

    async def list_changes(self, *, auth: AuthContext | None = None) -> list[ConfigChangeSummary]:
        runner_notice = None
        fetched_at = None
        if self._forgejo is not None:
            runner_notice = await self._forgejo.runner_notice()
            fetched_at = self._forgejo.browse_fetched_at()

        summaries: list[ConfigChangeSummary] = []
        seen: set[tuple[str, int]] = set()

        for repo in self._configured_repos():
            owner, repo_name = _split_repo_slug(repo)
            open_prs: list[dict] = []
            if self._forgejo is not None:
                try:
                    open_prs = await self._forgejo.list_open_pull_requests_cached(owner, repo_name)
                except Exception:
                    open_prs = []
            if not open_prs:
                # Fallback: reviewed PRs only when Forgejo list is unavailable.
                for stored_repo, pr_ref in self._decisions.list_distinct_prs():
                    if stored_repo != repo:
                        continue
                    pr_number = _pr_number_from_ref(pr_ref)
                    if pr_number is None:
                        continue
                    try:
                        pr = await self._git.get_pull_request(owner, repo_name, pr_number)
                    except Exception:
                        continue
                    open_prs.append(pr)

            for pr in open_prs:
                pr_number = int(pr.get("number") or 0)
                if pr_number <= 0:
                    continue
                key = (repo, pr_number)
                if key in seen:
                    continue
                seen.add(key)

                pr_ref = f"PR-{pr_number}"
                commit_sha = (pr.get("head") or {}).get("sha") or "unknown"
                author = (pr.get("user") or {}).get("login")
                branch = (pr.get("head") or {}).get("ref")
                title = pr.get("title")
                base_ref = (pr.get("base") or {}).get("ref") or self._config.gate.protected_branch
                config_scope = "config"
                if self._forgejo is not None:
                    try:
                        config_scope = await self._forgejo.classify_pr_scope(owner, repo_name, pr_number)
                    except Exception:
                        config_scope = "config"

                state_result = self.compute_state(
                    repo=repo,
                    pr_ref=pr_ref,
                    commit_sha=commit_sha,
                    pr_number=pr_number,
                )
                gate = self._approvals.check_deployment_gate(
                    repo=repo,
                    pr_ref=pr_ref,
                    commit_sha=commit_sha,
                )
                forgejo_url = (
                    self._forgejo.pr_url(owner, repo_name, pr_number) if self._forgejo else None
                )
                summaries.append(
                    ConfigChangeSummary(
                        repo=repo,
                        pr_ref=pr_ref,
                        pr_number=pr_number,
                        owner=owner,
                        repo_name=repo_name,
                        title=title,
                        author=author,
                        branch=branch,
                        target_environment=base_ref,
                        commit_sha=commit_sha,
                        change_state=state_result.state,
                        next_action=state_result.next_action,
                        viewer_action=self.viewer_action(
                            state=state_result.state,
                            auth=auth,
                            commit_author=author,
                        ),
                        config_scope=config_scope,
                        gate_allowed=gate.allowed,
                        forgejo_pr_url=forgejo_url,
                        forgejo_state=str(pr.get("state") or "open"),
                        runner_notice=runner_notice,
                        last_fetched_at=fetched_at,
                    )
                )

        summaries.sort(key=lambda item: (item.repo, item.pr_number))
        return summaries

    async def state_for_pr(
        self,
        *,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> ChangeStateResult:
        repo_slug = f"{owner}/{repo}"
        pr_ref = f"PR-{pr_number}"
        pr = await self._git.get_pull_request(owner, repo, pr_number)
        commit_sha = pr.get("head", {}).get("sha") or "unknown"
        return self.compute_state(
            repo=repo_slug,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            pr_number=pr_number,
        )
