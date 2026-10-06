"""Core PR review workflow."""

from __future__ import annotations

import logging
import time

from shift_left.analysis.result import TargetAnalysisResult, completed_no_findings
from shift_left.handlers.code_cwe_rules import findings_from_code_handlers
from shift_left.handlers.config.gate_findings import findings_from_config_handlers
from shift_left.handlers.unclaimed_files import findings_for_unclaimed_paths
from shift_left.approval.service import ApprovalService
from shift_left.approval.waiver_service import FindingWaiverService
from shift_left.changes.workflow import ChangeWorkflowService
from shift_left.deployment.service import DeploymentPlanService
from shift_left.system.settings import SettingsService
from shift_left.system.services import ServiceLifecycleManager
from shift_left.system.status import SystemStatusService
from shift_left.config import (
    AppConfig,
    resolve_audit_sqlite_path,
    resolve_auth_sqlite_path,
    resolve_foundation_sec_service_url,
    runtime_allowed_endpoints,
)
from shift_left.diff.config_extractor import parse_config_diff
from shift_left.diff.extractor import parse_unified_diff
from shift_left.enrichment.service import EnrichmentService
from shift_left.foundation_sec.client import FoundationSecClient
from shift_left.auth.tokens import TokenStore
from shift_left.gate.service import GateService
from shift_left.git.factory import create_git_backend
from shift_left.git.forgejo_read import ForgejoEmbedService
from shift_left.git.protocol import GitBackend
from shift_left.http.local_client import LocalOnlyAsyncClient
from shift_left.handlers.config.secret_values import extract_secret_values_from_content
from shift_left.ui.advisory_line_attribution import is_advisory_finding
from shift_left.ui.config_redaction import redact_display_text
from shift_left.ui.secret_value_provenance import (
    SecretResolutionCache,
    build_secret_index_for_findings,
    secrets_for_indexed_finding,
)
from shift_left.models.database import (
    SYSTEM_ACTOR,
    ApprovalStore,
    AuditStore,
    BlockOverrideStore,
    FindingWaiverStore,
    FindingsStore,
    PlanStore,
    PolicyDecisionStore,
)
from shift_left.models.schema import (
    ChangeState,
    EnrichmentStatus,
    Finding,
    FindingStatus,
    FindingStatusUpdate,
    PolicyAction,
    ReviewRequest,
    ReviewResult,
    ReviewSummary,
    TargetKind,
)
from shift_left.policy.engine import PolicyEngine
from shift_left.policy.finding_waiver import apply_waivers_to_decision, waiver_matches_finding
from shift_left.policy.handler_trace import handler_rule_id_from_trace
from shift_left.policy.severity import apply_policy_severities
from shift_left.reference.cache import ReferenceDataCache
from shift_left.reference.enricher import FindingEnricher
from shift_left.routing.path_claim import unclaimed_paths
from shift_left.routing.router import route_changes

logger = logging.getLogger(__name__)

_RATIONALE_REQUIRED = {FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK}


class ReviewService:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        allowed = runtime_allowed_endpoints(config)
        self._git: GitBackend = create_git_backend(config)
        self._forgejo_embed = ForgejoEmbedService(config=config, git=self._git)
        fs_cfg = config.models.foundation_sec
        self._foundation_sec: FoundationSecClient | None = None
        if fs_cfg.enabled:
            self._foundation_sec = FoundationSecClient(
                resolve_foundation_sec_service_url(config),
                timeout=float(fs_cfg.request_timeout_seconds),
                max_context_tokens=fs_cfg.max_context_tokens,
                chunk_overlap_lines=fs_cfg.chunk_overlap_lines,
                context_lines_before=fs_cfg.context_lines_before,
                context_lines_after=fs_cfg.context_lines_after,
                stage_timeouts=fs_cfg.stage_timeouts,
            )
            self._foundation_sec._http = LocalOnlyAsyncClient(
                timeout=float(fs_cfg.request_timeout_seconds),
                allowed_endpoints=allowed,
                stage_timeouts=fs_cfg.stage_timeouts,
            )

        db_path = config.findings_store.sqlite_path
        audit_path = resolve_audit_sqlite_path(config)
        self._store = FindingsStore(db_path)
        self._audit = AuditStore(audit_path, retention_days=config.audit.retention_days)
        self._policy_decisions = PolicyDecisionStore(db_path)
        self._plans = PlanStore(db_path)
        self._approvals = ApprovalStore(db_path)
        self._overrides = BlockOverrideStore(db_path)
        self._finding_waivers = FindingWaiverStore(db_path)
        self._token_store = TokenStore(resolve_auth_sqlite_path(config))
        self._policy_engine = PolicyEngine(config.policy)
        self._waiver_service = FindingWaiverService(
            config=config,
            findings_store=self._store,
            policy_decisions=self._policy_decisions,
            waivers=self._finding_waivers,
            audit=self._audit,
            git=self._git,
        )
        self._approval_service = ApprovalService(
            config=config,
            sqlite_path=db_path,
            policy_config=config.policy,
            findings_store=self._store,
            policy_decisions=self._policy_decisions,
            approvals=self._approvals,
            overrides=self._overrides,
            waivers=self._waiver_service,
            git=self._git,
        )
        self._gate_service = GateService(
            config=config,
            git=self._git,
            approvals=self._approval_service,
        )
        self._deployment = DeploymentPlanService(
            config=config,
            plans=self._plans,
            approvals=self._approval_service,
            audit=self._audit,
        )
        self._changes = ChangeWorkflowService(
            config=config,
            policy_decisions=self._policy_decisions,
            plans=self._plans,
            approvals=self._approval_service,
            audit=self._audit,
            git=self._git,
            forgejo_embed=self._forgejo_embed,
        )
        from shift_left.targets.registry import ManagedTargetRegistry
        from shift_left.targets.service import TargetService
        from shift_left.targets.write import ManagedTargetWriteService

        self._target_registry = ManagedTargetRegistry(config)
        self._targets = TargetService(
            config=config,
            registry=self._target_registry,
            forgejo=self._forgejo_embed,
            git=self._git,
            changes=self._changes,
            findings_store=self._store,
            policy_decisions=self._policy_decisions,
            approvals=self._approval_service,
            plans=self._plans,
        )
        self._target_writes = ManagedTargetWriteService(config=config, audit=self._audit)
        self._reference = ReferenceDataCache(
            config.reference_data.cache_dir,
            max_staleness_days=config.reference_data.max_staleness_days,
        )
        self._system_status = SystemStatusService(
            config=config,
            git=self._git,
            reference=self._reference,
            audit=self._audit,
            foundation_client=self._foundation_sec,
        )
        self._settings = SettingsService(config=config, audit=self._audit)
        self._service_lifecycle = ServiceLifecycleManager(config=config, audit=self._audit)
        self._service_lifecycle.attach_prerequisite_checker(self._system_status._prerequisites)
        self._enricher = FindingEnricher(self._reference)
        self._model_enrichment = EnrichmentService(
            config,
            http=LocalOnlyAsyncClient(
                timeout=float(config.models.foundation_sec.request_timeout_seconds),
                allowed_endpoints=allowed,
                stage_timeouts=config.models.foundation_sec.stage_timeouts,
            ),
            allowed_endpoints=allowed,
        )

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    @property
    def audit(self) -> AuditStore:
        return self._audit

    @property
    def approvals(self) -> ApprovalService:
        return self._approval_service

    @property
    def waivers(self) -> FindingWaiverService:
        return self._waiver_service

    @property
    def gate(self) -> GateService:
        return self._gate_service

    @property
    def changes(self) -> ChangeWorkflowService:
        return self._changes

    @property
    def targets(self):
        return self._targets

    @property
    def target_writes(self):
        return self._target_writes

    def refresh_config(self, new_config: AppConfig) -> None:
        from shift_left.targets.registry import ManagedTargetRegistry

        self._config = new_config
        self.settings._config = new_config
        self.system_status._config = new_config
        self.service_lifecycle._config = new_config
        self._target_registry = ManagedTargetRegistry(new_config)
        self._targets._config = new_config
        self._targets._registry = self._target_registry
        self._target_writes._config = new_config
        self.service_lifecycle._refresh_service_catalog()

    @property
    def deployment(self) -> DeploymentPlanService:
        return self._deployment

    @property
    def system_status(self) -> SystemStatusService:
        return self._system_status

    @property
    def settings(self) -> SettingsService:
        return self._settings

    @property
    def service_lifecycle(self) -> ServiceLifecycleManager:
        return self._service_lifecycle

    @property
    def token_store(self) -> TokenStore:
        return self._token_store

    async def review_pull_request(self, request: ReviewRequest) -> ReviewResult:
        owner = request.owner
        repo_name = request.repo
        repo_slug = f"{owner}/{repo_name}"
        pr_ref = f"PR-{request.pr_number}"

        pr = await self._git.get_pull_request(owner, repo_name, request.pr_number)
        commit_sha = request.commit_sha or pr.get("head", {}).get("sha") or "unknown"
        if not commit_sha or commit_sha == "unknown":
            commit_sha = (
                pr.get("sha")
                or (pr.get("diff_refs") or {}).get("head_sha")
                or "unknown"
            )
        diff_text = await self._git.get_pull_diff(owner, repo_name, request.pr_number)

        self._audit.log(
            actor=SYSTEM_ACTOR,
            action="review.started",
            subject=f"{repo_slug}/{pr_ref}",
            details={"commit_sha": commit_sha},
        )

        invalidated = self._approval_service.invalidate_on_new_commit(
            repo_slug,
            pr_ref,
            new_commit_sha=commit_sha,
        )
        if invalidated:
            self._audit.log(
                actor=SYSTEM_ACTOR,
                action="approval.invalidated",
                subject=f"{repo_slug}/{pr_ref}",
                details={"count": invalidated, "commit_sha": commit_sha},
            )

        expired_waivers = self._waiver_service.invalidate_on_new_commit(
            repo_slug,
            pr_ref,
            new_commit_sha=commit_sha,
            actor=SYSTEM_ACTOR,
        )
        if expired_waivers:
            self._audit.log(
                actor=SYSTEM_ACTOR,
                action="waiver.expired_batch",
                subject=f"{repo_slug}/{pr_ref}",
                details={"count": len(expired_waivers), "commit_sha": commit_sha},
            )

        plan_invalidated = self._deployment.invalidate_plans(
            repo_slug, pr_ref, new_commit_sha=commit_sha
        )
        if plan_invalidated:
            self._audit.log(
                actor=SYSTEM_ACTOR,
                action="deployment.plan_invalidated",
                subject=f"{repo_slug}/{pr_ref}",
                details={"count": plan_invalidated, "commit_sha": commit_sha},
            )
            self._changes.audit_state_transition(
                actor=SYSTEM_ACTOR,
                repo=repo_slug,
                pr_ref=pr_ref,
                commit_sha=commit_sha,
                state=ChangeState.VALIDATING,
                reason="New commit invalidated prior plan and approval.",
            )

        result = await self.review_diff(
            diff_text=diff_text,
            repo=repo_slug,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            skip_advisory=request.skip_advisory,
        )

        await self._post_pr_comment(
            owner=owner,
            repo=repo_name,
            pr_number=request.pr_number,
            findings=result.findings,
            policy_decision=result.policy_decision,
            review_summary=result.review_summary,
            enrichment_unavailable=result.enrichment_unavailable,
        )
        return result

    async def review_diff(
        self,
        *,
        diff_text: str,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        skip_advisory: bool = False,
    ) -> ReviewResult:
        if len(diff_text.encode()) > self._config.resources.max_diff_bytes:
            raise ValueError(
                f"Diff exceeds max_diff_bytes ({self._config.resources.max_diff_bytes})"
            )

        fs_cfg = self._config.models.foundation_sec
        code_files = parse_unified_diff(diff_text, max_hunk_lines=200)
        config_files = parse_config_diff(
            diff_text,
            max_hunk_lines=fs_cfg.max_hunk_lines,
            context_lines_before=fs_cfg.context_lines_before,
            context_lines_after=fs_cfg.context_lines_after,
        )

        changed_paths = sorted(
            {item.path for item in code_files} | {item.path for item in config_files}
        )
        targets = self._config.managed_targets.targets
        gate_unclaimed = unclaimed_paths(
            changed_paths,
            self._config.routing,
            repo=repo,
            targets=targets,
        )

        routed_code = route_changes(
            code_files,
            self._config.routing,
            repo=repo,
            targets=targets,
        ).code_files
        routed_config = route_changes(
            config_files,
            self._config.routing,
            repo=repo,
            targets=targets,
        ).config_files

        if len(routed_code) + len(routed_config) > self._config.resources.max_files_per_review:
            raise ValueError(
                f"Too many changed files for review (> {self._config.resources.max_files_per_review})"
            )

        findings: list[Finding] = []
        if gate_unclaimed:
            findings.extend(
                findings_for_unclaimed_paths(
                    gate_unclaimed,
                    gate=self._config.gate.unclaimed_files,
                    repo=repo,
                    pr_ref=pr_ref,
                    commit_sha=commit_sha,
                )
            )
        analysis_results: list[TargetAnalysisResult] = []
        stage_timings_ms: dict[str, int] = {}

        if routed_code:
            logger.info(
                "Evaluating %d code file(s) with deterministic handler rules (PR gate path)",
                len(routed_code),
            )
            handler_findings = findings_from_code_handlers(
                routed_code,
                repo=repo,
                pr_ref=pr_ref,
                commit_sha=commit_sha,
            )
            findings.extend(handler_findings)
            analysis_results.append(completed_no_findings(TargetKind.CODE))

        if routed_config:
            handler_started = time.monotonic()
            handler_findings = findings_from_config_handlers(
                routed_config,
                repo=repo,
                pr_ref=pr_ref,
                commit_sha=commit_sha,
                targets=targets,
                config=self._config,
            )
            stage_timings_ms["handler_eval_ms"] = int(
                (time.monotonic() - handler_started) * 1000
            )
            findings.extend(handler_findings)

            if skip_advisory:
                analysis_results.append(completed_no_findings(TargetKind.CONFIG))
            elif self._config.models.foundation_sec.enabled and self._foundation_sec:
                logger.info("Routing %d config file(s) to Foundation-Sec", len(routed_config))
                try:
                    config_result = await self._foundation_sec.analyze_hunks(
                        repo=repo,
                        pr_ref=pr_ref,
                        commit_sha=commit_sha,
                        files=routed_config,
                    )
                finally:
                    await self._unload_foundation_sec_if_on_demand()
                analysis_results.append(config_result)
                stage_timings_ms.update(
                    {
                        f"foundation_sec_{key}": value
                        for key, value in config_result.timings_ms.items()
                    }
                )
                if config_result.incomplete:
                    self._audit.log(
                        actor=SYSTEM_ACTOR,
                        action="analysis.failed",
                        subject=f"{repo}/{pr_ref}",
                        details={
                            "commit_sha": commit_sha,
                            "target_kind": config_result.target_kind.value,
                            "failure_class": (
                                config_result.failure_class.value
                                if config_result.failure_class
                                else None
                            ),
                            "failure_stage": (
                                config_result.failure_stage.value
                                if config_result.failure_stage
                                else None
                            ),
                            "failure_message": config_result.failure_message,
                        },
                    )
                else:
                    covered_rules = {
                        handler_rule_id_from_trace(item.trace) for item in handler_findings
                    }
                    covered_rules.discard(None)
                    for item in config_result.findings:
                        rule_id = handler_rule_id_from_trace(item.trace)
                        if rule_id and rule_id in covered_rules:
                            continue
                        findings.append(item)
            else:
                raise RuntimeError(
                    f"{len(routed_config)} config file(s) in diff but Foundation-Sec is disabled."
                )

        findings = self._apply_enrichment(findings)

        enrichment_unavailable = False
        review_summary: ReviewSummary | None = None
        if findings and self._model_enrichment.enabled and not skip_advisory:
            findings, prose_failed = await self._model_enrichment.enrich_findings(findings)
            enrichment_unavailable = prose_failed
            if prose_failed:
                self._audit.log(
                    actor=SYSTEM_ACTOR,
                    action="enrichment.unavailable",
                    subject=f"{repo}/{pr_ref}",
                    details={"commit_sha": commit_sha},
                )
            review_summary = await self._model_enrichment.generate_review_summary(findings)
            if review_summary is None and self._config.enrichment.generate_review_summary:
                enrichment_unavailable = True

        findings = apply_policy_severities(findings, self._config)

        if findings:
            self._store.save_findings(findings)
            self._audit.log(
                actor=SYSTEM_ACTOR,
                action="findings.created",
                subject=f"{repo}/{pr_ref}",
                details={"count": len(findings), "commit_sha": commit_sha},
            )

        evaluation = self._policy_engine.evaluate(
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            findings=findings,
        )
        policy_decision = evaluation.pr_decision
        self._policy_decisions.save(policy_decision)
        block_sources = [
            {
                "finding_id": item.finding_id,
                "decision_source": item.matched_policy_id,
            }
            for item in policy_decision.finding_decisions
            if item.decision == PolicyAction.BLOCK
        ]
        self._audit.log(
            actor=SYSTEM_ACTOR,
            action="policy.decision_rendered",
            subject=f"{repo}/{pr_ref}",
            details={
                "commit_sha": commit_sha,
                "pr_decision": policy_decision.pr_decision.value,
                "explanation": policy_decision.explanation,
                "block_findings": block_sources,
            },
        )

        self._audit.log(
            actor=SYSTEM_ACTOR,
            action="review.completed",
            subject=f"{repo}/{pr_ref}",
            details={
                "commit_sha": commit_sha,
                "finding_count": len(findings),
                "policy_decision": policy_decision.pr_decision.value,
            },
        )

        owner, repo_name = repo.split("/", 1)
        pr_number: int | None = None
        if pr_ref.startswith("PR-"):
            suffix = pr_ref.removeprefix("PR-")
            if suffix.isdigit():
                pr_number = int(suffix)
        await self._gate_service.evaluate_and_publish(
            owner=owner,
            repo_name=repo_name,
            repo_slug=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            pr_number=pr_number,
            analysis_results=analysis_results,
        )

        state = self._changes.compute_state(
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            pr_number=pr_number,
        )
        self._changes.audit_state_transition(
            actor=SYSTEM_ACTOR,
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            state=state.state,
            reason=state.reason,
        )

        return ReviewResult(
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            findings=findings,
            policy_decision=policy_decision,
            advisory_action=policy_decision.pr_decision,
            review_summary=review_summary,
            enrichment_unavailable=enrichment_unavailable,
            analysis_results=analysis_results,
            stage_timings_ms=stage_timings_ms,
            message=(
                f"Review complete. Policy decision: {policy_decision.pr_decision.value} "
                "(advisory — not a compliance verdict)."
                if findings
                else "Review complete. No handler findings matched changed hunks."
            ),
        )

    def update_finding_status(
        self,
        finding_id: str,
        update: FindingStatusUpdate,
        *,
        actor: str,
    ) -> Finding:
        if not actor or not actor.strip():
            raise ValueError("Actor must be derived from API token")
        if update.status in _RATIONALE_REQUIRED and not (update.rationale or "").strip():
            raise ValueError(
                f"Rationale is required when setting status to '{update.status.value}'."
            )
        previous = self._store.get(finding_id)
        if previous is None:
            raise LookupError("Finding not found")

        updated = self._store.update_status(
            finding_id,
            update.status,
            actor=actor,
            rationale=update.rationale,
        )
        assert updated is not None
        self._audit.log(
            actor=actor,
            action="finding.status_changed",
            subject=finding_id,
            details={
                "from": previous.status.value,
                "to": update.status.value,
                "rationale": update.rationale,
                "repo": updated.repo,
                "pr_ref": updated.pr_ref,
            },
        )
        return updated

    def _stored_review_commit_sha(self, repo_slug: str, pr_ref: str) -> str:
        """Commit the local store already reviewed, used when Forgejo has no head SHA."""
        decision = self._policy_decisions.latest_for_pr(repo_slug, pr_ref)
        if decision is not None and decision.commit_sha:
            return decision.commit_sha
        for finding in self._store.list_for_pr(repo_slug, pr_ref):
            if finding.commit_sha:
                return finding.commit_sha
        records = self.approvals._approvals.list_for_pr(repo_slug, pr_ref)
        for record in records:
            if record.commit_sha and not record.invalidated:
                return record.commit_sha
        for record in records:
            if record.commit_sha:
                return record.commit_sha
        return "unknown"

    async def build_pr_review_context(
        self,
        *,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> dict:
        from shift_left.ui.diff_view import build_diff_file_views
        from shift_left.ui.forgejo_views import build_commit_timeline, compare_gate_status

        repo_slug = f"{owner}/{repo}"
        pr_ref = f"PR-{pr_number}"
        forgejo_unavailable = False
        forgejo_notice: str | None = None
        pr: dict = {}
        diff_text = ""
        try:
            pr = await self._forgejo_embed.get_pull_request_cached(owner, repo, pr_number)
            diff_text = await self._forgejo_embed.get_pull_diff_cached(owner, repo, pr_number)
        except Exception as exc:  # noqa: BLE001
            forgejo_unavailable = True
            forgejo_notice = (
                f"Forgejo metadata unavailable ({exc}). "
                "Findings below are from the orchestrator store."
            )

        if forgejo_unavailable:
            commit_sha = self._stored_review_commit_sha(repo_slug, pr_ref)
        else:
            commit_sha = pr.get("head", {}).get("sha") or "unknown"
        try:
            commit_author = await self._git.get_commit_author(owner, repo, commit_sha)
        except Exception:  # noqa: BLE001
            commit_author = None
        findings = self._store.list_for_pr(repo_slug, pr_ref)
        policy_decision = self._policy_decisions.for_commit(repo_slug, pr_ref, commit_sha)
        if policy_decision is None:
            policy_decision = self._policy_decisions.latest_for_pr(repo_slug, pr_ref)
        active_waivers = self._waiver_service.active_for_commit(repo_slug, pr_ref, commit_sha)
        effective_policy_decision = policy_decision
        if policy_decision is not None:
            waiver_result = apply_waivers_to_decision(policy_decision, findings, active_waivers)
            effective_policy_decision = waiver_result.effective_decision
        waiver_for_finding: dict[str, object] = {}
        for finding in findings:
            for waiver in active_waivers:
                if waiver_matches_finding(waiver, finding):
                    waiver_for_finding[finding.id] = waiver
                    break
        approvals = self.approvals._approvals.list_for_pr(repo_slug, pr_ref)
        gate = self.approvals.check_deployment_gate(
            repo=repo_slug,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
        )
        file_views = build_diff_file_views(diff_text, findings)
        enrichment_events = self._audit.list_events(action="enrichment.unavailable", limit=50)
        enrichment_unavailable = any(
            event.subject.startswith(f"{repo_slug}/{pr_ref}") for event in enrichment_events
        )
        change_state = self._changes.compute_state(
            repo=repo_slug,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            pr_number=pr_number,
        )
        plan = self._deployment.plan_for_commit(repo_slug, pr_ref, commit_sha)
        stale_plan = self._deployment.latest_plan(repo_slug, pr_ref)
        base_ref = (pr.get("base") or {}).get("ref") or self._config.gate.protected_branch
        invalidated_approvals = [
            record for record in approvals if record.invalidated and record.commit_sha != commit_sha
        ]
        model_only_findings = [item for item in findings if item.is_model_only]

        commit_timeline: list = []
        pr_comments: list = []
        gate_status_comparison = None
        branch_protection_gate_required = None
        gate_bypass_warning = None
        config_scope = "config"
        if not forgejo_unavailable:
            commits_raw = await self._forgejo_embed.list_pr_commits_cached(owner, repo, pr_number)
            commit_timeline = build_commit_timeline(commits_raw, approvals, head_sha=commit_sha)
            pr_comments = await self._forgejo_embed.list_pr_comments_cached(owner, repo, pr_number)
            forgejo_statuses = await self._forgejo_embed.list_commit_statuses_cached(
                owner, repo, commit_sha
            )
            gate_status_comparison = compare_gate_status(gate=gate, forgejo_statuses=forgejo_statuses)
            branch_protection_gate_required = await self._git.branch_protection_requires_status_check(
                owner,
                repo,
                base_ref,
                self._config.gate.status_context,
            )
            if branch_protection_gate_required is False:
                gate_bypass_warning = (
                    f"Branch protection on {base_ref!r} does not require the gate status check "
                    f"{self._config.gate.status_context!r}. The gate can be bypassed by editing the "
                    "workflow or merging without the check — configure branch protection in Forgejo."
                )
            elif branch_protection_gate_required is None:
                gate_bypass_warning = (
                    "Could not verify branch protection for the target branch. "
                    "Assume the gate may be bypassable until confirmed in Forgejo."
                )
            config_scope = await self._forgejo_embed.classify_pr_scope(owner, repo, pr_number)
        analysis_failure = self._changes.latest_analysis_failure(repo_slug, pr_ref, commit_sha)
        if analysis_failure and analysis_failure.get("failure_message"):
            analysis_failure = {
                **analysis_failure,
                "failure_message": redact_display_text(str(analysis_failure["failure_message"])),
            }

        return {
            "repo": repo_slug,
            "pr_ref": pr_ref,
            "pr_number": pr_number,
            "commit_sha": commit_sha,
            "commit_author": commit_author,
            "base_ref": base_ref,
            "findings": findings,
            "model_only_findings": model_only_findings,
            "policy_decision": policy_decision,
            "effective_policy_decision": effective_policy_decision,
            "active_waivers": active_waivers,
            "waiver_for_finding": waiver_for_finding,
            "approvals": approvals,
            "invalidated_approvals": invalidated_approvals,
            "gate": gate,
            "change_state": change_state,
            "plan": plan,
            "stale_plan": stale_plan if stale_plan and stale_plan.commit_sha != commit_sha else None,
            "file_views": file_views,
            "enrichment_unavailable": enrichment_unavailable,
            "reference_cache": self._reference.cache_status(),
            "allow_block_override": self._config.policy.allow_block_override,
            "separation_of_duties_enforced": self._config.policy.approval.separation_of_duties_enforced,
            "rbac_allow_self_approval": self._config.rbac.allow_self_approval,
            "forgejo_unavailable": forgejo_unavailable,
            "forgejo_notice": forgejo_notice,
            "pr_title": pr.get("title"),
            "pr_body": pr.get("body"),
            "pr_author": (pr.get("user") or {}).get("login"),
            "source_branch": (pr.get("head") or {}).get("ref"),
            "target_branch": base_ref,
            "pr_state": pr.get("state"),
            "forgejo_pr_url": self._forgejo_embed.pr_url(owner, repo, pr_number),
            "forgejo_repo_url": self._forgejo_embed.repo_url(owner, repo),
            "browse_fetched_at": self._forgejo_embed.browse_fetched_at(),
            "commit_timeline": commit_timeline,
            "pr_comments": pr_comments,
            "gate_status_comparison": gate_status_comparison,
            "branch_protection_gate_required": branch_protection_gate_required,
            "gate_bypass_warning": gate_bypass_warning,
            "config_scope": config_scope,
            "analysis_failure": analysis_failure,
        }

    async def _post_pr_comment(
        self,
        *,
        owner: str,
        repo: str,
        pr_number: int,
        findings: list[Finding],
        policy_decision,
        review_summary: ReviewSummary | None = None,
        enrichment_unavailable: bool = False,
    ) -> None:
        secret_index, _provenance = await build_secret_index_for_findings(
            findings,
            self._git,
            cache=SecretResolutionCache(),
        )
        body = self._format_comment(
            findings,
            policy_decision,
            review_summary=review_summary,
            enrichment_unavailable=enrichment_unavailable,
            secret_index=secret_index,
        )
        await self._git.post_pull_request_comment(owner, repo, pr_number, body)

    async def _unload_foundation_sec_if_on_demand(self) -> None:
        if self._config.models.foundation_sec.load_strategy != "on_demand":
            return
        if not self._foundation_sec:
            return
        try:
            await self._foundation_sec.unload()
        except Exception as exc:
            logger.debug("Foundation-Sec unload optional endpoint unavailable: %s", exc)
            self._audit.log(
                actor=SYSTEM_ACTOR,
                action="model.unload_failed",
                subject="foundation-sec-server",
                details={"error": str(exc)},
            )

    def _apply_enrichment(self, findings: list[Finding]) -> list[Finding]:
        if not findings:
            return findings
        if not self._config.reference_data.enrich_findings:
            return findings
        return self._enricher.enrich(findings)

    def _format_comment(
        self,
        findings: list[Finding],
        policy_decision,
        *,
        review_summary: ReviewSummary | None = None,
        enrichment_unavailable: bool = False,
        secret_index: dict[tuple[str, str], object] | None = None,
    ) -> str:
        prefix = self._config.orchestrator.comment_prefix.strip()
        lines = [prefix, ""] if prefix else []

        lines.extend(
            [
                "## A. Policy decision (deterministic)",
                "",
                f"**Policy decision:** `{policy_decision.pr_decision.value}` "
                "(advisory gate signal — **not a compliance verdict**)",
                "",
                f"_{policy_decision.explanation}_",
                "",
            ]
        )

        matched = [
            item for item in policy_decision.finding_decisions if item.matched_policy_id
        ]
        if matched:
            lines.append("**Policy matches (explainability):**")
            for item in matched[:10]:
                lines.append(
                    f"- Finding `{item.finding_id[:8]}…`: {item.explanation}"
                )
            lines.append("")

        cache_status = self._reference.cache_status()
        if cache_status["present"]:
            stale_note = " (stale — run sync-reference-data)" if cache_status["stale"] else ""
            lines.append(
                f"_Reference data: v{cache_status.get('data_version')} "
                f"synced {cache_status.get('synced_at')}{stale_note}_"
            )
            lines.append("")

        lines.extend(["## B. Handler findings (deterministic)", ""])

        omit_advisory = self._config.advisory_suppression.omit_from_pr_comments
        if omit_advisory:
            handler_findings = [item for item in findings if not is_advisory_finding(item)]
            advisory_omitted = sum(1 for item in findings if is_advisory_finding(item))
        else:
            handler_findings = list(findings)
            advisory_omitted = 0

        if not handler_findings:
            lines.append("No handler-asserted findings matched changed hunks.")
        else:
            lines.append(f"**{len(handler_findings)} handler finding(s) for review:**")
            lines.append("")
            for index, finding in enumerate(handler_findings, start=1):
                location = finding.file_path
                if finding.line_range:
                    location += f":{finding.line_range.start}-{finding.line_range.end}"
                lines.extend(
                    [
                        f"### {index}. {finding.title}",
                        f"- **Source:** `{finding.source.value}` | "
                        f"**Model-asserted severity:** `{finding.model_asserted_severity.value}` | "
                        f"**Policy severity:** `{finding.policy_severity.value}` | "
                        f"**Confidence:** `{finding.confidence:.0%}`",
                        f"- **Location:** `{location}`",
                    ]
                )
                if finding.model_asserted_cwe:
                    lines.append(f"- **CWE (model):** `{finding.model_asserted_cwe}`")
                if finding.handler_asserted_cwe:
                    lines.append(
                        f"- **CWE (handler rule):** `{finding.handler_asserted_cwe}`"
                    )
                elif finding.target_kind == TargetKind.CONFIG:
                    lines.append("- **CWE (handler rule):** _unclassified_")
                secrets = (
                    secrets_for_indexed_finding(finding, secret_index)
                    if secret_index is not None
                    else extract_secret_values_from_content(
                        f"{finding.description}\n{finding.evidence or ''}",
                        path=finding.file_path,
                    )
                )
                lines.append(
                    f"- **Description (model):** {redact_display_text(finding.description, path=finding.file_path, secret_values=secrets)}"
                )
                from shift_left.handlers.config.rules.registry import rule_by_id

                traced_rule = rule_by_id(handler_rule_id_from_trace(finding.trace) or "")
                if traced_rule is not None and traced_rule.remediation:
                    lines.append(
                        "- **Remediation:** "
                        + redact_display_text(
                            traced_rule.remediation,
                            path=finding.file_path,
                            secret_values=secrets,
                        )
                    )
                if finding.evidence:
                    lines.append(
                        f"- **Evidence (model):** {redact_display_text(finding.evidence, path=finding.file_path, secret_values=secrets)}"
                    )
                if finding.enrichment and finding.enrichment.status != EnrichmentStatus.NONE:
                    lines.append(
                        f"- **Reference enrichment:** `{finding.enrichment.status.value}`"
                    )
                    if finding.enrichment.cwe_detail:
                        lines.append(
                            f"- **CWE detail (cache):** {finding.enrichment.cwe_detail[:400]}"
                        )
                    for summary in finding.enrichment.cve_summaries[:3]:
                        lines.append(f"- **CVE (cache):** {summary[:300]}")
                    if finding.enrichment.note:
                        lines.append(f"- _{finding.enrichment.note}_")
                if finding.trace:
                    lines.append(
                        f"<details><summary>Model trace</summary>\n\n{finding.trace}\n</details>"
                    )
                lines.append("")

        if advisory_omitted:
            lines.append(
                f"_{advisory_omitted} advisory finding(s) omitted from this comment "
                "(Foundation-Sec / Antares). Review them in the Shift-Left UI; "
                "they are not a gate signal._"
            )
            lines.append("")

        lines.extend(["## C. Reviewer summary (advisory prose)", ""])
        lines.append(
            "_Advisory reviewer summary is not posted on the PR "
            "(Principle II — model prose stays in the Shift-Left UI)._"
        )
        if review_summary is not None or enrichment_unavailable:
            lines.append("")
            lines.append(
                "_Open the Shift-Left UI for model prose. It does not override "
                "policy decisions or gate outcomes._"
            )

        lines.extend(
            [
                "",
                "_Evaluates supplied diff text only — does not scan live infrastructure._",
            ]
        )
        return "\n".join(lines)

    async def health_details(self, *, force_refresh: bool = False) -> dict:
        status = await self._system_status.build_status(force_refresh=force_refresh)
        status["policy_rules_loaded"] = len(self._policy_engine.policies)
        return status
