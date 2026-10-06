"""Target-centric NetSecOps service — declared state, history, in-flight changes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from shift_left.auth.context import AuthContext, TokenCapability
from shift_left.changes.workflow import ChangeWorkflowService
from shift_left.config import AppConfig, ManagedTargetConfig
from shift_left.git.forgejo_read import ForgejoEmbedService
from shift_left.models.schema import (
    AppliedRevision,
    ChangeState,
    Finding,
    FindingSource,
    PolicyAction,
    PolicySeverity,
    TerraformPlanRecord,
)
from shift_left.ui.timefmt import relative_time
from shift_left.routing.config_scope import paths_from_unified_diff
from shift_left.routing.globmatch import matches_any
from shift_left.targets.registry import ManagedTargetRegistry
from shift_left.targets.validation import resolve_path_to_target


def _split_repo(repo: str) -> tuple[str, str]:
    owner, _, name = repo.partition("/")
    return owner, name


def _short_sha(sha: str) -> str:
    return sha[:7] if len(sha) >= 7 else sha


def _parse_commit_time(payload: dict[str, Any]) -> datetime | None:
    commit = payload.get("commit") or {}
    raw = commit.get("committer", {}).get("date") or commit.get("author", {}).get("date")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class TrustAlert:
    level: str  # warn | critical
    message: str


@dataclass
class TargetOverviewCard:
    target: ManagedTargetConfig
    declared_head_sha: str
    declared_head_short: str
    declared_head_at: datetime | None
    last_applied_label: str
    last_applied_sha: str | None
    last_applied_at: datetime | None
    divergence_commits: int | None
    in_flight_count: int
    blocking_summary: str | None
    health_label: str
    health_icon: str
    primary_action: str | None
    primary_action_href: str | None


@dataclass
class TargetCommitRow:
    sha: str
    short_sha: str
    author: str
    committed_at: datetime | None
    message: str
    files_changed: list[str]
    applied: bool
    approval_bound: bool


@dataclass
class TargetInflightChange:
    repo: str
    pr_number: int
    title: str | None
    commit_sha: str
    change_state: ChangeState
    next_action: str
    validation_label: str
    gate_allowed: bool | None
    href: str


@dataclass
class TargetsOverview:
    cards: list[TargetOverviewCard]
    trust_alerts: list[TrustAlert]
    unclaimed_by_repo: dict[str, list[str]]


@dataclass
class ConfigFileRow:
    path: str
    last_commit_message: str
    last_commit_relative: str
    last_commit_sha: str


@dataclass
class ValidationFindingRow:
    finding: Finding
    policy_decision: str | None
    cwe_label: str
    severity_label: str
    severity_class: str
    is_advisory: bool


@dataclass
class ValidationSummary:
    sha_short: str
    state: str  # pass | incomplete | awaiting | blocked
    state_icon: str
    state_label: str
    policy_decision: str | None
    policy_explanation: str | None
    policy_rule: str | None
    review_summary: str | None
    deterministic: list[ValidationFindingRow]
    advisory: list[ValidationFindingRow]


@dataclass
class TargetDetail:
    target: ManagedTargetConfig
    declared_head_sha: str
    declared_head_short: str
    declared_head_at: datetime | None
    declared_head_relative: str
    last_applied: AppliedRevision | None
    last_applied_label: str
    divergence_commits: int | None
    declared_files: list[dict[str, Any]]
    config_file_rows: list[ConfigFileRow]
    commit_count: int
    history: list[TargetCommitRow]
    inflight: list[TargetInflightChange]
    findings: list[Finding]
    validation: ValidationSummary
    plan: TerraformPlanRecord | None
    plan_stale: bool
    plan_refused_reason: str | None
    diff_base: str
    diff_head: str
    diff_files: list[dict[str, Any]]
    trust_alerts: list[TrustAlert]
    forgejo_repo_url: str | None
    primary_action: str | None
    primary_action_href: str | None
    active_tab: str
    selected_file: str | None
    selected_file_view: dict[str, Any] | None
    path_filter: str
    active_revision: str


class TargetService:
    def __init__(
        self,
        *,
        config: AppConfig,
        registry: ManagedTargetRegistry,
        forgejo: ForgejoEmbedService | None,
        git: Any,
        changes: ChangeWorkflowService,
        findings_store: Any,
        policy_decisions: Any,
        approvals: Any,
        plans: Any,
    ) -> None:
        self._config = config
        self._registry = registry
        self._forgejo = forgejo
        self._git = git
        self._changes = changes
        self._findings = findings_store
        self._decisions = policy_decisions
        self._approvals = approvals
        self._plans = plans

    async def overview(self, *, auth: AuthContext | None = None) -> TargetsOverview:
        alerts = await self._trust_alerts()
        unclaimed: dict[str, list[str]] = {}
        cards: list[TargetOverviewCard] = []
        for target in self._registry.targets:
            card = await self._build_overview_card(target, auth=auth)
            cards.append(card)
            owner, repo_name = _split_repo(target.repo)
            try:
                paths = await self._list_repo_paths(owner, repo_name, target.branch)
                unclaimed[target.repo] = self._registry.unclaimed_in_repo(paths, target.repo)
            except Exception:
                unclaimed[target.repo] = []

        for repo, paths in unclaimed.items():
            if paths:
                sample = ", ".join(paths[:3])
                extra = f" (+{len(paths) - 3} more)" if len(paths) > 3 else ""
                alerts.append(
                    TrustAlert(
                        level="warn",
                        message=(
                            f"Unclaimed config files in {repo}: {sample}{extra} — "
                            "changes may go unwatched."
                        ),
                    )
                )
        return TargetsOverview(cards=cards, trust_alerts=alerts, unclaimed_by_repo=unclaimed)

    async def detail(
        self,
        target_id: str,
        *,
        auth: AuthContext | None = None,
        tab: str = "config",
        revision: str | None = None,
        selected_file: str | None = None,
        path_filter: str = "",
        diff_base: str | None = None,
        diff_head: str | None = None,
    ) -> TargetDetail | None:
        target = self._registry.get(target_id)
        if target is None:
            return None

        owner, repo_name = _split_repo(target.repo)
        head_sha, head_at = await self._declared_head(target)
        view_sha = revision or head_sha
        applied = self._registry.applied_for_target(target_id)
        last_label = (
            "no apply recorded — plan-only mode"
            if applied is None
            else f"{_short_sha(applied.applied_sha)} at {applied.applied_at.isoformat()}"
        )
        divergence = await self._divergence_commits(target, head_sha, applied)

        declared_files = await self._declared_config_files(target, view_sha)
        config_file_rows = await self._config_file_rows(target, view_sha)
        if path_filter:
            needle = path_filter.lower()
            config_file_rows = [row for row in config_file_rows if needle in row.path.lower()]
        history = await self._config_history(target, head_sha)
        inflight = await self._inflight_for_target(target, auth=auth)
        findings = self._findings_for_target(target)
        validation = await self._validation_summary(target, view_sha, findings)

        base = diff_base or (history[1].sha if len(history) > 1 else head_sha)
        head = diff_head or view_sha
        diff_files = await self._compare_target_paths(owner, repo_name, base, head, target)

        plan = self._plans.latest_for_target(target_id)
        plan_stale = bool(plan and plan.commit_sha != head_sha)

        forgejo_url = self._forgejo.repo_url(owner, repo_name) if self._forgejo else None
        action, action_href = self._primary_action(target, head_sha, inflight, auth)

        selected_view = None
        if selected_file:
            for item in declared_files:
                if item["path"] == selected_file:
                    selected_view = item
                    break

        allowed_tabs = {"config", "history", "changes", "findings", "deploy"}
        active_tab = tab if tab in allowed_tabs else "config"

        return TargetDetail(
            target=target,
            declared_head_sha=head_sha,
            declared_head_short=_short_sha(head_sha),
            declared_head_at=head_at,
            declared_head_relative=relative_time(head_at),
            last_applied=applied,
            last_applied_label=last_label,
            divergence_commits=divergence,
            declared_files=declared_files,
            config_file_rows=config_file_rows,
            commit_count=len(history),
            history=history,
            inflight=inflight,
            findings=findings,
            validation=validation,
            plan=plan,
            plan_stale=plan_stale,
            plan_refused_reason=None,
            diff_base=base,
            diff_head=head,
            diff_files=diff_files,
            trust_alerts=await self._trust_alerts(),
            forgejo_repo_url=forgejo_url,
            primary_action=action,
            primary_action_href=action_href,
            active_tab=active_tab,
            selected_file=selected_file,
            selected_file_view=selected_view,
            path_filter=path_filter,
            active_revision=view_sha,
        )

    async def live_head_sha(self, target: ManagedTargetConfig) -> str:
        owner, repo_name = _split_repo(target.repo)
        get_branch = getattr(self._git, "get_branch", None)
        if get_branch is None:
            return "unknown"
        branch = await get_branch(owner, repo_name, target.branch)
        return (branch.get("commit") or {}).get("id") or "unknown"

    async def commit_allows_plan(self, repo: str, commit_sha: str) -> tuple[bool, str]:
        owner, repo_name = _split_repo(repo)
        statuses = await self._forgejo.list_commit_statuses_cached(owner, repo_name, commit_sha) if self._forgejo else []
        context = self._config.gate.status_context
        for item in statuses:
            if item.get("context") != context:
                continue
            status = str(item.get("status", "")).lower()
            if status == "success":
                return True, "gate success"
            return False, f"gate status is {status or 'unknown'}"
        return False, f"no allowing gate status ({context}) on commit"

    async def _trust_alerts(self) -> list[TrustAlert]:
        alerts: list[TrustAlert] = []
        if self._forgejo is not None:
            notice = await self._forgejo.runner_notice()
            if notice:
                alerts.append(TrustAlert(level="critical", message=notice))

        gate = self._config.gate
        if gate.warn_if_branch_protection_missing and gate.check_repo:
            owner, repo_name = _split_repo(gate.check_repo)
            probe = getattr(self._git, "branch_protection_requires_status_check", None)
            if probe is not None:
                try:
                    configured = await probe(
                        owner,
                        repo_name,
                        gate.protected_branch,
                        gate.status_context,
                    )
                except Exception as exc:
                    alerts.append(
                        TrustAlert(
                            level="warn",
                            message=f"Could not verify branch protection for {gate.check_repo}: {exc}",
                        )
                    )
                else:
                    if configured is not True:
                        alerts.append(
                            TrustAlert(
                                level="critical",
                                message=(
                                    f"Branch {gate.check_repo}@{gate.protected_branch} does not require "
                                    f"status check '{gate.status_context}' — gate may be bypassable."
                                ),
                            )
                        )
        return alerts

    async def _declared_head(
        self, target: ManagedTargetConfig
    ) -> tuple[str, datetime | None]:
        owner, repo_name = _split_repo(target.repo)
        get_branch = getattr(self._git, "get_branch", None)
        if get_branch is None:
            return "unknown", None
        try:
            branch = await get_branch(owner, repo_name, target.branch)
        except Exception:
            return "unknown", None
        commit = branch.get("commit") or {}
        sha = commit.get("id") or "unknown"
        committed = commit.get("timestamp") or commit.get("created")
        committed_at = None
        if committed:
            try:
                committed_at = datetime.fromisoformat(str(committed).replace("Z", "+00:00"))
            except ValueError:
                committed_at = None
        return sha, committed_at

    async def _divergence_commits(
        self,
        target: ManagedTargetConfig,
        head_sha: str,
        applied: AppliedRevision | None,
    ) -> int | None:
        if applied is None:
            return None
        if head_sha == applied.applied_sha:
            return 0
        owner, repo_name = _split_repo(target.repo)
        compare = getattr(self._git, "compare_commits", None)
        if compare is None:
            return None
        try:
            payload = await compare(owner, repo_name, applied.applied_sha, head_sha)
        except Exception:
            return None
        commits = payload.get("commits") or []
        return len(commits)

    async def _build_overview_card(
        self, target: ManagedTargetConfig, *, auth: AuthContext | None
    ) -> TargetOverviewCard:
        head_sha, head_at = await self._declared_head(target)
        applied = self._registry.applied_for_target(target.id)
        last_label = (
            "no apply recorded — plan-only mode"
            if applied is None
            else f"{_short_sha(applied.applied_sha)}"
        )
        divergence = await self._divergence_commits(target, head_sha, applied)
        inflight = await self._inflight_for_target(target, auth=auth)
        blocking = None
        if inflight:
            priority = [
                ChangeState.BLOCKED_BY_POLICY,
                ChangeState.AWAITING_APPROVAL,
                ChangeState.VALIDATING,
                ChangeState.DRAFT_OPEN,
            ]
            for state in priority:
                matches = [item for item in inflight if item.change_state == state]
                if matches:
                    blocking = f"{len(matches)} PR(s): {matches[0].next_action}"
                    break

        health_label, health_icon = await self._health_for_head(target, head_sha)
        action, href = self._primary_action(target, head_sha, inflight, auth)

        return TargetOverviewCard(
            target=target,
            declared_head_sha=head_sha,
            declared_head_short=_short_sha(head_sha),
            declared_head_at=head_at,
            last_applied_label=last_label,
            last_applied_sha=applied.applied_sha if applied else None,
            last_applied_at=applied.applied_at if applied else None,
            divergence_commits=divergence,
            in_flight_count=len(inflight),
            blocking_summary=blocking,
            health_label=health_label,
            health_icon=health_icon,
            primary_action=action,
            primary_action_href=href,
        )

    async def _health_for_head(self, target: ManagedTargetConfig, head_sha: str) -> tuple[str, str]:
        if head_sha == "unknown":
            return "Unknown — cannot read branch", "?"
        allowed, reason = await self.commit_allows_plan(target.repo, head_sha)
        if allowed:
            return "Passed — gate allowing", "OK"
        if "no allowing" in reason:
            return "Awaiting validation", "…"
        return f"Blocked — {reason}", "BLOCK"

    def _primary_action(
        self,
        target: ManagedTargetConfig,
        head_sha: str,
        inflight: list[TargetInflightChange],
        auth: AuthContext | None,
    ) -> tuple[str | None, str | None]:
        href = f"/ui/targets/{target.id}"
        if inflight and auth and auth.has_capability(TokenCapability.REVIEW):
            first = inflight[0]
            return first.next_action, first.href
        if auth and auth.has_capability(TokenCapability.DEPLOY):
            return "View deployment plan", f"{href}?tab=deploy"
        return "View declared configuration", f"{href}?tab=config"

    async def _config_file_rows(
        self, target: ManagedTargetConfig, ref: str
    ) -> list[ConfigFileRow]:
        owner, repo_name = _split_repo(target.repo)
        list_commits = getattr(self._git, "list_repo_commits", None)
        try:
            all_paths = await self._list_repo_paths(owner, repo_name, ref)
        except Exception:
            all_paths = []
        rows: list[ConfigFileRow] = []
        for path in sorted(all_paths):
            if not matches_any(path, target.config_paths):
                continue
            message = "(no commits)"
            relative = "—"
            short_sha = "—"
            if list_commits is not None:
                try:
                    commits = await list_commits(
                        owner, repo_name, sha=ref, path=path, limit=1
                    )
                except Exception:
                    commits = []
                if commits:
                    item = commits[0]
                    commit = item.get("commit") or {}
                    message = (commit.get("message") or "").splitlines()[0] or message
                    committed_at = _parse_commit_time(item)
                    relative = relative_time(committed_at)
                    short_sha = _short_sha(item.get("sha") or "")
            rows.append(
                ConfigFileRow(
                    path=path,
                    last_commit_message=message,
                    last_commit_relative=relative,
                    last_commit_sha=short_sha,
                )
            )
        return rows

    async def _validation_summary(
        self,
        target: ManagedTargetConfig,
        head_sha: str,
        findings: list[Finding],
    ) -> ValidationSummary:
        from shift_left.ui.presentation import policy_severity_class, policy_severity_label

        head_findings = [item for item in findings if item.commit_sha == head_sha]
        if not head_findings:
            head_findings = findings[:20]

        policy_decision = None
        policy_explanation = None
        policy_rule = None
        for stored_repo, pr_ref in self._decisions.list_distinct_prs():
            if stored_repo != target.repo:
                continue
            decision = self._decisions.for_commit(target.repo, pr_ref, head_sha)
            if decision is not None:
                policy_decision = decision.pr_decision.value.upper()
                policy_explanation = decision.explanation
                if decision.finding_decisions:
                    first = decision.finding_decisions[0]
                    policy_rule = first.matched_policy_name or first.matched_policy_id
                break

        state = "awaiting"
        state_icon = "…"
        state_label = "Awaiting validation"
        if self._forgejo is not None and head_sha != "unknown":
            owner, repo_name = _split_repo(target.repo)
            statuses = await self._forgejo.list_commit_statuses_cached(
                owner, repo_name, head_sha
            )
            context = self._config.gate.status_context
            for item in statuses:
                if item.get("context") != context:
                    continue
                status = str(item.get("status", "")).lower()
                if status == "success":
                    state = "pass"
                    state_icon = "OK"
                    state_label = "Validation complete"
                elif status == "failure":
                    state = "incomplete"
                    state_icon = "FAIL"
                    state_label = "Validation incomplete"
                    stage = item.get("description") or context
                    policy_explanation = f"Gate status failure at {stage}"
                else:
                    state = "awaiting"
                    state_icon = "…"
                    state_label = f"Validation pending ({status or 'unknown'})"
                break
            else:
                failed = [
                    item
                    for item in statuses
                    if str(item.get("status", "")).lower() == "failure"
                    and "shift-left" in str(item.get("context", ""))
                ]
                if failed:
                    state = "incomplete"
                    state_icon = "FAIL"
                    state_label = "Validation incomplete"
                    policy_explanation = failed[0].get("description") or "shift-left check failed"

        if policy_decision == PolicyAction.BLOCK.value.upper():
            state = "blocked"
            state_icon = "BLOCK"
            state_label = "Blocked by policy"

        deterministic: list[ValidationFindingRow] = []
        advisory: list[ValidationFindingRow] = []
        severity_order = {
            PolicySeverity.CRITICAL: 0,
            PolicySeverity.HIGH: 1,
            PolicySeverity.MEDIUM: 2,
            PolicySeverity.LOW: 3,
            PolicySeverity.INFO: 4,
            PolicySeverity.UNCLASSIFIED: 99,
        }

        for finding in head_findings:
            is_advisory = finding.source == FindingSource.ANTARES or (
                finding.handler_asserted_cwe is None
                and finding.model_asserted_cwe is not None
            )
            cwe = finding.handler_asserted_cwe or finding.model_asserted_cwe or "—"
            row = ValidationFindingRow(
                finding=finding,
                policy_decision=None,
                cwe_label=cwe,
                severity_label=policy_severity_label(finding.policy_severity),
                severity_class=policy_severity_class(finding.policy_severity),
                is_advisory=is_advisory,
            )
            if is_advisory:
                advisory.append(row)
            else:
                deterministic.append(row)

        deterministic.sort(key=lambda item: severity_order.get(item.finding.policy_severity, 50))

        return ValidationSummary(
            sha_short=_short_sha(head_sha),
            state=state,
            state_icon=state_icon,
            state_label=state_label,
            policy_decision=policy_decision,
            policy_explanation=policy_explanation,
            policy_rule=policy_rule,
            review_summary=None,
            deterministic=deterministic,
            advisory=advisory,
        )

    async def _declared_config_files(
        self, target: ManagedTargetConfig, ref: str
    ) -> list[dict[str, Any]]:
        from shift_left.ui.diff_view import build_static_file_view

        owner, repo_name = _split_repo(target.repo)
        get_file = getattr(self._git, "get_file_content", None)
        if get_file is None:
            return []
        files: list[dict[str, Any]] = []
        try:
            all_paths = await self._list_repo_paths(owner, repo_name, ref)
        except Exception:
            all_paths = []
        for path in all_paths:
            if not matches_any(path, target.config_paths):
                continue
            try:
                content = await get_file(owner, repo_name, path, ref)
            except Exception:
                content = "(unable to load file)"
            files.append(build_static_file_view(path, content))
        return files

    async def _config_history(
        self, target: ManagedTargetConfig, head_sha: str
    ) -> list[TargetCommitRow]:
        owner, repo_name = _split_repo(target.repo)
        list_commits = getattr(self._git, "list_repo_commits", None)
        if list_commits is None:
            return []
        seen_shas: set[str] = set()
        rows: list[TargetCommitRow] = []
        for pattern in target.config_paths:
            probe = pattern.rstrip("/").replace("**", "x").replace("*", "file")
            if probe.endswith("/"):
                probe = f"{probe}main.tf"
            try:
                commits = await list_commits(owner, repo_name, sha=target.branch, path=probe, limit=30)
            except Exception:
                commits = []
            for item in commits:
                sha = item.get("sha") or ""
                if not sha or sha in seen_shas:
                    continue
                seen_shas.add(sha)
                commit = item.get("commit") or {}
                message = (commit.get("message") or "").splitlines()[0] if commit.get("message") else ""
                author = (commit.get("author") or {}).get("name") or "unknown"
                applied = self._is_applied_revision(target.id, sha)
                approval_bound = self._approval_bound_sha(target.repo, sha)
                rows.append(
                    TargetCommitRow(
                        sha=sha,
                        short_sha=_short_sha(sha),
                        author=author,
                        committed_at=_parse_commit_time(item),
                        message=message,
                        files_changed=[probe],
                        applied=applied,
                        approval_bound=approval_bound,
                    )
                )
        rows.sort(key=lambda item: item.committed_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        if not rows and head_sha != "unknown":
            rows.append(
                TargetCommitRow(
                    sha=head_sha,
                    short_sha=_short_sha(head_sha),
                    author="unknown",
                    committed_at=None,
                    message="(current branch head)",
                    files_changed=[],
                    applied=self._is_applied_revision(target.id, head_sha),
                    approval_bound=self._approval_bound_sha(target.repo, head_sha),
                )
            )
        return rows

    def _is_applied_revision(self, target_id: str, sha: str) -> bool:
        for item in self._config.managed_targets.applied_revisions:
            if item.target_id == target_id and item.applied_sha == sha:
                return True
        return False

    def _approval_bound_sha(self, repo: str, sha: str) -> bool:
        for stored_repo, pr_ref in self._decisions.list_distinct_prs():
            if stored_repo != repo:
                continue
            decision = self._decisions.for_commit(repo, pr_ref, sha)
            if decision is None:
                continue
            approval = self._approvals.active_for_commit(repo, pr_ref, sha)
            if approval is not None:
                return True
        return False

    async def _inflight_for_target(
        self, target: ManagedTargetConfig, *, auth: AuthContext | None
    ) -> list[TargetInflightChange]:
        owner, repo_name = _split_repo(target.repo)
        open_prs: list[dict[str, Any]] = []
        if self._forgejo is not None:
            try:
                open_prs = await self._forgejo.list_open_pull_requests_cached(owner, repo_name)
            except Exception:
                open_prs = []

        results: list[TargetInflightChange] = []
        for pr in open_prs:
            pr_number = int(pr.get("number") or 0)
            if pr_number <= 0:
                continue
            touches = await self._pr_touches_target(owner, repo_name, pr_number, target)
            if not touches:
                continue
            commit_sha = (pr.get("head") or {}).get("sha") or "unknown"
            pr_ref = f"PR-{pr_number}"
            state_result = self._changes.compute_state(
                repo=target.repo,
                pr_ref=pr_ref,
                commit_sha=commit_sha,
                pr_number=pr_number,
            )
            decision = self._decisions.for_commit(target.repo, pr_ref, commit_sha)
            if decision is None:
                validation_label = "Awaiting validation"
            else:
                validation_label = f"Policy: {decision.pr_decision.value}"
            gate = self._approvals.check_deployment_gate(
                repo=target.repo,
                pr_ref=pr_ref,
                commit_sha=commit_sha,
            )
            results.append(
                TargetInflightChange(
                    repo=target.repo,
                    pr_number=pr_number,
                    title=pr.get("title"),
                    commit_sha=commit_sha,
                    change_state=state_result.state,
                    next_action=state_result.next_action,
                    validation_label=validation_label,
                    gate_allowed=gate.allowed,
                    href=f"/ui/pr/{owner}/{repo_name}/{pr_number}",
                )
            )
        return results

    async def _pr_touches_target(
        self,
        owner: str,
        repo_name: str,
        pr_number: int,
        target: ManagedTargetConfig,
    ) -> bool:
        if self._forgejo is None:
            return True
        try:
            diff = await self._forgejo.get_pull_diff_cached(owner, repo_name, pr_number)
        except Exception:
            return True
        for path in paths_from_unified_diff(diff):
            if matches_any(path, target.config_paths):
                return True
        return False

    def _findings_for_target(self, target: ManagedTargetConfig) -> list[Finding]:
        all_findings = self._findings.list_filtered(repo=target.repo, limit=500)
        scoped: list[Finding] = []
        for finding in all_findings:
            try:
                resolve_path_to_target(finding.file_path, [target], repo=target.repo)
            except Exception:
                if matches_any(finding.file_path, target.config_paths):
                    scoped.append(finding)
                continue
            scoped.append(finding)
        return scoped

    async def _compare_target_paths(
        self,
        owner: str,
        repo_name: str,
        base: str,
        head: str,
        target: ManagedTargetConfig,
    ) -> list[dict[str, Any]]:
        from shift_left.ui.diff_view import build_diff_file_views

        compare = getattr(self._git, "compare_commits", None)
        if compare is None or base == head:
            return []
        try:
            payload = await compare(owner, repo_name, base, head)
        except Exception:
            return []
        diff_text = payload.get("diff") or ""
        if not diff_text:
            return []
        try:
            files = build_diff_file_views(diff_text, [])
        except Exception:
            return []
        return [item for item in files if matches_any(item["path"], target.config_paths)]

    async def config_diff_for_commits(
        self,
        target: ManagedTargetConfig,
        base: str,
        head: str,
        findings: list[Finding],
    ) -> list[dict[str, Any]]:
        """Unified diff file views for config paths between two commits (read-only)."""
        from shift_left.ui.diff_view import build_diff_file_views

        owner, repo_name = _split_repo(target.repo)
        compare = getattr(self._git, "compare_commits", None)
        if compare is None or base == head:
            return []
        try:
            payload = await compare(owner, repo_name, base, head)
        except Exception:
            return []
        diff_text = payload.get("diff") or ""
        if not diff_text:
            return []
        try:
            files = build_diff_file_views(diff_text, findings)
        except Exception:
            return []
        return [item for item in files if matches_any(item["path"], target.config_paths)]

    async def _list_repo_paths(self, owner: str, repo_name: str, ref: str) -> list[str]:
        list_tree = getattr(self._git, "list_repo_tree_paths", None)
        if list_tree is None:
            return []
        return await list_tree(owner, repo_name, ref)
