"""Presentation models for the managed target Changes tab."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from shift_left.config import AppConfig, ManagedTargetConfig, RoutingConfig
from shift_left.handlers.config.rules.registry import rules_for_target_type
from shift_left.models.schema import (
    Finding,
    FindingSource,
    PolicyAction,
    PullRequestPolicyDecision,
)
from shift_left.policy.waiver_policy import is_unclaimed_finding
from shift_left.routing.path_claim import PathClaim, classify_path
from shift_left.targets.service import TargetDetail, TargetService
from shift_left.ui.target_detail_view import _unclaimed_remedy_text


@dataclass(frozen=True)
class ChangeFileClaimRow:
    path: str
    claim_label: str
    remedy_text: str | None = None


@dataclass(frozen=True)
class TargetChangeCard:
    sha: str
    short_sha: str
    author: str
    committed_at: datetime | None
    committed_at_label: str
    pr_ref: str | None
    gate_outcome: str
    rules_evaluated: int
    findings_count: int
    evaluation_summary: str
    invalidation_notices: tuple[str, ...]
    changed_files: tuple[ChangeFileClaimRow, ...]
    diff_files: tuple[dict[str, Any], ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class TargetChangesPanel:
    declared_head_sha: str
    declared_head_short: str
    changes: tuple[TargetChangeCard, ...]


def _format_commit_time(committed_at: datetime | None) -> str:
    if committed_at is None:
        return "—"
    from shift_left.ui.timefmt import relative_time

    return relative_time(committed_at)


def _claim_label(claim: PathClaim) -> str:
    if claim == PathClaim.CONFIG:
        return "CONFIG (parser-scoped)"
    return claim.value.upper()


def _handler_findings(findings: list[Finding]) -> list[Finding]:
    return [
        item
        for item in findings
        if not (
            item.source == FindingSource.ANTARES
            or (item.handler_asserted_cwe is None and item.model_asserted_cwe is not None)
        )
    ]


def _finding_count(findings: list[Finding]) -> int:
    return len(_handler_findings(findings))


def _rules_evaluated_count(
    target_type: str,
    changed_paths: list[str],
    *,
    routing: RoutingConfig,
    target: ManagedTargetConfig,
    targets: list[ManagedTargetConfig],
) -> int:
    if not changed_paths:
        return 0
    claims = [
        classify_path(path, routing, repo=target.repo, targets=targets)
        for path in changed_paths
    ]
    if not any(claim == PathClaim.CONFIG for claim in claims):
        return 0
    count = len(rules_for_target_type(target_type))
    if target_type in {"cisco_ftd", "generic_terraform"}:
        count += 1
    return count


def _policy_decision_for_commit(
    detail: TargetDetail,
    commit_sha: str,
    *,
    decisions_store: Any,
) -> PullRequestPolicyDecision | None:
    for stored_repo, pr_ref in decisions_store.list_distinct_prs():
        if stored_repo != detail.target.repo:
            continue
        decision = decisions_store.for_commit(detail.target.repo, pr_ref, commit_sha)
        if decision is not None:
            return decision
    return None


def _pr_ref_for_commit(
    detail: TargetDetail,
    commit_sha: str,
    commit_findings: list[Finding],
    decision: PullRequestPolicyDecision | None,
) -> str | None:
    if decision is not None:
        return decision.pr_ref
    for finding in commit_findings:
        if finding.pr_ref:
            return finding.pr_ref
    for item in detail.inflight:
        if item.commit_sha == commit_sha:
            return f"PR-{item.pr_number}"
    return None


def _gate_outcome(
    decision: PullRequestPolicyDecision | None,
    findings: list[Finding],
) -> str:
    if decision is not None:
        return decision.pr_decision.value
    handler = _handler_findings(findings)
    if not handler:
        return PolicyAction.PASS.value
    from shift_left.handlers.config.rules.registry import rule_by_id
    from shift_left.policy.handler_trace import handler_rule_id_from_trace

    for finding in handler:
        if is_unclaimed_finding(finding):
            return PolicyAction.BLOCK.value
        rule_id = handler_rule_id_from_trace(finding.trace)
        rule = rule_by_id(rule_id) if rule_id else None
        if rule is not None and rule.severity == "block":
            return PolicyAction.BLOCK.value
    return PolicyAction.FLAG.value


def _invalidation_notices(
    *,
    repo: str,
    commit_sha: str,
    parent_sha: str | None,
    decisions_store: Any,
    approvals_store: Any,
    waiver_store: Any,
    extra_pr_refs: set[str] | None = None,
) -> tuple[str, ...]:
    if parent_sha is None:
        return ()
    notices: list[str] = []
    pr_refs = {
        pr_ref for stored_repo, pr_ref in decisions_store.list_distinct_prs() if stored_repo == repo
    }
    if extra_pr_refs:
        pr_refs.update(extra_pr_refs)
    for pr_ref in sorted(pr_refs):
        for approval in approvals_store.list_for_pr(repo, pr_ref):
            if approval.invalidated and approval.commit_sha == parent_sha:
                notices.append(
                    f"Approval bound to {approval.commit_sha[:7]} was invalidated by "
                    f"commit {commit_sha[:7]}."
                )
        for waiver in waiver_store.list_for_pr(repo, pr_ref):
            if waiver.invalidated and waiver.commit_sha == parent_sha:
                notices.append(
                    f"Waiver for {waiver.rule_id} at {waiver.file_path} "
                    f"(commit {waiver.commit_sha[:7]}) was invalidated by commit {commit_sha[:7]}."
                )
    return tuple(notices)


def _changed_paths_from_diff(diff_files: list[dict[str, Any]]) -> list[str]:
    return [str(item.get("path") or "") for item in diff_files if item.get("path")]


def _file_claim_rows(
    paths: list[str],
    *,
    routing: RoutingConfig,
    target: ManagedTargetConfig,
    targets: list[ManagedTargetConfig],
) -> tuple[ChangeFileClaimRow, ...]:
    remedy = _unclaimed_remedy_text(routing)
    rows: list[ChangeFileClaimRow] = []
    for path in paths:
        claim = classify_path(path, routing, repo=target.repo, targets=targets)
        rows.append(
            ChangeFileClaimRow(
                path=path,
                claim_label=_claim_label(claim),
                remedy_text=remedy if claim == PathClaim.UNCLAIMED else None,
            )
        )
    return tuple(rows)


async def build_changes_panel(
    detail: TargetDetail,
    config: AppConfig,
    *,
    target_service: TargetService,
    decisions_store: Any,
    approvals_store: Any,
    waiver_store: Any,
) -> TargetChangesPanel:
    routing = config.routing
    targets = config.managed_targets.targets
    history = detail.history
    cards: list[TargetChangeCard] = []

    for index, row in enumerate(history):
        parent_sha = history[index + 1].sha if index + 1 < len(history) else None
        commit_findings = [item for item in detail.findings if item.commit_sha == row.sha]
        diff_files: list[dict[str, Any]] = []
        if parent_sha is not None:
            diff_files = await target_service.config_diff_for_commits(
                detail.target,
                parent_sha,
                row.sha,
                commit_findings,
            )
        changed_paths = _changed_paths_from_diff(diff_files)
        decision = _policy_decision_for_commit(
            detail,
            row.sha,
            decisions_store=decisions_store,
        )
        pr_ref = _pr_ref_for_commit(detail, row.sha, commit_findings, decision)
        known_pr_refs = {item for item in (pr_ref,) if item}
        for finding in commit_findings:
            if finding.pr_ref:
                known_pr_refs.add(finding.pr_ref)
        for finding in detail.findings:
            if finding.repo == detail.target.repo and finding.pr_ref:
                known_pr_refs.add(finding.pr_ref)
        rules_evaluated = _rules_evaluated_count(
            detail.target.target_type,
            changed_paths,
            routing=routing,
            target=detail.target,
            targets=targets,
        )
        findings_count = _finding_count(commit_findings)
        gate = _gate_outcome(decision, commit_findings)

        cards.append(
            TargetChangeCard(
                sha=row.sha,
                short_sha=row.short_sha,
                author=row.author,
                committed_at=row.committed_at,
                committed_at_label=_format_commit_time(row.committed_at),
                pr_ref=pr_ref,
                gate_outcome=gate,
                rules_evaluated=rules_evaluated,
                findings_count=findings_count,
                evaluation_summary=(
                    f"{rules_evaluated} rules evaluated, {findings_count} findings"
                ),
                invalidation_notices=_invalidation_notices(
                    repo=detail.target.repo,
                    commit_sha=row.sha,
                    parent_sha=parent_sha,
                    decisions_store=decisions_store,
                    approvals_store=approvals_store,
                    waiver_store=waiver_store,
                    extra_pr_refs=known_pr_refs,
                ),
                changed_files=_file_claim_rows(
                    changed_paths,
                    routing=routing,
                    target=detail.target,
                    targets=targets,
                ),
                diff_files=tuple(diff_files),
            )
        )

    return TargetChangesPanel(
        declared_head_sha=detail.declared_head_sha,
        declared_head_short=detail.declared_head_short,
        changes=tuple(cards),
    )
