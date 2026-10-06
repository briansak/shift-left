"""Per-finding waiver identity and policy-decision filtering."""

from __future__ import annotations

from dataclasses import dataclass

from shift_left.models.schema import (
    Finding,
    FindingPolicyDecision,
    FindingWaiverRecord,
    PolicyAction,
    PullRequestPolicyDecision,
)
from shift_left.policy.actions import strictest_action
from shift_left.policy.handler_trace import handler_rule_id_from_trace


@dataclass(frozen=True)
class FindingWaiverIdentity:
    """Stable waiver key: path + construct + weakness class (Constitution VIII).

    ``rule_id`` and ``line_start`` are carried for grant/audit display only.
    They are not part of ``storage_key``.
    """

    repo: str
    pr_ref: str
    target_kind: str
    file_path: str
    construct_key: str
    weakness_class: str
    rule_id: str
    line_start: int

    def storage_key(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.repo,
            self.pr_ref,
            self.target_kind,
            self.file_path,
            self.construct_key,
            self.weakness_class,
        )


@dataclass(frozen=True)
class WaiverApplicationResult:
    effective_decision: PullRequestPolicyDecision
    waived_finding_ids: frozenset[str]
    waivers_used: tuple[FindingWaiverRecord, ...]


def finding_waiver_identity(finding: Finding) -> FindingWaiverIdentity | None:
    rule_id = handler_rule_id_from_trace(finding.trace)
    if not rule_id:
        return None
    construct_key = (finding.construct_key or "").strip()
    weakness_class = (finding.handler_asserted_cwe or "").strip()
    if not construct_key or not weakness_class:
        return None
    line_start = finding.line_range.start if finding.line_range else 1
    return FindingWaiverIdentity(
        repo=finding.repo,
        pr_ref=finding.pr_ref,
        target_kind=finding.target_kind.value,
        file_path=finding.file_path,
        construct_key=construct_key,
        weakness_class=weakness_class,
        rule_id=rule_id,
        line_start=line_start,
    )


def waiver_matches_finding(waiver: FindingWaiverRecord, finding: Finding) -> bool:
    identity = finding_waiver_identity(finding)
    if identity is None:
        return False
    return (
        waiver.repo == identity.repo
        and waiver.pr_ref == identity.pr_ref
        and waiver.target_kind == identity.target_kind
        and waiver.file_path == identity.file_path
        and waiver.construct_key == identity.construct_key
        and waiver.weakness_class == identity.weakness_class
    )


def apply_waivers_to_decision(
    decision: PullRequestPolicyDecision,
    findings: list[Finding],
    active_waivers: list[FindingWaiverRecord],
) -> WaiverApplicationResult:
    """
    Remove waived findings from PR aggregation.

    Matching uses the stable identity key ``(repo, pr_ref, target_kind, file_path,
    construct_key, weakness_class)`` — never ``finding_id`` or ``line_start``.
    A waiver granted against one finding_id therefore applies to any regenerated
    finding at the same SHA with the same construct and weakness class.
    Commit SHA remains the freshness control (invalidation on new commit).
    """
    finding_by_id = {item.id: item for item in findings}
    waiver_keys = {
        (
            waiver.repo,
            waiver.pr_ref,
            waiver.target_kind,
            waiver.file_path,
            waiver.construct_key,
            waiver.weakness_class,
        ): waiver
        for waiver in active_waivers
        if not waiver.invalidated and waiver.construct_key and waiver.weakness_class
    }

    waived_ids: set[str] = set()
    used_waivers: dict[str, FindingWaiverRecord] = {}
    retained: list[FindingPolicyDecision] = []

    for item in decision.finding_decisions:
        finding = finding_by_id.get(item.finding_id)
        if finding is None:
            retained.append(item)
            continue
        identity = finding_waiver_identity(finding)
        if identity is None:
            retained.append(item)
            continue
        waiver = waiver_keys.get(identity.storage_key())
        if waiver is None:
            retained.append(item)
            continue
        waived_ids.add(item.finding_id)
        used_waivers[waiver.id] = waiver

    if not retained:
        effective_action = PolicyAction.PASS
    else:
        effective_action = strictest_action([entry.decision for entry in retained])

    waived_count = len(waived_ids)
    explanation = decision.explanation
    if waived_count:
        explanation = (
            f"{decision.explanation} "
            f"{waived_count} finding(s) waived for commit {decision.commit_sha} — "
            f"effective PR policy decision '{effective_action.value}'."
        )

    effective = PullRequestPolicyDecision(
        repo=decision.repo,
        pr_ref=decision.pr_ref,
        commit_sha=decision.commit_sha,
        default_action=decision.default_action,
        pr_decision=effective_action,
        finding_decisions=retained,
        explanation=explanation,
    )
    return WaiverApplicationResult(
        effective_decision=effective,
        waived_finding_ids=frozenset(waived_ids),
        waivers_used=tuple(used_waivers.values()),
    )
