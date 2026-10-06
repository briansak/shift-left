"""Deterministic policy evaluation with explainable decisions."""

from __future__ import annotations

from dataclasses import dataclass

from shift_left.config import PolicyConfig
from shift_left.models.schema import (
    Finding,
    FindingPolicyDecision,
    Policy,
    PolicyAction,
    PolicyRule,
    PolicySeverity,
    PullRequestPolicyDecision,
)
from shift_left.policy.loader import _normalize_rules, load_and_validate_policies
from shift_left.policy.actions import strictest_action
from shift_left.policy.handler_trace import handler_rule_id_from_trace
from shift_left.policy.registry_gate import (
    attribute_gate_decision,
    merge_policy_registry_and_operator_actions,
    operator_escalation_action,
    registry_gate_action,
)
from shift_left.routing.globmatch import matches_any

_POLICY_SEVERITY_RANK = {
    PolicySeverity.UNCLASSIFIED: -1,
    PolicySeverity.INFO: 0,
    PolicySeverity.LOW: 1,
    PolicySeverity.MEDIUM: 2,
    PolicySeverity.HIGH: 3,
    PolicySeverity.CRITICAL: 4,
}

_ACTION_RANK = {
    PolicyAction.PASS: 0,
    PolicyAction.FLAG: 1,
    PolicyAction.BLOCK: 2,
}


def _normalize_cwe(value: str | None) -> str | None:
    if not value:
        return None
    text = value.upper().strip()
    if not text.startswith("CWE-"):
        text = f"CWE-{text.replace('CWE', '').strip('-')}"
    return text


def _severity_meets_threshold(finding: Finding, threshold: PolicySeverity) -> bool:
    if finding.policy_severity == PolicySeverity.UNCLASSIFIED:
        return False
    return (
        _POLICY_SEVERITY_RANK[finding.policy_severity]
        >= _POLICY_SEVERITY_RANK[threshold]
    )


def _rule_matches(finding: Finding, rule: PolicyRule) -> tuple[bool, str]:
    parts: list[str] = []

    if rule.severity_threshold is not None:
        if not _severity_meets_threshold(finding, rule.severity_threshold):
            return False, ""
        parts.append(f"policy_severity>={rule.severity_threshold.value}")

    finding_cwe = _normalize_cwe(finding.handler_asserted_cwe)
    if rule.cwe_blocklist:
        blockset = {_normalize_cwe(item) for item in rule.cwe_blocklist}
        if finding_cwe not in blockset:
            return False, ""
        # Registry CWE-657 (HCL-002 / FTD-009) is a coverage gap — not an unclaimed-path violation.
        if finding_cwe == "CWE-657" and handler_rule_id_from_trace(finding.trace) is not None:
            return False, ""
        # Broad CWE block policies do not apply to flag-severity registry rules.
        # Deliberate BLOCK requires policy.operator_escalations with an explicit rule_id.
        rule_id = handler_rule_id_from_trace(finding.trace)
        if rule_id is not None:
            from shift_left.handlers.config.rules.registry import rule_by_id

            registry_rule = rule_by_id(rule_id)
            if (
                registry_rule is not None
                and registry_rule.registry_status == "enabled"
                and registry_rule.severity == "flag"
            ):
                return False, ""
        parts.append(f"cwe in blocklist {sorted(blockset)}")

    if rule.cwe_allowlist:
        allowset = {_normalize_cwe(item) for item in rule.cwe_allowlist}
        if finding_cwe not in allowset:
            return False, ""
        parts.append(f"cwe in allowlist {sorted(allowset)}")

    if not parts:
        return False, ""
    return True, "; ".join(parts)


def _policy_applies_to(finding: Finding, policy: Policy) -> bool:
    if policy.applies_to.target_kind is not None:
        if finding.target_kind != policy.applies_to.target_kind:
            return False
    return matches_any(finding.file_path, policy.applies_to.path_globs)


def _policy_matches_finding(
    finding: Finding,
    policy: Policy,
) -> tuple[bool, str, int, PolicyRule | None]:
    if not policy.enabled:
        return False, "", -1, None
    if not _policy_applies_to(finding, policy):
        return False, "", -1, None

    rules = _normalize_rules(policy.rules)
    for index, rule in enumerate(rules):
        matched, reason = _rule_matches(finding, rule)
        if matched:
            return True, reason, index, rule
    return False, "", -1, None


def _strictest_action(actions: list[PolicyAction]) -> PolicyAction:
    return strictest_action(actions)


def _cap_action_for_unclassified(action: PolicyAction, finding: Finding) -> PolicyAction:
    """
    Unclassified findings may flag but must never block.

    Model-only assertions derive policy_severity=unclassified and are advisory.
    """
    if finding.policy_severity == PolicySeverity.UNCLASSIFIED and action == PolicyAction.BLOCK:
        return PolicyAction.FLAG
    return action


@dataclass(frozen=True)
class PolicyEvaluationResult:
    pr_decision: PullRequestPolicyDecision

    @property
    def pr_action(self) -> PolicyAction:
        return self.pr_decision.pr_decision


class PolicyEngine:
    """
    Evaluates configured policies against findings using policy_severity only.

    Output is a **policy decision** (pass/flag/block) — an advisory gate signal,
    never a compliance verdict.
    """

    def __init__(self, config: PolicyConfig) -> None:
        self._config = config
        self._policies = load_and_validate_policies(config)

    @property
    def policies(self) -> list[Policy]:
        return list(self._policies)

    def evaluate(
        self,
        *,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        findings: list[Finding],
    ) -> PolicyEvaluationResult:
        finding_decisions: list[FindingPolicyDecision] = []

        for finding in findings:
            decision = self._evaluate_finding(finding)
            finding_decisions.append(decision)

        if not findings:
            pr_action = self._config.default_action
            explanation = (
                f"No findings — PR policy decision is configured default "
                f"'{pr_action.value}' (not a compliance verdict)."
            )
        else:
            actions = [item.decision for item in finding_decisions]
            pr_action = _strictest_action(actions)
            matched = [item for item in finding_decisions if item.matched_policy_id]
            explanation = (
                f"PR policy decision '{pr_action.value}' from {len(matched)} matched finding(s) "
                f"and {len(findings) - len(matched)} default-action finding(s). "
                "This is an advisory policy decision, not a compliance verdict."
            )

        pr_decision = PullRequestPolicyDecision(
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            default_action=self._config.default_action,
            pr_decision=pr_action,
            finding_decisions=finding_decisions,
            explanation=explanation,
        )
        return PolicyEvaluationResult(pr_decision=pr_decision)

    def _evaluate_finding(self, finding: Finding) -> FindingPolicyDecision:
        policy_action: PolicyAction | None = None
        matched_policy: Policy | None = None
        matched_rule_index: int | None = None
        matched_reason: str | None = None

        for policy in self._policies:
            matched, reason, rule_index, rule = _policy_matches_finding(finding, policy)
            if matched and rule is not None:
                policy_action = _cap_action_for_unclassified(policy.action, finding)
                matched_policy = policy
                matched_rule_index = rule_index
                matched_reason = reason
                break

        registry_action = registry_gate_action(finding)
        escalation_action = operator_escalation_action(
            finding, self._config.operator_escalations
        )
        decision = _cap_action_for_unclassified(
            merge_policy_registry_and_operator_actions(
                policy_action=policy_action,
                registry_action=registry_action,
                operator_escalation=escalation_action,
                default_action=self._config.default_action,
            ),
            finding,
        )

        source_id, source_name, source_rule_index, source_reason = attribute_gate_decision(
            finding,
            decision=decision,
            registry_action=registry_action,
            policy_action=policy_action,
            operator_escalation=escalation_action,
            matched_policy=matched_policy,
            matched_rule_index=matched_rule_index,
            matched_reason=matched_reason,
        )

        if source_id is not None and source_id.startswith("operator-escalation:"):
            return FindingPolicyDecision(
                finding_id=finding.id,
                decision=decision,
                matched_policy_id=source_id,
                matched_policy_name=source_name,
                matched_rule_index=source_rule_index,
                rule_explanation=source_reason,
                explanation=(
                    f"Operator escalation for registry rule "
                    f"'{source_id.removeprefix('operator-escalation:')}'. "
                    f"Policy decision: {decision.value} "
                    "(advisory — not a compliance verdict)."
                ),
            )

        if source_id is not None and source_id.startswith("registry:"):
            return FindingPolicyDecision(
                finding_id=finding.id,
                decision=decision,
                matched_policy_id=source_id,
                matched_policy_name=source_name,
                matched_rule_index=source_rule_index,
                rule_explanation=source_reason,
                explanation=(
                    f"Registry rule '{source_id.removeprefix('registry:')}' severity "
                    f"'{registry_action.value if registry_action else decision.value}' "
                    f"applied. Policy decision: {decision.value} "
                    "(advisory — not a compliance verdict)."
                ),
            )

        if matched_policy is not None and matched_rule_index is not None:
            return FindingPolicyDecision(
                finding_id=finding.id,
                decision=decision,
                matched_policy_id=matched_policy.id,
                matched_policy_name=matched_policy.name,
                matched_rule_index=matched_rule_index,
                rule_explanation=matched_reason,
                explanation=(
                    f"Policy '{matched_policy.name}' ({matched_policy.id}) "
                    f"rule[{matched_rule_index}] matched: {matched_reason}. "
                    f"Policy decision: {decision.value} "
                    "(advisory — not a compliance verdict)."
                ),
            )

        default_explanation = (
            f"No enabled policy matched. Default policy decision: "
            f"{decision.value} (advisory — not a compliance verdict)."
        )
        if finding.policy_severity == PolicySeverity.UNCLASSIFIED:
            default_explanation = (
                f"Finding has unclassified policy_severity — configured default action "
                f"'{decision.value}' applies (advisory — not a compliance verdict)."
            )

        return FindingPolicyDecision(
            finding_id=finding.id,
            decision=decision,
            matched_policy_id=source_id,
            matched_policy_name=source_name,
            matched_rule_index=source_rule_index,
            rule_explanation=source_reason,
            explanation=default_explanation,
        )
