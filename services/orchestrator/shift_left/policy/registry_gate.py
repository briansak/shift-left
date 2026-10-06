"""Registry rule severity drives gate action when policies do not fully decide."""

from __future__ import annotations

from shift_left.handlers.config.rules.registry import rule_by_id, rule_registry_enforced
from shift_left.models.schema import Finding, OperatorEscalation, PolicyAction, PolicySeverity
from shift_left.policy.handler_trace import handler_rule_id_from_trace

_BLOCKING_POLICY_SEVERITIES = frozenset({PolicySeverity.HIGH, PolicySeverity.CRITICAL})

_SEVERITY_RANK = {
    PolicySeverity.UNCLASSIFIED: -1,
    PolicySeverity.INFO: 0,
    PolicySeverity.LOW: 1,
    PolicySeverity.MEDIUM: 2,
    PolicySeverity.HIGH: 3,
    PolicySeverity.CRITICAL: 4,
}


def _severity_meets_blocking_threshold(finding: Finding) -> bool:
    if finding.policy_severity == PolicySeverity.UNCLASSIFIED:
        return False
    return _SEVERITY_RANK[finding.policy_severity] >= _SEVERITY_RANK[PolicySeverity.HIGH]


def registry_gate_action(finding: Finding) -> PolicyAction | None:
    """
    Map an enabled handler registry rule to a gate floor action.

    ``block`` registry rules with blocking ``policy_severity`` floor at BLOCK.
    ``flag`` registry rules floor at FLAG (never below FLAG).
    """
    rule_id = handler_rule_id_from_trace(finding.trace)
    if rule_id is None:
        return None
    rule = rule_by_id(rule_id)
    if rule is None or not rule_registry_enforced(rule):
        return None
    if rule.severity == "flag":
        return PolicyAction.FLAG
    if rule.severity == "block" and _severity_meets_blocking_threshold(finding):
        return PolicyAction.BLOCK
    return None


def operator_escalation_action(
    finding: Finding,
    escalations: list[OperatorEscalation],
) -> PolicyAction | None:
    """Return explicit operator escalation for a handler rule, if configured."""
    rule_id = handler_rule_id_from_trace(finding.trace)
    if rule_id is None:
        return None
    for item in escalations:
        if item.rule_id == rule_id:
            return item.action
    return None


def merge_policy_registry_and_operator_actions(
    *,
    policy_action: PolicyAction | None,
    registry_action: PolicyAction | None,
    operator_escalation: PolicyAction | None,
    default_action: PolicyAction,
) -> PolicyAction:
    """
    Combine policy, registry floor, and explicit operator escalation.

    Registry severity is the **floor** (minimum gate action) for handler findings.
    Broad CWE block policies do not apply to ``flag`` registry rules (see engine).
    ``operator_escalations`` may **escalate** a specific rule_id to BLOCK.
    """
    from shift_left.policy.actions import strictest_action

    actions: list[PolicyAction] = []
    if policy_action is not None:
        actions.append(policy_action)
    else:
        actions.append(default_action)
    if registry_action is not None:
        actions.append(registry_action)
    if operator_escalation is not None:
        actions.append(operator_escalation)
    return strictest_action(actions)


def registry_decision_source_id(rule_id: str) -> str:
    return f"registry:{rule_id}"


def operator_escalation_source_id(rule_id: str) -> str:
    return f"operator-escalation:{rule_id}"


def attribute_gate_decision(
    finding: Finding,
    *,
    decision: PolicyAction,
    registry_action: PolicyAction | None,
    policy_action: PolicyAction | None,
    operator_escalation: PolicyAction | None,
    matched_policy: object | None,
    matched_rule_index: int | None,
    matched_reason: str | None,
) -> tuple[str | None, str | None, int | None, str | None]:
    """
    Choose audit provenance for a gate decision.

    Operator escalation wins when it supplies BLOCK. Registry attribution applies
    when registry supplies or floors the action. CWE operator policies attribute
    when they alone drive BLOCK (e.g. CWE-657 unclaimed).
    """
    rule_id = handler_rule_id_from_trace(finding.trace)
    if (
        rule_id is not None
        and operator_escalation == PolicyAction.BLOCK
        and decision == PolicyAction.BLOCK
    ):
        return (
            operator_escalation_source_id(rule_id),
            f"Operator escalation for {rule_id}",
            None,
            f"operator escalation rule_id={rule_id}",
        )

    if rule_id is not None and registry_action is not None:
        registry_supplies_block = (
            registry_action == PolicyAction.BLOCK
            and decision == PolicyAction.BLOCK
            and policy_action != PolicyAction.BLOCK
            and operator_escalation != PolicyAction.BLOCK
        )
        registry_supplies_flag = (
            registry_action == PolicyAction.FLAG
            and decision == PolicyAction.FLAG
            and policy_action is None
            and operator_escalation is None
        )
        registry_floors_flag = (
            registry_action == PolicyAction.FLAG
            and decision == PolicyAction.FLAG
            and operator_escalation is None
        )
        if registry_supplies_block or registry_supplies_flag or registry_floors_flag:
            return (
                registry_decision_source_id(rule_id),
                f"Registry rule {rule_id}",
                None,
                f"registry severity={registry_action.value}",
            )

    if matched_policy is not None and matched_rule_index is not None:
        return (
            matched_policy.id,
            matched_policy.name,
            matched_rule_index,
            matched_reason,
        )

    if (
        rule_id is not None
        and registry_action == PolicyAction.BLOCK
        and decision == PolicyAction.BLOCK
    ):
        return (
            registry_decision_source_id(rule_id),
            f"Registry rule {rule_id}",
            None,
            f"registry severity={registry_action.value}",
        )

    return None, None, None, None
