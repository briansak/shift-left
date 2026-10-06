"""Waiver eligibility, capability requirements, and rejection messages."""

from __future__ import annotations

from shift_left.auth.context import TokenCapability
from shift_left.config import AppConfig
from shift_left.handlers.config.rules.registry import UNDETERMINED_PLATFORM_RULE_ID, rule_by_id
from shift_left.handlers.unclaimed_files import UNCLAIMED_TRACE
from shift_left.models.schema import Finding, FindingPolicyDecision, PolicyAction
from shift_left.policy.handler_trace import handler_rule_id_from_trace

UNDETERMINED_PLATFORM_WAIVER_REJECTION = (
    "CLI-001 (platform could not be determined) cannot be waived. "
    "The remedy is a config edit, not a code change: add a managed_targets.targets "
    "entry in shift-left.yaml with id, display_name, repo, branch, config_paths "
    "covering this file, and target_type set to cisco_secure_firewall, cisco_ios_xe, "
    "or cisco_nx_os."
)

UNCLAIMED_WAIVER_REJECTION = (
    "Unclaimed-path findings (CWE-657) cannot be waived. "
    "Remediate by claiming the path in routing.config_globs "
    "(and routing.routing_parser_claim_globs when a structural parser applies) "
    "or add routing.pr_gate_exclusion_globs for an explicit gate exclusion."
)


def is_unclaimed_finding(finding: Finding) -> bool:
    """True for CWE-657 gate findings that carry no registry rule_id."""
    if finding.trace == UNCLAIMED_TRACE:
        return True
    if finding.handler_asserted_cwe == "CWE-657" and handler_rule_id_from_trace(finding.trace) is None:
        return True
    return False


def is_undetermined_platform_finding(finding: Finding) -> bool:
    """True for CLI-001. The trace carries a real rule id; this is not a missing-id check."""
    return handler_rule_id_from_trace(finding.trace) == UNDETERMINED_PLATFORM_RULE_ID


def assert_finding_waivable(finding: Finding, config: AppConfig) -> str:
    """
    Return the registry rule_id for a waivable finding.

    Unclaimed findings (CWE-657, trace ``handler:unclaimed-file``) have no rule_id;
    they are rejected explicitly here rather than via a None identity comparison.
    CLI-001 is a registered rule and is rejected by that rule id, not by a missing id.
    """
    if is_unclaimed_finding(finding):
        raise ValueError(UNCLAIMED_WAIVER_REJECTION)
    if is_undetermined_platform_finding(finding):
        raise ValueError(UNDETERMINED_PLATFORM_WAIVER_REJECTION)

    rule_id = handler_rule_id_from_trace(finding.trace)
    if rule_id is None:
        raise ValueError(
            "Finding has no registry rule_id (handler trace is missing or non-registry) "
            "and cannot be waived."
        )

    rule = rule_by_id(rule_id)
    if rule is None:
        raise ValueError(f"Unknown registry rule {rule_id!r}; cannot waive.")
    if not rule.waivable:
        raise ValueError(
            f"Registry rule {rule_id} is marked waivable=false and cannot be waived."
        )
    return rule_id


def finding_policy_action(
    finding: Finding,
    finding_decisions: list[FindingPolicyDecision] | None,
) -> PolicyAction | None:
    if not finding_decisions:
        return None
    for item in finding_decisions:
        if item.finding_id == finding.id:
            return item.decision
    return None


def required_waiver_capability(
    finding: Finding,
    finding_decisions: list[FindingPolicyDecision] | None,
) -> TokenCapability:
    """BLOCK-level findings require approve; flag-level findings allow triage."""
    decision = finding_policy_action(finding, finding_decisions)
    if decision == PolicyAction.BLOCK:
        return TokenCapability.APPROVE
    return TokenCapability.TRIAGE


def assert_sufficient_waiver_capability(
    *,
    capability_used: TokenCapability,
    required: TokenCapability,
) -> None:
    if required == TokenCapability.APPROVE:
        if capability_used != TokenCapability.APPROVE:
            raise ValueError(
                "BLOCK-level findings require the approve capability to waive; "
                "triage is insufficient."
            )
        return
    if capability_used not in {TokenCapability.TRIAGE, TokenCapability.APPROVE}:
        raise ValueError("Flag-level findings require triage or approve capability to waive.")
