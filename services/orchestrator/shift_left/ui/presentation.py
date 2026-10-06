"""Server-side presentation helpers — no policy or severity logic."""

from __future__ import annotations

from shift_left.auth.context import AuthContext, TokenCapability
from shift_left.models.schema import (
    EnrichmentStatus,
    Finding,
    PolicyAction,
    PolicySeverity,
    PullRequestPolicyDecision,
)
from shift_left.ui.labels import sanitize_advisory_prose


def capability_set(auth: AuthContext | None) -> set[str]:
    if auth is None:
        return set()
    if TokenCapability.ADMIN in auth.capabilities:
        return {cap.value for cap in TokenCapability}
    return {cap.value for cap in auth.capabilities}


def can(auth: AuthContext | None, capability: TokenCapability) -> bool:
    return auth is not None and auth.has_capability(capability)


def policy_severity_label(severity: PolicySeverity) -> str:
    if severity == PolicySeverity.UNCLASSIFIED:
        return "Unclassified — no deterministic policy signal"
    return severity.value.upper()


def policy_severity_class(severity: PolicySeverity) -> str:
    if severity == PolicySeverity.UNCLASSIFIED:
        return "severity-unclassified"
    return f"severity-{severity.value}"


def policy_action_label(action: PolicyAction | str) -> str:
    if isinstance(action, str):
        return action.upper()
    return action.value.upper()


def enrichment_badge(finding: Finding) -> str | None:
    if finding.enrichment is None:
        return None
    status = finding.enrichment.status
    if status in {EnrichmentStatus.CACHE_EMPTY, EnrichmentStatus.CACHE_STALE, EnrichmentStatus.NONE}:
        return status.value.replace("_", " ")
    if finding.enrichment.stale:
        return "reference cache stale"
    return None


def finding_policy_decision(
    finding_id: str,
    decision: PullRequestPolicyDecision | None,
) -> dict | None:
    if decision is None:
        return None
    for item in decision.finding_decisions:
        if item.finding_id == finding_id:
            return {
                "decision": item.decision.value,
                "policy_id": item.matched_policy_id,
                "policy_name": item.matched_policy_name,
                "rule_index": item.matched_rule_index,
                "explanation": item.explanation,
            }
    return None


def format_advisory(text: str | None) -> str:
    return sanitize_advisory_prose(text or "")
