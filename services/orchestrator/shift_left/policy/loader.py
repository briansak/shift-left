"""Policy config validation — fail loud on malformed policy at startup."""

from __future__ import annotations

from typing import Any

from shift_left.config import PolicyConfig
from shift_left.models.schema import Policy, PolicyRule, PolicySeverity


class PolicyValidationError(ValueError):
    """Raised when policy configuration is invalid."""


FORBIDDEN_POLICY_RULE_FIELDS = frozenset(
    {
        "model_context",
        "recommended_actions",
        "enrichment_source",
        "enrichment_generated_at",
        "model_asserted_severity",
        "model_asserted_cwe",
        "summary_text",
        "suggested_course_of_action",
        "findings_covered",
        "generated_at",
        "generator",
        "is_advisory",
        "review_summary",
        "localization_result",
        "ranked_files",
        "cwe_queried",
        "exploration_trace",
        "turn_count",
        "published_file_f1",
        "model_variant",
    }
)


def _collect_forbidden_rule_keys(rule: dict[str, Any], *, policy_id: str, rule_index: int) -> list[str]:
    hits = [key for key in rule if key in FORBIDDEN_POLICY_RULE_FIELDS]
    if hits:
        raise PolicyValidationError(
            f"policy ({policy_id}) rule[{rule_index}]: forbidden field(s) {hits} — "
            "enrichment and ReviewSummary fields are not policy inputs "
            "(PolicyRule uses extra=forbid; advisory prose must not drive policy)."
        )
    return hits


def _validate_raw_policy_rules(raw_policy: dict[str, Any], *, index: int) -> None:
    policy_id = str(raw_policy.get("id") or f"rules[{index}]")
    rules_raw = raw_policy.get("rules")
    if rules_raw is None:
        return
    if isinstance(rules_raw, dict):
        _collect_forbidden_rule_keys(rules_raw, policy_id=policy_id, rule_index=0)
        return
    if isinstance(rules_raw, list):
        for rule_index, rule in enumerate(rules_raw):
            if isinstance(rule, dict):
                _collect_forbidden_rule_keys(rule, policy_id=policy_id, rule_index=rule_index)


def validate_raw_policies(raw_rules: list[Any]) -> None:
    """Reject policy YAML that references enrichment or ReviewSummary fields."""
    for index, raw_policy in enumerate(raw_rules):
        if isinstance(raw_policy, dict):
            _validate_raw_policy_rules(raw_policy, index=index)


def _normalize_rules(rules: PolicyRule | list[PolicyRule]) -> list[PolicyRule]:
    if isinstance(rules, list):
        return rules
    return [rules]


def _rule_has_condition(rule: PolicyRule) -> bool:
    return bool(
        rule.severity_threshold is not None
        or rule.cwe_allowlist
        or rule.cwe_blocklist
    )


def validate_policy(policy: Policy, *, index: int) -> None:
    prefix = f"policy.rules[{index}]"
    if not policy.id.strip():
        raise PolicyValidationError(f"{prefix}: id is required")
    if not policy.name.strip():
        raise PolicyValidationError(f"{prefix}: name is required")
    if not policy.applies_to.path_globs:
        raise PolicyValidationError(f"{prefix} ({policy.id}): applies_to.path_globs must not be empty")

    rule_list = _normalize_rules(policy.rules)
    if not rule_list:
        raise PolicyValidationError(f"{prefix} ({policy.id}): at least one rule is required")
    for rule_index, rule in enumerate(rule_list):
        if not _rule_has_condition(rule):
            raise PolicyValidationError(
                f"{prefix} ({policy.id}) rule[{rule_index}]: "
                "must specify severity_threshold and/or CWE allowlist/blocklist"
            )


def validate_severity_mappings(config: PolicyConfig) -> None:
    allowed = {item.value for item in PolicySeverity if item != PolicySeverity.UNCLASSIFIED}
    for label, mapping in (
        ("policy.cwe_severity_mapping", config.cwe_severity_mapping),
        ("policy.pattern_severity_mapping", config.pattern_severity_mapping),
    ):
        for key, value in mapping.items():
            if str(value).lower() not in allowed:
                raise PolicyValidationError(
                    f"{label}[{key!r}]: invalid severity {value!r} — "
                    f"must be one of {sorted(allowed)}"
                )


def load_and_validate_policies(config: PolicyConfig) -> list[Policy]:
    """
    Validate policy configuration at startup.

    Precedence (documented):
    1. Enabled policies are evaluated in YAML declaration order.
    2. For each finding, the first matching enabled policy wins.
    3. PR-level policy decision = strictest action across finding decisions
       (block > flag > pass).
    4. When no policy matches a finding, ``default_action`` applies.
    """
    if not config.human_review_required:
        raise PolicyValidationError(
            "policy.human_review_required must remain true — "
            "auto-approve is not supported under any configuration"
        )

    validate_severity_mappings(config)

    seen_ids: set[str] = set()
    validated: list[Policy] = []
    for index, policy in enumerate(config.rules):
        validate_policy(policy, index=index)
        if policy.id in seen_ids:
            raise PolicyValidationError(f"Duplicate policy id: {policy.id}")
        seen_ids.add(policy.id)
        validated.append(policy)
    return validated
