"""Detect Terraform provider prefixes not covered by registry rules (silent-pass guard)."""

from __future__ import annotations

import re

from shift_left.handlers.config.hcl_parse import iter_hcl_resources, parse_hcl_content
from shift_left.handlers.config.types import ConfigRuleMatch
from shift_left.policy import construct_key as construct

HCL_UNCOVERED_PROVIDER_RULE_ID = "HCL-002"
FTD_UNCOVERED_PROVIDER_RULE_ID = "FTD-009"

# Prefixes each enabled registry rule family can evaluate (structural HCL handlers).
GENERIC_TERRAFORM_COVERED_PREFIXES: frozenset[str] = frozenset(
    {"aws_", "azurerm_", "google_", "fmc_"}
)
CISCO_FTD_COVERED_PREFIXES: frozenset[str] = frozenset({"fmc_"})

_UNCOVERED_RULE_BY_TARGET: dict[str, str] = {
    "generic_terraform": HCL_UNCOVERED_PROVIDER_RULE_ID,
    "cisco_ftd": FTD_UNCOVERED_PROVIDER_RULE_ID,
}

_RESOURCE_HEADER_RE = re.compile(
    r'^\s*resource\s+"([^"]+)"\s+"',
    re.MULTILINE,
)


def covered_prefixes_for_target(target_type: str) -> frozenset[str]:
    if target_type == "cisco_ftd":
        return CISCO_FTD_COVERED_PREFIXES
    if target_type == "generic_terraform":
        return GENERIC_TERRAFORM_COVERED_PREFIXES
    return frozenset()


def provider_prefix(resource_type: str) -> str:
    if "_" not in resource_type:
        return f"{resource_type}_"
    return f"{resource_type.split('_', 1)[0]}_"


def is_resource_type_covered(resource_type: str, target_type: str) -> bool:
    covered = covered_prefixes_for_target(target_type)
    return any(resource_type.startswith(prefix) for prefix in covered)


def _first_resource_line(content: str, resource_type: str) -> int:
    pattern = re.compile(
        rf'^\s*resource\s+"{re.escape(resource_type)}"\s+"',
        re.MULTILINE,
    )
    for index, line in enumerate(content.splitlines(), start=1):
        if pattern.match(line):
            return index
    return 1


def uncovered_provider_prefixes(target_type: str, content: str) -> list[str]:
    """Return sorted uncovered provider prefixes (e.g. iosxe_) in parsed HCL."""
    if target_type not in _UNCOVERED_RULE_BY_TARGET:
        return []
    status = parse_hcl_content(content)
    if status.parsed is None:
        return []
    uncovered: set[str] = set()
    for resource_type, _name, _attrs in iter_hcl_resources(status.parsed):
        if not is_resource_type_covered(resource_type, target_type):
            uncovered.add(provider_prefix(resource_type))
    return sorted(uncovered)


def uncovered_provider_matches(
    content: str,
    target_type: str,
    *,
    line_offset: int = 0,
) -> list[ConfigRuleMatch]:
    """FLAG-level matches when parsed resources use providers outside registry scope."""
    rule_id = _UNCOVERED_RULE_BY_TARGET.get(target_type)
    if rule_id is None:
        return []
    status = parse_hcl_content(content)
    if status.parsed is None:
        return []

    covered = covered_prefixes_for_target(target_type)
    prefix_to_type: dict[str, str] = {}
    for resource_type, _name, _attrs in iter_hcl_resources(status.parsed):
        if is_resource_type_covered(resource_type, target_type):
            continue
        prefix = provider_prefix(resource_type)
        prefix_to_type.setdefault(prefix, resource_type)

    matches: list[ConfigRuleMatch] = []
    for prefix in sorted(prefix_to_type):
        example_type = prefix_to_type[prefix]
        line_no = _first_resource_line(content, example_type) + line_offset
        covered_list = ", ".join(sorted(covered))
        matches.append(
            ConfigRuleMatch(
                cwe="CWE-657",
                pattern_id=rule_id,
                line_start=line_no,
                line_end=line_no,
                evaluation_status="matched",
                title=f"Uncovered Terraform provider ({prefix.rstrip('_')})",
                description=(
                    f"Parsed resource type '{example_type}' uses provider prefix '{prefix}' "
                    f"which no enabled registry rule evaluates for {target_type}. "
                    f"Covered prefixes: {covered_list}."
                ),
                construct_key=construct.provider(prefix),
            )
        )
    return matches


def uncovered_rule_id_for_target(target_type: str) -> str | None:
    return _UNCOVERED_RULE_BY_TARGET.get(target_type)
