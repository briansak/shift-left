"""Unified registry rule matching for eval harness and PR gate."""

from __future__ import annotations

from dataclasses import dataclass

from shift_left.handlers.config.hcl_parse import (
    HCL_INTERPRETABILITY_RULE_ID,
    hcl_interpretability_matches,
)
from shift_left.handlers.config.hcl_provider_coverage import (
    FTD_UNCOVERED_PROVIDER_RULE_ID,
    HCL_UNCOVERED_PROVIDER_RULE_ID,
    uncovered_provider_matches,
)
from shift_left.handlers.config.parser_scope import path_in_target_parser_scope
from shift_left.handlers.config.parsers import invoke_parser
from shift_left.handlers.config.parsers.ios_xe.platform import SniffedPlatform, sniff_platform
from shift_left.handlers.config.rules.registry import (
    UNDECLARED_TARGET_TYPE,
    UNDETERMINED_PLATFORM_RULE_ID,
    Rule,
    rule_by_id,
    rules_for_target_type,
)
from shift_left.handlers.config.types import ConfigRuleMatch


@dataclass(frozen=True)
class RegistryRuleMatch:
    rule_id: str
    line_start: int
    line_end: int
    cwe: str
    pattern_id: str
    title: str | None = None
    description: str | None = None
    construct_key: str = ""


def _parser_matches_for_rule(
    rule: Rule,
    content: str,
    *,
    target_type: str,
) -> list[ConfigRuleMatch]:
    matches = invoke_parser(
        rule.parser,
        chunk_content=content,
        line_offset=0,
        rule_id=rule.id,
        declared_target_type=target_type,
    )
    if rule.parser in {"asa_config", "ftd_fmc", "ios_xe_config", "nx_os_config"}:
        return matches
    return [item for item in matches if item.evaluation_status == "matched"]


def _from_raw(rule_id: str, raw: ConfigRuleMatch) -> RegistryRuleMatch:
    line_start = raw.line_start or 1
    line_end = raw.line_end or line_start
    return RegistryRuleMatch(
        rule_id=rule_id,
        line_start=line_start,
        line_end=line_end,
        cwe=raw.cwe,
        pattern_id=raw.pattern_id,
        title=raw.title,
        description=raw.description,
        construct_key=raw.construct_key,
    )


def _normalize_match(rule: Rule, raw: ConfigRuleMatch) -> RegistryRuleMatch:
    return _from_raw(rule.id, raw)


def _normalize_interpretability_match(raw: ConfigRuleMatch) -> RegistryRuleMatch:
    return _from_raw(HCL_INTERPRETABILITY_RULE_ID, raw)


def _normalize_uncovered_provider_match(
    raw: ConfigRuleMatch,
    *,
    target_type: str,
) -> RegistryRuleMatch:
    rule_id = (
        FTD_UNCOVERED_PROVIDER_RULE_ID
        if target_type == "cisco_ftd"
        else HCL_UNCOVERED_PROVIDER_RULE_ID
    )
    return _from_raw(rule_id, raw)


_HCL_TARGET_TYPES = frozenset({"cisco_ftd", "generic_terraform"})


def undetermined_platform_matches(content: str) -> list[RegistryRuleMatch]:
    """CLI-001 when content has no platform markers. Does not guess a platform."""
    if not content.strip():
        return []
    if sniff_platform(content) != SniffedPlatform.UNKNOWN:
        return []
    rule = rule_by_id(UNDETERMINED_PLATFORM_RULE_ID)
    if rule is None:
        return []
    line_count = max(1, len(content.splitlines()))
    return [
        RegistryRuleMatch(
            rule_id=rule.id,
            line_start=1,
            line_end=line_count,
            cwe=rule.cwe,
            pattern_id=rule.id,
            title="Platform could not be determined",
            description=rule.description,
            construct_key="file",
        )
    ]


def match_undeclared_cli(content: str) -> list[RegistryRuleMatch]:
    """Undeclared CLI body: sniffed platform rules, or CLI-001 when sniff is unknown."""
    sniffed = sniff_platform(content)
    if sniffed == SniffedPlatform.UNKNOWN:
        return undetermined_platform_matches(content)
    return match_registry_rules(sniffed.value, content)


def match_registry_rules(target_type: str, content: str) -> list[RegistryRuleMatch]:
    """Return normalized registry rule matches for one config body."""
    results: list[RegistryRuleMatch] = []
    if target_type == UNDECLARED_TARGET_TYPE:
        return match_undeclared_cli(content)
    if target_type in _HCL_TARGET_TYPES:
        interpretability = hcl_interpretability_matches(content)
        if interpretability:
            return [_normalize_interpretability_match(item) for item in interpretability]
        for raw in uncovered_provider_matches(content, target_type):
            results.append(_normalize_uncovered_provider_match(raw, target_type=target_type))

    for rule in rules_for_target_type(target_type):
        for raw in _parser_matches_for_rule(rule, content, target_type=target_type):
            if raw.evaluation_status != "matched":
                continue
            results.append(_normalize_match(rule, raw))
    return results


def registry_rule_line_set(target_type: str, content: str) -> frozenset[tuple[str, int]]:
    """(rule_id, line_start) pairs from the unified registry matching path."""
    return frozenset((match.rule_id, match.line_start) for match in match_registry_rules(target_type, content))


def registry_rule_line_set_for_path(
    target_type: str,
    path: str,
    content: str,
) -> frozenset[tuple[str, int]]:
    """Registry rule lines when the path is in parser scope; otherwise empty."""
    if target_type == UNDECLARED_TARGET_TYPE:
        return registry_rule_line_set(target_type, content)
    if not path_in_target_parser_scope(target_type, path):
        return frozenset()
    return registry_rule_line_set(target_type, content)


def matched_registry_rule_ids(target_type: str, content: str) -> set[str]:
    return {match.rule_id for match in match_registry_rules(target_type, content)}


def matched_registry_rule_ids_for_path(target_type: str, path: str, content: str) -> set[str]:
    if target_type == UNDECLARED_TARGET_TYPE:
        return matched_registry_rule_ids(target_type, content)
    if not path_in_target_parser_scope(target_type, path):
        return set()
    return matched_registry_rule_ids(target_type, content)
