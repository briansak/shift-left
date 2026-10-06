"""FTD FMC Terraform deterministic rule checks."""

from __future__ import annotations

from shift_left.handlers.config.parsers.ftd.parser import (
    ParsedFtdConfig,
    is_broad_network_access_rule,
    is_management_exposure,
    is_missing_allow_logging,
    is_missing_intrusion_policy,
    is_shadowed_allow_rule,
    parse_ftd_fmc_config,
    unresolved_network_object_refs,
)
from shift_left.handlers.config.parsers.ftd.resolver import rule_key
from shift_left.handlers.config.types import ConfigRuleMatch
from shift_left.policy import construct_key as construct


def _match(
    *,
    rule_id: str,
    cwe: str,
    line_start: int,
    line_end: int,
    description: str,
    construct_key: str,
) -> ConfigRuleMatch:
    return ConfigRuleMatch(
        cwe=cwe,
        pattern_id=rule_id,
        line_start=line_start,
        line_end=line_end,
        evaluation_status="matched",
        title=f"Deterministic rule: {rule_id}",
        description=description,
        construct_key=construct_key,
    )


def check_ftd_002(config: ParsedFtdConfig, *, rule_id: str = "FTD-002") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for port in config.port_objects:
        if port.is_permissive:
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-284",
                    line_start=port.line_start,
                    line_end=port.line_end,
                    description="FMC port object permits any protocol or unconstrained TCP/UDP.",
                    construct_key=construct.resource("fmc_port_object", port.name),
                )
            )
    return matches


def check_ftd_001(config: ParsedFtdConfig, *, rule_id: str = "FTD-001") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for rule in config.access_rules:
        resolution = config.rule_resolutions.get(rule_key(rule))
        if resolution is None:
            continue
        if is_broad_network_access_rule(rule, resolution):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-284",
                    line_start=rule.line_start,
                    line_end=rule.line_end,
                    description=(
                        "FMC ALLOW rule uses internet-wide resolved source or "
                        "destination networks (including via object references)."
                    ),
                    construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                )
            )
    for bulk in config.access_rules_bulk:
        for rule in bulk.rules:
            resolution = config.rule_resolutions.get(rule_key(rule))
            if resolution is None:
                continue
            if is_broad_network_access_rule(rule, resolution):
                matches.append(
                    _match(
                        rule_id=rule_id,
                        cwe="CWE-284",
                        line_start=bulk.line_start,
                        line_end=bulk.line_end,
                        description=(
                            "FMC ALLOW rule in fmc_access_rules uses internet-wide "
                            "resolved source or destination networks."
                        ),
                        construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                    )
                )
    return matches


def check_ftd_003(config: ParsedFtdConfig, *, rule_id: str = "FTD-003") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for rule in config.access_rules:
        if is_missing_allow_logging(rule):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-778",
                    line_start=rule.line_start,
                    line_end=rule.line_end,
                    description=(
                        "FMC access rule ALLOW has no connection logging enabled "
                        "(log_begin / log_connection_begin or log_end / log_connection_end)."
                    ),
                    construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                )
            )
    for bulk in config.access_rules_bulk:
        for rule in bulk.rules:
            if is_missing_allow_logging(rule):
                matches.append(
                    _match(
                        rule_id=rule_id,
                        cwe="CWE-778",
                        line_start=bulk.line_start,
                        line_end=bulk.line_end,
                        description=(
                            "FMC ALLOW rule in fmc_access_rules has no connection logging enabled."
                        ),
                        construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                    )
                )
    return matches


def check_ftd_004(config: ParsedFtdConfig, *, rule_id: str = "FTD-004") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for policy in config.vpn_ike_policies:
        if policy.is_weak:
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-327",
                    line_start=policy.line_start,
                    line_end=policy.line_end,
                    description="FMC IKEv2 policy uses weak encryption, integrity, or DH group < 14.",
                    construct_key=construct.resource("fmc_vpn_ike_policy", policy.name),
                )
            )
    return matches


def check_ftd_005(config: ParsedFtdConfig, *, rule_id: str = "FTD-005") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for rule in config.access_rules:
        resolution = config.rule_resolutions.get(rule_key(rule))
        if resolution is None:
            continue
        if is_management_exposure(rule, resolution.source):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-284",
                    line_start=rule.line_start,
                    line_end=rule.line_end,
                    description="FMC ALLOW rule exposes management ports to non-RFC1918 sources.",
                    construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                )
            )
    for bulk in config.access_rules_bulk:
        for rule in bulk.rules:
            resolution = config.rule_resolutions.get(rule_key(rule))
            if resolution is None:
                continue
            if is_management_exposure(rule, resolution.source):
                matches.append(
                    _match(
                        rule_id=rule_id,
                        cwe="CWE-284",
                        line_start=bulk.line_start,
                        line_end=bulk.line_end,
                        description=(
                            "FMC ALLOW rule in fmc_access_rules exposes management ports "
                            "to non-RFC1918 sources."
                        ),
                        construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                    )
                )
    return matches


def check_ftd_006(config: ParsedFtdConfig, *, rule_id: str = "FTD-006") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for bulk in config.access_rules_bulk:
        for index, rule in enumerate(bulk.rules):
            prior = bulk.rules[:index]
            if is_shadowed_allow_rule(rule, prior, config.rule_resolutions):
                matches.append(
                    _match(
                        rule_id=rule_id,
                        cwe="CWE-693",
                        line_start=rule.line_start,
                        line_end=rule.line_end,
                        description=(
                            "FMC ALLOW rule in fmc_access_rules is preceded by a "
                            "catch-all BLOCK rule in the same ordered set."
                        ),
                        construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                    )
                )
    return matches


def check_ftd_007(config: ParsedFtdConfig, *, rule_id: str = "FTD-007") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for rule in config.access_rules:
        if is_missing_intrusion_policy(rule):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-693",
                    line_start=rule.line_start,
                    line_end=rule.line_end,
                    description=(
                        "FMC ALLOW rule has no intrusion_policy_id (or legacy intrusion_policy) attached."
                    ),
                    construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                )
            )
    for bulk in config.access_rules_bulk:
        for rule in bulk.rules:
            if is_missing_intrusion_policy(rule):
                matches.append(
                    _match(
                        rule_id=rule_id,
                        cwe="CWE-693",
                        line_start=bulk.line_start,
                        line_end=bulk.line_end,
                        description=(
                            "FMC ALLOW rule in fmc_access_rules has no intrusion policy attached."
                        ),
                        construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                    )
                )
    return matches


def check_ftd_008(config: ParsedFtdConfig, *, rule_id: str = "FTD-008") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for rule in config.access_rules:
        for field, address in unresolved_network_object_refs(rule, config.network_symbols):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-754",
                    line_start=rule.line_start,
                    line_end=rule.line_end,
                    description=(
                        f"FMC access rule references undefined network object {address!r} "
                        f"in {field}."
                    ),
                    construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                )
            )
    for bulk in config.access_rules_bulk:
        for rule in bulk.rules:
            for field, address in unresolved_network_object_refs(rule, config.network_symbols):
                matches.append(
                    _match(
                        rule_id=rule_id,
                        cwe="CWE-754",
                        line_start=bulk.line_start,
                        line_end=bulk.line_end,
                        description=(
                            f"FMC access rule references undefined network object {address!r} "
                            f"in {field}."
                        ),
                        construct_key=construct.ftd_rule(rule.name, rule.sequence_index),
                    )
                )
    return matches


_RULE_CHECKS = {
    "FTD-001": check_ftd_001,
    "FTD-002": check_ftd_002,
    "FTD-003": check_ftd_003,
    "FTD-004": check_ftd_004,
    "FTD-005": check_ftd_005,
    "FTD-006": check_ftd_006,
    "FTD-007": check_ftd_007,
    "FTD-008": check_ftd_008,
}


def match_ftd_rule(
    *,
    chunk_content: str,
    line_offset: int = 0,
    rule_id: str,
) -> list[ConfigRuleMatch]:
    checker = _RULE_CHECKS.get(rule_id)
    if checker is None:
        return []
    config = parse_ftd_fmc_config(chunk_content)
    matches = checker(config, rule_id=rule_id)
    return [item.with_line_offset(line_offset) for item in matches]
