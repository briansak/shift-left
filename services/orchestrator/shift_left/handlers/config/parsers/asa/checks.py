"""ASA / FTD deterministic rule checks over parsed configuration."""

from __future__ import annotations

from shift_left.handlers.config.parsers.asa.parser import (
    ParsedAsaConfig,
    is_permissive_service_object,
    is_weak_crypto_block,
    management_allows_non_rfc1918,
    parse_asa_config,
)
from shift_left.handlers.config.parsers.asa.resolver import (
    _resolve_service_name,
    is_resolved_permissive_ace,
    is_resolved_shadowed_permit,
    is_unresolvable_ace,
)
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


def _ace_resolutions(config: ParsedAsaConfig):
    return config.ace_resolutions


def check_asa_001(config: ParsedAsaConfig, *, rule_id: str = "ASA-001") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    ace_resolutions = _ace_resolutions(config)
    for entry in config.access_list_entries:
        ace = ace_resolutions.get(entry.line_no)
        if ace is None:
            continue
        if is_resolved_permissive_ace(ace, entry):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-284",
                    line_start=entry.line_no,
                    line_end=entry.line_no,
                    description="ASA ACL permit ACE allows any source to any destination.",
                    construct_key=construct.ace(entry.acl_name, entry.raw),
                )
            )
    return matches


def check_asa_002(config: ParsedAsaConfig, *, rule_id: str = "ASA-002") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    services = {item.name: item for item in config.service_objects}
    service_groups = {item.name: item for item in config.service_object_groups}
    for obj in config.service_objects:
        if is_permissive_service_object(obj):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-284",
                    line_start=obj.line_start,
                    line_end=obj.line_end,
                    description="Service object permits any protocol or unconstrained TCP/UDP.",
                    construct_key=construct.named_object(obj.name),
                )
            )
    for group in config.service_object_groups:
        result = _resolve_service_name(
            group.name,
            services=services,
            service_groups=service_groups,
            stack=(),
            depth=0,
        )
        if result.is_permissive and result.failure is None:
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-284",
                    line_start=group.line_start,
                    line_end=group.line_end,
                    description="Service object-group permits any protocol or unconstrained TCP/UDP.",
                    construct_key=construct.named_object(group.name),
                )
            )
    return matches


def check_asa_003(config: ParsedAsaConfig, *, rule_id: str = "ASA-003") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for entry in config.access_list_entries:
        if entry.action == "permit" and not entry.has_log:
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-778",
                    line_start=entry.line_no,
                    line_end=entry.line_no,
                    description="Permit ACE does not include the log keyword.",
                    construct_key=construct.ace(entry.acl_name, entry.raw),
                )
            )
    return matches


def check_asa_004(config: ParsedAsaConfig, *, rule_id: str = "ASA-004") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for block in config.crypto_blocks:
        if is_weak_crypto_block(block):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-327",
                    line_start=block.line_start,
                    line_end=block.line_end,
                    description="IKEv2/IPsec proposal uses weak encryption, integrity, or DH group < 14.",
                    construct_key=construct.crypto(block.kind, block.name),
                )
            )
    return matches


def check_asa_005(config: ParsedAsaConfig, *, rule_id: str = "ASA-005") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for entry in config.management_access:
        if management_allows_non_rfc1918(entry):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-284",
                    line_start=entry.line_no,
                    line_end=entry.line_no,
                    description=(
                        f"Management service {entry.service} is permitted from a non-RFC1918 source."
                    ),
                    construct_key=construct.management(
                        entry.service, entry.network, entry.mask, entry.interface
                    ),
                )
            )
    return matches


def check_asa_006(config: ParsedAsaConfig, *, rule_id: str = "ASA-006") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    ace_resolutions = _ace_resolutions(config)
    for entry in config.access_list_entries:
        if is_resolved_shadowed_permit(
            config.access_list_entries,
            ace_resolutions,
            entry,
        ):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-693",
                    line_start=entry.line_no,
                    line_end=entry.line_no,
                    description="Permit ACE is preceded by deny ip any any and will never match.",
                    construct_key=construct.ace(entry.acl_name, entry.raw),
                )
            )
    return matches


def check_asa_007(config: ParsedAsaConfig, *, rule_id: str = "ASA-007") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for line in config.unparsed_access_list_lines:
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-754",
                line_start=line.line_no,
                line_end=line.line_no,
                description="ASA access-list statement is not representable by the structural parser.",
                construct_key=construct.unparsed(line.raw),
            )
        )
    ace_resolutions = _ace_resolutions(config)
    for entry in config.access_list_entries:
        ace = ace_resolutions.get(entry.line_no)
        if ace is None or not is_unresolvable_ace(ace):
            continue
        reason = (
            ace.source.failure
            or ace.destination.failure
            or (ace.service.failure if ace.service else None)
        )
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-754",
                line_start=entry.line_no,
                line_end=entry.line_no,
                description=(
                    "ASA access-list ACE references an object or object-group that could not be resolved "
                    f"({reason.value if reason else 'unresolvable'})."
                ),
                construct_key=construct.ace(entry.acl_name, entry.raw),
            )
        )
    return matches


_RULE_CHECKS = {
    "ASA-001": check_asa_001,
    "ASA-002": check_asa_002,
    "ASA-003": check_asa_003,
    "ASA-004": check_asa_004,
    "ASA-005": check_asa_005,
    "ASA-006": check_asa_006,
    "ASA-007": check_asa_007,
}


def match_asa_rule(
    *,
    chunk_content: str,
    line_offset: int = 0,
    rule_id: str,
) -> list[ConfigRuleMatch]:
    checker = _RULE_CHECKS.get(rule_id)
    if checker is None:
        return []
    config = parse_asa_config(chunk_content)
    matches = checker(config, rule_id=rule_id)
    return [item.with_line_offset(line_offset) for item in matches]
