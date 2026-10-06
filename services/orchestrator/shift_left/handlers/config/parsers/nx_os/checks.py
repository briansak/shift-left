"""NX-OS deterministic rule checks."""

from __future__ import annotations

from shift_left.handlers.config.parsers.nx_os.network import (
    allows_non_rfc1918,
    is_resolved_permissive_ace_nx,
)
from shift_left.handlers.config.parsers.nx_os.parser import ParsedNxOsConfig, parse_nx_os_config
from shift_left.handlers.config.parsers.nx_os.platform import platform_mismatch_line
from shift_left.handlers.config.types import ConfigRuleMatch
from shift_left.policy import construct_key as construct

_WEAK_SNMP_COMMUNITIES = frozenset({"public", "private"})
_UNENCRYPTED_TRANSFER_FEATURES = frozenset({"ftp", "tftp", "scp-server"})
_MANAGEMENT_VRF_NAME = "management"


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


def _feature_enabled(parsed: ParsedNxOsConfig, feature: str) -> bool:
    state: dict[str, bool] = {}
    for item in parsed.feature_declarations:
        state[item.feature.lower()] = item.enabled
    return state.get(feature.lower(), False)


def _vty_blocks(parsed: ParsedNxOsConfig):
    return [block for block in parsed.line_blocks if "vty" in block.line_type.lower()]


def _acl_entries(parsed: ParsedNxOsConfig, acl_name: str):
    return [entry for entry in parsed.access_list_entries if entry.acl_name == acl_name]


def _has_management_vrf(parsed: ParsedNxOsConfig) -> bool:
    return any(vrf.name.lower() == _MANAGEMENT_VRF_NAME for vrf in parsed.vrf_contexts)


def check_nxos_001(
    parsed: ParsedNxOsConfig,
    *,
    content: str,
    declared_target_type: str,
    rule_id: str = "NXOS-001",
) -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for item in parsed.unparsed_lines:
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-754",
                line_start=item.line_no,
                line_end=item.line_no,
                description=f"unparsed NX-OS config line ({item.category})",
                construct_key=construct.unparsed(item.raw),
            )
        )
    for item in parsed.unresolved_references:
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-754",
                line_start=item.line_no,
                line_end=item.line_no,
                description=f"unresolved {item.ref_kind} reference: {item.ref_name}",
                construct_key=construct.unresolved(item.ref_kind, item.ref_name),
            )
        )
    return matches


def check_nxos_002(
    parsed: ParsedNxOsConfig,
    *,
    content: str,
    declared_target_type: str,
    rule_id: str = "NXOS-002",
) -> list[ConfigRuleMatch]:
    mismatch = platform_mismatch_line(
        declared_target_type=declared_target_type,
        content=content,
    )
    if mismatch is None:
        return []
    return [
        _match(
            rule_id=rule_id,
            cwe="CWE-754",
            line_start=1,
            line_end=1,
            description=mismatch,
            construct_key=construct.file_scope(),
        )
    ]


def check_nxos_003(parsed: ParsedNxOsConfig, *, rule_id: str = "NXOS-003") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    if not _feature_enabled(parsed, "telnet"):
        return matches
    for item in parsed.feature_declarations:
        if item.feature.lower() == "telnet" and item.enabled:
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-319",
                    line_start=item.line_no,
                    line_end=item.line_no,
                    description="Cleartext telnet feature is enabled on the management plane.",
                    construct_key=construct.feature(item.feature),
                )
            )
            break
    return matches


def check_nxos_004(parsed: ParsedNxOsConfig, *, rule_id: str = "NXOS-004") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    ssh_enabled = _feature_enabled(parsed, "ssh")
    if ssh_enabled:
        return matches
    for item in parsed.feature_declarations:
        if item.feature.lower() == "ssh" and not item.enabled:
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-287",
                    line_start=item.line_no,
                    line_end=item.line_no,
                    description="SSH feature is explicitly disabled (no feature ssh).",
                    construct_key=construct.feature(item.feature),
                )
            )
            return matches
    if not _vty_blocks(parsed):
        return matches
    matches.append(
        _match(
            rule_id=rule_id,
            cwe="CWE-287",
            line_start=_vty_blocks(parsed)[0].line_start,
            line_end=_vty_blocks(parsed)[0].line_start,
            description="VTY lines are configured but SSH feature is not enabled.",
            construct_key=construct.feature("ssh"),
        )
    )
    return matches


def check_nxos_005(parsed: ParsedNxOsConfig, *, rule_id: str = "NXOS-005") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for community in parsed.snmp_communities:
        if community.community.lower() in _WEAK_SNMP_COMMUNITIES:
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-284",
                    line_start=community.line_no,
                    line_end=community.line_no,
                    description=(
                        f"SNMP community '{community.community}' is a well-known default credential."
                    ),
                    construct_key=construct.directive(community.raw),
                )
            )
            continue
        if community.access == "RW":
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-284",
                    line_start=community.line_no,
                    line_end=community.line_no,
                    description="SNMP community grants read-write access.",
                    construct_key=construct.directive(community.raw),
                )
            )
    return matches


def check_nxos_006(parsed: ParsedNxOsConfig, *, rule_id: str = "NXOS-006") -> list[ConfigRuleMatch]:
    if not _vty_blocks(parsed):
        return []
    if parsed.aaa_login_authenticated:
        return []
    line_no = parsed.aaa_config.line_start if parsed.aaa_config else _vty_blocks(parsed)[0].line_start
    return [
        _match(
            rule_id=rule_id,
            cwe="CWE-287",
            line_start=line_no,
            line_end=line_no,
            description="AAA login authentication is not configured for VTY access.",
            construct_key=construct.directive("aaa authentication login"),
        )
    ]


def check_nxos_007(parsed: ParsedNxOsConfig, *, rule_id: str = "NXOS-007") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for role in parsed.role_definitions:
        for rule_no, action, remainder in role.rules:
            if action != "permit":
                continue
            lowered = remainder.lower()
            if lowered == "command *" or lowered.endswith(" command *"):
                matches.append(
                    _match(
                        rule_id=rule_id,
                        cwe="CWE-284",
                        line_start=role.line_start,
                        line_end=role.line_start,
                        description=(
                            f"Role '{role.name}' grants broad permit command * privilege."
                        ),
                        construct_key=construct.role(role.name),
                    )
                )
                break
            if role.name.lower() == "network-admin" and lowered.startswith("command"):
                matches.append(
                    _match(
                        rule_id=rule_id,
                        cwe="CWE-284",
                        line_start=role.line_start,
                        line_end=role.line_start,
                        description=(
                            f"Role '{role.name}' defines network-admin command privileges."
                        ),
                        construct_key=construct.role(role.name),
                    )
                )
                break
    return matches


def check_nxos_008(parsed: ParsedNxOsConfig, *, rule_id: str = "NXOS-008") -> list[ConfigRuleMatch]:
    if not _has_management_vrf(parsed):
        return []
    matches: list[ConfigRuleMatch] = []
    for block in _vty_blocks(parsed):
        acl_name = block.access_class_in
        if acl_name is None:
            continue
        for entry in _acl_entries(parsed, acl_name):
            if entry.action != "permit":
                continue
            resolved = parsed.ace_resolutions.get(entry.line_no)
            if resolved is None or resolved.unresolved:
                continue
            if allows_non_rfc1918(resolved.source_values):
                matches.append(
                    _match(
                        rule_id=rule_id,
                        cwe="CWE-284",
                        line_start=entry.line_no,
                        line_end=entry.line_no,
                        description=(
                            f"Management VRF VTY access-class '{acl_name}' permits "
                            "non-RFC1918 sources."
                        ),
                        construct_key=construct.ace(entry.acl_name, entry.raw),
                    )
                )
    return matches


def check_nxos_009(parsed: ParsedNxOsConfig, *, rule_id: str = "NXOS-009") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for entry in parsed.access_list_entries:
        resolved = parsed.ace_resolutions.get(entry.line_no)
        if resolved is None:
            continue
        if is_resolved_permissive_ace_nx(resolved, entry):
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-284",
                    line_start=entry.line_no,
                    line_end=entry.line_no,
                    description="ACL permit ACE allows any resolved source to any resolved destination.",
                    construct_key=construct.ace(entry.acl_name, entry.raw),
                )
            )
    return matches


def check_nxos_010(parsed: ParsedNxOsConfig, *, rule_id: str = "NXOS-010") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for item in parsed.feature_declarations:
        if not item.enabled:
            continue
        if item.feature.lower() not in _UNENCRYPTED_TRANSFER_FEATURES:
            continue
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-319",
                line_start=item.line_no,
                line_end=item.line_no,
                description=f"Unencrypted file-transfer feature '{item.feature}' is enabled.",
                construct_key=construct.feature(item.feature),
            )
        )
    return matches


_RULE_CHECKS = {
    "NXOS-001": check_nxos_001,
    "NXOS-002": check_nxos_002,
    "NXOS-003": check_nxos_003,
    "NXOS-004": check_nxos_004,
    "NXOS-005": check_nxos_005,
    "NXOS-006": check_nxos_006,
    "NXOS-007": check_nxos_007,
    "NXOS-008": check_nxos_008,
    "NXOS-009": check_nxos_009,
    "NXOS-010": check_nxos_010,
}


def match_nx_os_rule(
    *,
    chunk_content: str,
    line_offset: int = 0,
    rule_id: str,
    declared_target_type: str = "cisco_nx_os",
) -> list[ConfigRuleMatch]:
    checker = _RULE_CHECKS.get(rule_id)
    if checker is None:
        return []
    parsed = parse_nx_os_config(chunk_content)
    if rule_id in {"NXOS-001", "NXOS-002"}:
        matches = checker(
            parsed,
            content=chunk_content,
            declared_target_type=declared_target_type,
            rule_id=rule_id,
        )
    else:
        matches = checker(parsed, rule_id=rule_id)
    return [item.with_line_offset(line_offset) for item in matches]
