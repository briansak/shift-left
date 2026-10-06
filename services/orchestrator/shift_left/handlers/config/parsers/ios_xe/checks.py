"""IOS-XE deterministic rule checks."""

from __future__ import annotations

from shift_left.handlers.config.parsers.ios_xe.network import (
    allows_non_rfc1918,
    is_resolved_permissive_ace,
)
from shift_left.handlers.config.parsers.ios_xe.parser import ParsedIosXeConfig, parse_ios_xe_config
from shift_left.handlers.config.parsers.ios_xe.platform import platform_mismatch_line
from shift_left.handlers.config.types import ConfigRuleMatch
from shift_left.policy import construct_key as construct

_WEAK_SNMP_COMMUNITIES = frozenset({"public", "private"})


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


def _vty_blocks(parsed: ParsedIosXeConfig):
    return [block for block in parsed.line_blocks if "vty" in block.line_type.lower()]


def _acl_entries(parsed: ParsedIosXeConfig, acl_name: str):
    return [entry for entry in parsed.access_list_entries if entry.acl_name == acl_name]


def check_ios_001(
    parsed: ParsedIosXeConfig,
    *,
    content: str,
    declared_target_type: str,
    rule_id: str = "IOS-001",
) -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for item in parsed.unparsed_lines:
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-754",
                line_start=item.line_no,
                line_end=item.line_no,
                description=f"unparsed IOS-XE config line ({item.category})",
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


def check_ios_010(
    parsed: ParsedIosXeConfig,
    *,
    content: str,
    declared_target_type: str,
    rule_id: str = "IOS-010",
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


def check_ios_002(parsed: ParsedIosXeConfig, *, rule_id: str = "IOS-002") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for block in _vty_blocks(parsed):
        if not block.transport_input:
            continue
        allows_telnet = "telnet" in block.transport_input or "all" in block.transport_input
        if allows_telnet:
            line_no = block.line_start
            for line in block.body_lines:
                if line.startswith("transport input"):
                    line_no = block.line_start + block.body_lines.index(line) + 1
                    break
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-319",
                    line_start=line_no,
                    line_end=line_no,
                    description="VTY line permits cleartext telnet transport.",
                    construct_key=construct.line_block(
                        block.line_type, "transport-input:" + " ".join(block.transport_input)
                    ),
                )
            )
    return matches


def check_ios_003(parsed: ParsedIosXeConfig, *, rule_id: str = "IOS-003") -> list[ConfigRuleMatch]:
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


def check_ios_004(parsed: ParsedIosXeConfig, *, rule_id: str = "IOS-004") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    if parsed.aaa_new_model and not parsed.aaa_login_authenticated:
        line_no = parsed.aaa_config.line_start if parsed.aaa_config else 1
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-287",
                line_start=line_no,
                line_end=line_no,
                description="AAA new-model is enabled without login authentication.",
                construct_key=construct.directive("aaa new-model"),
            )
        )
    if parsed.enable_password_weak and not parsed.enable_secret_configured:
        line_no = parsed.enable_password_line_no or 1
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-287",
                line_start=line_no,
                line_end=line_no,
                description="Enable password uses reversible type-7 encoding without enable secret.",
                construct_key=construct.directive("enable password"),
            )
        )
    return matches


def check_ios_005(parsed: ParsedIosXeConfig, *, rule_id: str = "IOS-005") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    if parsed.password_encryption_disabled:
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-319",
                line_start=parsed.password_encryption_line_no or 1,
                line_end=parsed.password_encryption_line_no or 1,
                description="Password encryption service is disabled.",
                construct_key=construct.directive("no service password-encryption"),
            )
        )
    if parsed.http_server_enabled:
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-319",
                line_start=parsed.http_server_line_no or 1,
                line_end=parsed.http_server_line_no or 1,
                description="Cleartext HTTP management server is enabled.",
                construct_key=construct.directive("ip http server"),
            )
        )
    return matches


def check_ios_006(parsed: ParsedIosXeConfig, *, rule_id: str = "IOS-006") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for entry in parsed.access_list_entries:
        resolved = parsed.ace_resolutions.get(entry.line_no)
        if resolved is None:
            continue
        if is_resolved_permissive_ace(resolved, entry):
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


def check_ios_007(parsed: ParsedIosXeConfig, *, rule_id: str = "IOS-007") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for iface in parsed.interface_blocks:
        if iface.shutdown:
            continue
        is_trunk = (
            iface.mode == "trunk"
            or iface.trunk_allowed is not None
            or iface.trunk_native_vlan is not None
            or iface.dtp_mode in {"auto", "desirable"}
        )
        if not is_trunk:
            continue
        if iface.trunk_native_vlan == "1":
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-693",
                    line_start=iface.line_start,
                    line_end=iface.line_start,
                    description="Trunk interface uses default native VLAN 1.",
                    construct_key=construct.interface(iface.name),
                )
            )
        if iface.dtp_mode in {"auto", "desirable"}:
            matches.append(
                _match(
                    rule_id=rule_id,
                    cwe="CWE-693",
                    line_start=iface.line_start,
                    line_end=iface.line_start,
                    description=f"Trunk interface negotiates DTP in {iface.dtp_mode} mode.",
                    construct_key=construct.interface(iface.name),
                )
            )
    return matches


def check_ios_008(parsed: ParsedIosXeConfig, *, rule_id: str = "IOS-008") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for block in _vty_blocks(parsed):
        acl_name = block.access_class_in or block.access_class_out
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
                            f"VTY access-class ACL '{acl_name}' permits non-RFC1918 sources."
                        ),
                        construct_key=construct.ace(entry.acl_name, entry.raw),
                    )
                )
    return matches


def check_ios_009(parsed: ParsedIosXeConfig, *, rule_id: str = "IOS-009") -> list[ConfigRuleMatch]:
    matches: list[ConfigRuleMatch] = []
    for iface in parsed.interface_blocks:
        if iface.shutdown:
            continue
        if iface.mode != "access":
            continue
        if iface.bpdu_guard or iface.port_security:
            continue
        matches.append(
            _match(
                rule_id=rule_id,
                cwe="CWE-693",
                line_start=iface.line_start,
                line_end=iface.line_start,
                description=(
                    "Access port lacks both BPDU guard and port-security hardening."
                ),
                construct_key=construct.interface(iface.name),
            )
        )
    return matches


_RULE_CHECKS = {
    "IOS-001": check_ios_001,
    "IOS-010": check_ios_010,
    "IOS-002": check_ios_002,
    "IOS-003": check_ios_003,
    "IOS-004": check_ios_004,
    "IOS-005": check_ios_005,
    "IOS-006": check_ios_006,
    "IOS-007": check_ios_007,
    "IOS-008": check_ios_008,
    "IOS-009": check_ios_009,
}


def match_ios_xe_rule(
    *,
    chunk_content: str,
    line_offset: int = 0,
    rule_id: str,
    declared_target_type: str = "cisco_ios_xe",
) -> list[ConfigRuleMatch]:
    checker = _RULE_CHECKS.get(rule_id)
    if checker is None:
        return []
    parsed = parse_ios_xe_config(chunk_content)
    if rule_id in {"IOS-001", "IOS-010"}:
        matches = checker(
            parsed,
            content=chunk_content,
            declared_target_type=declared_target_type,
            rule_id=rule_id,
        )
    else:
        matches = checker(parsed, rule_id=rule_id)
    return [item.with_line_offset(line_offset) for item in matches]
