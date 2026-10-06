"""Structural parser for Cisco IOS-XE (Catalyst) CLI configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from shift_left.handlers.config.secret_values import SecretValueSet


class ConfigLineKind(str, Enum):
    GLOBAL = "global"
    LINE = "line"
    INTERFACE = "interface"
    AAA = "aaa"
    SNMP = "snmp"
    MANAGEMENT = "management"
    ACL = "acl"
    OBJECT_GROUP = "object-group"
    OTHER = "other"


@dataclass(frozen=True)
class GroupMember:
    kind: str
    ref: str | None = None
    value: str | None = None
    port: str | None = None


@dataclass(frozen=True)
class NetworkObjectGroup:
    name: str
    line_start: int
    line_end: int
    members: tuple[GroupMember, ...]


@dataclass(frozen=True)
class ServiceObjectGroup:
    name: str
    line_start: int
    line_end: int
    members: tuple[GroupMember, ...]


@dataclass(frozen=True)
class UnparsedConfigLine:
    line_no: int
    raw: str
    category: str


@dataclass(frozen=True)
class UnresolvedReference:
    line_no: int
    ref_name: str
    ref_kind: str
    raw: str


@dataclass(frozen=True)
class AccessListEntry:
    acl_name: str
    acl_kind: str
    action: str
    protocol: str
    line_no: int
    raw: str
    source_kind: str
    source: str
    destination_kind: str
    destination: str
    service_ref: str | None = None
    service_group_ref: str | None = None


@dataclass(frozen=True)
class GlobalSetting:
    line_no: int
    raw: str


@dataclass(frozen=True)
class LineBlock:
    line_type: str
    line_start: int
    line_end: int
    body_lines: tuple[str, ...]
    transport_input: tuple[str, ...] = ()
    access_class_in: str | None = None
    access_class_out: str | None = None


@dataclass(frozen=True)
class InterfaceBlock:
    name: str
    line_start: int
    line_end: int
    mode: str | None
    trunk_allowed: str | None
    access_vlan: str | None
    shutdown: bool
    body_lines: tuple[str, ...]
    trunk_native_vlan: str | None = None
    dtp_mode: str | None = None
    bpdu_guard: bool = False
    port_security: bool = False


@dataclass(frozen=True)
class SnmpCommunity:
    community: str
    access: str
    line_no: int
    raw: str


@dataclass(frozen=True)
class AaaConfig:
    line_start: int
    line_end: int
    body_lines: tuple[str, ...]


@dataclass(frozen=True)
class SnmpConfig:
    line_start: int
    line_end: int
    body_lines: tuple[str, ...]


@dataclass(frozen=True)
class ManagementService:
    service: str
    line_no: int
    raw: str


@dataclass
class ParsedIosXeConfig:
    global_settings: list[GlobalSetting] = field(default_factory=list)
    line_blocks: list[LineBlock] = field(default_factory=list)
    interface_blocks: list[InterfaceBlock] = field(default_factory=list)
    aaa_config: AaaConfig | None = None
    snmp_config: SnmpConfig | None = None
    management_services: list[ManagementService] = field(default_factory=list)
    network_object_groups: list[NetworkObjectGroup] = field(default_factory=list)
    service_object_groups: list[ServiceObjectGroup] = field(default_factory=list)
    access_list_entries: list[AccessListEntry] = field(default_factory=list)
    snmp_communities: list[SnmpCommunity] = field(default_factory=list)
    unparsed_lines: list[UnparsedConfigLine] = field(default_factory=list)
    unresolved_references: list[UnresolvedReference] = field(default_factory=list)
    ace_resolutions: dict = field(default_factory=dict)
    password_encryption_disabled: bool = False
    password_encryption_line_no: int | None = None
    http_server_enabled: bool = False
    http_server_line_no: int | None = None
    aaa_new_model: bool = False
    aaa_login_authenticated: bool = False
    enable_secret_configured: bool = False
    enable_password_weak: bool = False
    enable_password_line_no: int | None = None
    secret_values: SecretValueSet = field(default_factory=SecretValueSet.empty)


def _strip_comment(line: str) -> str:
    if "!" in line:
        line = line.split("!", 1)[0]
    return line.strip()


def _continuation_lines(lines: list[str], start_index: int) -> tuple[tuple[str, ...], int]:
    collected: list[str] = []
    index = start_index
    while index < len(lines):
        raw = lines[index]
        if not raw.strip():
            index += 1
            continue
        if not raw.startswith((" ", "\t")):
            break
        collected.append(raw.strip())
        index += 1
    return tuple(collected), index


def _is_acl_bearing_line(line: str) -> bool:
    lowered = line.lower()
    return lowered.startswith("access-list ") or lowered.startswith("ip access-list ")


def count_evaluable_cli_lines(content: str) -> int:
    """ACL-bearing lines the IOS-XE parser attempts to tokenize."""
    config = parse_ios_xe_config(content)
    unparsed_acl = sum(1 for item in config.unparsed_lines if item.category == "acl")
    return len(config.access_list_entries) + unparsed_acl


def cli_parse_coverage(content: str) -> tuple[int, int]:
    """Return (parsed_acl_entries, evaluable_acl_bearing_lines) for IOS-XE configs."""
    config = parse_ios_xe_config(content)
    parsed = len(config.access_list_entries)
    total = count_evaluable_cli_lines(content)
    return parsed, total


def _parse_network_group_member(line: str) -> GroupMember | None:
    tokens = line.split()
    if not tokens:
        return None
    if tokens[0] == "group-object" and len(tokens) >= 2:
        return GroupMember(kind="group-object", ref=tokens[1])
    if tokens[0] == "network-object":
        if len(tokens) >= 2 and tokens[1].lower() == "host" and len(tokens) >= 3:
            return GroupMember(kind="network-object", value=f"host:{tokens[2]}")
        if len(tokens) >= 3:
            return GroupMember(kind="network-object", value=f"net:{tokens[1]}/{tokens[2]}")
    return None


def _parse_service_group_member(line: str) -> GroupMember | None:
    tokens = line.split()
    if not tokens:
        return None
    if tokens[0] == "group-object" and len(tokens) >= 2:
        return GroupMember(kind="group-object", ref=tokens[1])
    if tokens[0] == "tcp" and len(tokens) >= 3 and tokens[1] == "eq":
        return GroupMember(kind="service-object", ref="tcp", port=tokens[2])
    if tokens[0] == "udp" and len(tokens) >= 3 and tokens[1] == "eq":
        return GroupMember(kind="service-object", ref="udp", port=tokens[2])
    return None


def _parse_group_members(body_lines: tuple[str, ...], *, parser) -> tuple[GroupMember, ...]:
    members: list[GroupMember] = []
    for line in body_lines:
        member = parser(line)
        if member is not None:
            members.append(member)
    return tuple(members)


def _parse_endpoint(tokens: list[str], index: int) -> tuple[str, str, int] | None:
    if index >= len(tokens):
        return None
    token = tokens[index].lower()
    if token == "any":
        return "literal", "any", index + 1
    if token == "host":
        if index + 1 >= len(tokens):
            return None
        return "literal", f"host:{tokens[index + 1]}", index + 2
    if token == "object-group":
        if index + 1 >= len(tokens):
            return None
        return "object-group", tokens[index + 1], index + 2
    if index + 1 >= len(tokens):
        return None
    return "literal", f"net:{tokens[index]}/{tokens[index + 1]}", index + 2


def _parse_numbered_acl(line: str, line_no: int) -> AccessListEntry | None:
    tokens = line.split()
    if len(tokens) < 4 or tokens[0] != "access-list":
        return None
    acl_name = tokens[1]
    action = tokens[2].lower()
    if action not in {"permit", "deny"}:
        return None

    if len(tokens) == 5 and tokens[3].count(".") == 3:
        return AccessListEntry(
            acl_name=acl_name,
            acl_kind="standard-numbered",
            action=action,
            protocol="ip",
            line_no=line_no,
            raw=line,
            source_kind="literal",
            source=f"net:{tokens[3]}/{tokens[4]}",
            destination_kind="literal",
            destination="any",
        )

    if len(tokens) < 6:
        return None
    protocol = tokens[3].lower()
    index = 4
    service_ref = None
    service_group_ref = None
    if protocol == "object-group":
        if index >= len(tokens):
            return None
        service_group_ref = tokens[index]
        index += 1
    source = _parse_endpoint(tokens, index)
    if source is None:
        return None
    source_kind, source_value, index = source
    destination = _parse_endpoint(tokens, index)
    if destination is None:
        return None
    destination_kind, destination_value, _index = destination
    return AccessListEntry(
        acl_name=acl_name,
        acl_kind="extended-numbered",
        action=action,
        protocol=protocol,
        line_no=line_no,
        raw=line,
        source_kind=source_kind,
        source=source_value,
        destination_kind=destination_kind,
        destination=destination_value,
        service_ref=service_ref,
        service_group_ref=service_group_ref,
    )


def _parse_named_ace(line: str, line_no: int, acl_name: str, acl_kind: str) -> AccessListEntry | None:
    tokens = line.split()
    if len(tokens) < 2:
        return None
    offset = 0
    if tokens[0].isdigit():
        offset = 1
    if offset >= len(tokens):
        return None
    action = tokens[offset].lower()
    if action not in {"permit", "deny"}:
        return None
    if acl_kind == "standard-named":
        if len(tokens) == offset + 2 and tokens[offset + 1].lower() == "any":
            return AccessListEntry(
                acl_name=acl_name,
                acl_kind=acl_kind,
                action=action,
                protocol="ip",
                line_no=line_no,
                raw=line,
                source_kind="literal",
                source="any",
                destination_kind="literal",
                destination="any",
            )
        if len(tokens) == offset + 3:
            return AccessListEntry(
                acl_name=acl_name,
                acl_kind=acl_kind,
                action=action,
                protocol="ip",
                line_no=line_no,
                raw=line,
                source_kind="literal",
                source=f"net:{tokens[offset + 1]}/{tokens[offset + 2]}",
                destination_kind="literal",
                destination="any",
            )
        if len(tokens) < offset + 3:
            return None
        return None
    if len(tokens) < offset + 4:
        return None
    protocol = tokens[offset + 1].lower()
    index = offset + 2
    source = _parse_endpoint(tokens, index)
    if source is None:
        return None
    source_kind, source_value, index = source
    destination = _parse_endpoint(tokens, index)
    if destination is None:
        return None
    destination_kind, destination_value, _index = destination
    return AccessListEntry(
        acl_name=acl_name,
        acl_kind=acl_kind,
        action=action,
        protocol=protocol,
        line_no=line_no,
        raw=line,
        source_kind=source_kind,
        source=source_value,
        destination_kind=destination_kind,
        destination=destination_value,
    )


def _parse_line_block(line_type: str, line_no: int, body: tuple[str, ...]) -> LineBlock:
    transport: list[str] = []
    access_in: str | None = None
    access_out: str | None = None
    for line in body:
        tokens = line.split()
        if len(tokens) >= 3 and tokens[0] == "transport" and tokens[1] == "input":
            transport = [token.lower() for token in tokens[2:]]
        if len(tokens) >= 3 and tokens[0] == "access-class":
            direction = tokens[-1].lower()
            name = tokens[1]
            if direction == "in":
                access_in = name
            elif direction == "out":
                access_out = name
    return LineBlock(
        line_type=line_type,
        line_start=line_no,
        line_end=line_no + len(body),
        body_lines=body,
        transport_input=tuple(transport),
        access_class_in=access_in,
        access_class_out=access_out,
    )


def _parse_interface_block(name: str, line_no: int, body: tuple[str, ...]) -> InterfaceBlock:
    mode = None
    trunk_allowed = None
    access_vlan = None
    shutdown = False
    trunk_native_vlan = None
    dtp_mode = None
    bpdu_guard = False
    port_security = False
    for line in body:
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0] == "shutdown":
            shutdown = True
        if len(tokens) >= 3 and tokens[0] == "switchport" and tokens[1] == "mode":
            mode = tokens[2]
        if len(tokens) >= 4 and tokens[0] == "switchport" and tokens[1] == "trunk" and tokens[2] == "allowed":
            trunk_allowed = " ".join(tokens[3:])
        if len(tokens) >= 5 and tokens[0] == "switchport" and tokens[1] == "trunk" and tokens[2] == "native":
            trunk_native_vlan = tokens[4]
        if len(tokens) >= 4 and tokens[0] == "switchport" and tokens[1] == "access" and tokens[2] == "vlan":
            access_vlan = tokens[3]
        if len(tokens) >= 3 and tokens[0] == "switchport" and tokens[1] == "nonegotiate":
            dtp_mode = "none"
        if len(tokens) >= 4 and tokens[0] == "switchport" and tokens[1] == "mode" and tokens[2] == "dynamic":
            dtp_mode = tokens[3].lower()
        if line.startswith("spanning-tree bpduguard enable"):
            bpdu_guard = True
        if tokens[0] == "switchport" and tokens[1] == "port-security":
            port_security = True
    return InterfaceBlock(
        name=name,
        line_start=line_no,
        line_end=line_no + len(body),
        mode=mode,
        trunk_allowed=trunk_allowed,
        access_vlan=access_vlan,
        shutdown=shutdown,
        body_lines=body,
        trunk_native_vlan=trunk_native_vlan,
        dtp_mode=dtp_mode,
        bpdu_guard=bpdu_guard,
        port_security=port_security,
    )


def _parse_snmp_community(line: str, line_no: int) -> SnmpCommunity | None:
    tokens = line.split()
    if len(tokens) < 4 or tokens[0] != "snmp-server" or tokens[1] != "community":
        return None
    return SnmpCommunity(
        community=tokens[2],
        access=tokens[3].upper(),
        line_no=line_no,
        raw=line,
    )


def _apply_global_security_line(parsed: ParsedIosXeConfig, line: str, line_no: int) -> bool:
    lowered = line.lower()
    if lowered == "no service password-encryption":
        parsed.password_encryption_disabled = True
        parsed.password_encryption_line_no = line_no
        return True
    if lowered.startswith("service password-encryption"):
        parsed.password_encryption_disabled = False
        parsed.password_encryption_line_no = None
        return True
    if lowered.startswith("ip http server") and not lowered.startswith("no ip http server"):
        parsed.http_server_enabled = True
        parsed.http_server_line_no = line_no
        return True
    if lowered.startswith("no ip http server"):
        parsed.http_server_enabled = False
        parsed.http_server_line_no = None
        return True
    if lowered.startswith("enable secret"):
        parsed.enable_secret_configured = True
        return True
    if lowered.startswith("enable password"):
        parsed.enable_password_weak = True
        parsed.enable_password_line_no = line_no
        return True
    community = _parse_snmp_community(line, line_no)
    if community is not None:
        parsed.snmp_communities.append(community)
        return True
    return False


def _finalize_aaa(parsed: ParsedIosXeConfig) -> None:
    if parsed.aaa_config is None:
        return
    for line in parsed.aaa_config.body_lines:
        lowered = line.lower()
        if lowered.startswith("aaa new-model"):
            parsed.aaa_new_model = True
        if lowered.startswith("aaa authentication login"):
            parsed.aaa_login_authenticated = True


def _record_unresolved(
    parsed: ParsedIosXeConfig,
    *,
    line_no: int,
    ref_name: str,
    ref_kind: str,
    raw: str,
) -> None:
    parsed.unresolved_references.append(
        UnresolvedReference(
            line_no=line_no,
            ref_name=ref_name,
            ref_kind=ref_kind,
            raw=raw,
        )
    )


def _finalize_resolutions(parsed: ParsedIosXeConfig) -> None:
    from shift_left.handlers.config.parsers.ios_xe.resolver import resolve_ios_xe_config

    resolved = resolve_ios_xe_config(parsed)
    parsed.ace_resolutions = resolved.ace_resolutions
    for item in resolved.unresolved_references:
        if item not in parsed.unresolved_references:
            parsed.unresolved_references.append(item)


def parse_ios_xe_config(content: str) -> ParsedIosXeConfig:
    lines = content.splitlines()
    parsed = ParsedIosXeConfig()
    index = 0
    active_acl: tuple[str, str] | None = None
    aaa_lines: list[str] = []
    aaa_start: int | None = None
    snmp_lines: list[str] = []
    snmp_start: int | None = None

    while index < len(lines):
        raw = lines[index]
        line_no = index + 1
        line = _strip_comment(raw)
        if not line:
            index += 1
            continue

        if active_acl is not None:
            stripped_raw = raw.rstrip()
            is_ace_continuation = stripped_raw.startswith((" ", "\t")) or (
                bool(line) and line[0].isdigit()
            )
            if not is_ace_continuation:
                active_acl = None
            else:
                acl_name, acl_kind = active_acl
                entry = _parse_named_ace(line, line_no, acl_name, acl_kind)
                if entry is not None:
                    parsed.access_list_entries.append(entry)
                else:
                    parsed.unparsed_lines.append(
                        UnparsedConfigLine(line_no=line_no, raw=line, category="acl")
                    )
                index += 1
                continue

        if line.startswith("ip access-list "):
            parts = line.split()
            if len(parts) >= 4:
                acl_kind = f"{parts[2]}-named"
                active_acl = (parts[3], acl_kind)
            else:
                parsed.unparsed_lines.append(
                    UnparsedConfigLine(line_no=line_no, raw=line, category="acl")
                )
            index += 1
            continue

        if line.startswith("access-list "):
            entry = _parse_numbered_acl(line, line_no)
            if entry is not None:
                parsed.access_list_entries.append(entry)
            else:
                parsed.unparsed_lines.append(
                    UnparsedConfigLine(line_no=line_no, raw=line, category="acl")
                )
            index += 1
            continue

        if line.startswith("object-group network "):
            parts = line.split()
            name = parts[2] if len(parts) >= 3 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.network_object_groups.append(
                NetworkObjectGroup(
                    name=name,
                    line_start=line_no,
                    line_end=next_index if body else line_no,
                    members=_parse_group_members(body, parser=_parse_network_group_member),
                )
            )
            index = next_index
            continue

        if line.startswith("object-group service "):
            parts = line.split()
            name = parts[2] if len(parts) >= 3 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.service_object_groups.append(
                ServiceObjectGroup(
                    name=name,
                    line_start=line_no,
                    line_end=next_index if body else line_no,
                    members=_parse_group_members(body, parser=_parse_service_group_member),
                )
            )
            index = next_index
            continue

        if line.startswith("interface "):
            parts = line.split(maxsplit=1)
            name = parts[1] if len(parts) > 1 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.interface_blocks.append(_parse_interface_block(name, line_no, body))
            index = next_index
            continue

        if line.startswith("line "):
            parts = line.split()
            line_type = " ".join(parts[1:]) if len(parts) > 1 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.line_blocks.append(_parse_line_block(line_type, line_no, body))
            index = next_index
            continue

        if line.startswith("aaa "):
            if aaa_start is None:
                aaa_start = line_no
            aaa_lines.append(line)
            index += 1
            continue

        if line.startswith("snmp-server "):
            if snmp_start is None:
                snmp_start = line_no
            snmp_lines.append(line)
            community = _parse_snmp_community(line, line_no)
            if community is not None:
                parsed.snmp_communities.append(community)
            index += 1
            continue

        if _apply_global_security_line(parsed, line, line_no):
            index += 1
            continue

        lowered = line.lower()
        if lowered.startswith(("ip ssh ", "ip http ", "ip https ", "transport input ")):
            parsed.management_services.append(
                ManagementService(service=line.split()[1], line_no=line_no, raw=line)
            )
            index += 1
            continue

        if _is_acl_bearing_line(line):
            parsed.unparsed_lines.append(
                UnparsedConfigLine(line_no=line_no, raw=line, category="acl")
            )
            index += 1
            continue

        parsed.global_settings.append(GlobalSetting(line_no=line_no, raw=line))
        index += 1

    if aaa_start is not None:
        parsed.aaa_config = AaaConfig(
            line_start=aaa_start,
            line_end=aaa_start + len(aaa_lines) - 1,
            body_lines=tuple(aaa_lines),
        )
    if snmp_start is not None:
        parsed.snmp_config = SnmpConfig(
            line_start=snmp_start,
            line_end=snmp_start + len(snmp_lines) - 1,
            body_lines=tuple(snmp_lines),
        )

    _finalize_aaa(parsed)
    _finalize_resolutions(parsed)
    from shift_left.handlers.config.secret_values import extract_secret_values_from_content

    parsed.secret_values = extract_secret_values_from_content(content)
    return parsed
