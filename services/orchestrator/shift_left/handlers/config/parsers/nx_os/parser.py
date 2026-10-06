"""Structural parser for Cisco NX-OS CLI configuration."""

from __future__ import annotations

from dataclasses import dataclass, field

from shift_left.handlers.config.secret_values import SecretValueSet


@dataclass(frozen=True)
class GroupMember:
    kind: str
    ref: str | None = None
    value: str | None = None
    port: str | None = None


@dataclass(frozen=True)
class AddressObjectGroup:
    name: str
    line_start: int
    line_end: int
    members: tuple[GroupMember, ...]


@dataclass(frozen=True)
class PortObjectGroup:
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
    sequence: int | None
    action: str
    protocol: str
    line_no: int
    raw: str
    source_kind: str
    source: str
    destination_kind: str
    destination: str
    source_port_ref: str | None = None
    destination_port_ref: str | None = None
    port_group_ref: str | None = None


@dataclass(frozen=True)
class GlobalSetting:
    line_no: int
    raw: str


@dataclass(frozen=True)
class FeatureDeclaration:
    feature: str
    enabled: bool
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


@dataclass(frozen=True)
class RoleDefinition:
    name: str
    line_start: int
    line_end: int
    rules: tuple[tuple[int, str, str], ...]


@dataclass(frozen=True)
class VrfContext:
    name: str
    line_start: int
    line_end: int
    body_lines: tuple[str, ...]
    interfaces: tuple[str, ...] = ()


@dataclass(frozen=True)
class InterfaceBlock:
    name: str
    line_start: int
    line_end: int
    vrf: str | None
    shutdown: bool
    body_lines: tuple[str, ...]


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


@dataclass
class ParsedNxOsConfig:
    global_settings: list[GlobalSetting] = field(default_factory=list)
    feature_declarations: list[FeatureDeclaration] = field(default_factory=list)
    line_blocks: list[LineBlock] = field(default_factory=list)
    role_definitions: list[RoleDefinition] = field(default_factory=list)
    vrf_contexts: list[VrfContext] = field(default_factory=list)
    interface_blocks: list[InterfaceBlock] = field(default_factory=list)
    aaa_config: AaaConfig | None = None
    snmp_config: SnmpConfig | None = None
    address_object_groups: list[AddressObjectGroup] = field(default_factory=list)
    port_object_groups: list[PortObjectGroup] = field(default_factory=list)
    access_list_entries: list[AccessListEntry] = field(default_factory=list)
    snmp_communities: list[SnmpCommunity] = field(default_factory=list)
    unparsed_lines: list[UnparsedConfigLine] = field(default_factory=list)
    unresolved_references: list[UnresolvedReference] = field(default_factory=list)
    ace_resolutions: dict = field(default_factory=dict)
    aaa_login_authenticated: bool = False
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
    return lowered.startswith("ip access-list ") or lowered.startswith("access-list ")


def count_evaluable_cli_lines(content: str) -> int:
    """ACL-bearing lines the NX-OS parser attempts to tokenize."""
    config = parse_nx_os_config(content)
    unparsed_acl = sum(1 for item in config.unparsed_lines if item.category == "acl")
    return len(config.access_list_entries) + unparsed_acl


def cli_parse_coverage(content: str) -> tuple[int, int]:
    """Return (parsed_acl_entries, evaluable_acl_bearing_lines) for NX-OS configs."""
    config = parse_nx_os_config(content)
    parsed = len(config.access_list_entries)
    total = count_evaluable_cli_lines(content)
    return parsed, total


def _parse_address_group_member(line: str) -> GroupMember | None:
    tokens = line.split()
    if not tokens:
        return None
    offset = 1 if tokens[0].isdigit() else 0
    if offset >= len(tokens):
        return None
    kind = tokens[offset]
    if kind == "group-object" and len(tokens) >= offset + 2:
        return GroupMember(kind="group-object", ref=tokens[offset + 1])
    if kind == "host" and len(tokens) >= offset + 2:
        return GroupMember(kind="address", value=f"host:{tokens[offset + 1]}")
    if kind == "ip" and len(tokens) >= offset + 2:
        return GroupMember(kind="address", value=f"net:{tokens[offset + 1]}")
    return None


def _parse_port_group_member(line: str) -> GroupMember | None:
    tokens = line.split()
    if not tokens:
        return None
    offset = 1 if tokens[0].isdigit() else 0
    if offset >= len(tokens):
        return None
    kind = tokens[offset]
    if kind == "group-object" and len(tokens) >= offset + 2:
        return GroupMember(kind="group-object", ref=tokens[offset + 1])
    if kind == "eq" and len(tokens) >= offset + 2:
        return GroupMember(kind="port", port=tokens[offset + 1])
    if kind == "range" and len(tokens) >= offset + 3:
        return GroupMember(kind="port", port=f"{tokens[offset + 1]}-{tokens[offset + 2]}")
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
    if token == "addr" and index + 2 < len(tokens) and tokens[index + 1].lower() == "group":
        return "object-group", tokens[index + 2], index + 3
    if "/" in tokens[index]:
        return "literal", f"net:{tokens[index]}", index + 1
    if index + 1 < len(tokens) and tokens[index + 1].count(".") == 3:
        return "literal", f"net:{tokens[index]}/{tokens[index + 1]}", index + 2
    return None


def _skip_port_spec(tokens: list[str], index: int) -> int:
    if index >= len(tokens):
        return index
    token = tokens[index].lower()
    if token in {"eq", "lt", "gt", "neq"}:
        return index + 2 if index + 1 < len(tokens) else index + 1
    if token == "range" and index + 2 < len(tokens):
        return index + 3
    if token == "port" and index + 2 < len(tokens) and tokens[index + 1].lower() == "group":
        return index + 3
    return index


def _parse_acl_ace(line: str, line_no: int, acl_name: str) -> AccessListEntry | None:
    tokens = line.split()
    if len(tokens) < 4:
        return None
    offset = 0
    sequence: int | None = None
    if tokens[0].isdigit():
        sequence = int(tokens[0])
        offset = 1
    if offset >= len(tokens):
        return None
    action = tokens[offset].lower()
    if action not in {"permit", "deny"}:
        return None
    if offset + 1 >= len(tokens):
        return None
    protocol = tokens[offset + 1].lower()
    index = offset + 2
    port_group_ref: str | None = None
    source_port_ref: str | None = None
    destination_port_ref: str | None = None

    source = _parse_endpoint(tokens, index)
    if source is None:
        return None
    source_kind, source_value, index = source

    if index < len(tokens) and tokens[index].lower() in {"eq", "lt", "gt", "neq", "range"}:
        if tokens[index].lower() == "eq" and index + 1 < len(tokens):
            source_port_ref = tokens[index + 1]
        index = _skip_port_spec(tokens, index)
    elif (
        index + 2 < len(tokens)
        and tokens[index].lower() == "port"
        and tokens[index + 1].lower() == "group"
    ):
        port_group_ref = tokens[index + 2]
        index += 3

    destination = _parse_endpoint(tokens, index)
    if destination is None:
        return None
    destination_kind, destination_value, index = destination

    if index < len(tokens) and tokens[index].lower() in {"eq", "lt", "gt", "neq", "range"}:
        if tokens[index].lower() == "eq" and index + 1 < len(tokens):
            destination_port_ref = tokens[index + 1]
        _skip_port_spec(tokens, index)

    return AccessListEntry(
        acl_name=acl_name,
        acl_kind="named",
        sequence=sequence,
        action=action,
        protocol=protocol,
        line_no=line_no,
        raw=line,
        source_kind=source_kind,
        source=source_value,
        destination_kind=destination_kind,
        destination=destination_value,
        source_port_ref=source_port_ref,
        destination_port_ref=destination_port_ref,
        port_group_ref=port_group_ref,
    )


def _parse_line_block(line_type: str, line_no: int, body: tuple[str, ...]) -> LineBlock:
    transport: list[str] = []
    access_in: str | None = None
    for line in body:
        tokens = line.split()
        if len(tokens) >= 3 and tokens[0] == "transport" and tokens[1] == "input":
            transport = [token.lower() for token in tokens[2:]]
        if len(tokens) >= 3 and tokens[0] == "access-class":
            direction = tokens[-1].lower()
            if direction == "in":
                access_in = tokens[1]
    return LineBlock(
        line_type=line_type,
        line_start=line_no,
        line_end=line_no + len(body),
        body_lines=body,
        transport_input=tuple(transport),
        access_class_in=access_in,
    )


def _parse_interface_block(
    name: str,
    line_no: int,
    body: tuple[str, ...],
    *,
    vrf: str | None = None,
) -> InterfaceBlock:
    shutdown = False
    for line in body:
        if line.split()[0:1] == ["shutdown"]:
            shutdown = True
    return InterfaceBlock(
        name=name,
        line_start=line_no,
        line_end=line_no + len(body),
        vrf=vrf,
        shutdown=shutdown,
        body_lines=body,
    )


def _parse_vrf_context(name: str, line_no: int, body: tuple[str, ...]) -> VrfContext:
    interfaces: list[str] = []
    for line in body:
        tokens = line.split()
        if len(tokens) >= 2 and tokens[0] == "interface":
            interfaces.append(tokens[1])
    return VrfContext(
        name=name,
        line_start=line_no,
        line_end=line_no + len(body),
        body_lines=body,
        interfaces=tuple(interfaces),
    )


def _parse_role_definition(name: str, line_no: int, body: tuple[str, ...]) -> RoleDefinition:
    rules: list[tuple[int, str, str]] = []
    for line in body:
        tokens = line.split()
        if len(tokens) < 4 or tokens[0] != "rule" or not tokens[1].isdigit():
            continue
        action = tokens[2].lower()
        if action not in {"permit", "deny"}:
            continue
        rules.append((int(tokens[1]), action, " ".join(tokens[3:])))
    return RoleDefinition(
        name=name,
        line_start=line_no,
        line_end=line_no + len(body),
        rules=tuple(rules),
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


def _parse_feature_line(line: str, line_no: int) -> FeatureDeclaration | None:
    tokens = line.split()
    if len(tokens) < 2:
        return None
    if tokens[0] == "feature":
        return FeatureDeclaration(feature=tokens[1], enabled=True, line_no=line_no, raw=line)
    if tokens[0] == "no" and tokens[1] == "feature" and len(tokens) >= 3:
        return FeatureDeclaration(feature=tokens[2], enabled=False, line_no=line_no, raw=line)
    return None


def _finalize_aaa(parsed: ParsedNxOsConfig) -> None:
    if parsed.aaa_config is None:
        return
    for line in parsed.aaa_config.body_lines:
        lowered = line.lower()
        if lowered.startswith("aaa authentication login"):
            parsed.aaa_login_authenticated = True


def _finalize_resolutions(parsed: ParsedNxOsConfig) -> None:
    from shift_left.handlers.config.parsers.nx_os.resolver import resolve_nx_os_config

    resolved = resolve_nx_os_config(parsed)
    parsed.ace_resolutions = resolved.ace_resolutions
    for item in resolved.unresolved_references:
        if item not in parsed.unresolved_references:
            parsed.unresolved_references.append(item)


def parse_nx_os_config(content: str) -> ParsedNxOsConfig:
    lines = content.splitlines()
    parsed = ParsedNxOsConfig()
    index = 0
    active_acl: str | None = None
    active_vrf: str | None = None
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
                entry = _parse_acl_ace(line, line_no, active_acl)
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
            if len(parts) >= 3:
                active_acl = parts[2]
            else:
                parsed.unparsed_lines.append(
                    UnparsedConfigLine(line_no=line_no, raw=line, category="acl")
                )
            index += 1
            continue

        feature = _parse_feature_line(line, line_no)
        if feature is not None:
            parsed.feature_declarations.append(feature)
            index += 1
            continue

        if line.startswith("object-group ip address "):
            parts = line.split()
            name = parts[3] if len(parts) >= 4 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.address_object_groups.append(
                AddressObjectGroup(
                    name=name,
                    line_start=line_no,
                    line_end=next_index if body else line_no,
                    members=_parse_group_members(body, parser=_parse_address_group_member),
                )
            )
            index = next_index
            continue

        if line.startswith("object-group ip port "):
            parts = line.split()
            name = parts[3] if len(parts) >= 4 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.port_object_groups.append(
                PortObjectGroup(
                    name=name,
                    line_start=line_no,
                    line_end=next_index if body else line_no,
                    members=_parse_group_members(body, parser=_parse_port_group_member),
                )
            )
            index = next_index
            continue

        if line.startswith("vrf context "):
            parts = line.split(maxsplit=2)
            name = parts[2] if len(parts) > 2 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.vrf_contexts.append(_parse_vrf_context(name, line_no, body))
            index = next_index
            continue

        if line.startswith("role name "):
            parts = line.split(maxsplit=2)
            name = parts[2] if len(parts) > 2 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.role_definitions.append(_parse_role_definition(name, line_no, body))
            index = next_index
            continue

        if line.startswith("interface "):
            parts = line.split(maxsplit=1)
            name = parts[1] if len(parts) > 1 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.interface_blocks.append(
                _parse_interface_block(name, line_no, body, vrf=active_vrf)
            )
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
