"""Structural parser for Cisco ASA / FTD CLI configuration fragments."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from shift_left.handlers.config.secret_values import SecretValueSet


@dataclass(frozen=True)
class ServiceObject:
    name: str
    line_start: int
    line_end: int
    body_lines: tuple[str, ...]


@dataclass(frozen=True)
class NetworkObject:
    name: str
    line_start: int
    line_end: int
    body_lines: tuple[str, ...]


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
class UnparsedAccessListLine:
    line_no: int
    raw: str


@dataclass(frozen=True)
class AccessListEntry:
    acl_name: str
    action: str
    protocol: str
    line_no: int
    raw: str
    has_log: bool
    source_kind: str
    source: str
    destination_kind: str
    destination: str
    service_ref: str | None = None
    service_group_ref: str | None = None


@dataclass(frozen=True)
class ManagementAccess:
    service: str
    network: str
    mask: str
    interface: str
    line_no: int


@dataclass(frozen=True)
class CryptoBlock:
    kind: str
    name: str
    line_start: int
    line_end: int
    body_lines: tuple[str, ...]


@dataclass
class ParsedAsaConfig:
    service_objects: list[ServiceObject] = field(default_factory=list)
    network_objects: list[NetworkObject] = field(default_factory=list)
    network_object_groups: list[NetworkObjectGroup] = field(default_factory=list)
    service_object_groups: list[ServiceObjectGroup] = field(default_factory=list)
    access_list_entries: list[AccessListEntry] = field(default_factory=list)
    unparsed_access_list_lines: list[UnparsedAccessListLine] = field(default_factory=list)
    management_access: list[ManagementAccess] = field(default_factory=list)
    crypto_blocks: list[CryptoBlock] = field(default_factory=list)
    ace_resolutions: dict = field(default_factory=dict)
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
    return line.lower().startswith("access-list ")


def _is_access_list_remark(line: str) -> bool:
    tokens = line.split()
    return len(tokens) >= 3 and tokens[0] == "access-list" and tokens[2].lower() == "remark"


def count_acl_bearing_lines(content: str) -> int:
    """Count access-list lines eligible for extended ACE parsing (remarks excluded)."""
    total = 0
    for raw in content.splitlines():
        line = _strip_comment(raw)
        if line and _is_acl_bearing_line(line) and not _is_access_list_remark(line):
            total += 1
    return total


def count_acl_remark_lines(content: str) -> int:
    total = 0
    for raw in content.splitlines():
        line = _strip_comment(raw)
        if line and _is_acl_bearing_line(line) and _is_access_list_remark(line):
            total += 1
    return total


def acl_parse_coverage(content: str) -> tuple[int, int]:
    """Return (parsed_acl_lines, evaluable_acl_bearing_lines) for ASA extended ACEs.

    Remark lines (``access-list NAME remark ...``) are excluded from the denominator.
    """
    config = parse_asa_config(content)
    total = count_acl_bearing_lines(content)
    parsed = len(config.access_list_entries)
    return parsed, total


def _parse_network_group_member(line: str) -> GroupMember | None:
    tokens = line.split()
    if not tokens:
        return None
    if tokens[0] == "group-object" and len(tokens) >= 2:
        return GroupMember(kind="group-object", ref=tokens[1])
    if tokens[0] == "network-object":
        if len(tokens) >= 2 and tokens[1].lower() in {"any", "any4", "any6"}:
            return GroupMember(kind="any")
        if len(tokens) >= 3 and tokens[1] == "host":
            return GroupMember(kind="network-object", value=f"host:{tokens[2]}")
        if len(tokens) >= 3 and tokens[1] == "object":
            return GroupMember(kind="object", ref=tokens[2])
        if len(tokens) >= 3:
            return GroupMember(kind="network-object", value=f"net:{tokens[1]}/{tokens[2]}")
    return None


def _parse_service_group_member(line: str) -> GroupMember | None:
    tokens = line.split()
    if not tokens:
        return None
    if tokens[0] == "group-object" and len(tokens) >= 2:
        return GroupMember(kind="group-object", ref=tokens[1])
    if tokens[0] == "service-object":
        if len(tokens) >= 3 and tokens[1] == "object":
            return GroupMember(kind="object", ref=tokens[2])
        if len(tokens) >= 2:
            port = " ".join(tokens[2:]) if len(tokens) > 2 else None
            return GroupMember(kind="service-object", ref=tokens[1].lower(), port=port)
    return None


def _parse_group_members(
    body_lines: tuple[str, ...],
    *,
    parser,
) -> tuple[GroupMember, ...]:
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
    if token in {"any", "any4", "any6"}:
        return "literal", token, index + 1
    if token == "object":
        if index + 1 >= len(tokens):
            return None
        return "object", tokens[index + 1], index + 2
    if token == "object-group":
        if index + 1 >= len(tokens):
            return None
        return "object-group", tokens[index + 1], index + 2
    if token == "host":
        if index + 1 >= len(tokens):
            return None
        return "literal", f"host:{tokens[index + 1]}", index + 2
    if index + 1 >= len(tokens):
        return None
    return "literal", f"net:{tokens[index]}/{tokens[index + 1]}", index + 2


def _parse_acl_line(line: str, line_no: int) -> AccessListEntry | None | str:
    tokens = line.split()
    if len(tokens) >= 3 and tokens[0] == "access-list" and tokens[2].lower() == "remark":
        return "remark"
    if len(tokens) < 7 or tokens[0] != "access-list" or tokens[2] != "extended":
        return None
    action = tokens[3].lower()
    if action not in {"permit", "deny"}:
        return None

    protocol = tokens[4].lower()
    has_log = any(token.lower() == "log" for token in tokens)
    service_ref: str | None = None
    service_group_ref: str | None = None
    index = 5

    if protocol == "object":
        if index >= len(tokens):
            return None
        service_ref = tokens[index]
        index += 1
    elif protocol == "object-group":
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
        acl_name=tokens[1],
        action=action,
        protocol=protocol,
        line_no=line_no,
        raw=line,
        has_log=has_log,
        source_kind=source_kind,
        source=source_value,
        destination_kind=destination_kind,
        destination=destination_value,
        service_ref=service_ref,
        service_group_ref=service_group_ref,
    )


def _finalize_resolutions(parsed: ParsedAsaConfig) -> None:
    from shift_left.handlers.config.parsers.asa.resolver import resolve_asa_config

    resolved = resolve_asa_config(parsed)
    parsed.ace_resolutions = resolved.ace_resolutions


def parse_asa_config(content: str) -> ParsedAsaConfig:
    lines = content.splitlines()
    parsed = ParsedAsaConfig()
    index = 0
    while index < len(lines):
        raw = lines[index]
        line_no = index + 1
        line = _strip_comment(raw)
        if not line:
            index += 1
            continue

        if line.startswith("object service "):
            parts = line.split()
            name = parts[2] if len(parts) >= 3 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.service_objects.append(
                ServiceObject(
                    name=name,
                    line_start=line_no,
                    line_end=next_index if body else line_no,
                    body_lines=body,
                )
            )
            index = next_index
            continue

        if line.startswith("object network "):
            parts = line.split()
            name = parts[2] if len(parts) >= 3 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.network_objects.append(
                NetworkObject(
                    name=name,
                    line_start=line_no,
                    line_end=next_index if body else line_no,
                    body_lines=body,
                )
            )
            index = next_index
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

        if line.startswith("access-list "):
            entry = _parse_acl_line(line, line_no)
            if entry == "remark":
                index += 1
                continue
            if entry is not None:
                parsed.access_list_entries.append(entry)
            else:
                parsed.unparsed_access_list_lines.append(
                    UnparsedAccessListLine(line_no=line_no, raw=line)
                )
            index += 1
            continue

        mgmt_parts = line.split()
        if len(mgmt_parts) == 4 and mgmt_parts[0].lower() in {"ssh", "http", "https", "telnet"}:
            parsed.management_access.append(
                ManagementAccess(
                    service=mgmt_parts[0].lower(),
                    network=mgmt_parts[1],
                    mask=mgmt_parts[2],
                    interface=mgmt_parts[3].lower(),
                    line_no=line_no,
                )
            )
            index += 1
            continue

        if line.startswith("crypto ipsec transform-set "):
            parts = line.split()
            kind = "transform-set"
            name = parts[3] if len(parts) >= 4 else ""
            inline = tuple(parts[4:]) if len(parts) > 4 else ()
            body, next_index = _continuation_lines(lines, index + 1)
            if inline:
                body = (" ".join(inline),) + body
            parsed.crypto_blocks.append(
                CryptoBlock(
                    kind=kind,
                    name=name,
                    line_start=line_no,
                    line_end=next_index if body else line_no,
                    body_lines=body,
                )
            )
            index = next_index
            continue

        if line.startswith("crypto "):
            parts = line.split()
            kind = " ".join(parts[:3]) if len(parts) >= 3 else line
            name = parts[-1] if len(parts) >= 2 else ""
            if line.startswith("crypto ipsec transform-set "):
                kind = "transform-set"
                name = parts[3] if len(parts) >= 4 else ""
            elif line.startswith("crypto isakmp policy "):
                kind = "isakmp-policy"
                name = parts[3] if len(parts) >= 4 else ""
            elif line.startswith("crypto ikev2 policy "):
                kind = "ikev2-policy"
                name = parts[3] if len(parts) >= 4 else ""
            elif line.startswith("crypto ipsec ikev2 ipsec-proposal "):
                kind = "ipsec-proposal"
                name = parts[4] if len(parts) >= 5 else ""
            body, next_index = _continuation_lines(lines, index + 1)
            parsed.crypto_blocks.append(
                CryptoBlock(
                    kind=kind,
                    name=name,
                    line_start=line_no,
                    line_end=next_index if body else line_no,
                    body_lines=body,
                )
            )
            index = next_index
            continue

        index += 1

    _finalize_resolutions(parsed)
    from shift_left.handlers.config.secret_values import extract_secret_values_from_content

    parsed.secret_values = extract_secret_values_from_content(content)
    return parsed


def is_any_address(token: str) -> bool:
    return token.lower() in {"any", "any4", "any6"}


def is_permissive_service_object(obj: ServiceObject) -> bool:
    for line in obj.body_lines:
        tokens = line.split()
        if len(tokens) >= 3 and tokens[0] == "service" and tokens[1] == "protocol":
            return tokens[2].lower() == "ip"
        if tokens == ["service", "tcp"] or tokens == ["service", "udp"]:
            return True
    return False


def is_permissive_service_object_group(group: ServiceObjectGroup) -> bool:
    for member in group.members:
        if member.kind == "service-object" and member.ref in {"tcp", "udp"} and not member.port:
            return True
        if member.kind == "group-object" and member.ref:
            nested = next((item for item in group.members if item.ref == member.ref), None)
            if nested is None:
                continue
    return False


def is_weak_crypto_block(block: CryptoBlock) -> bool:
    weak_encryption = {"des", "3des", "triple-des"}
    weak_integrity = {"md5", "sha1", "sha-96"}
    weak_groups = set(range(1, 14))

    first_line = block.body_lines[0] if block.body_lines else ""
    if block.kind == "transform-set":
        lowered = f"{block.name} {first_line}".lower()
        if any(token in lowered for token in weak_encryption | weak_integrity):
            return True

    for line in block.body_lines:
        tokens = [token.lower() for token in line.split()]
        if not tokens:
            continue
        if tokens[0] == "encryption" and any(item in weak_encryption for item in tokens[1:]):
            return True
        if tokens[0] == "integrity" and any(item in weak_integrity for item in tokens[1:]):
            return True
        if tokens[0] == "hash" and any(item in weak_integrity for item in tokens[1:]):
            return True
        if tokens[0] == "group" and len(tokens) >= 2:
            try:
                if int(tokens[1]) in weak_groups:
                    return True
            except ValueError:
                continue
        if tokens[0] == "protocol" and "esp" in tokens:
            for token in tokens:
                if token in weak_encryption or token in weak_integrity:
                    return True
    return False


def _mask_to_prefix(mask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
    except ValueError:
        return None


def management_allows_non_rfc1918(entry: ManagementAccess) -> bool:
    if entry.mask == "0.0.0.0":
        return True
    prefix_len = _mask_to_prefix(entry.mask)
    if prefix_len is None:
        return False
    try:
        network = ipaddress.IPv4Network(f"{entry.network}/{prefix_len}", strict=False)
    except ValueError:
        return False
    private = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if any(network.subnet_of(private_net) for private_net in private):
        return False
    return True


def is_deny_all_ip(entry: AccessListEntry) -> bool:
    return (
        entry.action == "deny"
        and entry.protocol == "ip"
        and entry.source_kind == "literal"
        and entry.destination_kind == "literal"
        and is_any_address(entry.source)
        and is_any_address(entry.destination)
    )


def is_permissive_ace(entry: AccessListEntry) -> bool:
    """True when a permit ACE allows any source to any destination (literal tokens only)."""
    if entry.action != "permit":
        return False
    return (
        entry.source_kind == "literal"
        and entry.destination_kind == "literal"
        and is_any_address(entry.source)
        and is_any_address(entry.destination)
    )


def is_shadowed_permit(entries: list[AccessListEntry], entry: AccessListEntry) -> bool:
    if entry.action != "permit":
        return False
    prior = [item for item in entries if item.acl_name == entry.acl_name and item.line_no < entry.line_no]
    return any(is_deny_all_ip(item) for item in prior)
