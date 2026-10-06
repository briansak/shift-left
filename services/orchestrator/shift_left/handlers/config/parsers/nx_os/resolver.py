"""Resolve NX-OS object-group references before rule evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field

from shift_left.handlers.config.parsers.nx_os.parser import (
    AccessListEntry,
    GroupMember,
    ParsedNxOsConfig,
    UnresolvedReference,
)

MAX_RESOLVE_DEPTH = 16


class ResolveFailure(Exception):
    def __init__(self, reason: str, ref_name: str, ref_kind: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.ref_name = ref_name
        self.ref_kind = ref_kind


@dataclass
class ResolvedAce:
    line_no: int
    acl_name: str
    source_values: tuple[str, ...]
    destination_values: tuple[str, ...]
    service_values: tuple[str, ...]
    unresolved: tuple[UnresolvedReference, ...] = field(default_factory=tuple)


@dataclass
class ResolvedNxOsConfig:
    ace_resolutions: dict[int, ResolvedAce]
    unresolved_references: list[UnresolvedReference]


def _address_groups(parsed: ParsedNxOsConfig) -> dict[str, tuple[GroupMember, ...]]:
    return {group.name: group.members for group in parsed.address_object_groups}


def _port_groups(parsed: ParsedNxOsConfig) -> dict[str, tuple[GroupMember, ...]]:
    return {group.name: group.members for group in parsed.port_object_groups}


def _resolve_address_group(
    name: str,
    groups: dict[str, tuple[GroupMember, ...]],
    *,
    stack: tuple[str, ...],
) -> tuple[str, ...]:
    if name in stack:
        raise ResolveFailure("circular object-group reference", name, "address-object-group")
    if len(stack) >= MAX_RESOLVE_DEPTH:
        raise ResolveFailure("object-group resolution depth exceeded", name, "address-object-group")
    members = groups.get(name)
    if members is None:
        raise ResolveFailure("undefined address object-group", name, "address-object-group")
    values: list[str] = []
    for member in members:
        if member.kind == "group-object" and member.ref:
            values.extend(_resolve_address_group(member.ref, groups, stack=stack + (name,)))
        elif member.value:
            values.append(member.value)
    return tuple(values)


def _resolve_port_group(
    name: str,
    groups: dict[str, tuple[GroupMember, ...]],
    *,
    stack: tuple[str, ...],
) -> tuple[str, ...]:
    if name in stack:
        raise ResolveFailure("circular object-group reference", name, "port-object-group")
    if len(stack) >= MAX_RESOLVE_DEPTH:
        raise ResolveFailure("object-group resolution depth exceeded", name, "port-object-group")
    members = groups.get(name)
    if members is None:
        raise ResolveFailure("undefined port object-group", name, "port-object-group")
    values: list[str] = []
    for member in members:
        if member.kind == "group-object" and member.ref:
            values.extend(_resolve_port_group(member.ref, groups, stack=stack + (name,)))
        elif member.port:
            values.append(member.port)
    return tuple(values)


def _resolve_endpoint(
    kind: str,
    value: str,
    *,
    address_groups: dict[str, tuple[GroupMember, ...]],
    unresolved: list[UnresolvedReference],
    line_no: int,
    raw: str,
    ref_kind: str,
) -> tuple[str, ...]:
    if kind == "literal":
        return (value,)
    if kind != "object-group":
        unresolved.append(
            UnresolvedReference(
                line_no=line_no,
                ref_name=value,
                ref_kind=ref_kind,
                raw=raw,
            )
        )
        return ("*",)
    try:
        return _resolve_address_group(value, address_groups, stack=())
    except ResolveFailure:
        unresolved.append(
            UnresolvedReference(
                line_no=line_no,
                ref_name=value,
                ref_kind=ref_kind,
                raw=raw,
            )
        )
        return ("*",)


def _resolve_service(
    entry: AccessListEntry,
    *,
    port_groups: dict[str, tuple[GroupMember, ...]],
    unresolved: list[UnresolvedReference],
) -> tuple[str, ...]:
    values: list[str] = []
    if entry.port_group_ref:
        try:
            values.extend(_resolve_port_group(entry.port_group_ref, port_groups, stack=()))
        except ResolveFailure:
            unresolved.append(
                UnresolvedReference(
                    line_no=entry.line_no,
                    ref_name=entry.port_group_ref,
                    ref_kind="port-object-group",
                    raw=entry.raw,
                )
            )
            return ("*",)
    if entry.source_port_ref:
        values.append(f"src:{entry.source_port_ref}")
    if entry.destination_port_ref:
        values.append(f"dst:{entry.destination_port_ref}")
    if not values and entry.protocol in {"tcp", "udp", "ip"}:
        return (entry.protocol,)
    if not values:
        return (entry.protocol,)
    return tuple(values)


def resolve_nx_os_config(parsed: ParsedNxOsConfig) -> ResolvedNxOsConfig:
    address_groups = _address_groups(parsed)
    port_groups = _port_groups(parsed)
    ace_resolutions: dict[int, ResolvedAce] = {}
    unresolved: list[UnresolvedReference] = []

    for entry in parsed.access_list_entries:
        entry_unresolved: list[UnresolvedReference] = []
        source_values = _resolve_endpoint(
            entry.source_kind,
            entry.source,
            address_groups=address_groups,
            unresolved=entry_unresolved,
            line_no=entry.line_no,
            raw=entry.raw,
            ref_kind="address-object-group",
        )
        destination_values = _resolve_endpoint(
            entry.destination_kind,
            entry.destination,
            address_groups=address_groups,
            unresolved=entry_unresolved,
            line_no=entry.line_no,
            raw=entry.raw,
            ref_kind="address-object-group",
        )
        service_values = _resolve_service(
            entry,
            port_groups=port_groups,
            unresolved=entry_unresolved,
        )
        ace_resolutions[entry.line_no] = ResolvedAce(
            line_no=entry.line_no,
            acl_name=entry.acl_name,
            source_values=source_values,
            destination_values=destination_values,
            service_values=service_values,
            unresolved=tuple(entry_unresolved),
        )
        unresolved.extend(entry_unresolved)

    return ResolvedNxOsConfig(
        ace_resolutions=ace_resolutions,
        unresolved_references=unresolved,
    )


def count_nxos_001_targets(parsed: ParsedNxOsConfig) -> tuple[int, int]:
    """Return (unparsed_acl_line_count, unresolvable_reference_count)."""
    unparsed_acl = sum(1 for item in parsed.unparsed_lines if item.category == "acl")
    return unparsed_acl, len(parsed.unresolved_references)
