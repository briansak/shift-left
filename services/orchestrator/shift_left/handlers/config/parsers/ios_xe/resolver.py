"""Resolve IOS-XE object-group references before rule evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field

from shift_left.handlers.config.parsers.ios_xe.parser import (
    AccessListEntry,
    GroupMember,
    ParsedIosXeConfig,
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
class ResolvedIosXeConfig:
    ace_resolutions: dict[int, ResolvedAce]
    unresolved_references: list[UnresolvedReference]


def _network_groups(parsed: ParsedIosXeConfig) -> dict[str, tuple[GroupMember, ...]]:
    return {group.name: group.members for group in parsed.network_object_groups}


def _service_groups(parsed: ParsedIosXeConfig) -> dict[str, tuple[GroupMember, ...]]:
    return {group.name: group.members for group in parsed.service_object_groups}


def _resolve_network_group(
    name: str,
    groups: dict[str, tuple[GroupMember, ...]],
    *,
    stack: tuple[str, ...],
) -> tuple[str, ...]:
    if name in stack:
        raise ResolveFailure("circular object-group reference", name, "network-object-group")
    if len(stack) >= MAX_RESOLVE_DEPTH:
        raise ResolveFailure("object-group resolution depth exceeded", name, "network-object-group")
    members = groups.get(name)
    if members is None:
        raise ResolveFailure("undefined network object-group", name, "network-object-group")
    values: list[str] = []
    for member in members:
        if member.kind == "group-object" and member.ref:
            values.extend(
                _resolve_network_group(member.ref, groups, stack=stack + (name,))
            )
        elif member.value:
            values.append(member.value)
    return tuple(values)


def _resolve_service_group(
    name: str,
    groups: dict[str, tuple[GroupMember, ...]],
    *,
    stack: tuple[str, ...],
) -> tuple[str, ...]:
    if name in stack:
        raise ResolveFailure("circular object-group reference", name, "service-object-group")
    if len(stack) >= MAX_RESOLVE_DEPTH:
        raise ResolveFailure("object-group resolution depth exceeded", name, "service-object-group")
    members = groups.get(name)
    if members is None:
        raise ResolveFailure("undefined service object-group", name, "service-object-group")
    values: list[str] = []
    for member in members:
        if member.kind == "group-object" and member.ref:
            values.extend(
                _resolve_service_group(member.ref, groups, stack=stack + (name,))
            )
        elif member.ref and member.port:
            values.append(f"{member.ref}:{member.port}")
    return tuple(values)


def _resolve_endpoint(
    kind: str,
    value: str,
    *,
    network_groups: dict[str, tuple[GroupMember, ...]],
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
        return _resolve_network_group(value, network_groups, stack=())
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
    service_groups: dict[str, tuple[GroupMember, ...]],
    unresolved: list[UnresolvedReference],
) -> tuple[str, ...]:
    if entry.service_group_ref:
        try:
            return _resolve_service_group(entry.service_group_ref, service_groups, stack=())
        except ResolveFailure:
            unresolved.append(
                UnresolvedReference(
                    line_no=entry.line_no,
                    ref_name=entry.service_group_ref,
                    ref_kind="service-object-group",
                    raw=entry.raw,
                )
            )
            return ("*",)
    if entry.protocol in {"tcp", "udp", "ip"}:
        return (entry.protocol,)
    return (entry.protocol,)


def resolve_ios_xe_config(parsed: ParsedIosXeConfig) -> ResolvedIosXeConfig:
    network_groups = _network_groups(parsed)
    service_groups = _service_groups(parsed)
    ace_resolutions: dict[int, ResolvedAce] = {}
    unresolved: list[UnresolvedReference] = []

    for entry in parsed.access_list_entries:
        entry_unresolved: list[UnresolvedReference] = []
        source_values = _resolve_endpoint(
            entry.source_kind,
            entry.source,
            network_groups=network_groups,
            unresolved=entry_unresolved,
            line_no=entry.line_no,
            raw=entry.raw,
            ref_kind="network-object-group",
        )
        destination_values = _resolve_endpoint(
            entry.destination_kind,
            entry.destination,
            network_groups=network_groups,
            unresolved=entry_unresolved,
            line_no=entry.line_no,
            raw=entry.raw,
            ref_kind="network-object-group",
        )
        service_values = _resolve_service(
            entry,
            service_groups=service_groups,
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

    return ResolvedIosXeConfig(
        ace_resolutions=ace_resolutions,
        unresolved_references=unresolved,
    )


def count_ios_001_targets(parsed: ParsedIosXeConfig) -> tuple[int, int]:
    """Return (unparsed_acl_line_count, unresolvable_reference_count).

    ``unparsed_acl_line_count`` matches the parse-coverage gap:
    ``evaluable_acl_bearing_lines - parsed_acl_entries``.
    """
    unparsed_acl = sum(1 for item in parsed.unparsed_lines if item.category == "acl")
    return unparsed_acl, len(parsed.unresolved_references)
