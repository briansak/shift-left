"""Resolve ASA object / object-group indirection for rule evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from shift_left.handlers.config.parsers.asa.parser import (
    AccessListEntry,
    NetworkObject,
    NetworkObjectGroup,
    ParsedAsaConfig,
    ServiceObject,
    ServiceObjectGroup,
    is_any_address,
    is_permissive_service_object,
)

MAX_RESOLVE_DEPTH = 16


class ResolveFailure(str, Enum):
    UNDEFINED = "undefined"
    CIRCULAR = "circular"
    DEPTH = "depth"


@dataclass(frozen=True)
class NetworkResolution:
    is_any: bool = False
    is_narrow: bool = True
    failure: ResolveFailure | None = None


@dataclass(frozen=True)
class ServiceResolution:
    is_permissive: bool = False
    failure: ResolveFailure | None = None


@dataclass
class AceResolution:
    line_no: int
    source: NetworkResolution
    destination: NetworkResolution
    service: ServiceResolution | None = None


@dataclass
class ResolvedAsaConfig:
    config: ParsedAsaConfig
    ace_resolutions: dict[int, AceResolution] = field(default_factory=dict)


def _literal_network_is_any(value: str) -> bool:
    if is_any_address(value):
        return True
    lowered = value.lower()
    return lowered in {"host:0.0.0.0", "net:0.0.0.0/0.0.0.0", "net:0.0.0.0/0"}


def _network_object_is_any(obj: NetworkObject) -> bool:
    for line in obj.body_lines:
        tokens = line.split()
        if len(tokens) >= 2 and tokens[0] == "host" and tokens[1] in {"0.0.0.0", "any"}:
            return True
        if (
            len(tokens) >= 3
            and tokens[0] == "subnet"
            and tokens[1] == "0.0.0.0"
            and tokens[2] in {"0.0.0.0", "0"}
        ):
            return True
        if len(tokens) >= 2 and tokens[0] == "range" and tokens[1] == "0.0.0.0":
            return True
    return False


def _resolve_network_name(
    name: str,
    *,
    networks: dict[str, NetworkObject],
    network_groups: dict[str, NetworkObjectGroup],
    stack: tuple[str, ...],
    depth: int,
) -> NetworkResolution:
    if depth > MAX_RESOLVE_DEPTH:
        return NetworkResolution(is_any=False, is_narrow=False, failure=ResolveFailure.DEPTH)
    if name in stack:
        return NetworkResolution(is_any=False, is_narrow=False, failure=ResolveFailure.CIRCULAR)

    obj = networks.get(name)
    if obj is not None:
        if _network_object_is_any(obj):
            return NetworkResolution(is_any=True, is_narrow=False)
        return NetworkResolution(is_any=False, is_narrow=True)

    group = network_groups.get(name)
    if group is None:
        return NetworkResolution(is_any=False, is_narrow=False, failure=ResolveFailure.UNDEFINED)

    next_stack = stack + (name,)
    saw_member = False
    all_any = True
    for member in group.members:
        saw_member = True
        if member.kind == "any":
            return NetworkResolution(is_any=True, is_narrow=False)
        if member.kind == "network-object":
            if member.value is not None and _literal_network_is_any(member.value):
                return NetworkResolution(is_any=True, is_narrow=False)
            all_any = False
        elif member.kind == "object":
            if member.ref is None:
                all_any = False
                continue
            resolved = _resolve_network_name(
                member.ref,
                networks=networks,
                network_groups=network_groups,
                stack=next_stack,
                depth=depth + 1,
            )
            if resolved.failure is not None:
                return resolved
            if resolved.is_any:
                return NetworkResolution(is_any=True, is_narrow=False)
            all_any = False
        elif member.kind == "group-object":
            if member.ref is None:
                return NetworkResolution(is_any=False, is_narrow=False, failure=ResolveFailure.UNDEFINED)
            resolved = _resolve_network_name(
                member.ref,
                networks=networks,
                network_groups=network_groups,
                stack=next_stack,
                depth=depth + 1,
            )
            if resolved.failure is not None:
                return resolved
            if resolved.is_any:
                return NetworkResolution(is_any=True, is_narrow=False)
            all_any = False
        else:
            all_any = False

    if not saw_member:
        return NetworkResolution(is_any=False, is_narrow=False, failure=ResolveFailure.UNDEFINED)
    if all_any:
        return NetworkResolution(is_any=True, is_narrow=False)
    return NetworkResolution(is_any=False, is_narrow=True)


def _resolve_service_name(
    name: str,
    *,
    services: dict[str, ServiceObject],
    service_groups: dict[str, ServiceObjectGroup],
    stack: tuple[str, ...],
    depth: int,
) -> ServiceResolution:
    if depth > MAX_RESOLVE_DEPTH:
        return ServiceResolution(failure=ResolveFailure.DEPTH)
    if name in stack:
        return ServiceResolution(failure=ResolveFailure.CIRCULAR)

    obj = services.get(name)
    if obj is not None:
        return ServiceResolution(is_permissive=is_permissive_service_object(obj))

    group = service_groups.get(name)
    if group is None:
        return ServiceResolution(failure=ResolveFailure.UNDEFINED)

    next_stack = stack + (name,)
    saw_member = False
    for member in group.members:
        saw_member = True
        if member.kind == "any":
            return ServiceResolution(is_permissive=True)
        if member.kind == "service-object":
            if member.ref is None:
                continue
            if member.ref in {"tcp", "udp"} and member.port is None:
                return ServiceResolution(is_permissive=True)
            nested = services.get(member.ref)
            if nested is not None and is_permissive_service_object(nested):
                return ServiceResolution(is_permissive=True)
        elif member.kind == "object":
            if member.ref is None:
                return ServiceResolution(failure=ResolveFailure.UNDEFINED)
            resolved = _resolve_service_name(
                member.ref,
                services=services,
                service_groups=service_groups,
                stack=next_stack,
                depth=depth + 1,
            )
            if resolved.failure is not None:
                return resolved
            if resolved.is_permissive:
                return ServiceResolution(is_permissive=True)
        elif member.kind == "group-object":
            if member.ref is None:
                return ServiceResolution(failure=ResolveFailure.UNDEFINED)
            resolved = _resolve_service_name(
                member.ref,
                services=services,
                service_groups=service_groups,
                stack=next_stack,
                depth=depth + 1,
            )
            if resolved.failure is not None:
                return resolved
            if resolved.is_permissive:
                return ServiceResolution(is_permissive=True)

    if not saw_member:
        return ServiceResolution(failure=ResolveFailure.UNDEFINED)
    return ServiceResolution(is_permissive=False)


def _resolve_endpoint(
    entry: AccessListEntry,
    which: str,
    *,
    networks: dict[str, NetworkObject],
    network_groups: dict[str, NetworkObjectGroup],
) -> NetworkResolution:
    kind = entry.source_kind if which == "source" else entry.destination_kind
    value = entry.source if which == "source" else entry.destination

    if kind == "literal":
        if _literal_network_is_any(value):
            return NetworkResolution(is_any=True, is_narrow=False)
        return NetworkResolution(is_any=False, is_narrow=True)
    if kind == "object":
        return _resolve_network_name(
            value,
            networks=networks,
            network_groups=network_groups,
            stack=(),
            depth=0,
        )
    if kind == "object-group":
        return _resolve_network_name(
            value,
            networks=networks,
            network_groups=network_groups,
            stack=(),
            depth=0,
        )
    return NetworkResolution(is_any=False, is_narrow=False, failure=ResolveFailure.UNDEFINED)


def resolve_asa_config(config: ParsedAsaConfig) -> ResolvedAsaConfig:
    networks = {item.name: item for item in config.network_objects}
    network_groups = {item.name: item for item in config.network_object_groups}
    services = {item.name: item for item in config.service_objects}
    service_groups = {item.name: item for item in config.service_object_groups}

    ace_resolutions: dict[int, AceResolution] = {}
    for entry in config.access_list_entries:
        source = _resolve_endpoint(
            entry, "source", networks=networks, network_groups=network_groups
        )
        destination = _resolve_endpoint(
            entry, "destination", networks=networks, network_groups=network_groups
        )
        service: ServiceResolution | None = None
        if entry.service_ref:
            service = _resolve_service_name(
                entry.service_ref,
                services=services,
                service_groups=service_groups,
                stack=(),
                depth=0,
            )
        elif entry.protocol == "object-group" and entry.service_group_ref:
            service = _resolve_service_name(
                entry.service_group_ref,
                services=services,
                service_groups=service_groups,
                stack=(),
                depth=0,
            )
        ace_resolutions[entry.line_no] = AceResolution(
            line_no=entry.line_no,
            source=source,
            destination=destination,
            service=service,
        )

    return ResolvedAsaConfig(config=config, ace_resolutions=ace_resolutions)


def is_resolved_permissive_ace(resolved: AceResolution, entry: AccessListEntry) -> bool:
    if entry.action != "permit":
        return False
    if resolved.source.failure or resolved.destination.failure:
        return False
    if not (resolved.source.is_any and resolved.destination.is_any):
        return False
    if entry.protocol in {"ip", "icmp", "tcp", "udp"}:
        return True
    if entry.protocol in {"object", "object-group"}:
        return True
    return False


def is_resolved_shadowed_permit(
    entries: list[AccessListEntry],
    ace_resolutions: dict[int, AceResolution],
    entry: AccessListEntry,
) -> bool:
    if entry.action != "permit":
        return False
    prior = [item for item in entries if item.acl_name == entry.acl_name and item.line_no < entry.line_no]
    for item in prior:
        if item.action != "deny" or item.protocol != "ip":
            continue
        res = ace_resolutions.get(item.line_no)
        if res and res.source.is_any and res.destination.is_any and not res.source.failure:
            return True
        if is_any_address(item.source) and is_any_address(item.destination):
            return True
    return False


def is_unresolvable_ace(resolved: AceResolution) -> bool:
    """True when any network or service object reference on the ACE cannot be resolved."""
    if resolved.source.failure or resolved.destination.failure:
        return True
    if resolved.service and resolved.service.failure:
        return True
    return False


def count_asa_007_targets(config: ParsedAsaConfig) -> tuple[int, int]:
    """Return (unparsed_acl_line_count, unresolvable_parsed_ace_count).

    ``unparsed_acl_line_count`` matches the parse-coverage gap:
    ``evaluable_acl_bearing_lines - parsed_acl_lines``.
    """
    unparsed = len(config.unparsed_access_list_lines)
    unresolvable = 0
    for entry in config.access_list_entries:
        ace = config.ace_resolutions.get(entry.line_no)
        if ace is not None and is_unresolvable_ace(ace):
            unresolvable += 1
    return unparsed, unresolvable
