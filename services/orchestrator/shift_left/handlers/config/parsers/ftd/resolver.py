"""Resolve FMC Terraform network object indirection for rule evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from shift_left.handlers.config.parsers.ftd.parser import (
    FmcAccessRule,
    FmcNetworkSymbol,
    _is_open_network_value,
    _network_allows_non_rfc1918,
)

if TYPE_CHECKING:
    from shift_left.handlers.config.parsers.ftd.parser import ParsedFtdConfig

MAX_RESOLVE_DEPTH = 16


class ResolveFailure(str, Enum):
    UNDEFINED = "undefined"
    CIRCULAR = "circular"
    DEPTH = "depth"


@dataclass(frozen=True)
class NetworkResolution:
    values: tuple[str, ...] = ()
    is_any: bool = False
    is_exposed: bool = False
    has_no_constraint: bool = False
    failure: ResolveFailure | None = None


@dataclass(frozen=True)
class RuleNetworkResolution:
    source: NetworkResolution
    destination: NetworkResolution


def rule_key(rule: FmcAccessRule) -> tuple[int, int | None]:
    return (rule.line_start, rule.sequence_index)


def _literal_resolution(values: tuple[str, ...]) -> NetworkResolution:
    if not values:
        return NetworkResolution()
    is_any = False
    is_exposed = False
    for value in values:
        if _is_open_network_value(value):
            is_any = True
        if _network_allows_non_rfc1918(value):
            is_exposed = True
    return NetworkResolution(
        values=values,
        is_any=is_any,
        is_exposed=is_exposed or is_any,
    )


def _merge_resolutions(parts: list[NetworkResolution]) -> NetworkResolution:
    if not parts:
        return NetworkResolution()
    for part in parts:
        if part.failure is not None:
            return part
    values: list[str] = []
    is_any = False
    is_exposed = False
    for part in parts:
        values.extend(part.values)
        is_any = is_any or part.is_any
        is_exposed = is_exposed or part.is_exposed
    return NetworkResolution(values=tuple(values), is_any=is_any, is_exposed=is_exposed)


def _resolve_symbol_address(
    address: str,
    *,
    symbols: dict[str, FmcNetworkSymbol],
    stack: tuple[str, ...],
    depth: int,
) -> NetworkResolution:
    if depth > MAX_RESOLVE_DEPTH:
        return NetworkResolution(failure=ResolveFailure.DEPTH)
    if address in stack:
        return NetworkResolution(failure=ResolveFailure.CIRCULAR)

    symbol = symbols.get(address)
    if symbol is None:
        return NetworkResolution(failure=ResolveFailure.UNDEFINED)

    if symbol.kind in {"network", "host", "range"}:
        if symbol.value is None:
            return NetworkResolution(failure=ResolveFailure.UNDEFINED)
        return _literal_resolution((symbol.value,))

    if symbol.kind == "group":
        if not symbol.member_refs:
            return NetworkResolution(failure=ResolveFailure.UNDEFINED)
        next_stack = stack + (address,)
        member_parts: list[NetworkResolution] = []
        for member_ref in symbol.member_refs:
            member_parts.append(
                _resolve_symbol_address(
                    member_ref,
                    symbols=symbols,
                    stack=next_stack,
                    depth=depth + 1,
                )
            )
        return _merge_resolutions(member_parts)

    return NetworkResolution(failure=ResolveFailure.UNDEFINED)


def _endpoint_field_refs(rule: FmcAccessRule, side: str) -> tuple[str, ...]:
    prefixes = ("source_",) if side == "source" else ("destination_",)
    return tuple(
        address
        for field, address in rule.network_object_refs
        if any(field.startswith(prefix) for prefix in prefixes)
    )


def resolve_endpoint(
    rule: FmcAccessRule,
    side: str,
    *,
    symbols: dict[str, FmcNetworkSymbol],
) -> NetworkResolution:
    literals = rule.source_networks if side == "source" else rule.destination_networks
    refs = _endpoint_field_refs(rule, side)
    if not literals and not refs:
        return NetworkResolution(has_no_constraint=True)

    parts: list[NetworkResolution] = []
    if literals:
        parts.append(_literal_resolution(literals))
    for address in refs:
        parts.append(
            _resolve_symbol_address(
                address,
                symbols=symbols,
                stack=(),
                depth=0,
            )
        )
    return _merge_resolutions(parts)


def resolve_ftd_config(config: ParsedFtdConfig) -> None:
    resolutions: dict[tuple[int, int | None], RuleNetworkResolution] = {}
    for rule in config.access_rules:
        resolutions[rule_key(rule)] = RuleNetworkResolution(
            source=resolve_endpoint(rule, "source", symbols=config.network_symbols),
            destination=resolve_endpoint(rule, "destination", symbols=config.network_symbols),
        )
    for bulk in config.access_rules_bulk:
        for rule in bulk.rules:
            resolutions[rule_key(rule)] = RuleNetworkResolution(
                source=resolve_endpoint(rule, "source", symbols=config.network_symbols),
                destination=resolve_endpoint(
                    rule, "destination", symbols=config.network_symbols
                ),
            )
    config.rule_resolutions = resolutions


def is_unresolved_endpoint(resolution: NetworkResolution) -> bool:
    return resolution.failure is not None


def is_resolved_open_endpoint(resolution: NetworkResolution) -> bool:
    """True when endpoint resolves to any / 0.0.0.0/0 (not unresolvable, not unconstrained)."""
    if resolution.failure is not None or resolution.has_no_constraint:
        return False
    return resolution.is_any


def is_resolved_catch_all_endpoint(resolution: NetworkResolution) -> bool:
    """True when endpoint resolves to any / 0.0.0.0/0."""
    if resolution.failure is not None or resolution.has_no_constraint:
        return False
    return resolution.is_any
