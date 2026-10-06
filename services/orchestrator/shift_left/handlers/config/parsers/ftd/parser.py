"""Structural parser for Cisco FTD FMC Terraform (HCL) configuration.

Attribute names follow CiscoDevNet/fmc v2.0.1 (``access_control_policy_id``,
``intrusion_policy_id``, ``log_connection_begin``, ``source_network_objects``).
The parser still accepts legacy aliases (``access_policy_id``, ``log_begin``,
``value`` on ``fmc_network``) when reading HCL; corpus fixtures use v2.0.1 names.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from shift_left.config import resolve_repo_root
from shift_left.handlers.config.secret_values import SecretValueSet

import hcl2

# Provider schema baseline for attribute verification (CiscoDevNet/fmc v2.0.1).
FMC_PROVIDER_VERSION = "2.0.1"


def _fmc_provider_schema_path() -> Path:
    return (
        resolve_repo_root()
        / "validation"
        / "schemas"
        / "fmc-2.0.1-schema.json"
    )


FMC_PROVIDER_SCHEMA_PATH = _fmc_provider_schema_path()
_NETWORK_OBJECT_RESOURCES = frozenset(
    {
        "fmc_host",
        "fmc_hosts",
        "fmc_network",
        "fmc_networks",
        "fmc_range",
        "fmc_ranges",
        "fmc_network_group",
        "fmc_network_groups",
    }
)

_OPEN_NETWORK_VALUES = frozenset({"*", "0.0.0.0/0", "::/0", "any", "internet"})
_OPEN_PORT_VALUES = frozenset({"any", "*"})
_MGMT_PORTS = frozenset({"22", "443", "8443"})
_WEAK_ENCRYPTION = frozenset({"des", "3des", "triple-des", "tripledes"})
_WEAK_INTEGRITY = frozenset({"md5", "sha", "sha1", "sha96", "sha-96"})
_IKEV2_POLICY_RESOURCES = frozenset(
    {
        "fmc_ikev2_policy",
        "fmc_ikev2_policies",
        # Legacy resource types kept for parser-only backward compatibility.
        "fmc_vpn_ikev2_policy",
        "fmc_device_vpn_ikev2_policy",
    }
)
_WEAK_DH_GROUPS = set(range(1, 14))
_IP_ETHERTYPES = frozenset({"2048", "ip"})


@dataclass(frozen=True)
class FmcPortObject:
    name: str
    protocol: str
    port: str | None
    line_start: int
    line_end: int
    is_permissive: bool


@dataclass(frozen=True)
class FmcAccessRule:
    name: str
    action: str
    enabled: bool
    log_begin: bool | None
    log_end: bool | None
    log_connection_begin: bool | None
    log_connection_end: bool | None
    intrusion_policy: str | None
    source_networks: tuple[str, ...]
    destination_networks: tuple[str, ...]
    destination_ports: tuple[str, ...]
    network_object_refs: tuple[tuple[str, str], ...]
    line_start: int
    line_end: int
    policy_ref: str | None
    sequence_index: int | None


@dataclass(frozen=True)
class FmcAccessRulesBulk:
    policy_ref: str | None
    line_start: int
    line_end: int
    rules: tuple[FmcAccessRule, ...]


@dataclass(frozen=True)
class FmcNetworkSymbol:
    resource_address: str
    kind: str
    value: str | None = None
    member_refs: tuple[str, ...] = ()
    line_start: int = 1
    line_end: int = 1


@dataclass(frozen=True)
class FmcVpnIkePolicy:
    name: str
    encryption: tuple[str, ...]
    integrity: tuple[str, ...]
    dh_group: int | None
    line_start: int
    line_end: int
    is_weak: bool


@dataclass
class ParsedFtdConfig:
    port_objects: list[FmcPortObject] = field(default_factory=list)
    access_rules: list[FmcAccessRule] = field(default_factory=list)
    access_rules_bulk: list[FmcAccessRulesBulk] = field(default_factory=list)
    vpn_ike_policies: list[FmcVpnIkePolicy] = field(default_factory=list)
    network_symbols: dict[str, FmcNetworkSymbol] = field(default_factory=dict)
    rule_resolutions: dict[tuple[int, int | None], object] = field(default_factory=dict)
    defined_resource_addresses: frozenset[str] = field(default_factory=frozenset)
    secret_values: SecretValueSet = field(default_factory=SecretValueSet.empty)


def _strip_quotes(value: Any) -> str:
    if not isinstance(value, str):
        return str(value)
    text = value.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _find_resource_line_range(content: str, resource_type: str, resource_name: str) -> tuple[int, int]:
    lines = content.splitlines()
    header = re.compile(
        rf'^\s*resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"',
        re.IGNORECASE,
    )
    start_idx = None
    for index, line in enumerate(lines):
        if header.match(line):
            start_idx = index
            break
    if start_idx is None:
        return 1, max(1, len(lines))
    depth = 0
    end_idx = start_idx
    for index in range(start_idx, len(lines)):
        depth += lines[index].count("{") - lines[index].count("}")
        end_idx = index
        if index > start_idx and depth <= 0:
            break
    return start_idx + 1, end_idx + 1


def _network_literals(block: Any) -> list[str]:
    values: list[str] = []
    for entry in _as_list(block):
        if not isinstance(entry, dict):
            continue
        if "value" in entry:
            values.append(_strip_quotes(entry["value"]))
            continue
        for literal in _as_list(entry.get("literal")):
            if isinstance(literal, dict) and "value" in literal:
                values.append(_strip_quotes(literal["value"]))
    return values


def _v051_network_blocks(block: Any, nested_key: str) -> list[str]:
    """Parse v0.5.x ``source_networks { source_network { id = ... } }`` blocks."""
    refs: list[str] = []
    for entry in _as_list(block):
        if not isinstance(entry, dict):
            continue
        for nested in _as_list(entry.get(nested_key)):
            if isinstance(nested, dict) and "id" in nested:
                refs.append(_strip_quotes(nested["id"]))
    return refs


def _network_object_entries(block: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for entry in _as_list(block):
        if isinstance(entry, dict) and "id" in entry:
            entries.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        for nested_key in ("objects", "source_network", "destination_network"):
            for nested in _as_list(entry.get(nested_key)):
                if isinstance(nested, dict):
                    entries.append(nested)
    return entries


def _terraform_resource_reference(value: Any) -> str | None:
    text = _strip_quotes(value).strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    if not text or text.startswith("var."):
        return None
    parts = text.split(".")
    if len(parts) < 2:
        return None
    if parts[0] in {"data", "module"}:
        return None
    return f"{parts[0]}.{parts[1]}"


def _collect_network_object_refs(attrs: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    refs: list[tuple[str, str]] = []
    for field in (
        "source_network_objects",
        "destination_network_objects",
        "source_networks",
        "destination_networks",
    ):
        block = attrs.get(field)
        if field.endswith("_networks"):
            nested_key = "source_network" if field.startswith("source") else "destination_network"
            for ref in _v051_network_blocks(block, nested_key):
                address = _terraform_resource_reference(ref)
                if address:
                    refs.append((field, address))
            continue
        for entry in _network_object_entries(block):
            address = _terraform_resource_reference(entry.get("id"))
            if address:
                refs.append((field, address))
    return tuple(refs)


def _intrusion_policy_value(attrs: dict[str, Any]) -> str | None:
    for key in ("intrusion_policy_id", "intrusion_policy", "ips_policy"):
        if key not in attrs:
            continue
        value = attrs.get(key)
        if value is None:
            continue
        text = _strip_quotes(value).strip()
        if text:
            return text
    return None


def _logging_begin(attrs: dict[str, Any]) -> bool | None:
    if "log_connection_begin" in attrs:
        return _bool_attr(attrs, "log_connection_begin")
    return _bool_attr(attrs, "log_begin")


def _logging_end(attrs: dict[str, Any]) -> bool | None:
    if "log_connection_end" in attrs:
        return _bool_attr(attrs, "log_connection_end")
    return _bool_attr(attrs, "log_end")


def _port_literals(block: Any) -> list[str]:
    ports: list[str] = []
    for entry in _as_list(block):
        if not isinstance(entry, dict):
            continue
        if "port" in entry:
            ports.append(_strip_quotes(entry["port"]))
            continue
        for literal in _as_list(entry.get("literal")):
            if isinstance(literal, dict) and "port" in literal:
                ports.append(_strip_quotes(literal["port"]))
    return ports


def _is_open_network_value(value: str) -> bool:
    return value.lower() in _OPEN_NETWORK_VALUES


def _is_open_network(values: tuple[str, ...]) -> bool:
    if not values:
        return True
    return any(_is_open_network_value(value) for value in values)


def _is_permissive_port_object(protocol: str, port: str | None) -> bool:
    protocol_text = protocol.strip().lower()
    if protocol_text in _IP_ETHERTYPES:
        return True
    if protocol_text in {"tcp", "udp", "6", "17"} and (port is None or port.strip() == ""):
        return True
    if port is not None and port.strip().lower() in _OPEN_PORT_VALUES:
        return True
    return False


def _parse_port_attrs(
    *,
    resource_name: str,
    attrs: dict[str, Any],
    line_start: int,
    line_end: int,
) -> FmcPortObject:
    protocol = _strip_quotes(attrs.get("protocol", ""))
    port_raw = attrs.get("port")
    port = _strip_quotes(port_raw) if port_raw is not None else None
    return FmcPortObject(
        name=_strip_quotes(attrs.get("name", resource_name)),
        protocol=protocol,
        port=port,
        line_start=line_start,
        line_end=line_end,
        is_permissive=_is_permissive_port_object(protocol, port),
    )


def _bool_attr(attrs: dict[str, Any], key: str) -> bool | None:
    if key not in attrs:
        return None
    value = attrs.get(key)
    if isinstance(value, bool):
        return value
    text = _strip_quotes(value).lower()
    if text in {"true", "1"}:
        return True
    if text in {"false", "0"}:
        return False
    return None


def _parse_access_rule_attrs(
    *,
    attrs: dict[str, Any],
    resource_name: str,
    line_start: int,
    line_end: int,
    policy_ref: str | None,
    sequence_index: int | None,
) -> FmcAccessRule:
    source_literals = _network_literals(attrs.get("source_network_literals"))
    dest_literals = _network_literals(attrs.get("destination_network_literals"))
    return FmcAccessRule(
        name=_strip_quotes(attrs.get("name", resource_name)),
        action=_strip_quotes(attrs.get("action", "")).upper(),
        enabled=_bool_attr(attrs, "enabled") is not False,
        log_begin=_bool_attr(attrs, "log_begin"),
        log_end=_bool_attr(attrs, "log_end"),
        log_connection_begin=_logging_begin(attrs),
        log_connection_end=_logging_end(attrs),
        intrusion_policy=_intrusion_policy_value(attrs),
        source_networks=tuple(source_literals),
        destination_networks=tuple(dest_literals),
        destination_ports=tuple(_port_literals(attrs.get("destination_port_literals"))),
        network_object_refs=_collect_network_object_refs(attrs),
        line_start=line_start,
        line_end=line_end,
        policy_ref=policy_ref,
        sequence_index=sequence_index,
    )


def _normalize_crypto_token(value: Any) -> str:
    return _strip_quotes(value).lower().replace("-", "").replace("_", "")


def _parse_dh_group(attrs: dict[str, Any]) -> int | None:
    dh_groups_raw = attrs.get("dh_groups")
    if dh_groups_raw is not None:
        weakest: int | None = None
        for item in _as_list(dh_groups_raw):
            try:
                group = int(_strip_quotes(item))
            except ValueError:
                continue
            if weakest is None or group < weakest:
                weakest = group
        return weakest
    dh_group_raw = attrs.get("diffie_hellman_group", attrs.get("group"))
    if dh_group_raw is None:
        return None
    try:
        return int(_strip_quotes(dh_group_raw))
    except ValueError:
        return None


def _parse_vpn_ike_attrs(
    *,
    resource_name: str,
    attrs: dict[str, Any],
    line_start: int,
    line_end: int,
) -> FmcVpnIkePolicy:
    encryption_raw = attrs.get("encryption_algorithms", attrs.get("encryption"))
    integrity_raw = attrs.get("integrity_algorithms", attrs.get("integrity"))
    encryption = tuple(_normalize_crypto_token(item) for item in _as_list(encryption_raw))
    integrity = tuple(_normalize_crypto_token(item) for item in _as_list(integrity_raw))
    dh_group = _parse_dh_group(attrs)
    is_weak = any(item in _WEAK_ENCRYPTION for item in encryption) or any(
        item in _WEAK_INTEGRITY for item in integrity
    )
    if dh_group is not None and dh_group in _WEAK_DH_GROUPS:
        is_weak = True
    return FmcVpnIkePolicy(
        name=_strip_quotes(attrs.get("name", resource_name)),
        encryption=encryption,
        integrity=integrity,
        dh_group=dh_group,
        line_start=line_start,
        line_end=line_end,
        is_weak=is_weak,
    )


def _parse_ikev2_policies_bulk(
    *,
    resource_name: str,
    attrs: dict[str, Any],
    line_start: int,
    line_end: int,
    parsed: ParsedFtdConfig,
) -> None:
    items = attrs.get("items")
    if isinstance(items, dict):
        for item_name, item_attrs in items.items():
            if not isinstance(item_attrs, dict):
                continue
            parsed.vpn_ike_policies.append(
                _parse_vpn_ike_attrs(
                    resource_name=_strip_quotes(item_name),
                    attrs=item_attrs,
                    line_start=line_start,
                    line_end=line_end,
                )
            )
        return
    parsed.vpn_ike_policies.append(
        _parse_vpn_ike_attrs(
            resource_name=resource_name,
            attrs=attrs,
            line_start=line_start,
            line_end=line_end,
        )
    )


def _iter_resources(parsed: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    resources: list[tuple[str, str, dict[str, Any]]] = []
    for block in _as_list(parsed.get("resource")):
        if not isinstance(block, dict):
            continue
        for raw_type, instances in block.items():
            resource_type = _strip_quotes(raw_type)
            if not isinstance(instances, dict):
                continue
            for raw_name, attrs in instances.items():
                resource_name = _strip_quotes(raw_name)
                if isinstance(attrs, dict):
                    resources.append((resource_type, resource_name, attrs))
    return resources


def _parse_ports_bulk(
    *,
    content: str,
    resource_name: str,
    attrs: dict[str, Any],
    line_start: int,
    line_end: int,
    parsed: ParsedFtdConfig,
) -> None:
    items = attrs.get("items")
    if isinstance(items, dict):
        for item_name, item_attrs in items.items():
            if not isinstance(item_attrs, dict):
                continue
            port_obj = _parse_port_attrs(
                resource_name=_strip_quotes(item_name),
                attrs=item_attrs,
                line_start=line_start,
                line_end=line_end,
            )
            parsed.port_objects.append(port_obj)
        return
    parsed.port_objects.append(
        _parse_port_attrs(
            resource_name=resource_name,
            attrs=attrs,
            line_start=line_start,
            line_end=line_end,
        )
    )


def _parse_group_member_refs(attrs: dict[str, Any]) -> tuple[str, ...]:
    refs: list[str] = []
    for entry in _network_object_entries(attrs.get("objects")):
        address = _terraform_resource_reference(entry.get("id"))
        if address:
            refs.append(address)
    return tuple(refs)


def _register_network_symbol(
    parsed: ParsedFtdConfig,
    *,
    resource_type: str,
    resource_name: str,
    attrs: dict[str, Any],
    line_start: int,
    line_end: int,
) -> None:
    address = f"{resource_type}.{resource_name}"
    if resource_type in {"fmc_network", "fmc_networks"}:
        value = _strip_quotes(attrs.get("prefix", attrs.get("value", ""))) or None
        parsed.network_symbols[address] = FmcNetworkSymbol(
            resource_address=address,
            kind="network",
            value=value,
            line_start=line_start,
            line_end=line_end,
        )
        return
    if resource_type in {"fmc_host", "fmc_hosts"}:
        ip = _strip_quotes(attrs.get("ip", attrs.get("value", ""))) or None
        parsed.network_symbols[address] = FmcNetworkSymbol(
            resource_address=address,
            kind="host",
            value=ip,
            line_start=line_start,
            line_end=line_end,
        )
        return
    if resource_type in {"fmc_range", "fmc_ranges"}:
        value = _strip_quotes(attrs.get("ip_range", attrs.get("value", ""))) or None
        parsed.network_symbols[address] = FmcNetworkSymbol(
            resource_address=address,
            kind="range",
            value=value,
            line_start=line_start,
            line_end=line_end,
        )
        return
    if resource_type in {"fmc_network_group", "fmc_network_groups"}:
        parsed.network_symbols[address] = FmcNetworkSymbol(
            resource_address=address,
            kind="group",
            member_refs=_parse_group_member_refs(attrs),
            line_start=line_start,
            line_end=line_end,
        )


def _parse_network_symbols_bulk(
    *,
    resource_type: str,
    resource_name: str,
    attrs: dict[str, Any],
    line_start: int,
    line_end: int,
    parsed: ParsedFtdConfig,
) -> None:
    items = attrs.get("items")
    if isinstance(items, dict):
        for item_name, item_attrs in items.items():
            if not isinstance(item_attrs, dict):
                continue
            _register_network_symbol(
                parsed,
                resource_type=resource_type.removesuffix("s"),
                resource_name=_strip_quotes(item_name),
                attrs=item_attrs,
                line_start=line_start,
                line_end=line_end,
            )
        return
    _register_network_symbol(
        parsed,
        resource_type=resource_type.removesuffix("s"),
        resource_name=resource_name,
        attrs=attrs,
        line_start=line_start,
        line_end=line_end,
    )


def _parse_access_rules_bulk(
    *,
    content: str,
    resource_name: str,
    attrs: dict[str, Any],
    line_start: int,
    line_end: int,
    parsed: ParsedFtdConfig,
) -> None:
    policy_ref = (
        _strip_quotes(
            attrs.get("access_control_policy_id", attrs.get("access_policy_id", ""))
        )
        or None
    )
    rules: list[FmcAccessRule] = []
    items = attrs.get("items")
    for index, item in enumerate(_as_list(items)):
        if not isinstance(item, dict):
            continue
        rules.append(
            _parse_access_rule_attrs(
                attrs=item,
                resource_name=_strip_quotes(item.get("name", f"item-{index}")),
                line_start=line_start,
                line_end=line_end,
                policy_ref=policy_ref,
                sequence_index=index,
            )
        )
    if rules:
        parsed.access_rules_bulk.append(
            FmcAccessRulesBulk(
                policy_ref=policy_ref,
                line_start=line_start,
                line_end=line_end,
                rules=tuple(rules),
            )
        )


def parse_ftd_fmc_config(content: str, *, path: str | None = None) -> ParsedFtdConfig:
    from shift_left.handlers.config.hcl_parse import parse_hcl_content

    status = parse_hcl_content(content, path=path)
    if status.parsed is None:
        return ParsedFtdConfig(secret_values=status.secret_values)

    parsed = ParsedFtdConfig()
    parsed_hcl = status.parsed
    resource_rows = _iter_resources(parsed_hcl)
    parsed.defined_resource_addresses = frozenset(
        f"{resource_type}.{resource_name}"
        for resource_type, resource_name, _attrs in resource_rows
        if resource_type in _NETWORK_OBJECT_RESOURCES
        or resource_type.startswith("fmc_")
    )
    for resource_type, resource_name, attrs in resource_rows:
        line_start, line_end = _find_resource_line_range(content, resource_type, resource_name)
        if resource_type in {"fmc_networks", "fmc_hosts", "fmc_ranges", "fmc_network_groups"}:
            _parse_network_symbols_bulk(
                resource_type=resource_type,
                resource_name=resource_name,
                attrs=attrs,
                line_start=line_start,
                line_end=line_end,
                parsed=parsed,
            )
            continue
        if resource_type in {"fmc_network", "fmc_host", "fmc_range", "fmc_network_group"}:
            _register_network_symbol(
                parsed,
                resource_type=resource_type,
                resource_name=resource_name,
                attrs=attrs,
                line_start=line_start,
                line_end=line_end,
            )
            continue
        if resource_type == "fmc_port":
            parsed.port_objects.append(
                _parse_port_attrs(
                    resource_name=resource_name,
                    attrs=attrs,
                    line_start=line_start,
                    line_end=line_end,
                )
            )
            continue
        if resource_type == "fmc_ports":
            _parse_ports_bulk(
                content=content,
                resource_name=resource_name,
                attrs=attrs,
                line_start=line_start,
                line_end=line_end,
                parsed=parsed,
            )
            continue
        if resource_type == "fmc_access_rule":
            parsed.access_rules.append(
                _parse_access_rule_attrs(
                    attrs=attrs,
                    resource_name=resource_name,
                    line_start=line_start,
                    line_end=line_end,
                    policy_ref=_strip_quotes(
                        attrs.get("access_control_policy_id", attrs.get("access_policy_id", ""))
                    )
                    or None,
                    sequence_index=None,
                )
            )
            continue
        if resource_type == "fmc_access_rules":
            _parse_access_rules_bulk(
                content=content,
                resource_name=resource_name,
                attrs=attrs,
                line_start=line_start,
                line_end=line_end,
                parsed=parsed,
            )
            continue
        if resource_type == "fmc_ikev2_policies":
            _parse_ikev2_policies_bulk(
                resource_name=resource_name,
                attrs=attrs,
                line_start=line_start,
                line_end=line_end,
                parsed=parsed,
            )
            continue
        if resource_type in _IKEV2_POLICY_RESOURCES:
            parsed.vpn_ike_policies.append(
                _parse_vpn_ike_attrs(
                    resource_name=resource_name,
                    attrs=attrs,
                    line_start=line_start,
                    line_end=line_end,
                )
            )
    from shift_left.handlers.config.parsers.ftd.resolver import resolve_ftd_config

    resolve_ftd_config(parsed)
    parsed.secret_values = status.secret_values
    return parsed


def is_management_exposure(rule: FmcAccessRule, source: object) -> bool:
    from shift_left.handlers.config.parsers.ftd.resolver import NetworkResolution

    if rule.action != "ALLOW" or not rule.enabled:
        return False
    if not any(port in _MGMT_PORTS for port in rule.destination_ports):
        return False
    if not isinstance(source, NetworkResolution):
        return False
    if source.failure is not None:
        return False
    if source.has_no_constraint:
        return True
    if source.is_any or source.is_exposed:
        return True
    return False


def _network_allows_non_rfc1918(value: str) -> bool:
    try:
        if "/" in value:
            network = ipaddress.IPv4Network(value, strict=False)
        else:
            network = ipaddress.IPv4Network(f"{value}/32", strict=False)
    except ValueError:
        return False
    private = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if any(network.subnet_of(item) for item in private):
        return False
    return True


def is_block_all_rule(rule: FmcAccessRule, resolution: object) -> bool:
    from shift_left.handlers.config.parsers.ftd.resolver import (
        RuleNetworkResolution,
        is_resolved_catch_all_endpoint,
    )

    if rule.action not in {"BLOCK", "DENY"} or not rule.enabled:
        return False
    if not isinstance(resolution, RuleNetworkResolution):
        return False
    if resolution.source.failure is not None or resolution.destination.failure is not None:
        return False
    return is_resolved_catch_all_endpoint(
        resolution.source
    ) and is_resolved_catch_all_endpoint(resolution.destination)


def is_shadowed_allow_rule(
    rule: FmcAccessRule,
    prior_rules: tuple[FmcAccessRule, ...],
    rule_resolutions: dict[tuple[int, int | None], object],
) -> bool:
    from shift_left.handlers.config.parsers.ftd.resolver import rule_key

    if rule.action != "ALLOW" or not rule.enabled:
        return False
    for prior in prior_rules:
        prior_resolution = rule_resolutions.get(rule_key(prior))
        if prior_resolution is not None and is_block_all_rule(prior, prior_resolution):
            return True
    return False


def is_broad_network_access_rule(rule: FmcAccessRule, resolution: object) -> bool:
    """True when an ALLOW rule's resolved source or destination is internet-wide."""
    from shift_left.handlers.config.parsers.ftd.resolver import (
        RuleNetworkResolution,
        is_resolved_open_endpoint,
    )

    if rule.action != "ALLOW" or not rule.enabled:
        return False
    if not isinstance(resolution, RuleNetworkResolution):
        return False
    if resolution.source.failure is not None or resolution.destination.failure is not None:
        return False
    return is_resolved_open_endpoint(resolution.source) or is_resolved_open_endpoint(
        resolution.destination
    )


def is_missing_allow_logging(rule: FmcAccessRule) -> bool:
    if rule.action != "ALLOW" or not rule.enabled:
        return False
    if rule.log_connection_begin is True or rule.log_begin is True:
        return False
    if rule.log_connection_end is True or rule.log_end is True:
        return False
    return True


def is_missing_intrusion_policy(rule: FmcAccessRule) -> bool:
    if rule.action != "ALLOW" or not rule.enabled:
        return False
    return rule.intrusion_policy is None


def unresolved_network_object_refs(
    rule: FmcAccessRule,
    symbols: dict[str, FmcNetworkSymbol],
) -> tuple[tuple[str, str], ...]:
    from shift_left.handlers.config.parsers.ftd.resolver import (
        _resolve_symbol_address,
        is_unresolved_endpoint,
    )

    unresolved: list[tuple[str, str]] = []
    for field, address in rule.network_object_refs:
        resolved = _resolve_symbol_address(
            address,
            symbols=symbols,
            stack=(),
            depth=0,
        )
        if is_unresolved_endpoint(resolved):
            unresolved.append((field, address))
    return tuple(unresolved)


# CiscoDevNet/fmc v2.0.1 resource attribute baseline — loaded from validation/schemas/.
@lru_cache(maxsize=1)
def _load_fmc_provider_schema() -> dict[str, object]:
    data = json.loads(_fmc_provider_schema_path().read_text(encoding="utf-8"))
    return data


@lru_cache(maxsize=1)
def fmc_provider_resources() -> dict[str, frozenset[str]]:
    data = _load_fmc_provider_schema()
    resources = data.get("resources", {})
    return {
        str(resource_type): frozenset(str(attr) for attr in attributes)
        for resource_type, attributes in resources.items()
    }


@lru_cache(maxsize=1)
def fmc_resolver_membership_attributes() -> dict[str, frozenset[str]]:
    data = _load_fmc_provider_schema()
    raw = data.get("resolver_membership_attributes", {})
    return {
        str(resource_type): frozenset(str(attr) for attr in attributes)
        for resource_type, attributes in raw.items()
    }


# Module-level dict for existing importers (loaded from validation/schemas/fmc-2.0.1-schema.json).
FMC_PROVIDER_RESOURCES_V201 = fmc_provider_resources()

FTD_RULE_SCHEMA_DEPS: dict[str, tuple[tuple[str, frozenset[str]], ...]] = {
    "FTD-001": (
        ("fmc_access_rule", frozenset({"action", "enabled", "source_network_literals", "destination_network_literals"})),
        ("fmc_access_rules", frozenset({"items"})),
    ),
    "FTD-002": (
        ("fmc_port", frozenset({"protocol", "port"})),
        ("fmc_ports", frozenset({"items"})),
    ),
    "FTD-003": (
        (
            "fmc_access_rule",
            frozenset({"action", "enabled", "log_connection_begin", "log_connection_end"}),
        ),
        ("fmc_access_rules", frozenset({"items"})),
    ),
    "FTD-004": (
        (
            "fmc_ikev2_policy",
            frozenset({"encryption_algorithms", "integrity_algorithms", "dh_groups"}),
        ),
        ("fmc_ikev2_policies", frozenset({"items"})),
    ),
    "FTD-005": (
        (
            "fmc_access_rule",
            frozenset({"action", "enabled", "source_network_literals", "destination_port_literals"}),
        ),
        ("fmc_access_rules", frozenset({"items"})),
    ),
    "FTD-006": (("fmc_access_rules", frozenset({"items"})),),
    "FTD-007": (
        (
            "fmc_access_rule",
            frozenset({"action", "enabled", "intrusion_policy_id"}),
        ),
        ("fmc_access_rules", frozenset({"items"})),
    ),
    "FTD-008": (
        (
            "fmc_access_rule",
            frozenset({"source_network_objects", "destination_network_objects"}),
        ),
        ("fmc_access_rules", frozenset({"items"})),
    ),
}


def audit_ftd_rule_schema() -> list[dict[str, object]]:
    """Return schema-validity audit rows for enabled FTD rules."""
    from shift_left.handlers.config.rules.registry import ALL_RULES

    rows: list[dict[str, object]] = []
    for rule in sorted(ALL_RULES, key=lambda item: item.id):
        if not rule.id.startswith("FTD-") or not rule.enabled:
            continue
        deps = FTD_RULE_SCHEMA_DEPS.get(rule.id, ())
        resource_rows: list[dict[str, object]] = []
        all_valid = True
        for resource_type, attributes in deps:
            known_attrs = FMC_PROVIDER_RESOURCES_V201.get(resource_type, frozenset())
            resource_valid = resource_type in FMC_PROVIDER_RESOURCES_V201
            attr_rows = []
            for attr in sorted(attributes):
                exists = attr in known_attrs if resource_valid else False
                if not exists:
                    all_valid = False
                attr_rows.append({"attribute": attr, "exists_in_provider": exists})
            resource_rows.append(
                {
                    "resource_type": resource_type,
                    "exists_in_provider": resource_valid,
                    "attributes": attr_rows,
                }
            )
        rows.append(
            {
                "rule_id": rule.id,
                "schema_valid": all_valid,
                "resources": resource_rows,
            }
        )
    return rows


def audit_ftd_resolver_schema() -> list[dict[str, object]]:
    """Verify resolver membership attribute names against the FMC v2.0.1 schema."""
    resources = fmc_provider_resources()
    resolver_attrs = fmc_resolver_membership_attributes()
    parser_usage = {
        "fmc_network": "prefix",
        "fmc_host": "ip",
        "fmc_range": "ip_range",
        "fmc_network_group": "objects",
    }
    rows: list[dict[str, object]] = []
    for resource_type, attr in sorted(parser_usage.items()):
        known_attrs = resources.get(resource_type, frozenset())
        schema_attrs = resolver_attrs.get(resource_type, frozenset())
        rows.append(
            {
                "resource_type": resource_type,
                "parser_attribute": attr,
                "exists_in_provider": attr in known_attrs,
                "listed_in_resolver_schema": attr in schema_attrs,
                "resource_exists_in_provider": resource_type in resources,
            }
        )
    return rows
