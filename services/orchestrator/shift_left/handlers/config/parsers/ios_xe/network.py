"""Network value helpers for IOS-XE resolved ACE evaluation."""

from __future__ import annotations

import ipaddress

from shift_left.handlers.config.parsers.ios_xe.parser import AccessListEntry
from shift_left.handlers.config.parsers.ios_xe.resolver import ResolvedAce

_PRIVATE_NETS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def is_any_network(value: str) -> bool:
    if value == "any":
        return True
    if value.startswith("net:"):
        _, mask = value[4:].split("/", 1)
        return mask in {"0.0.0.0", "255.255.255.255"}
    return False


def network_from_value(value: str) -> ipaddress.IPv4Network | None:
    if value == "any" or value == "*":
        return None
    if value.startswith("host:"):
        host = value.removeprefix("host:")
        try:
            return ipaddress.IPv4Network(f"{host}/32", strict=False)
        except ValueError:
            return None
    if value.startswith("net:"):
        body = value.removeprefix("net:")
        address, mask = body.split("/", 1)
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
            return ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
        except ValueError:
            return None
    return None


def is_rfc1918_network(value: str) -> bool:
    network = network_from_value(value)
    if network is None:
        return False
    return any(network.subnet_of(private) for private in _PRIVATE_NETS)


def allows_non_rfc1918(values: tuple[str, ...]) -> bool:
    if not values:
        return False
    if any(is_any_network(value) for value in values):
        return True
    if any(value == "*" for value in values):
        return True
    return any(not is_rfc1918_network(value) for value in values if network_from_value(value))


def is_resolved_permissive_ace(resolved: ResolvedAce, entry: AccessListEntry) -> bool:
    if entry.action != "permit":
        return False
    if resolved.unresolved:
        return False
    if not resolved.source_values or not resolved.destination_values:
        return False
    source_open = all(is_any_network(value) for value in resolved.source_values)
    dest_open = all(is_any_network(value) for value in resolved.destination_values)
    if not (source_open and dest_open):
        return False
    return entry.protocol in {"ip", "icmp", "tcp", "udp"}
