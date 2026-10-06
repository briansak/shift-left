"""Network value helpers for NX-OS resolved ACE evaluation."""

from __future__ import annotations

from shift_left.handlers.config.parsers.ios_xe.network import (
    allows_non_rfc1918,
    is_any_network,
    is_resolved_permissive_ace,
    is_rfc1918_network,
    network_from_value,
)

from shift_left.handlers.config.parsers.nx_os.parser import AccessListEntry
from shift_left.handlers.config.parsers.nx_os.resolver import ResolvedAce

__all__ = [
    "allows_non_rfc1918",
    "is_any_network",
    "is_resolved_permissive_ace",
    "is_rfc1918_network",
    "network_from_value",
    "is_resolved_permissive_ace_nx",
]


def is_resolved_permissive_ace_nx(resolved: ResolvedAce, entry: AccessListEntry) -> bool:
    return is_resolved_permissive_ace(resolved, entry)
