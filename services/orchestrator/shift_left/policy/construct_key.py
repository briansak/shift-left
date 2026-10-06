"""Line-independent construct identity for Constitution VIII waivers.

Waiver identity is path + construct + weakness class. Line numbers are display
only; commit SHA remains the freshness control.
"""

from __future__ import annotations

import re

_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    return _WS.sub(" ", (text or "").strip().lower())


def ace(acl_name: str, raw: str) -> str:
    return f"ace:{normalize(acl_name)}:{normalize(raw)}"


def named_object(name: str) -> str:
    return f"object:{normalize(name)}"


def crypto(kind: str, name: str) -> str:
    return f"crypto:{normalize(kind)}:{normalize(name)}"


def unparsed(raw: str) -> str:
    return f"unparsed:{normalize(raw)}"


def unresolved(ref_kind: str, ref_name: str) -> str:
    return f"unresolved:{normalize(ref_kind)}:{normalize(ref_name)}"


def directive(raw: str) -> str:
    return f"directive:{normalize(raw)}"


def interface(name: str) -> str:
    return f"interface:{normalize(name)}"


def line_block(line_type: str, marker: str) -> str:
    return f"line:{normalize(line_type)}:{normalize(marker)}"


def resource(resource_type: str, resource_name: str) -> str:
    return f"resource:{normalize(resource_type)}.{normalize(resource_name)}"


def ftd_rule(name: str, sequence_index: int | None) -> str:
    seq = sequence_index if sequence_index is not None else 0
    return f"rule:{normalize(name)}:seq:{seq}"


def feature(name: str) -> str:
    return f"feature:{normalize(name)}"


def role(name: str) -> str:
    return f"role:{normalize(name)}"


def provider(prefix: str) -> str:
    return f"provider:{normalize(prefix)}"


def snippet(matched: str) -> str:
    return f"snippet:{normalize(matched)}"


def file_scope() -> str:
    return "file"


def management(service: str, network: str, mask: str, interface_name: str) -> str:
    return (
        f"mgmt:{normalize(service)}:{normalize(network)}:"
        f"{normalize(mask)}:{normalize(interface_name)}"
    )
