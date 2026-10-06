"""Grounding checks for model prose (identifiers, IPs, CIDRs vs supplied config)."""

from __future__ import annotations

import re
from typing import Any

_IP_CIDR_RE = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|::/0|(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]*(?:/\d{1,3})?)\b",
    re.IGNORECASE,
)

_IDENTIFIER_RE = re.compile(
    r"`([^`]+)`|\"([A-Za-z0-9_./:-]{2,64})\"|'([A-Za-z0-9_./:-]{2,64})'|"
    r"\b([A-Z][A-Z0-9_-]{2,})\b|"
    r"\b(fmc_[a-z_]+\.[A-Za-z0-9_]+)\b|"
    r"\b(object-group\s+[A-Za-z0-9_-]+)\b|"
    r"\b([A-Za-z0-9_.-]*\d[A-Za-z0-9_.-]*)\b",
)

_CLI_NAME_PATTERNS = (
    re.compile(r"^\s*hostname\s+(\S+)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*interface\s+(\S+)", re.MULTILINE | re.IGNORECASE),
    re.compile(
        r"^\s*object(?:-group)?\s+(?:network|service)\s+(\S+)",
        re.MULTILINE | re.IGNORECASE,
    ),
    re.compile(r"^\s*object\s+network\s+(\S+)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*access-list\s+(\S+)", re.MULTILINE | re.IGNORECASE),
    re.compile(r'resource\s+"[^"]+"\s+"([^"]+)"', re.MULTILINE),
)


def known_config_literals(config_content: str) -> set[str]:
    known: set[str] = set()
    for match in _IP_CIDR_RE.finditer(config_content):
        known.add(match.group(0).lower())
    for match in re.finditer(r'"([^"]{1,96})"', config_content):
        known.add(match.group(1).lower())
    for match in re.finditer(r"'([^']{1,96})'", config_content):
        known.add(match.group(1).lower())
    for pattern in _CLI_NAME_PATTERNS:
        for match in pattern.finditer(config_content):
            known.add(match.group(1).lower())
    for match in re.finditer(
        r"^\s*(?:transport input|name|policy-map|class-map)\s+(.+)$",
        config_content,
        re.MULTILINE | re.IGNORECASE,
    ):
        for token in re.split(r"\s+", match.group(1).strip()):
            if token and not token.isdigit():
                known.add(token.lower())
    return known


def _is_grounded(token: str, known: set[str]) -> bool:
    lowered = token.strip().lower()
    if not lowered:
        return True
    if lowered in known:
        return True
    return any(lowered in item or item in lowered for item in known)


def _is_config_like_reference(token: str) -> bool:
    if _IP_CIDR_RE.fullmatch(token):
        return True
    if re.search(r"[_./:-]", token):
        return True
    if re.search(r"\d", token):
        return True
    if token.isupper() and len(token) >= 3:
        return True
    if token.lower().startswith("fmc_"):
        return True
    return False


def response_reference_tokens(response: str) -> list[str]:
    refs: list[str] = []
    for match in _IDENTIFIER_RE.finditer(response):
        token = next(group for group in match.groups() if group)
        if _is_config_like_reference(token):
            refs.append(token)
    for match in _IP_CIDR_RE.finditer(response):
        refs.append(match.group(0))
    return refs


def grounding_tokens(response: str, config_content: str) -> tuple[list[str], list[str]]:
    """Return (grounded_refs, ungrounded_refs) for identifiers, IPs, and CIDRs."""
    known = known_config_literals(config_content)
    grounded: list[str] = []
    ungrounded: list[str] = []
    seen: set[str] = set()

    for token in response_reference_tokens(response):
        key = token.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        if _is_grounded(token, known):
            grounded.append(token)
        else:
            ungrounded.append(token)

    return grounded, ungrounded


def score_grounding(response: str, config_content: str) -> dict[str, Any]:
    grounded, ungrounded = grounding_tokens(response, config_content)
    total = len(grounded) + len(ungrounded)
    return {
        "grounded_reference_count": len(grounded),
        "ungrounded_reference_count": len(ungrounded),
        "total_reference_count": total,
        "ungrounded_rate": round(len(ungrounded) / total, 4) if total else 0.0,
        "has_ungrounded_references": bool(ungrounded),
        "ungrounded_references": ungrounded[:25],
    }


def aggregate_grounding(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total_refs = sum(int(row.get("total_reference_count") or 0) for row in rows)
    ungrounded_refs = sum(int(row.get("ungrounded_reference_count") or 0) for row in rows)
    files_with = sum(1 for row in rows if row.get("has_ungrounded_references"))
    return {
        "file_count": len(rows),
        "files_with_ungrounded_references": files_with,
        "files_with_ungrounded_rate": round(files_with / len(rows), 4) if rows else 0.0,
        "ungrounded_reference_count": ungrounded_refs,
        "total_reference_count": total_refs,
        "ungrounded_reference_rate": round(ungrounded_refs / total_refs, 4) if total_refs else 0.0,
    }
