"""Adjudication helpers for Experiment G contextual remediation quality."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

_CANDIDATE_RE = re.compile(
    r"`([^`]+)`|\"([A-Za-z0-9_./:-]{2,64})\"|'([A-Za-z0-9_./:-]{2,64})'|"
    r"\b([A-Z][A-Z0-9_-]{2,})\b|"
    r"\b(fmc_[a-z_]+\.[A-Za-z0-9_]+)\b|"
    r"\b(object-group\s+[A-Za-z0-9_-]+)\b",
    re.IGNORECASE,
)

_STOPWORDS = frozenset(
    {
        "the",
        "and",
        "for",
        "with",
        "from",
        "that",
        "this",
        "change",
        "replace",
        "update",
        "remove",
        "add",
        "use",
        "set",
        "enable",
        "disable",
        "high",
        "medium",
        "low",
        "allow",
        "deny",
        "rule",
        "access",
        "network",
        "object",
        "group",
        "tcp",
        "udp",
        "ip",
        "ssh",
        "https",
        "http",
        "true",
        "false",
        "aes",
        "sha",
        "md5",
        "des",
        "cwe",
    }
)


def _normalize_known(known: set[str] | tuple[str, ...]) -> set[str]:
    return {item.strip().lower() for item in known if item and str(item).strip()}


def candidate_references(remediation: str) -> list[str]:
    refs: list[str] = []
    for match in _CANDIDATE_RE.finditer(remediation):
        token = next(group for group in match.groups() if group)
        if token.lower() in _STOPWORDS:
            continue
        if token.isdigit():
            continue
        refs.append(token)
    return refs


def invented_reference_candidates(
    remediation: str,
    known_identifiers: set[str] | tuple[str, ...],
) -> list[str]:
    known = _normalize_known(known_identifiers)
    invented: list[str] = []
    for token in candidate_references(remediation):
        lowered = token.lower()
        if lowered in known:
            continue
        if any(lowered in known_item or known_item in lowered for known_item in known):
            continue
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?", token):
            if lowered in known:
                continue
        invented.append(token)
    return invented


def deterministic_sample(
    rows: list[dict[str, Any]],
    *,
    sample_size: int,
) -> list[dict[str, Any]]:
    if len(rows) <= sample_size:
        return list(rows)

    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_type[row["target_type"]].append(row)
    for bucket in by_type.values():
        bucket.sort(key=lambda item: item["instance_id"])

    selected: list[dict[str, Any]] = []
    type_order = sorted(by_type)
    while len(selected) < sample_size:
        progressed = False
        for target_type in type_order:
            bucket = by_type[target_type]
            if not bucket:
                continue
            selected.append(bucket.pop(0))
            progressed = True
            if len(selected) >= sample_size:
                break
        if not progressed:
            break
    return selected[:sample_size]


def format_adjudication_worksheet(rows: list[dict[str, Any]]) -> str:
    lines = [
        "=== Experiment G: contextual remediation adjudication sample ===",
        "Score each response:",
        "  (a) references only objects/addresses present in file (fabrication check)",
        "  (b) proposed change would resolve the flagged defect",
        "  (c) more specific than registry static remediation",
        "",
    ]
    for index, row in enumerate(rows, start=1):
        invented = row.get("invented_reference_candidates") or []
        lines.extend(
            [
                f"--- [{index}] {row['instance_id']} ---",
                f"Rule/CWE: {row['rule_id']} / {row['cwe']}",
                f"Defect summary: {row['defect_summary']}",
                f"Registry remediation: {row['registry_remediation']}",
                f"Known identifiers ({len(row.get('known_identifiers') or [])}): "
                f"{', '.join((row.get('known_identifiers') or [])[:25])}"
                f"{'...' if len(row.get('known_identifiers') or []) > 25 else ''}",
                f"Heuristic invented-reference candidates: {invented or '(none)'}",
                "",
                "Model remediation:",
                row.get("model_response") or "(missing)",
                "",
            ]
        )
    return "\n".join(lines) + "\n"
