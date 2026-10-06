"""Harness validation for constrained-output model eval (Experiment B)."""

from __future__ import annotations

from typing import Any


def _line_count(content: str) -> int:
    if not content:
        return 1
    return max(1, content.count("\n") + (0 if content.endswith("\n") else 1))


def _finding_line_bounds(finding: dict[str, Any]) -> tuple[int, int]:
    start = int(finding.get("line_start") or 0)
    end = int(finding.get("line_end") or start)
    if start <= 0:
        return 0, 0
    if end < start:
        end = start
    return start, end


def validate_constrained_finding(
    finding: dict[str, Any],
    *,
    content: str,
    line_min: int,
    line_max: int,
) -> tuple[bool, str | None]:
    """Return (valid, rejection_reason). Reasons: missing_evidence, evidence_not_substring, line_out_of_range."""
    evidence = finding.get("evidence")
    if evidence is None or not str(evidence).strip():
        return False, "missing_evidence"

    evidence_text = str(evidence)
    if evidence_text not in content:
        return False, "evidence_not_substring"

    start, end = _finding_line_bounds(finding)
    if start <= 0:
        return False, "line_out_of_range"
    if start < line_min or end > line_max:
        return False, "line_out_of_range"
    if end > _line_count(content):
        return False, "line_out_of_range"

    return True, None


def partition_constrained_findings(
    findings: list[dict[str, Any]],
    *,
    content: str,
    line_min: int,
    line_max: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    valid: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    for finding in findings:
        ok, reason = validate_constrained_finding(
            finding,
            content=content,
            line_min=line_min,
            line_max=line_max,
        )
        if ok:
            valid.append(finding)
        else:
            invalid.append({**finding, "rejection_reason": reason})
    return valid, invalid


def summarize_rejections(invalid_findings: list[dict[str, Any]]) -> dict[str, int]:
    tally: dict[str, int] = {}
    for item in invalid_findings:
        reason = str(item.get("rejection_reason") or "unknown")
        tally[reason] = tally.get(reason, 0) + 1
    return tally
