"""Parse and score CTIBench-RCM-shaped CWE predictions."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

_CWE_LINE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
_CWE_ANY_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_CWE_WITH_SUFFIX_RE = re.compile(r"CWE-(\d+)\s*:", re.IGNORECASE)
_BARE_CWE_NUMBER_RE = re.compile(r"^(\d+)\s*\.?\s*$")


def parse_predicted_cwe_legacy(response: str) -> str | None:
    """Original parser (final-line exact CWE or last CWE token in text)."""
    text = (response or "").strip()
    if not text:
        return None

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines:
        last_line = lines[-1]
        if _CWE_LINE_RE.fullmatch(last_line):
            return last_line.upper()

    matches = _CWE_ANY_RE.findall(text)
    if not matches:
        return None
    return matches[-1].upper()


def parse_predicted_cwe(response: str, *, after_the_cwe_is: bool = False) -> str | None:
    """Extract CWE ID from completion suffix or multi-line CTIBench response."""
    text = (response or "").strip()
    if not text:
        return None

    # 5-shot suffix: bare number with optional trailing period (e.g. "778.")
    if after_the_cwe_is or "\n" not in text:
        bare = _BARE_CWE_NUMBER_RE.fullmatch(text)
        if bare:
            return f"CWE-{bare.group(1)}"

    # CWE-284: trailing prose (same line)
    suffix_match = _CWE_WITH_SUFFIX_RE.search(text)
    if suffix_match:
        return f"CWE-{suffix_match.group(1)}"

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines:
        last_line = lines[-1]
        if _CWE_LINE_RE.fullmatch(last_line):
            return last_line.upper()
        bare_line = _BARE_CWE_NUMBER_RE.fullmatch(last_line)
        if bare_line:
            return f"CWE-{bare_line.group(1)}"

    matches = _CWE_ANY_RE.findall(text)
    if not matches:
        return None
    return matches[-1].upper()


def score_predictions(
    rows: list[dict[str, Any]],
    *,
    label_field: str = "expected_cwe",
    prediction_field: str = "predicted_cwe",
    target_type_field: str = "target_type",
    parser: Any = None,
    after_the_cwe_is: bool = False,
) -> dict[str, Any]:
    parse = parser or (
        lambda response: parse_predicted_cwe(response, after_the_cwe_is=after_the_cwe_is)
    )

    scored_rows: list[dict[str, Any]] = []
    for row in rows:
        if parser is not None:
            predicted = parse(str(row.get("model_response") or ""))
        else:
            predicted = row.get(prediction_field)
            if prediction_field not in row or predicted is None:
                predicted = parse(str(row.get("model_response") or ""))
        scored_rows.append({**row, prediction_field: predicted})

    total = len(scored_rows)
    correct = sum(
        1
        for row in scored_rows
        if row.get(prediction_field) and row.get(prediction_field) == row.get(label_field)
    )
    per_target: dict[str, dict[str, int | float]] = defaultdict(
        lambda: {"total": 0, "correct": 0, "accuracy": 0.0}
    )
    for row in scored_rows:
        target_type = str(row.get(target_type_field) or "unknown")
        bucket = per_target[target_type]
        bucket["total"] = int(bucket["total"]) + 1
        if row.get(prediction_field) == row.get(label_field):
            bucket["correct"] = int(bucket["correct"]) + 1

    for bucket in per_target.values():
        total_for_type = int(bucket["total"])
        bucket["accuracy"] = round(int(bucket["correct"]) / total_for_type, 4) if total_for_type else 0.0

    invalid = sum(1 for row in scored_rows if not row.get(prediction_field))
    return {
        "total": total,
        "correct": correct,
        "incorrect": total - correct - invalid,
        "invalid_predictions": invalid,
        "accuracy": round(correct / total, 4) if total else 0.0,
        "per_target_type": dict(sorted(per_target.items())),
        "rows": scored_rows,
    }


def completion_token_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tokens = [int(row.get("completion_tokens") or 0) for row in rows]
    hit_max = sum(1 for row in rows if row.get("hit_max_tokens"))
    if not tokens:
        return {"count": 0, "mean": 0.0, "max": 0, "hit_max_tokens": hit_max}
    return {
        "count": len(tokens),
        "mean": round(sum(tokens) / len(tokens), 1),
        "max": max(tokens),
        "hit_max_tokens": hit_max,
    }


def rescore_rows(
    rows: list[dict[str, Any]],
    *,
    after_the_cwe_is: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    """Return legacy summary, corrected summary, and newly-valid count."""
    legacy = score_predictions(
        rows,
        parser=parse_predicted_cwe_legacy,
        after_the_cwe_is=False,
    )
    corrected = score_predictions(
        rows,
        parser=lambda response: parse_predicted_cwe(response, after_the_cwe_is=after_the_cwe_is),
        after_the_cwe_is=after_the_cwe_is,
    )
    legacy_invalid_ids = {
        row["instance_id"]
        for row in legacy["rows"]
        if not row.get("predicted_cwe")
    }
    newly_valid = sum(
        1
        for row in corrected["rows"]
        if row["instance_id"] in legacy_invalid_ids and row.get("predicted_cwe")
    )
    return legacy, corrected, newly_valid
