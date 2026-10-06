"""Detection-only scoring for cookbook prose responses (Experiment F)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from model_eval_matching import RuleSemantic, semantic_fit_score

# Calibrated on cookbook prose (Experiment F); see cookbook-semantic-fit-calibration.json.
COOKBOOK_DETECTION_THRESHOLD = 0.70


def prose_semantic_fit(prose: str, sem: RuleSemantic) -> float:
    """Score how well free-form prose describes a registry defect summary."""
    return semantic_fit_score(
        {
            "title": "",
            "description": prose,
            "evidence": "",
            "trace": "",
        },
        sem,
    )


def defect_detected(
    prose: str,
    *,
    defect_summary: str,
    rule_id: str,
    target_type: str,
    threshold: float = COOKBOOK_DETECTION_THRESHOLD,
) -> tuple[bool, float]:
    sem = RuleSemantic(
        rule_id=rule_id,
        target_type=target_type,
        cwe="",
        semantic_key=f"{target_type}/{rule_id}",
        defect_summary=defect_summary,
    )
    score = prose_semantic_fit(prose, sem)
    return score >= threshold, score


def score_detection_recall(
    rows: list[dict[str, Any]],
    *,
    target_type_field: str = "target_type",
) -> dict[str, Any]:
    total = len(rows)
    detected = sum(1 for row in rows if row.get("detected"))
    per_target: dict[str, dict[str, int | float]] = defaultdict(
        lambda: {"total": 0, "detected": 0, "recall": 0.0}
    )
    for row in rows:
        target_type = str(row.get(target_type_field) or "unknown")
        bucket = per_target[target_type]
        bucket["total"] = int(bucket["total"]) + 1
        if row.get("detected"):
            bucket["detected"] = int(bucket["detected"]) + 1

    for bucket in per_target.values():
        bucket_total = int(bucket["total"])
        bucket["recall"] = round(int(bucket["detected"]) / bucket_total, 4) if bucket_total else 0.0

    return {
        "labeled_defects": total,
        "detected": detected,
        "missed": total - detected,
        "recall": round(detected / total, 4) if total else 0.0,
        "semantic_fit_threshold": COOKBOOK_DETECTION_THRESHOLD,
        "per_target_type": dict(sorted(per_target.items())),
    }
