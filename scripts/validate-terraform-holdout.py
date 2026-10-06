#!/usr/bin/env python3
"""Validate Terraform handler rules against the held-out real-file set."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "services" / "orchestrator"
FSEC = ROOT / "services" / "foundation-sec-server"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ORCH, FSEC):
    sys.path.insert(0, str(path))

from foundation_sec_server.handlers.registry import DEFAULT_REGISTRY, TERRAFORM  # noqa: E402
from foundation_sec_server.preprocess import strip_inactive_lines  # noqa: E402
from shift_left.handlers.config.parsers.terraform_hcl import (  # noqa: E402
    TERRAFORM_RULE_SPECS,
    match_terraform_hcl_rules,
)

HOLDOUT = ROOT / "validation" / "holdout-terraform"
MANIFEST = HOLDOUT / "manifest.json"


def _evaluate_file(rel: str, content: str) -> dict:
    active, stripped = strip_inactive_lines(content, TERRAFORM)
    matches = match_terraform_hcl_rules(chunk_content=active)
    matched = [item for item in matches if item.evaluation_status == "matched"]
    unevaluated = [item for item in matches if item.evaluation_status == "unevaluated"]
    return {
        "path": rel,
        "stripped_comment_lines": stripped,
        "matched_rules": [item.pattern_id for item in matched],
        "unevaluated_rules": [item.pattern_id for item in unevaluated],
        "line_ranges": [
            {"rule": item.pattern_id, "start": item.line_start, "end": item.line_end}
            for item in matches
        ],
    }


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    entries = manifest.get("entries", [])
    rows = []
    false_positives: list[dict] = []
    false_negatives: list[dict] = []
    unevaluated_ok: list[dict] = []
    unrestricted_total = 0
    unrestricted_caught = 0

    for entry in entries:
        rel = entry["path"]
        content = (HOLDOUT / rel).read_text()
        row = _evaluate_file(rel, content)
        row["expect_flagged"] = bool(entry.get("expect_flagged"))
        row["expect_unevaluated"] = bool(entry.get("expect_unevaluated"))
        row["expected_rule"] = entry.get("expected_rule")
        row["source"] = entry.get("source")
        rows.append(row)

        matched = row["matched_rules"]
        if entry.get("expect_flagged"):
            unrestricted_total += 1
            if matched:
                unrestricted_caught += 1
            else:
                false_negatives.append(
                    {
                        "path": rel,
                        "content": content,
                        "reason": "expected unrestricted ingress match",
                    }
                )
        elif entry.get("expect_unevaluated"):
            if not row["unevaluated_rules"]:
                false_negatives.append(
                    {
                        "path": rel,
                        "content": content,
                        "reason": "expected unevaluated handler status",
                    }
                )
            else:
                unevaluated_ok.append(row)
        elif matched:
            false_positives.append(
                {
                    "path": rel,
                    "content": content,
                    "matched_rules": matched,
                }
            )

    per_rule: dict[str, dict] = {}
    for spec in TERRAFORM_RULE_SPECS:
        tp = fp = fn = 0
        fp_items: list[str] = []
        fn_items: list[str] = []
        for entry in entries:
            rel = entry["path"]
            row = next(item for item in rows if item["path"] == rel)
            matched = spec.id in row["matched_rules"]
            if entry.get("expected_rule") == spec.id:
                if matched:
                    tp += 1
                else:
                    fn += 1
                    fn_items.append(rel)
            elif entry.get("expect_flagged"):
                if matched and entry.get("expected_rule") != spec.id:
                    fp += 1
                    fp_items.append(rel)
            elif not entry.get("expect_unevaluated") and matched:
                fp += 1
                fp_items.append(rel)
        precision = round(tp / (tp + fp), 3) if (tp + fp) else None
        recall = round(tp / (tp + fn), 3) if (tp + fn) else None
        per_rule[spec.id] = {
            "provider": spec.provider,
            "covers": list(spec.covers),
            "does_not_cover": list(spec.does_not_cover),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "false_positive_items": fp_items,
            "false_negative_items": fn_items,
        }

    model_only_rate_note = (
        "Model-only rate requires Foundation-Sec inference on holdout files; "
        "run real-inference validation separately. Handler-only coverage is reported here."
    )

    report = {
        "holdout_entries": rows,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "unevaluated_expected": unevaluated_ok,
        "unrestricted_ingress": {
            "total": unrestricted_total,
            "caught_by_handlers": unrestricted_caught,
            "missed": unrestricted_total - unrestricted_caught,
        },
        "per_rule": per_rule,
        "rule_specs": [
            {
                "id": spec.id,
                "provider": spec.provider,
                "resource_types": sorted(spec.resource_types),
                "attribute_condition": spec.attribute_condition,
                "handler_asserted_cwe": spec.cwe,
                "covers": list(spec.covers),
                "does_not_cover": list(spec.does_not_cover),
                "description": spec.description,
            }
            for spec in TERRAFORM_RULE_SPECS
        ],
        "notes": {"model_only_rate": model_only_rate_note},
    }

    out = ROOT / "validation" / "reports" / "terraform-holdout-validation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 1 if false_positives or false_negatives else 0


if __name__ == "__main__":
    raise SystemExit(main())
