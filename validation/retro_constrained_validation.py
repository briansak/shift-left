#!/usr/bin/env python3
"""Retroactively apply constrained_finding_validation to cached findings (no inference)."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
VALIDATION = ROOT / "validation"
for path in (SHARED, ORCH, VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from constrained_finding_validation import (  # noqa: E402
    partition_constrained_findings,
    summarize_rejections,
)
from eval_model import RULE_SEMANTICS, is_model_originated  # noqa: E402
from model_eval_matching import (  # noqa: E402
    MATCHER_BEST_FIT,
    MATCHER_METADATA,
    MetricCounts,
    ModelMetricCounts,
    aggregate_model_metrics,
    build_per_rule_report,
    score_file,
)
from report_quant_stamping import merge_quant_metadata  # noqa: E402
from rescore_model_reports import _corpus_dir, _entry_from_record  # noqa: E402
from shift_left.ui.cwe_dictionary import unrecognized_model_cwe_tally  # noqa: E402

FINDINGS_CACHE_DIR = ROOT / "validation" / "reports" / "findings-cache"
REPORTS = ROOT / "validation" / "reports"

RUNS = (
    (
        "baseline",
        FINDINGS_CACHE_DIR / "baseline.findings.json",
        REPORTS / "model-vs-handler.json",
        REPORTS / "model-vs-handler-retro-constrained.json",
    ),
    (
        "platform_specific",
        FINDINGS_CACHE_DIR / "platform_specific.findings.json",
        REPORTS / "model-vs-handler-platform-specific.json",
        REPORTS / "model-vs-handler-platform-specific-retro-constrained.json",
    ),
)


def _line_count(content: str) -> int:
    if not content:
        return 1
    return max(1, content.count("\n") + (0 if content.endswith("\n") else 1))


def retro_validate_cache(
    records: list[dict[str, Any]],
    *,
    prompt_variant: str,
) -> dict[str, Any]:
    handler_stats: dict[str, dict[str, MetricCounts]] = {}
    model_stats: dict[str, dict[str, ModelMetricCounts]] = {}
    unlabeled_model_findings: list[dict[str, Any]] = []
    all_surviving: list[dict[str, Any]] = []
    invalid_findings: list[dict[str, Any]] = []
    emitted = 0

    for record in records:
        if record.get("model_outcome") not in {
            "completed_no_findings",
            "completed_with_findings",
        }:
            continue
        corpus_dir = _corpus_dir(str(record["corpus"]))
        entry = _entry_from_record(record, corpus_dir)
        content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
        file_lines = _line_count(content)
        raw = [f for f in (record.get("model_findings") or []) if is_model_originated(f)]
        emitted += len(raw)
        surviving, rejected = partition_constrained_findings(
            raw,
            content=content,
            line_min=1,
            line_max=file_lines,
        )
        for finding in rejected:
            invalid_findings.append(
                {
                    "corpus": record["corpus"],
                    "rel_path": entry.rel_path,
                    "target_type": entry.target_type,
                    "virtual_path": entry.virtual_path,
                    "finding": finding,
                    "rejection_reason": finding.get("rejection_reason"),
                }
            )
        for finding in surviving:
            all_surviving.append(
                {
                    "corpus": record["corpus"],
                    "rel_path": entry.rel_path,
                    "target_type": entry.target_type,
                    "virtual_path": entry.virtual_path,
                    "expected_rule_ids": sorted(set(entry.expected_rule_ids)),
                    "finding": finding,
                }
            )
        score_file(
            matcher=MATCHER_BEST_FIT,
            entry=entry,
            corpus_name=str(record["corpus"]),
            content=content,
            model_findings=surviving,
            handler_stats=handler_stats,
            model_stats=model_stats,
            unlabeled_model_findings=unlabeled_model_findings,
            rule_semantics=RULE_SEMANTICS,
        )

    tp, fp, fn = aggregate_model_metrics(model_stats)
    rejection_summary = summarize_rejections(
        [item["finding"] for item in invalid_findings]
    )
    evidence_not_substring = int(rejection_summary.get("evidence_not_substring") or 0)
    fabrication_rate_pct = round(100 * evidence_not_substring / emitted, 1) if emitted else 0.0

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "retro_constrained_validation",
        "prompt_variant": prompt_variant,
        "semantic_matcher": MATCHER_BEST_FIT,
        "semantic_matcher_metadata": MATCHER_METADATA[MATCHER_BEST_FIT],
        "validation": "constrained_finding_validation (retroactive, no re-inference)",
        "summary": {
            "model_findings_emitted": emitted,
            "invalid_findings_count": len(invalid_findings),
            "evidence_not_substring_count": evidence_not_substring,
            "fabrication_rate_pct": fabrication_rate_pct,
            "model_findings_surviving": len(all_surviving),
            "unlabeled_model_findings_count": len(unlabeled_model_findings),
            "aggregate_model": {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
            },
        },
        "invalid_findings_summary": rejection_summary,
        "invalid_findings": invalid_findings,
        "surviving_model_findings": all_surviving,
        "per_target_type_per_rule": build_per_rule_report(
            handler_stats, model_stats, RULE_SEMANTICS
        ),
        "unlabeled_model_findings": unlabeled_model_findings,
        "unrecognized_model_asserted_cwe": unrecognized_model_cwe_tally(all_surviving),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--variant",
        choices=("baseline", "platform_specific", "all"),
        default="all",
    )
    args = parser.parse_args()

    for label, cache_path, source_report_path, output_path in RUNS:
        if args.variant != "all" and label != args.variant:
            continue
        if not cache_path.is_file():
            print(f"ERROR: missing findings cache: {cache_path}", file=sys.stderr)
            return 1
        records = json.loads(cache_path.read_text(encoding="utf-8")).get("files") or []
        source_report = json.loads(source_report_path.read_text(encoding="utf-8"))
        sidecar = retro_validate_cache(records, prompt_variant=label)
        sidecar["source_findings_cache"] = str(cache_path.relative_to(ROOT))
        sidecar["source_report"] = str(source_report_path.relative_to(ROOT))
        sidecar["source_report_preserved"] = True
        sidecar = merge_quant_metadata(sidecar, source_report=source_report)
        output_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        summary = sidecar["summary"]
        print(f"Wrote {output_path.relative_to(ROOT)}")
        print(
            f"  emitted={summary['model_findings_emitted']} "
            f"rejected={summary['invalid_findings_count']} "
            f"evidence_not_substring={summary['evidence_not_substring_count']} "
            f"({summary['fabrication_rate_pct']}%) "
            f"surviving={summary['model_findings_surviving']} "
            f"TP/FP/FN={summary['aggregate_model']['true_positives']}/"
            f"{summary['aggregate_model']['false_positives']}/"
            f"{summary['aggregate_model']['false_negatives']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
