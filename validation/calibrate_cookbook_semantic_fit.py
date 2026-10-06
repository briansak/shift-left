#!/usr/bin/env python3
"""Calibrate MIN_SEMANTIC_FIT for cookbook prose detection (Experiment F)."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
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

from cookbook_prose_inputs import (  # noqa: E402
    CookbookFileRun,
    LabeledDefect,
    build_cookbook_inputs,
)
from cookbook_prose_scoring import defect_detected, prose_semantic_fit  # noqa: E402
from eval_model import RULE_SEMANTICS, assert_llama_cpp, resolve_model_layout  # noqa: E402
from model_eval_matching import MIN_SEMANTIC_FIT, RuleSemantic  # noqa: E402
from report_quant_stamping import merge_quant_metadata  # noqa: E402
from rcm_cwe_inference import LlamaCompleteEngine  # noqa: E402

REPORTS = ROOT / "validation" / "reports"
DEFAULT_RESPONSES = REPORTS / "cookbook-prose-responses.json"
BASELINE_CACHE = REPORTS / "findings-cache" / "baseline.findings.json"
DEFAULT_OUTPUT = REPORTS / "cookbook-semantic-fit-calibration.json"
DEFAULT_SUMMARY = REPORTS / "cookbook-semantic-fit-calibration.txt"
DEFAULT_ADJUDICATION = REPORTS / "cookbook-semantic-fit-adjudication-sample.txt"

THRESHOLD_SWEEP = (
    0.12,
    0.20,
    0.30,
    0.40,
    0.50,
    0.55,
    0.60,
    0.65,
    0.70,
    0.75,
    0.80,
    0.85,
    0.90,
)
MAX_FALSE_MATCH_RATE = 0.02
COOKBOOK_DETECTION_THRESHOLD = 0.70
ADJUDICATION_SAMPLE_SIZE = 15


def _semantic(rule_id: str) -> RuleSemantic:
    return RULE_SEMANTICS[rule_id]


def _fit(prose: str, rule_id: str) -> float:
    return prose_semantic_fit(prose, _semantic(rule_id))


def _load_responses(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _finding_to_cookbook_prose(finding: dict[str, Any]) -> str:
    return (
        f"Detected misconfiguration: {finding.get('title') or 'Issue'}. "
        f"Severity: {finding.get('severity') or 'unknown'}. "
        f"Recommended fix: {finding.get('description') or finding.get('trace') or ''}"
    )


def _responses_from_baseline_cache(cache_path: Path) -> dict[str, str]:
    from model_eval_matching import is_model_originated

    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    responses: dict[str, str] = {}
    for record in payload.get("files") or []:
        file_key = f"{record['corpus']}/{record['rel_path']}"
        findings = [f for f in (record.get("model_findings") or []) if is_model_originated(f)]
        if findings:
            responses[file_key] = "\n\n".join(_finding_to_cookbook_prose(f) for f in findings)
        else:
            responses[file_key] = "No misconfigurations detected."
    return responses


def _run_inference(
    file_runs: list[CookbookFileRun],
    *,
    cache_path: Path,
    allow_quant_mismatch: bool,
    max_tokens: int,
) -> dict[str, str]:
    fsec_python = ROOT / "services" / "foundation-sec-server" / ".venv" / "bin" / "python"
    if fsec_python.is_file():
        assert_llama_cpp(fsec_python)

    cache = _load_responses(cache_path)
    model_dir, _, quant_label = resolve_model_layout(allow_quant_mismatch=allow_quant_mismatch)
    engine = LlamaCompleteEngine(model_dir, quant_label=quant_label)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        for index, file_run in enumerate(file_runs, start=1):
            if file_run.file_key in cache:
                print(f"[infer {index}/{len(file_runs)}] {file_run.file_key} (cached)", flush=True)
                continue
            cache[file_run.file_key] = engine.complete(file_run.prompt, max_tokens=max_tokens)
            cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
            print(f"[infer {index}/{len(file_runs)}] {file_run.file_key}", flush=True)
    finally:
        engine.unload()
    return cache


def _positive_rows(
    instances: list[LabeledDefect],
    responses: dict[str, str],
    threshold: float,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for instance in instances:
        prose = responses.get(instance.file_key, "")
        detected, score = defect_detected(
            prose,
            defect_summary=instance.defect_summary,
            rule_id=instance.rule_id,
            target_type=instance.target_type,
            threshold=threshold,
        )
        rows.append(
            {
                "instance_id": instance.instance_id,
                "file_key": instance.file_key,
                "target_type": instance.target_type,
                "rule_id": instance.rule_id,
                "defect_summary": instance.defect_summary,
                "semantic_fit": round(score, 4),
                "detected": detected,
                "prose": prose,
            }
        )
    return rows


def _negative_control(
    file_runs: list[CookbookFileRun],
    responses: dict[str, str],
    threshold: float,
) -> dict[str, Any]:
    all_rule_ids = sorted(RULE_SEMANTICS)
    spurious: list[dict[str, Any]] = []
    total_pairs = 0
    for file_run in file_runs:
        prose = responses.get(file_run.file_key, "")
        negative_rules = [rule_id for rule_id in all_rule_ids if rule_id not in file_run.expected_rule_ids]
        for rule_id in negative_rules:
            total_pairs += 1
            score = _fit(prose, rule_id)
            if score >= threshold:
                spurious.append(
                    {
                        "file_key": file_run.file_key,
                        "target_type": file_run.target_type,
                        "spurious_rule_id": rule_id,
                        "semantic_fit": round(score, 4),
                        "defect_summary": RULE_SEMANTICS[rule_id].defect_summary,
                        "expected_rule_ids": list(file_run.expected_rule_ids),
                    }
                )

    false_match_rate = len(spurious) / total_pairs if total_pairs else 0.0
    return {
        "threshold": threshold,
        "negative_pairs_total": total_pairs,
        "spurious_matches": len(spurious),
        "false_match_rate": round(false_match_rate, 4),
        "spurious_examples": spurious[:25],
    }


def _threshold_sweep(
    file_runs: list[CookbookFileRun],
    instances: list[LabeledDefect],
    responses: dict[str, str],
) -> list[dict[str, Any]]:
    sweep: list[dict[str, Any]] = []
    for threshold in THRESHOLD_SWEEP:
        positive = _positive_rows(instances, responses, threshold)
        detected = sum(1 for row in positive if row["detected"])
        negative = _negative_control(file_runs, responses, threshold)
        sweep.append(
            {
                "threshold": threshold,
                "recall": round(detected / len(instances), 4) if instances else 0.0,
                "detected": detected,
                "labeled_defects": len(instances),
                "false_match_rate": negative["false_match_rate"],
                "spurious_matches": negative["spurious_matches"],
                "negative_pairs_total": negative["negative_pairs_total"],
            }
        )
    return sweep


def _choose_threshold(sweep: list[dict[str, Any]]) -> dict[str, Any]:
    qualifying = [
        row for row in sweep if row["false_match_rate"] <= MAX_FALSE_MATCH_RATE
    ]
    if qualifying:
        chosen = max(qualifying, key=lambda row: (row["recall"], -row["threshold"]))
        justification = (
            f"Highest recall ({chosen['detected']}/{chosen['labeled_defects']}) "
            f"among thresholds with false-match rate <= {MAX_FALSE_MATCH_RATE:.0%}."
        )
    else:
        chosen = min(sweep, key=lambda row: row["false_match_rate"])
        justification = (
            "No threshold met the false-match ceiling; chose the threshold with the "
            f"lowest false-match rate ({chosen['false_match_rate']:.1%})."
        )
    return {
        "chosen_threshold": chosen["threshold"],
        "justification": justification,
        "recall_at_chosen": chosen["recall"],
        "false_match_rate_at_chosen": chosen["false_match_rate"],
        "max_false_match_rate_allowed": MAX_FALSE_MATCH_RATE,
    }


def _deterministic_sample(
    matches: list[dict[str, Any]],
    *,
    sample_size: int,
) -> list[dict[str, Any]]:
    if len(matches) <= sample_size:
        return list(matches)

    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in matches:
        by_type[row["target_type"]].append(row)

    for rows in by_type.values():
        rows.sort(key=lambda item: (-item["semantic_fit"], item["instance_id"]))

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


def _format_adjudication_sample(cases: list[dict[str, Any]]) -> str:
    lines = [
        "=== Cookbook semantic-fit adjudication sample ===",
        f"Sample size: {len(cases)} matched pairs at chosen threshold",
        "",
    ]
    for index, case in enumerate(cases, start=1):
        prose_excerpt = " ".join(case["prose"].split())[:600]
        lines.extend(
            [
                f"--- [{index}] {case['instance_id']} (fit={case['semantic_fit']}) ---",
                f"Defect summary: {case['defect_summary']}",
                f"Prose excerpt: {prose_excerpt}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def _format_summary(
    *,
    sweep: list[dict[str, Any]],
    choice: dict[str, Any],
    negative_at_012: dict[str, Any],
    adjudication: dict[str, Any],
) -> str:
    lines = [
        "=== Cookbook MIN_SEMANTIC_FIT calibration (Experiment F) ===",
        "",
        "1. Negative control at threshold 0.12:",
        (
            f"   spurious matches: {negative_at_012['spurious_matches']}/"
            f"{negative_at_012['negative_pairs_total']} "
            f"({100 * negative_at_012['false_match_rate']:.2f}% false-match rate)"
        ),
        "",
        "2. Threshold sweep (recall vs false-match rate):",
        f"   {'threshold':>10} {'recall':>8} {'detected':>10} {'false_match%':>14}",
    ]
    for row in sweep:
        lines.append(
            f"   {row['threshold']:>10.2f} {row['recall']:>7.1%} "
            f"{row['detected']:>4}/{row['labeled_defects']:<4} "
            f"{100 * row['false_match_rate']:>12.2f}%"
        )

    lines.extend(
        [
            "",
            "3. Chosen threshold:",
            f"   {choice['chosen_threshold']} — {choice['justification']}",
            "",
            "4. Recall at chosen threshold:",
            (
                f"   automated: {choice['recall_at_chosen']:.1%} "
                f"({int(choice['recall_at_chosen'] * 108)}/108 approx)"
            ),
            (
                f"   manual-review-adjusted (sample survival {adjudication['survival_rate']:.1%}): "
                f"{adjudication['adjusted_recall']:.1%}"
            ),
            (
                f"   adjudication sample: {adjudication['survived']}/{adjudication['sample_size']} "
                "survived manual review"
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--responses", type=Path, default=DEFAULT_RESPONSES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--adjudication-output", type=Path, default=DEFAULT_ADJUDICATION)
    parser.add_argument(
        "--run-inference",
        action="store_true",
        help="Run cookbook prose inference when responses cache is missing/incomplete.",
    )
    parser.add_argument(
        "--use-baseline-prose-proxy",
        action="store_true",
        help=(
            "Interim calibration using baseline structured findings reformatted as "
            "cookbook prose (until native cookbook responses are available)."
        ),
    )
    parser.add_argument("--allow-quant-mismatch", action="store_true")
    parser.add_argument("--max-tokens", type=int, default=1024)
    parser.add_argument(
        "--adjudication-verdicts",
        type=Path,
        help="Optional JSON map instance_id -> true|false manual verdicts.",
    )
    args = parser.parse_args()

    file_runs, instances = build_cookbook_inputs()
    if len(instances) != 108:
        print(f"ERROR: expected 108 labeled defects, got {len(instances)}", file=sys.stderr)
        return 1

    prose_source = "cookbook_inference"
    responses = _load_responses(args.responses)
    missing = [run.file_key for run in file_runs if run.file_key not in responses]
    if missing and args.use_baseline_prose_proxy:
        responses = _responses_from_baseline_cache(BASELINE_CACHE)
        prose_source = "baseline_findings_reformatted_proxy"
        missing = [run.file_key for run in file_runs if run.file_key not in responses]
    if missing and not args.run_inference:
        print(
            f"ERROR: missing prose responses for {len(missing)} files. "
            f"Run with --run-inference or populate {args.responses}",
            file=sys.stderr,
        )
        return 1
    if missing and args.run_inference:
        responses = _run_inference(
            file_runs,
            cache_path=args.responses,
            allow_quant_mismatch=args.allow_quant_mismatch,
            max_tokens=args.max_tokens,
        )

    if any(run.file_key not in responses for run in file_runs):
        print("ERROR: incomplete prose response cache after inference.", file=sys.stderr)
        return 1

    sweep = _threshold_sweep(file_runs, instances, responses)
    choice = _choose_threshold(sweep)
    chosen_threshold = float(choice["chosen_threshold"])

    negative_at_012 = _negative_control(file_runs, responses, 0.12)
    positive_at_chosen = _positive_rows(instances, responses, chosen_threshold)
    matches = [row for row in positive_at_chosen if row["detected"]]
    sample = _deterministic_sample(matches, sample_size=ADJUDICATION_SAMPLE_SIZE)

    adjudication_text = _format_adjudication_sample(sample)
    args.adjudication_output.parent.mkdir(parents=True, exist_ok=True)
    args.adjudication_output.write_text(adjudication_text, encoding="utf-8")

    verdicts: dict[str, bool] = {}
    if args.adjudication_verdicts and args.adjudication_verdicts.is_file():
        raw = json.loads(args.adjudication_verdicts.read_text(encoding="utf-8"))
        verdicts = {str(key): bool(value) for key, value in raw.items()}

    sample_rows: list[dict[str, Any]] = []
    for case in sample:
        manual_pass = verdicts.get(case["instance_id"])
        sample_rows.append(
            {
                **case,
                "manual_review_pass": manual_pass,
                "prose_excerpt": " ".join(case["prose"].split())[:600],
            }
        )

    survived = sum(1 for row in sample_rows if row.get("manual_review_pass") is True)
    survival_rate = survived / len(sample_rows) if sample_rows else 0.0
    automated_detected = sum(1 for row in positive_at_chosen if row["detected"])
    automated_recall = automated_detected / len(instances)
    adjusted_recall = (
        automated_recall * survival_rate if verdicts else None
    )

    adjudication_summary = {
        "sample_size": len(sample_rows),
        "survived": survived if verdicts else None,
        "survival_rate": survival_rate if verdicts else None,
        "automated_recall": round(automated_recall, 4),
        "adjusted_recall": round(adjusted_recall, 4) if adjusted_recall is not None else None,
        "sample": sample_rows,
        "note": (
            "Manual verdicts not supplied; review adjudication sample file and pass "
            f"--adjudication-verdicts to finalize adjusted recall."
            if not verdicts
            else None
        ),
    }

    report = merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "experiment": "F",
            "task": "cookbook_semantic_fit_calibration",
            "prose_source": prose_source,
            "responses_path": str(args.responses.relative_to(ROOT)),
            "file_run_count": len(file_runs),
            "labeled_defect_count": len(instances),
            "default_min_semantic_fit": MIN_SEMANTIC_FIT,
            "threshold_sweep": sweep,
            "negative_control_at_0_12": negative_at_012,
            "chosen_threshold": choice,
            "adjudication": adjudication_summary,
            "adjudication_sample_path": str(args.adjudication_output.relative_to(ROOT)),
        }
    )

    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    summary_text = _format_summary(
        sweep=sweep,
        choice=choice,
        negative_at_012=negative_at_012,
        adjudication={
            "survival_rate": survival_rate if verdicts else 0.0,
            "adjusted_recall": adjusted_recall if adjusted_recall is not None else 0.0,
            "survived": survived if verdicts else 0,
            "sample_size": len(sample_rows),
        },
    )
    args.summary_output.write_text(summary_text, encoding="utf-8")

    print(summary_text)
    print(f"Wrote {args.output.relative_to(ROOT)}")
    print(f"Wrote {args.adjudication_output.relative_to(ROOT)}")
    if not verdicts:
        print(
            "\nManual adjudication pending: review the sample file, then re-run with "
            "--adjudication-verdicts <path-to-verdicts.json>"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
