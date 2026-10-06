#!/usr/bin/env python3
"""Experiment D2: 5-shot RCM CWE assignment (technical report B.3.1 / model-card style)."""

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

from eval_model import assert_llama_cpp, resolve_model_layout  # noqa: E402
from report_quant_stamping import merge_quant_metadata  # noqa: E402
from rcm_cwe_5shot import (  # noqa: E402
    FIVE_SHOT_COMPLETION_STOP,
    FIVE_SHOT_MAX_TOKENS,
    SHOT_COUNT,
    build_5shot_prompts,
)
from rcm_cwe_inputs import build_rcm_instances  # noqa: E402
from rcm_cwe_inference import LlamaCompleteEngine  # noqa: E402
from rcm_cwe_scoring import (  # noqa: E402
    completion_token_stats,
    parse_predicted_cwe,
    score_predictions,
)

REPORTS = ROOT / "validation" / "reports"
D_REPORT_PATH = REPORTS / "rcm-cwe-eval.json"
REPORT_PATH = REPORTS / "rcm-cwe-5shot-eval.json"
SUMMARY_PATH = REPORTS / "rcm-cwe-5shot-eval.txt"

EXPERIMENT_D_BASELINE = {
    "correct": 19,
    "total": 108,
    "invalid_predictions": 23,
    "accuracy": 0.1759,
}


def _load_experiment_d_summary() -> dict[str, Any]:
    if not D_REPORT_PATH.is_file():
        return EXPERIMENT_D_BASELINE
    payload = json.loads(D_REPORT_PATH.read_text(encoding="utf-8"))
    fsec = (payload.get("models") or {}).get("foundation_sec") or {}
    summary = fsec.get("summary") or {}
    if not summary:
        return EXPERIMENT_D_BASELINE
    return {
        "correct": int(summary.get("correct") or EXPERIMENT_D_BASELINE["correct"]),
        "total": int(summary.get("total") or EXPERIMENT_D_BASELINE["total"]),
        "invalid_predictions": int(
            summary.get("invalid_predictions") or EXPERIMENT_D_BASELINE["invalid_predictions"]
        ),
        "accuracy": float(summary.get("accuracy") or EXPERIMENT_D_BASELINE["accuracy"]),
        "per_target_type": summary.get("per_target_type") or {},
    }


def _format_summary_text(report: dict[str, Any]) -> str:
    summary = report["foundation_sec"]["summary"]
    compare = report["comparison_vs_experiment_d"]
    lines = [
        "=== Experiment D2: 5-shot RCM CWE assignment (raw completion, B.3.1 style) ===",
        (
            f"quant_evaluated={report.get('quant_evaluated')} "
            f"quant_intended={report.get('quant_intended')} "
            f"accuracy_only={report.get('accuracy_only')}"
        ),
        "",
        f"Instances: {report['instance_count']} labeled handler defects",
        f"Shots per instance: {report['shot_count']} (rotated; target excluded from shots)",
        "Format: '<defect context>. The CWE is CWE-XXX.' × 5, then target ends 'The CWE is'",
        f"Harness: max_tokens={report.get('max_tokens', FIVE_SHOT_MAX_TOKENS)}, "
        f"stop={report.get('completion_stop')}",
        "Inference: raw completion (authoritative path)",
        "",
        "Foundation-Sec:",
        (
            f"  overall accuracy: {summary['correct']}/{summary['total']} "
            f"({100 * float(summary['accuracy']):.1f}%)"
        ),
        (
            f"  invalid predictions: {summary['invalid_predictions']} "
            f"incorrect: {summary['incorrect']}"
        ),
    ]
    token_stats = report["foundation_sec"].get("completion_token_stats") or {}
    if token_stats:
        lines.append(
            f"  completion tokens: mean={token_stats.get('mean')} "
            f"max={token_stats.get('max')} hit_max_tokens={token_stats.get('hit_max_tokens')}"
        )
    lines.append("  per target_type:")
    for target_type, bucket in (summary.get("per_target_type") or {}).items():
        lines.append(
            f"    {target_type:<22} {bucket['correct']}/{bucket['total']} "
            f"({100 * float(bucket['accuracy']):.1f}%)"
        )
    lines.extend(
        [
            "",
            "Comparison vs Experiment D (zero-shot CTIBench prompt):",
            (
                f"  D:  {compare['experiment_d']['correct']}/{compare['experiment_d']['total']} "
                f"({100 * compare['experiment_d']['accuracy']:.1f}%), "
                f"invalid={compare['experiment_d']['invalid_predictions']}"
            ),
            (
                f"  D2: {compare['experiment_d2']['correct']}/{compare['experiment_d2']['total']} "
                f"({100 * compare['experiment_d2']['accuracy']:.1f}%), "
                f"invalid={compare['experiment_d2']['invalid_predictions']}"
            ),
            (
                f"  delta accuracy: {compare['accuracy_delta']:+.1%} "
                f"({compare['correct_delta']:+d} correct, "
                f"{compare['invalid_delta']:+d} invalid)"
            ),
            "",
            f"Interpretation: {compare['interpretation']}",
        ]
    )
    return "\n".join(lines) + "\n"


def _interpret_comparison(d_summary: dict[str, Any], d2_summary: dict[str, Any]) -> str:
    invalid_delta = int(d2_summary["invalid_predictions"]) - int(d_summary["invalid_predictions"])
    correct_delta = int(d2_summary["correct"]) - int(d_summary["correct"])
    acc_delta = float(d2_summary["accuracy"]) - float(d_summary["accuracy"])

    invalid_collapsed = invalid_delta <= -10
    accuracy_rose = acc_delta >= 0.10

    if invalid_collapsed and accuracy_rose:
        return (
            "Invalid predictions collapsed and accuracy rose materially — Experiment D was "
            "largely measuring output-format compliance, not CWE taxonomy knowledge."
        )
    if acc_delta < 0.05:
        return (
            "Accuracy did not rise materially versus Experiment D — the model does not "
            "reliably map these handler defect signals to CWE IDs regardless of 5-shot "
            "raw-completion prompting."
        )
    if invalid_collapsed and not accuracy_rose:
        return (
            "Invalid predictions improved but accuracy did not rise materially — format "
            "compliance was a barrier in D, yet CWE taxonomy mapping remains weak."
        )
    return (
        "Mixed movement on accuracy and invalid rate — review per-target breakdown and "
        "sample completions before attributing gains to format vs taxonomy knowledge."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-quant-mismatch", action="store_true")
    parser.add_argument("--output", type=Path, default=REPORT_PATH)
    parser.add_argument("--summary-output", type=Path, default=SUMMARY_PATH)
    parser.add_argument(
        "--cache",
        type=Path,
        help="Optional JSON cache of instance_id -> model completion suffix.",
    )
    args = parser.parse_args()

    instances = build_rcm_instances()
    if len(instances) != 108:
        print(f"ERROR: expected 108 instances, built {len(instances)}", file=sys.stderr)
        return 1

    prompt_rows = build_5shot_prompts(instances)
    cache: dict[str, str] = {}
    if args.cache and args.cache.is_file():
        cache = json.loads(args.cache.read_text(encoding="utf-8"))

    fsec_python = ROOT / "services" / "foundation-sec-server" / ".venv" / "bin" / "python"
    if fsec_python.is_file():
        assert_llama_cpp(fsec_python)

    model_dir, _, quant_label = resolve_model_layout(allow_quant_mismatch=args.allow_quant_mismatch)
    engine = LlamaCompleteEngine(model_dir, quant_label=quant_label, n_ctx=8192)
    results: list[dict[str, Any]] = []

    try:
        for index, (instance, prompt, shot_ids) in enumerate(prompt_rows, start=1):
            if instance.instance_id in cache:
                response = cache[instance.instance_id]
                usage = {"completion_tokens": 0, "hit_max_tokens": False, "finish_reason": "cache"}
            else:
                response, usage = engine.complete_with_usage(
                    prompt,
                    max_tokens=FIVE_SHOT_MAX_TOKENS,
                    stop=FIVE_SHOT_COMPLETION_STOP,
                )
                cache[instance.instance_id] = response
            predicted = parse_predicted_cwe(response, after_the_cwe_is=True)
            results.append(
                {
                    "instance_id": instance.instance_id,
                    "corpus": instance.corpus,
                    "rel_path": instance.rel_path,
                    "target_type": instance.target_type,
                    "rule_id": instance.rule_id,
                    "expected_cwe": instance.expected_cwe,
                    "predicted_cwe": predicted,
                    "correct": predicted == instance.expected_cwe,
                    "shot_instance_ids": shot_ids,
                    "model_response": response,
                    "completion_tokens": usage["completion_tokens"],
                    "hit_max_tokens": usage["hit_max_tokens"],
                    "finish_reason": usage.get("finish_reason"),
                }
            )
            print(
                f"[D2 {index}/{len(instances)}] {instance.instance_id} "
                f"expected={instance.expected_cwe} predicted={predicted or '—'} "
                f"tokens={usage['completion_tokens']}"
            )
    finally:
        engine.unload()

    if args.cache:
        args.cache.parent.mkdir(parents=True, exist_ok=True)
        args.cache.write_text(json.dumps(cache, indent=2), encoding="utf-8")

    summary = score_predictions(
        results,
        parser=lambda response: parse_predicted_cwe(response, after_the_cwe_is=True),
    )
    summary = {
        k: summary[k]
        for k in ("total", "correct", "incorrect", "invalid_predictions", "accuracy", "per_target_type")
    }
    d_summary = _load_experiment_d_summary()
    compare = {
        "experiment_d": d_summary,
        "experiment_d2": summary,
        "correct_delta": int(summary["correct"]) - int(d_summary["correct"]),
        "invalid_delta": int(summary["invalid_predictions"]) - int(d_summary["invalid_predictions"]),
        "accuracy_delta": round(float(summary["accuracy"]) - float(d_summary["accuracy"]), 4),
        "interpretation": _interpret_comparison(d_summary, summary),
    }

    report = merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "experiment": "D2",
            "task": "rcm_cwe_assignment_5shot",
            "description": (
                "5-shot raw-completion RCM CWE mapping (technical report B.3.1 / model-card "
                "style). Same 108 handler-signal instances as Experiment D."
            ),
            "instance_count": len(instances),
            "shot_count": SHOT_COUNT,
            "inference_path": "raw_completion",
            "prompt_format": (
                "<defect context>. The CWE is CWE-XXX. (×5 shots) then "
                "<target defect context>. The CWE is <completion>"
            ),
            "experiment_d_report": str(D_REPORT_PATH.relative_to(ROOT)),
            "max_tokens": FIVE_SHOT_MAX_TOKENS,
            "completion_stop": FIVE_SHOT_COMPLETION_STOP,
            "harness_version": "rcm_v2_normalized_single_line",
            "foundation_sec": {
                "model_dir": engine.model_dir,
                "gguf_file": engine.gguf_file,
                "summary": summary,
                "completion_token_stats": completion_token_stats(results),
                "results": results,
            },
            "comparison_vs_experiment_d": compare,
        }
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    summary_text = _format_summary_text(report)
    args.summary_output.write_text(summary_text, encoding="utf-8")
    print(summary_text)
    print(f"Wrote {args.output.relative_to(ROOT)}")
    print(f"Wrote {args.summary_output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
