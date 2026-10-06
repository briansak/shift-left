#!/usr/bin/env python3
"""Experiment D: CTIBench-RCM-shaped CWE assignment from handler signals (no detection)."""

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

from eval_model import Q8_MODEL_DIR, assert_llama_cpp, resolve_model_layout  # noqa: E402
from report_quant_stamping import merge_quant_metadata  # noqa: E402
from rcm_cwe_inference import LlamaCompleteEngine, resolve_staged_model_dir  # noqa: E402
from rcm_cwe_inputs import (  # noqa: E402
    RcmInstance,
    ZERO_SHOT_COMPLETION_STOP,
    ZERO_SHOT_MAX_TOKENS,
    build_rcm_instances,
)
from rcm_cwe_scoring import (  # noqa: E402
    completion_token_stats,
    parse_predicted_cwe,
    score_predictions,
)

REPORTS = ROOT / "validation" / "reports"
INSTANCES_PATH = REPORTS / "rcm-cwe-instances.json"
REPORT_PATH = REPORTS / "rcm-cwe-eval.json"
SUMMARY_PATH = REPORTS / "rcm-cwe-eval.txt"

BASELINE_MODEL_CANDIDATES = [
    ROOT / "models" / "llama-3.1-8b-instruct-q4_k_m",
    ROOT / "models" / "llama-3.1-8b-instruct-q8_0",
    ROOT / "models" / "baseline-8b-instruct-q4_k_m",
    ROOT / "models" / "llama-3.1-8b-q4_k_m",
]


def _instances_payload(instances: list[RcmInstance]) -> dict[str, Any]:
    return merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "task": "rcm_cwe_assignment",
            "population": "labeled_handler_defects",
            "instance_count": len(instances),
            "instances": [item.as_dict() for item in instances],
        }
    )


def _run_model(
    label: str,
    engine: LlamaCompleteEngine,
    instances: list[RcmInstance],
    *,
    cache: dict[str, str] | None = None,
    max_tokens: int = ZERO_SHOT_MAX_TOKENS,
    stop: list[str] | None = None,
) -> dict[str, Any]:
    completion_stop = stop if stop is not None else ZERO_SHOT_COMPLETION_STOP
    rows: list[dict[str, Any]] = []
    for index, instance in enumerate(instances, start=1):
        if cache and instance.instance_id in cache:
            response = cache[instance.instance_id]
            usage = {"completion_tokens": 0, "hit_max_tokens": False, "finish_reason": "cache"}
        else:
            response, usage = engine.complete_with_usage(
                instance.prompt,
                max_tokens=max_tokens,
                stop=completion_stop,
            )
            if cache is not None:
                cache[instance.instance_id] = response
        predicted = parse_predicted_cwe(response, after_the_cwe_is=False)
        rows.append(
            {
                "instance_id": instance.instance_id,
                "corpus": instance.corpus,
                "rel_path": instance.rel_path,
                "target_type": instance.target_type,
                "rule_id": instance.rule_id,
                "expected_cwe": instance.expected_cwe,
                "predicted_cwe": predicted,
                "correct": predicted == instance.expected_cwe,
                "model_response": response,
                "completion_tokens": usage["completion_tokens"],
                "hit_max_tokens": usage["hit_max_tokens"],
                "finish_reason": usage.get("finish_reason"),
            }
        )
        print(
            f"[{label} {index}/{len(instances)}] {instance.instance_id} "
            f"expected={instance.expected_cwe} predicted={predicted or '—'} "
            f"tokens={usage['completion_tokens']}"
        )

    summary = score_predictions(
        rows,
        parser=lambda response: parse_predicted_cwe(response, after_the_cwe_is=False),
    )
    return {
        "label": label,
        "model_dir": engine.model_dir,
        "gguf_file": engine.gguf_file,
        "summary": {
            k: summary[k]
            for k in ("total", "correct", "incorrect", "invalid_predictions", "accuracy", "per_target_type")
        },
        "completion_token_stats": completion_token_stats(rows),
        "max_tokens": max_tokens,
        "completion_stop": completion_stop,
        "results": rows,
    }


def _format_summary_text(report: dict[str, Any]) -> str:
    lines = [
        "=== Experiment D: RCM-shaped CWE assignment (handler signals, no detection) ===",
        (
            f"quant_evaluated={report.get('quant_evaluated')} "
            f"quant_intended={report.get('quant_intended')} "
            f"accuracy_only={report.get('accuracy_only')}"
        ),
        "",
        f"Instances: {report['instance_count']} labeled handler defects",
        "Task: CTIBench-RCM output format (final line = CWE ID only); closed-form CWE mapping.",
        f"max_tokens={report.get('max_tokens', ZERO_SHOT_MAX_TOKENS)} "
        f"stop={report.get('completion_stop')}",
        "",
    ]

    for model_key in ("foundation_sec", "baseline_general"):
        payload = report["models"].get(model_key) or {}
        lines.append(f"{model_key}:")
        if payload.get("status") == "not_staged":
            lines.append(f"  status: not_staged ({payload.get('reason')})")
            continue
        summary = payload.get("summary") or {}
        token_stats = payload.get("completion_token_stats") or {}
        lines.append(
            f"  overall accuracy: {summary.get('correct')}/{summary.get('total')} "
            f"({100 * float(summary.get('accuracy') or 0):.1f}%)"
        )
        lines.append(
            f"  invalid predictions: {summary.get('invalid_predictions')} "
            f"incorrect: {summary.get('incorrect')}"
        )
        if token_stats:
            lines.append(
                f"  completion tokens: mean={token_stats.get('mean')} "
                f"max={token_stats.get('max')} hit_max_tokens={token_stats.get('hit_max_tokens')}"
            )
        per_target = summary.get("per_target_type") or {}
        if per_target:
            lines.append("  per target_type:")
            for target_type, bucket in per_target.items():
                lines.append(
                    f"    {target_type:<22} {bucket['correct']}/{bucket['total']} "
                    f"({100 * float(bucket['accuracy']):.1f}%)"
                )
        lines.append("")

    delta = report.get("security_pretraining_delta") or {}
    if delta.get("status") == "computed":
        lines.append(
            f"Security-pretraining delta (foundation_sec - baseline_general): "
            f"{delta['accuracy_delta']:+.1%} "
            f"({delta['foundation_sec_accuracy']:.1%} vs {delta['baseline_general_accuracy']:.1%})"
        )
    else:
        lines.append(f"Security-pretraining delta: {delta.get('reason', 'unavailable')}")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inputs-output",
        type=Path,
        default=INSTANCES_PATH,
        help="Where to write constructed RCM inputs.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPORT_PATH,
        help="JSON report path.",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=SUMMARY_PATH,
        help="Human-readable summary path.",
    )
    parser.add_argument(
        "--inputs-only",
        action="store_true",
        help="Build and write inputs only; skip model inference.",
    )
    parser.add_argument(
        "--allow-quant-mismatch",
        action="store_true",
        help="Use staged Q8_0 Foundation-Sec weights (accuracy-only run).",
    )
    parser.add_argument(
        "--skip-foundation-sec",
        action="store_true",
        help="Skip Foundation-Sec inference (baseline-only or inputs-only workflows).",
    )
    parser.add_argument(
        "--skip-baseline",
        action="store_true",
        help="Skip general baseline model inference.",
    )
    parser.add_argument(
        "--cache",
        type=Path,
        help="Optional JSON cache of instance_id -> model response to reuse.",
    )
    args = parser.parse_args()

    instances = build_rcm_instances()
    if len(instances) != 108:
        print(f"ERROR: expected 108 labeled instances, built {len(instances)}", file=sys.stderr)
        return 1

    inputs_payload = _instances_payload(instances)
    args.inputs_output.parent.mkdir(parents=True, exist_ok=True)
    args.inputs_output.write_text(json.dumps(inputs_payload, indent=2), encoding="utf-8")
    print(f"Wrote {args.inputs_output.relative_to(ROOT)} ({len(instances)} instances)")

    if args.inputs_only:
        return 0

    cache: dict[str, str] = {}
    if args.cache and args.cache.is_file():
        cache = json.loads(args.cache.read_text(encoding="utf-8"))

    models: dict[str, Any] = {}
    fsec_python = ROOT / "services" / "foundation-sec-server" / ".venv" / "bin" / "python"
    if fsec_python.is_file():
        assert_llama_cpp(fsec_python)

    if not args.skip_foundation_sec:
        try:
            model_dir, _, quant_label = resolve_model_layout(
                allow_quant_mismatch=args.allow_quant_mismatch
            )
            engine = LlamaCompleteEngine(model_dir, quant_label=quant_label)
            try:
                models["foundation_sec"] = _run_model(
                    "foundation_sec", engine, instances, cache=cache
                )
            finally:
                engine.unload()
        except (FileNotFoundError, ValueError) as exc:
            print(f"ERROR: Foundation-Sec inference unavailable: {exc}", file=sys.stderr)
            return 1
    else:
        models["foundation_sec"] = {
            "status": "skipped",
            "reason": "--skip-foundation-sec",
        }

    baseline_dir = resolve_staged_model_dir(BASELINE_MODEL_CANDIDATES)
    if not args.skip_baseline:
        if baseline_dir is None:
            models["baseline_general"] = {
                "status": "not_staged",
                "reason": (
                    "No general ~8B baseline GGUF found under models/. "
                    f"Checked: {', '.join(str(path.relative_to(ROOT)) for path in BASELINE_MODEL_CANDIDATES)}"
                ),
                "candidate_dirs": [str(path.relative_to(ROOT)) for path in BASELINE_MODEL_CANDIDATES],
            }
        else:
            engine = LlamaCompleteEngine(baseline_dir, quant_label=baseline_dir.name)
            try:
                models["baseline_general"] = _run_model(
                    "baseline_general",
                    engine,
                    instances,
                    cache=cache,
                )
            finally:
                engine.unload()
    else:
        models["baseline_general"] = {
            "status": "skipped",
            "reason": "--skip-baseline",
        }

    if args.cache:
        args.cache.parent.mkdir(parents=True, exist_ok=True)
        args.cache.write_text(json.dumps(cache, indent=2), encoding="utf-8")

    delta: dict[str, Any]
    fsec = models.get("foundation_sec") or {}
    base = models.get("baseline_general") or {}
    if fsec.get("summary") and base.get("summary"):
        fsec_acc = float(fsec["summary"]["accuracy"])
        base_acc = float(base["summary"]["accuracy"])
        delta = {
            "status": "computed",
            "foundation_sec_accuracy": fsec_acc,
            "baseline_general_accuracy": base_acc,
            "accuracy_delta": round(fsec_acc - base_acc, 4),
        }
    else:
        delta = {
            "status": "unavailable",
            "reason": "Requires both foundation_sec and baseline_general scored runs.",
        }

    report = merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "experiment": "D",
            "task": "rcm_cwe_assignment",
            "description": (
                "CTIBench-RCM-shaped CWE mapping from handler signals. "
                "The model does not detect defects; inputs are handler-parsed blocks, "
                "resolved values, and CWE-neutral match summaries."
            ),
            "instance_count": len(instances),
            "inputs_path": str(args.inputs_output.relative_to(ROOT)),
            "output_format": "CTIBench-RCM (final response line = CWE ID)",
            "max_tokens": ZERO_SHOT_MAX_TOKENS,
            "completion_stop": ZERO_SHOT_COMPLETION_STOP,
            "harness_version": "rcm_v3_zero_shot_512_stop",
            "models": models,
            "security_pretraining_delta": delta,
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
