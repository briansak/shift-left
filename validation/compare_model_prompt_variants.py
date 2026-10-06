#!/usr/bin/env python3
"""Compare baseline vs platform_specific model eval reports."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "validation" / "reports" / "model-vs-handler.json"
DEFAULT_EXPERIMENT = ROOT / "validation" / "reports" / "model-vs-handler-platform-specific.json"
ATTRIBUTION_SCRIPT = ROOT / "validation" / "analyze_model_line_attribution.py"


def _sum_model_metrics(report: dict[str, Any]) -> tuple[int, int, int]:
    tp = fp = fn = 0
    for rules in (report.get("per_target_type_per_rule") or {}).values():
        for metrics in rules.values():
            model = metrics.get("model")
            if model == "not_measured" or not isinstance(model, dict):
                continue
            tp += int(model.get("true_positives") or 0)
            fp += int(model.get("false_positives") or 0)
            fn += int(model.get("false_negatives") or 0)
    return tp, fp, fn


def _attribution_summary(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8")).get("summary") or {}


def _print_rule_table(baseline: dict[str, Any], experiment: dict[str, Any]) -> None:
    print("\nPer target_type / rule — model TP / FP / FN (baseline vs platform_specific)")
    base_rules = baseline.get("per_target_type_per_rule") or {}
    exp_rules = experiment.get("per_target_type_per_rule") or {}
    target_types = sorted(set(base_rules) | set(exp_rules))
    for target_type in target_types:
        print(f"\n  [{target_type}]")
        print(
            f"  {'Rule':<10} {'B-TP':>5} {'B-FP':>5} {'B-FN':>5}   "
            f"{'E-TP':>5} {'E-FP':>5} {'E-FN':>5}"
        )
        rule_ids = sorted(
            set(base_rules.get(target_type, {})) | set(exp_rules.get(target_type, {}))
        )
        for rule_id in rule_ids:
            b = base_rules.get(target_type, {}).get(rule_id, {}).get("model", {})
            e = exp_rules.get(target_type, {}).get(rule_id, {}).get("model", {})
            if b == "not_measured" and e == "not_measured":
                continue
            if b == "not_measured":
                b_vals = ("—", "—", "—")
            else:
                b_vals = (b["true_positives"], b["false_positives"], b["false_negatives"])
            if e == "not_measured":
                e_vals = ("—", "—", "—")
            else:
                e_vals = (e["true_positives"], e["false_positives"], e["false_negatives"])
            print(
                f"  {rule_id:<10} {b_vals[0]:>5} {b_vals[1]:>5} {b_vals[2]:>5}   "
                f"{e_vals[0]:>5} {e_vals[1]:>5} {e_vals[2]:>5}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--experiment", type=Path, default=DEFAULT_EXPERIMENT)
    parser.add_argument(
        "--skip-attribution",
        action="store_true",
        help="Do not regenerate line-attribution JSON for the experiment report.",
    )
    args = parser.parse_args()

    if not args.baseline.is_file():
        print(f"ERROR: baseline report missing: {args.baseline}", file=sys.stderr)
        return 1
    if not args.experiment.is_file():
        print(f"ERROR: experiment report missing: {args.experiment}", file=sys.stderr)
        return 1

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    experiment = json.loads(args.experiment.read_text(encoding="utf-8"))

    baseline_attr_path = args.baseline.with_name("model-line-attribution.json")
    experiment_attr_path = args.experiment.with_name(
        "model-line-attribution-platform-specific.json"
    )

    if not args.skip_attribution:
        subprocess.run(
            [sys.executable, str(ATTRIBUTION_SCRIPT), "--input", str(args.baseline), "--output", str(baseline_attr_path)],
            check=True,
        )
        subprocess.run(
            [
                sys.executable,
                str(ATTRIBUTION_SCRIPT),
                "--input",
                str(args.experiment),
                "--output",
                str(experiment_attr_path),
            ],
            check=True,
        )

    b_tp, b_fp, b_fn = _sum_model_metrics(baseline)
    e_tp, e_fp, e_fn = _sum_model_metrics(experiment)
    b_summary = baseline.get("summary") or {}
    e_summary = experiment.get("summary") or {}
    b_attr = _attribution_summary(baseline_attr_path)
    e_attr = _attribution_summary(experiment_attr_path)

    print("=== Model prompt variant comparison ===")
    print(f"Baseline:   {args.baseline.relative_to(ROOT)}")
    print(f"Experiment: {args.experiment.relative_to(ROOT)}")
    print(f"  prompt_variant baseline={baseline.get('prompt_variant', 'baseline')}")
    print(f"  prompt_variant experiment={experiment.get('prompt_variant')}")
    print(f"  quant_evaluated baseline={baseline.get('quant_evaluated')}")
    print(f"  quant_evaluated experiment={experiment.get('quant_evaluated')}")

    print("\nAggregate model metrics")
    print(f"  {'':18} {'baseline':>12} {'platform_specific':>18} {'delta':>8}")
    print(f"  {'TP (rule-level)':18} {b_tp:>12} {e_tp:>18} {e_tp - b_tp:>+8}")
    print(f"  {'FP (rule-level)':18} {b_fp:>12} {e_fp:>18} {e_fp - b_fp:>+8}")
    print(f"  {'FN (rule-level)':18} {b_fn:>12} {e_fn:>18} {e_fn - b_fn:>+8}")
    print(
        f"  {'Unlabeled findings':18} "
        f"{b_summary.get('unlabeled_model_findings_count', '—'):>12} "
        f"{e_summary.get('unlabeled_model_findings_count', '—'):>18}"
    )
    print(
        f"  {'Model findings tot':18} "
        f"{b_summary.get('model_findings_total', '—'):>12} "
        f"{e_summary.get('model_findings_total', '—'):>18}"
    )

    print("\nLine attribution (unlabeled findings)")
    print(f"  {'category':18} {'baseline':>12} {'platform_specific':>18} {'delta':>8}")
    for key in ("tight_anchor", "contains", "mismatch", "fabricated"):
        b_val = int(b_attr.get(key) or 0)
        e_val = int(e_attr.get(key) or 0)
        print(f"  {key:18} {b_val:>12} {e_val:>18} {e_val - b_val:>+8}")

    _print_rule_table(baseline, experiment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
