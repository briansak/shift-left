#!/usr/bin/env python3
"""Re-score existing model eval runs with legacy vs corrected semantic matchers."""

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
for path in (SHARED, ORCH, ROOT / "validation"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from eval_handlers import load_corpus  # noqa: E402
from eval_model import (  # noqa: E402
    RULE_SEMANTICS,
    analyze_file,
    collect_file_list,
    corpus_dirs,
    is_model_originated,
    resolve_interpreter,
    run_preflight,
    start_foundation_sec_server,
)
from report_quant_stamping import merge_quant_metadata  # noqa: E402
from model_eval_matching import (  # noqa: E402
    MATCHER_BEST_FIT,
    MATCHER_LEGACY,
    MATCHER_METADATA,
    MetricCounts,
    ModelMetricCounts,
    aggregate_model_metrics,
    build_per_rule_report,
    score_file,
    summarize_fp_diagnostics,
)
from shift_left.ui.cwe_dictionary import unrecognized_model_cwe_tally  # noqa: E402

import httpx  # noqa: E402

DEFAULT_BASELINE = ROOT / "validation" / "reports" / "model-vs-handler.json"
DEFAULT_EXPERIMENT = ROOT / "validation" / "reports" / "model-vs-handler-platform-specific.json"
FINDINGS_CACHE_DIR = ROOT / "validation" / "reports" / "findings-cache"


def _cache_path(prompt_variant: str) -> Path:
    return FINDINGS_CACHE_DIR / f"{prompt_variant}.findings.json"


def _load_findings_cache(path: Path) -> list[dict[str, Any]] | None:
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return list(payload.get("files") or [])


def _save_findings_cache(path: Path, *, prompt_variant: str, files: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "prompt_variant": prompt_variant,
                "generated_at": datetime.now(UTC).isoformat(),
                "files": files,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _infer_findings(prompt_variant: str, *, allow_quant_mismatch: bool) -> list[dict[str, Any]]:
    from eval_model import assert_llama_cpp, resolve_model_layout

    server_python = resolve_interpreter()
    llama_cpp_version = assert_llama_cpp(server_python)
    model_dir, use_low_memory, _ = resolve_model_layout(allow_quant_mismatch=allow_quant_mismatch)
    server_proc = None
    records: list[dict[str, Any]] = []
    try:
        server_pid, server_proc = start_foundation_sec_server(
            server_python,
            model_dir=model_dir,
            use_low_memory=use_low_memory,
        )
        with httpx.Client(timeout=600.0) as client:
            run_preflight(
                client,
                server_pid=server_pid,
                allow_quant_mismatch=allow_quant_mismatch,
            )
            for corpus_name, corpus_dir, entry in collect_file_list():
                content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
                result = analyze_file(
                    client,
                    virtual_path=entry.virtual_path,
                    content=content,
                    corpus_name=corpus_name,
                    target_type=entry.target_type,
                    prompt_variant=prompt_variant,
                )
                outcome = str(result.get("outcome") or "unknown")
                success = outcome in {"completed_no_findings", "completed_with_findings"}
                findings = []
                if success:
                    findings = [
                        f for f in (result.get("findings") or []) if is_model_originated(f)
                    ]
                records.append(
                    {
                        "corpus": corpus_name,
                        "rel_path": entry.rel_path,
                        "target_type": entry.target_type,
                        "virtual_path": entry.virtual_path,
                        "expected_rule_ids": list(entry.expected_rule_ids),
                        "model_outcome": outcome,
                        "model_findings": findings,
                    }
                )
                print(
                    f"[{prompt_variant}] {corpus_name}/{entry.rel_path} "
                    f"findings={len(findings)} outcome={outcome}",
                    flush=True,
                )
    finally:
        if server_proc is not None and server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=15)
            except Exception:
                server_proc.kill()
    return records


def _load_or_infer_findings(
    *,
    prompt_variant: str,
    cache_path: Path,
    force_infer: bool,
    allow_quant_mismatch: bool,
) -> list[dict[str, Any]]:
    if not force_infer:
        cached = _load_findings_cache(cache_path)
        if cached is not None:
            print(f"Loaded findings cache: {cache_path.relative_to(ROOT)}", flush=True)
            return cached
    print(f"Inferring findings for prompt_variant={prompt_variant} ...", flush=True)
    records = _infer_findings(prompt_variant, allow_quant_mismatch=allow_quant_mismatch)
    _save_findings_cache(cache_path, prompt_variant=prompt_variant, files=records)
    print(f"Wrote findings cache: {cache_path.relative_to(ROOT)}", flush=True)
    return records


def _entry_from_record(record: dict[str, Any], corpus_dir: Path) -> Any:
    from types import SimpleNamespace

    labels_path = corpus_dir / f"{record['rel_path']}.labels.json"
    labels = json.loads(labels_path.read_text(encoding="utf-8")) if labels_path.is_file() else {}
    return SimpleNamespace(
        rel_path=record["rel_path"],
        target_type=record["target_type"],
        virtual_path=record.get("virtual_path") or record["rel_path"],
        expected_rule_ids=tuple(record.get("expected_rule_ids") or labels.get("expected_rule_ids") or []),
    )


def _corpus_dir(corpus_name: str) -> Path:
    for name, path in corpus_dirs():
        if name == corpus_name:
            return path
    raise KeyError(corpus_name)


def rescore_findings(
    records: list[dict[str, Any]],
    *,
    matcher: str,
    collect_legacy_fp: bool = False,
) -> dict[str, Any]:
    handler_stats: dict[str, dict[str, MetricCounts]] = {}
    model_stats: dict[str, dict[str, ModelMetricCounts]] = {}
    unlabeled: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    legacy_fp_hits: dict[tuple[str, str, int, int, str, str], set[str]] = {}
    files_scored = 0

    for record in records:
        if record.get("model_outcome") not in {
            "completed_no_findings",
            "completed_with_findings",
        }:
            continue
        corpus_name = str(record["corpus"])
        corpus_dir = _corpus_dir(corpus_name)
        entry = _entry_from_record(record, corpus_dir)
        content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
        model_findings = list(record.get("model_findings") or [])
        all_findings.extend(model_findings)
        score_file(
            matcher=matcher,
            entry=entry,
            corpus_name=corpus_name,
            content=content,
            model_findings=model_findings,
            handler_stats=handler_stats,
            model_stats=model_stats,
            unlabeled_model_findings=unlabeled,
            rule_semantics=RULE_SEMANTICS,
            legacy_fp_hits=legacy_fp_hits if collect_legacy_fp else None,
        )
        files_scored += 1

    tp, fp, fn = aggregate_model_metrics(model_stats)
    result: dict[str, Any] = {
        "per_target_type_per_rule": build_per_rule_report(
            handler_stats, model_stats, RULE_SEMANTICS
        ),
        "summary": {
            "files_scored_successfully": files_scored,
            "model_findings_total": len(all_findings),
            "unlabeled_model_findings_count": len(unlabeled),
            "aggregate_model": {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
            },
        },
        "unlabeled_model_findings": unlabeled,
        "unrecognized_model_asserted_cwe": unrecognized_model_cwe_tally(all_findings),
    }
    if collect_legacy_fp:
        diag = summarize_fp_diagnostics(legacy_fp_hits)
        result["legacy_fp_diagnostics"] = {
            "distinct_fp_findings": diag.distinct_fp_findings,
            "max_rules_per_finding": diag.max_rules_per_finding,
            "rule_level_fp_count": diag.rule_level_fp_count,
            "multi_rule_fp_findings": diag.multi_rule_fp_findings,
            "samples": diag.finding_rule_hits[:25],
        }
    return result


def build_corrected_report(
    source_report: dict[str, Any],
    *,
    source_path: Path,
    legacy_rescore: dict[str, Any],
    corrected_rescore: dict[str, Any],
) -> dict[str, Any]:
    legacy_agg = legacy_rescore["summary"]["aggregate_model"]
    corrected_agg = corrected_rescore["summary"]["aggregate_model"]
    return merge_quant_metadata(
        {
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "rescored",
        "source_report": str(source_path.relative_to(ROOT)),
        "source_report_preserved": True,
        "prompt_variant": source_report.get("prompt_variant"),
        "semantic_matcher": MATCHER_BEST_FIT,
        "semantic_matcher_metadata": MATCHER_METADATA[MATCHER_BEST_FIT],
        "legacy_semantic_matcher": MATCHER_LEGACY,
        "legacy_semantic_matcher_metadata": MATCHER_METADATA[MATCHER_LEGACY],
        "legacy_fp_diagnostics": legacy_rescore.get("legacy_fp_diagnostics"),
        "legacy_rescore": {
            "matcher": MATCHER_LEGACY,
            "summary": legacy_rescore["summary"],
            "per_target_type_per_rule": legacy_rescore["per_target_type_per_rule"],
        },
        "corrected": {
            "matcher": MATCHER_BEST_FIT,
            "summary": corrected_rescore["summary"],
            "per_target_type_per_rule": corrected_rescore["per_target_type_per_rule"],
        },
        "delta_corrected_vs_legacy_rescore": {
            "true_positives": corrected_agg["true_positives"] - legacy_agg["true_positives"],
            "false_positives": corrected_agg["false_positives"] - legacy_agg["false_positives"],
            "false_negatives": corrected_agg["false_negatives"] - legacy_agg["false_negatives"],
            "unlabeled_model_findings": (
                corrected_rescore["summary"]["unlabeled_model_findings_count"]
                - legacy_rescore["summary"]["unlabeled_model_findings_count"]
            ),
        },
        "delta_corrected_vs_original_report": _delta_vs_original(
            source_report, corrected_rescore
        ),
        },
        source_report=source_report,
    )


def _delta_vs_original(
    source_report: dict[str, Any],
    corrected_rescore: dict[str, Any],
) -> dict[str, int]:
    orig_tp = orig_fp = orig_fn = 0
    for rules in (source_report.get("per_target_type_per_rule") or {}).values():
        for metrics in rules.values():
            model = metrics.get("model")
            if model == "not_measured" or not isinstance(model, dict):
                continue
            orig_tp += int(model.get("true_positives") or 0)
            orig_fp += int(model.get("false_positives") or 0)
            orig_fn += int(model.get("false_negatives") or 0)
    corrected = corrected_rescore["summary"]["aggregate_model"]
    return {
        "true_positives": corrected["true_positives"] - orig_tp,
        "false_positives": corrected["false_positives"] - orig_fp,
        "false_negatives": corrected["false_negatives"] - orig_fn,
        "unlabeled_model_findings": (
            corrected_rescore["summary"]["unlabeled_model_findings_count"]
            - int((source_report.get("summary") or {}).get("unlabeled_model_findings_count") or 0)
        ),
    }


def _print_side_by_side(
    baseline: dict[str, Any],
    experiment: dict[str, Any],
    *,
    title: str,
) -> None:
    print(f"\n=== {title} ===")
    for label, payload in (("baseline", baseline), ("experiment", experiment)):
        agg = payload["summary"]["aggregate_model"]
        diag = payload.get("legacy_fp_diagnostics") or {}
        print(f"\n[{label}]")
        print(
            f"  distinct FP findings: {diag.get('distinct_fp_findings', '—')} "
            f"(rule-level FP={diag.get('rule_level_fp_count', '—')})"
        )
        print(f"  max rules per finding: {diag.get('max_rules_per_finding', '—')}")
        print(f"  multi-rule FP findings: {diag.get('multi_rule_fp_findings', '—')}")
        print(
            f"  model TP/FP/FN: {agg['true_positives']}/{agg['false_positives']}/{agg['false_negatives']}"
        )
        print(f"  unlabeled: {payload['summary']['unlabeled_model_findings_count']}")

    print("\nPer target_type / rule — corrected model TP / FP / FN (baseline vs platform_specific)")
    base_rules = baseline["per_target_type_per_rule"]
    exp_rules = experiment["per_target_type_per_rule"]
    for target_type in sorted(set(base_rules) | set(exp_rules)):
        print(f"\n  [{target_type}]")
        print(
            f"  {'Rule':<10} {'B-TP':>5} {'B-FP':>5} {'B-FN':>5}   "
            f"{'E-TP':>5} {'E-FP':>5} {'E-FN':>5}"
        )
        rule_ids = sorted(set(base_rules.get(target_type, {})) | set(exp_rules.get(target_type, {})))
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
        "--baseline-output",
        type=Path,
        default=ROOT / "validation" / "reports" / "model-vs-handler-semantic-corrected.json",
    )
    parser.add_argument(
        "--experiment-output",
        type=Path,
        default=ROOT
        / "validation"
        / "reports"
        / "model-vs-handler-platform-specific-semantic-corrected.json",
    )
    parser.add_argument(
        "--comparison-output",
        type=Path,
        default=ROOT / "validation" / "reports" / "model-semantic-matcher-comparison.txt",
    )
    parser.add_argument("--force-infer", action="store_true")
    parser.add_argument(
        "--allow-quant-mismatch",
        action="store_true",
        help="Allow non-Q4_K_M weights when re-inferring findings.",
    )
    args = parser.parse_args()

    if not args.baseline.is_file() or not args.experiment.is_file():
        print("ERROR: baseline and experiment source reports must exist.", file=sys.stderr)
        return 1

    baseline_source = json.loads(args.baseline.read_text(encoding="utf-8"))
    experiment_source = json.loads(args.experiment.read_text(encoding="utf-8"))

    baseline_variant = str(baseline_source.get("prompt_variant") or "baseline")
    experiment_variant = str(experiment_source.get("prompt_variant") or "platform_specific")

    baseline_records = _load_or_infer_findings(
        prompt_variant=baseline_variant,
        cache_path=_cache_path(baseline_variant),
        force_infer=args.force_infer,
        allow_quant_mismatch=args.allow_quant_mismatch,
    )
    experiment_records = _load_or_infer_findings(
        prompt_variant=experiment_variant,
        cache_path=_cache_path(experiment_variant),
        force_infer=args.force_infer,
        allow_quant_mismatch=args.allow_quant_mismatch,
    )

    baseline_legacy = rescore_findings(baseline_records, matcher=MATCHER_LEGACY, collect_legacy_fp=True)
    baseline_corrected = rescore_findings(baseline_records, matcher=MATCHER_BEST_FIT)
    experiment_legacy = rescore_findings(
        experiment_records, matcher=MATCHER_LEGACY, collect_legacy_fp=True
    )
    experiment_corrected = rescore_findings(experiment_records, matcher=MATCHER_BEST_FIT)

    baseline_report = build_corrected_report(
        baseline_source,
        source_path=args.baseline,
        legacy_rescore=baseline_legacy,
        corrected_rescore=baseline_corrected,
    )
    experiment_report = build_corrected_report(
        experiment_source,
        source_path=args.experiment,
        legacy_rescore=experiment_legacy,
        corrected_rescore=experiment_corrected,
    )

    args.baseline_output.parent.mkdir(parents=True, exist_ok=True)
    args.baseline_output.write_text(json.dumps(baseline_report, indent=2), encoding="utf-8")
    args.experiment_output.write_text(json.dumps(experiment_report, indent=2), encoding="utf-8")

    lines: list[str] = []
    lines.append("=== Semantic matcher correction report ===")
    lines.append(f"Generated: {baseline_report['generated_at']}")
    lines.append(f"Matcher: {MATCHER_BEST_FIT}")
    lines.append(f"  {MATCHER_METADATA[MATCHER_BEST_FIT]['description']}")
    lines.append("")
    lines.append("Source reports (unchanged):")
    lines.append(f"  baseline:   {args.baseline.relative_to(ROOT)}")
    lines.append(f"  experiment: {args.experiment.relative_to(ROOT)}")
    lines.append("")
    lines.append("Corrected sidecar reports:")
    lines.append(f"  baseline:   {args.baseline_output.relative_to(ROOT)}")
    lines.append(f"  experiment: {args.experiment_output.relative_to(ROOT)}")
    lines.append("")

    def _append_run(label: str, report: dict[str, Any]) -> None:
        diag = report["legacy_fp_diagnostics"]
        legacy = report["legacy_rescore"]["summary"]["aggregate_model"]
        corrected = report["corrected"]["summary"]["aggregate_model"]
        delta = report["delta_corrected_vs_legacy_rescore"]
        orig_delta = report["delta_corrected_vs_original_report"]
        lines.append(f"--- {label} ---")
        lines.append(
            "Legacy matcher FP inflation (from full finding replay): "
            f"{diag['distinct_fp_findings']} distinct findings produced "
            f"{diag['rule_level_fp_count']} rule-level FPs "
            f"(max {diag['max_rules_per_finding']} rules/finding; "
            f"{diag['multi_rule_fp_findings']} findings hit >1 rule)"
        )
        lines.append(
            f"Legacy rescore TP/FP/FN: {legacy['true_positives']}/{legacy['false_positives']}/{legacy['false_negatives']}"
        )
        lines.append(
            f"Corrected TP/FP/FN:      {corrected['true_positives']}/{corrected['false_positives']}/{corrected['false_negatives']}"
        )
        lines.append(
            f"Delta corrected vs legacy: TP {delta['true_positives']:+d}, "
            f"FP {delta['false_positives']:+d}, FN {delta['false_negatives']:+d}, "
            f"unlabeled {delta['unlabeled_model_findings']:+d}"
        )
        lines.append(
            f"Delta corrected vs original report: TP {orig_delta['true_positives']:+d}, "
            f"FP {orig_delta['false_positives']:+d}, FN {orig_delta['false_negatives']:+d}, "
            f"unlabeled {orig_delta['unlabeled_model_findings']:+d}"
        )
        lines.append("")

    _append_run("baseline", baseline_report)
    _append_run("platform_specific", experiment_report)

    bl = baseline_report["corrected"]["summary"]["aggregate_model"]
    ex = experiment_report["corrected"]["summary"]["aggregate_model"]
    lines.append("Corrected aggregate — baseline vs platform_specific")
    lines.append(f"  TP: {bl['true_positives']} -> {ex['true_positives']} ({ex['true_positives'] - bl['true_positives']:+d})")
    lines.append(f"  FP: {bl['false_positives']} -> {ex['false_positives']} ({ex['false_positives'] - bl['false_positives']:+d})")
    lines.append(f"  FN: {bl['false_negatives']} -> {ex['false_negatives']} ({ex['false_negatives'] - bl['false_negatives']:+d})")

    args.comparison_output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    _print_side_by_side(
        baseline_corrected,
        experiment_corrected,
        title="Corrected matcher — baseline vs platform_specific",
    )
    print(f"\nWrote {args.comparison_output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
