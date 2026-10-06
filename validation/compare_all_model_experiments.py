#!/usr/bin/env python3
"""Compare four model eval experiments on a unified best_fit_v1 scoring basis."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "validation"
if str(VALIDATION) not in sys.path:
    sys.path.insert(0, str(VALIDATION))

from report_quant_stamping import QUANT_EVALUATED, QUANT_INTENDED, ACCURACY_ONLY, merge_quant_metadata  # noqa: E402
REPORTS = ROOT / "validation" / "reports"
FINDINGS_CACHE = REPORTS / "findings-cache"
ATTRIBUTION_SCRIPT = ROOT / "validation" / "analyze_model_line_attribution.py"

MATCHER_LABEL = "best_fit_v1"

# (label, metrics sidecar/report, emitted manifest source, attribution output)
RUNS: tuple[tuple[str, Path, str, Path], ...] = (
    (
        "baseline",
        REPORTS / "model-vs-handler-semantic-corrected.json",
        "cache:baseline",
        REPORTS / "model-line-attribution-baseline-emitted.json",
    ),
    (
        "platform_specific",
        REPORTS / "model-vs-handler-platform-specific-semantic-corrected.json",
        "cache:platform_specific",
        REPORTS / "model-line-attribution-platform-specific-emitted.json",
    ),
    (
        "constrained_output",
        REPORTS / "model-vs-handler-constrained-output.json",
        "report:constrained_output",
        REPORTS / "model-line-attribution-constrained-output-emitted.json",
    ),
    (
        "platform_constrained",
        REPORTS / "model-vs-handler-platform-constrained.json",
        "report:platform_constrained",
        REPORTS / "model-line-attribution-platform-constrained-emitted.json",
    ),
)

RETRO_SIDEcars = {
    "baseline": REPORTS / "model-vs-handler-retro-constrained.json",
    "platform_specific": REPORTS / "model-vs-handler-platform-specific-retro-constrained.json",
}

NATIVE_REPORTS = {
    "constrained_output": REPORTS / "model-vs-handler-constrained-output.json",
    "platform_constrained": REPORTS / "model-vs-handler-platform-constrained.json",
}


def _load(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _sum_model_from_per_rule(per_rule: dict[str, Any]) -> tuple[int, int, int]:
    tp = fp = fn = 0
    for rules in per_rule.values():
        for metrics in rules.values():
            model = metrics.get("model")
            if model == "not_measured" or not isinstance(model, dict):
                continue
            tp += int(model.get("true_positives") or 0)
            fp += int(model.get("false_positives") or 0)
            fn += int(model.get("false_negatives") or 0)
    return tp, fp, fn


def _metrics_from_corrected_sidecar(sidecar: dict[str, Any]) -> tuple[int, int, int]:
    agg = sidecar["corrected"]["summary"]["aggregate_model"]
    return int(agg["true_positives"]), int(agg["false_positives"]), int(agg["false_negatives"])


def _metrics_from_native_report(report: dict[str, Any]) -> tuple[int, int, int]:
    return _sum_model_from_per_rule(report.get("per_target_type_per_rule") or {})


def _fabrication_from_summary(
    summary: dict[str, Any],
    *,
    fallback_report: dict[str, Any] | None = None,
) -> tuple[int, int, int, float]:
    emitted = int(summary.get("model_findings_emitted") or 0)
    if not emitted and fallback_report:
        emitted = int((fallback_report.get("summary") or {}).get("model_findings_emitted") or 0)
    rejected = int(summary.get("invalid_findings_count") or 0)
    surviving = int(
        summary.get("model_findings_surviving")
        or summary.get("model_findings_total")
        or 0
    )
    if not surviving and fallback_report:
        surviving = int((fallback_report.get("summary") or {}).get("model_findings_total") or 0)
    inv_summary = summary.get("invalid_findings_summary")
    if isinstance(inv_summary, dict):
        evidence_not_substring = int(inv_summary.get("evidence_not_substring") or 0)
    else:
        evidence_not_substring = int(summary.get("evidence_not_substring_count") or rejected)
    rate = float(
        summary.get("fabrication_rate_pct")
        or (100 * evidence_not_substring / emitted if emitted else 0)
    )
    return evidence_not_substring, emitted, surviving, rate


def _source_report_for_run(label: str, source: str) -> dict[str, Any] | None:
    if source.startswith("cache:"):
        variant = source.split(":", 1)[1]
        cache_report = {
            "prompt_variant": variant,
            "source_findings_cache": str(
                (FINDINGS_CACHE / f"{variant}.findings.json").relative_to(ROOT)
            ),
        }
        native = REPORTS / f"model-vs-handler.json"
        if variant == "platform_specific":
            native = REPORTS / "model-vs-handler-platform-specific.json"
        return merge_quant_metadata(cache_report, source_report=_load(native) or {})
    variant = source.split(":", 1)[1]
    return _load(NATIVE_REPORTS[variant])


def _attribution_coverage(
    label: str,
    *,
    items_count: int,
    report: dict[str, Any],
) -> dict[str, Any] | None:
    emitted_expected = int((report.get("summary") or {}).get("model_findings_emitted") or 0)
    if not emitted_expected or items_count == emitted_expected:
        return None

    coverage = report.get("emitted_findings_coverage") or {}
    missing_tp = int(coverage.get("missing_tp_survivor_payloads") or (emitted_expected - items_count))
    return {
        "emitted": emitted_expected,
        "attributed": items_count,
        "missing_payloads": emitted_expected - items_count,
        "missing_tp_survivor_payloads": missing_tp,
        "note": (
            coverage.get("note")
            or (
                f"{missing_tp} TP survivor payloads were not persisted in the original report "
                "(no findings cache for this variant)."
            )
        ),
    }


def _build_emitted_manifest(label: str, source: str) -> dict[str, Any]:
    from emitted_findings import (  # noqa: E402
        dedupe_emitted_items,
        emitted_items_from_cache,
        emitted_items_from_report,
        write_emitted_manifest,
    )

    manifest_path = REPORTS / f"model-emitted-findings-{label.replace('_', '-')}.json"
    source_report = _source_report_for_run(label, source) or {}
    if source.startswith("cache:"):
        variant = source.split(":", 1)[1]
        items = emitted_items_from_cache(FINDINGS_CACHE / f"{variant}.findings.json")
        attribution_coverage = None
    else:
        variant = source.split(":", 1)[1]
        report = _load(NATIVE_REPORTS[variant]) or {}
        items = emitted_items_from_report(report)
        attribution_coverage = _attribution_coverage(label, items_count=len(items), report=report)
    items = dedupe_emitted_items(items)
    metadata: dict[str, Any] = {
        "prompt_variant": label,
        "population": "all_emitted_model_findings",
        "source": source,
    }
    if attribution_coverage:
        metadata["attribution_coverage"] = attribution_coverage
        metadata["coverage_note"] = (
            f"{attribution_coverage['attributed']}/{attribution_coverage['emitted']} "
            "emitted payloads stored in report"
        )
    return write_emitted_manifest(
        items=items,
        path=manifest_path,
        metadata=metadata,
        source_report=source_report,
    )


def _run_attribution(manifest_path: Path, output_path: Path) -> dict[str, Any]:
    subprocess.run(
        [
            sys.executable,
            str(ATTRIBUTION_SCRIPT),
            "--input",
            str(manifest_path.resolve()),
            "--output",
            str(output_path.resolve()),
            "--scope",
            "emitted",
        ],
        check=True,
        cwd=str(ROOT),
    )
    return (_load(output_path) or {}).get("summary") or {}


def _row_for_run(label: str, metrics_path: Path, source: str, attr_path: Path) -> dict[str, Any]:
    payload = _load(metrics_path) or {}

    if label in {"baseline", "platform_specific"}:
        tp, fp, fn = _metrics_from_corrected_sidecar(payload)
        retro = _load(RETRO_SIDEcars[label]) or {}
        fab_summary = retro.get("summary") or {}
    else:
        tp, fp, fn = _metrics_from_native_report(payload)
        fab_summary = dict(payload.get("summary") or {})
        inv = payload.get("invalid_findings_summary") or {}
        fab_summary.setdefault("invalid_findings_summary", inv)
        fab_summary.setdefault(
            "evidence_not_substring_count", inv.get("evidence_not_substring")
        )

    evidence_not_substring, emitted, surviving, fab_rate = _fabrication_from_summary(
        fab_summary,
        fallback_report=payload if label in NATIVE_REPORTS else None,
    )

    manifest = _build_emitted_manifest(label, source)
    attr = _run_attribution(
        REPORTS / f"model-emitted-findings-{label.replace('_', '-')}.json",
        attr_path,
    )

    attribution_coverage = manifest.get("attribution_coverage")
    return {
        "label": label,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "emitted": emitted,
        "rejected": int(fab_summary.get("invalid_findings_count") or evidence_not_substring),
        "evidence_not_substring": evidence_not_substring,
        "fabrication_rate_pct": fab_rate,
        "surviving": surviving,
        "attribution_n": attr.get("findings_total"),
        "attr_contains": attr.get("contains"),
        "attr_mismatch": attr.get("mismatch"),
        "attr_fabricated": attr.get("fabricated"),
        "attr_tight_anchor": attr.get("tight_anchor"),
        "attribution_coverage": attribution_coverage,
        "manifest_coverage": manifest.get("coverage_note"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPORTS / "model-experiments-comparison.txt",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=REPORTS / "model-experiments-comparison.json",
    )
    parser.add_argument(
        "--skip-attribution",
        action="store_true",
        help="Reuse existing emitted attribution JSON if present.",
    )
    args = parser.parse_args()

    missing = [label for label, path, _, _ in RUNS if not path.is_file()]
    if missing:
        print(f"ERROR: missing metrics sidecars/reports: {', '.join(missing)}", file=sys.stderr)
        return 1

    rows: list[dict[str, Any]] = []
    for label, metrics_path, source, attr_path in RUNS:
        if args.skip_attribution and attr_path.is_file():
            payload = _load(metrics_path) or {}
            if label in {"baseline", "platform_specific"}:
                tp, fp, fn = _metrics_from_corrected_sidecar(payload)
                retro = _load(RETRO_SIDEcars[label]) or {}
                fab_summary = retro.get("summary") or {}
                fallback = None
            else:
                tp, fp, fn = _metrics_from_native_report(payload)
                fab_summary = dict(payload.get("summary") or {})
                inv = payload.get("invalid_findings_summary") or {}
                fab_summary.setdefault("invalid_findings_summary", inv)
                fab_summary.setdefault(
                    "evidence_not_substring_count", inv.get("evidence_not_substring")
                )
                fallback = payload
            evidence_not_substring, emitted, surviving, fab_rate = _fabrication_from_summary(
                fab_summary,
                fallback_report=fallback,
            )
            attr = (_load(attr_path) or {}).get("summary") or {}
            rows.append(
                {
                    "label": label,
                    "tp": tp,
                    "fp": fp,
                    "fn": fn,
                    "emitted": emitted,
                    "rejected": int(fab_summary.get("invalid_findings_count") or 0),
                    "evidence_not_substring": evidence_not_substring,
                    "fabrication_rate_pct": fab_rate,
                    "surviving": surviving,
                    "attribution_n": attr.get("findings_total"),
                    "attr_contains": attr.get("contains"),
                    "attr_mismatch": attr.get("mismatch"),
                    "attr_fabricated": attr.get("fabricated"),
                    "attr_tight_anchor": attr.get("tight_anchor"),
                    "manifest_coverage": None,
                }
            )
        else:
            rows.append(_row_for_run(label, metrics_path, source, attr_path))

    quant_header = (
        f"quant_evaluated={QUANT_EVALUATED} quant_intended={QUANT_INTENDED} "
        f"accuracy_only={ACCURACY_ONLY}"
    )
    lines: list[str] = [
        f"=== Model eval experiments comparison ({quant_header}, semantic matcher: {MATCHER_LABEL}) ===",
        "",
        "Rule-level TP/FP/FN: baseline and platform_specific from semantic-corrected sidecars;",
        "constrained variants from native reports (same matcher). Fabrication = evidence_not_substring",
        "rejections / emitted findings. Line attribution population: all emitted model findings (n per run).",
        "",
        f"{'Experiment':<20} {'emit':>5} {'rej':>5} {'surv':>5} {'fab%':>6} "
        f"{'TP':>4} {'FP':>4} {'FN':>4} {'Recall':>8}",
    ]
    for row in rows:
        lines.append(
            f"{row['label']:<20} {row['emitted']:>5} {row['rejected']:>5} {row['surviving']:>5} "
            f"{row['fabrication_rate_pct']:>5.1f}% "
            f"{row['tp']:>4} {row['fp']:>4} {row['fn']:>4} {row['tp']}/108"
        )

    lines.append("")
    lines.append("Fabrication detail (evidence_not_substring / emitted):")
    for row in rows:
        lines.append(
            f"  {row['label']:<20} {row['evidence_not_substring']:>4}/{row['emitted']:<4} "
            f"({row['fabrication_rate_pct']:.1f}%)"
        )

    attribution_gaps = [row for row in rows if row.get("attribution_coverage")]
    if attribution_gaps:
        lines.append("")
        lines.append("Emitted-finding payload coverage (line attribution input):")
        for row in attribution_gaps:
            cov = row["attribution_coverage"]
            lines.append(
                f"  {row['label']:<20} {cov['attributed']}/{cov['emitted']} payloads stored "
                f"({cov['missing_payloads']} missing)"
            )
            lines.append(
                f"    gap: {cov['missing_tp_survivor_payloads']} TP survivor payloads not "
                "persisted in the original report (no findings cache for this variant)"
            )
            if cov.get("note"):
                lines.append(f"    note: {cov['note']}")

    lines.append("")
    lines.append("Line attribution (population: all emitted model findings):")
    lines.append(
        f"  {'experiment':<20} {'n':>5} {'contains':>8} {'mismatch':>8} "
        f"{'fabricated':>10} {'tight_anchor':>12}"
    )
    for row in rows:
        attr_note = ""
        cov = row.get("attribution_coverage")
        if cov:
            attr_note = (
                f"  [{cov['attributed']}/{cov['emitted']} payloads; "
                f"{cov['missing_tp_survivor_payloads']} missing TP survivors]"
            )
        lines.append(
            f"  {row['label']:<20} {row['attribution_n']:>5} "
            f"{row['attr_contains']:>8} {row['attr_mismatch']:>8} "
            f"{row['attr_fabricated']:>10} {row['attr_tight_anchor']:>12}{attr_note}"
        )

    lines.append("")
    lines.append(
        "Retro constrained validation — rule-level TP/FP/FN among survivors only "
        "(baseline/platform_specific sidecars; native for constrained variants):"
    )
    for row in rows:
        label = row["label"]
        if label in RETRO_SIDEcars:
            retro = _load(RETRO_SIDEcars[label]) or {}
            agg = (retro.get("summary") or {}).get("aggregate_model") or {}
            lines.append(
                f"  {label:<20} survivors={row['surviving']:>3}  "
                f"TP/FP/FN={agg.get('true_positives', '—')}/"
                f"{agg.get('false_positives', '—')}/"
                f"{agg.get('false_negatives', '—')}"
            )
        else:
            lines.append(
                f"  {label:<20} survivors={row['surviving']:>3}  "
                f"TP/FP/FN={row['tp']}/{row['fp']}/{row['fn']} (harness-scored)"
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    json_payload = merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "semantic_matcher": MATCHER_LABEL,
            "experiments": rows,
            "attribution_gaps": [
                {
                    "experiment": row["label"],
                    **row["attribution_coverage"],
                }
                for row in rows
                if row.get("attribution_coverage")
            ],
        }
    )
    args.json_output.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    print("\n".join(lines))
    print(f"\nWrote {args.output.relative_to(ROOT)}")
    print(f"Wrote {args.json_output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
