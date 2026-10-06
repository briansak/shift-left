#!/usr/bin/env python3
"""Experiment F: cookbook-format prose findings with detection-only scoring."""

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

from cookbook_prose_inputs import (  # noqa: E402
    CookbookFileRun,
    LabeledDefect,
    build_cookbook_inputs,
)
from cookbook_prose_prompt import COOKBOOK_PROMPT_SHAPE  # noqa: E402
from cookbook_prose_scoring import defect_detected, score_detection_recall  # noqa: E402
from eval_model import assert_llama_cpp, resolve_model_layout  # noqa: E402
from cookbook_prose_scoring import COOKBOOK_DETECTION_THRESHOLD  # noqa: E402
from report_quant_stamping import merge_quant_metadata  # noqa: E402
from rcm_cwe_inference import LlamaCompleteEngine  # noqa: E402

REPORTS = ROOT / "validation" / "reports"
INPUTS_PATH = REPORTS / "cookbook-prose-inputs.json"
REPORT_PATH = REPORTS / "cookbook-prose-eval.json"
SUMMARY_PATH = REPORTS / "cookbook-prose-eval.txt"

STRUCTURED_BASELINE_REF = {
    "experiment": "baseline_structured_json",
    "rule_level_tp": 11,
    "labeled_defects": 108,
    "note": "Semantic-corrected best_fit_v1 TP from model-vs-handler-semantic-corrected.json",
}


def _inputs_payload(
    file_runs: list[CookbookFileRun],
    instances: list[LabeledDefect],
) -> dict[str, Any]:
    return merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "experiment": "F",
            "task": "cookbook_prose_detection",
            "prompt_shape": COOKBOOK_PROMPT_SHAPE,
            "output_constraints": {
                "cwe": False,
                "line_numbers": False,
                "evidence": False,
                "structured_json": False,
            },
            "file_run_count": len(file_runs),
            "labeled_defect_count": len(instances),
            "file_runs": [item.as_dict() for item in file_runs],
            "labeled_defects": [item.as_dict() for item in instances],
        }
    )


def _run_inference(
    engine: LlamaCompleteEngine,
    file_runs: list[CookbookFileRun],
    *,
    cache: dict[str, str] | None = None,
    max_tokens: int = 1024,
) -> dict[str, str]:
    responses: dict[str, str] = {}
    for index, file_run in enumerate(file_runs, start=1):
        if cache and file_run.file_key in cache:
            response = cache[file_run.file_key]
        else:
            response = engine.complete(file_run.prompt, max_tokens=max_tokens)
            if cache is not None:
                cache[file_run.file_key] = response
        responses[file_run.file_key] = response
        print(f"[file {index}/{len(file_runs)}] {file_run.file_key} chars={len(response)}")
    return responses


def _score_instances(
    instances: list[LabeledDefect],
    responses: dict[str, str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for instance in instances:
        prose = responses.get(instance.file_key, "")
        detected, fit_score = defect_detected(
            prose,
            defect_summary=instance.defect_summary,
            rule_id=instance.rule_id,
            target_type=instance.target_type,
        )
        rows.append(
            {
                "instance_id": instance.instance_id,
                "file_key": instance.file_key,
                "corpus": instance.corpus,
                "rel_path": instance.rel_path,
                "target_type": instance.target_type,
                "rule_id": instance.rule_id,
                "defect_summary": instance.defect_summary,
                "detected": detected,
                "semantic_fit": round(fit_score, 4),
                "model_response_excerpt": prose[:500],
            }
        )
    return rows


def _format_summary_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "=== Experiment F: cookbook prose findings (detection-only scoring) ===",
        (
            f"quant_evaluated={report.get('quant_evaluated')} "
            f"quant_intended={report.get('quant_intended')} "
            f"accuracy_only={report.get('accuracy_only')}"
        ),
        "",
        f"Prompt shape: {report['prompt_shape']}",
        "Scoring: semantic match on registry defect summary; severity ignored.",
        f"Semantic-fit threshold: {report['semantic_fit_threshold']}",
        "",
        f"Overall recall: {summary['detected']}/{summary['labeled_defects']} "
        f"({100 * float(summary['recall']):.1f}%)",
        "",
        "Recall per target_type:",
    ]
    for target_type, bucket in (summary.get("per_target_type") or {}).items():
        lines.append(
            f"  {target_type:<22} {bucket['detected']}/{bucket['total']} "
            f"({100 * float(bucket['recall']):.1f}%)"
        )

    ref = report.get("structured_baseline_reference") or {}
    lines.extend(
        [
            "",
            "Comparison (structured JSON baseline, rule-level TP):",
            (
                f"  {ref.get('experiment')}: {ref.get('rule_level_tp')}/"
                f"{ref.get('labeled_defects')} labeled defects"
            ),
            f"  {ref.get('note')}",
            "",
            "Interpretation:",
            "  Substantially higher recall than structured baseline → output format was limiting.",
            "  Recall near structured baseline (~8–11/108) → detection capability is limiting.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-output", type=Path, default=INPUTS_PATH)
    parser.add_argument("--output", type=Path, default=REPORT_PATH)
    parser.add_argument("--summary-output", type=Path, default=SUMMARY_PATH)
    parser.add_argument("--inputs-only", action="store_true")
    parser.add_argument(
        "--allow-quant-mismatch",
        action="store_true",
        help="Use staged Q8_0 Foundation-Sec weights (accuracy-only run).",
    )
    parser.add_argument(
        "--cache",
        type=Path,
        help="Optional JSON cache of file_key -> model response.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=1024,
        help="Max completion tokens per file.",
    )
    args = parser.parse_args()

    file_runs, instances = build_cookbook_inputs()
    if len(instances) != 108:
        print(f"ERROR: expected 108 labeled defects, built {len(instances)}", file=sys.stderr)
        return 1

    inputs_payload = _inputs_payload(file_runs, instances)
    args.inputs_output.parent.mkdir(parents=True, exist_ok=True)
    args.inputs_output.write_text(json.dumps(inputs_payload, indent=2), encoding="utf-8")
    print(
        f"Wrote {args.inputs_output.relative_to(ROOT)} "
        f"({len(file_runs)} files, {len(instances)} labeled defects)"
    )

    if args.inputs_only:
        return 0

    cache: dict[str, str] = {}
    if args.cache and args.cache.is_file():
        cache = json.loads(args.cache.read_text(encoding="utf-8"))

    fsec_python = ROOT / "services" / "foundation-sec-server" / ".venv" / "bin" / "python"
    if fsec_python.is_file():
        assert_llama_cpp(fsec_python)

    try:
        model_dir, _, quant_label = resolve_model_layout(allow_quant_mismatch=args.allow_quant_mismatch)
        engine = LlamaCompleteEngine(model_dir, quant_label=quant_label)
        try:
            responses = _run_inference(
                engine,
                file_runs,
                cache=cache,
                max_tokens=args.max_tokens,
            )
        finally:
            engine.unload()
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: inference unavailable: {exc}", file=sys.stderr)
        return 1

    if args.cache:
        args.cache.parent.mkdir(parents=True, exist_ok=True)
        args.cache.write_text(json.dumps(cache, indent=2), encoding="utf-8")

    instance_rows = _score_instances(instances, responses)
    summary = score_detection_recall(instance_rows)

    report = merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "experiment": "F",
            "task": "cookbook_prose_detection",
            "purpose": (
                "Isolate whether structured-output constraints or detection capability "
                "limits Foundation-Sec on labeled handler defects."
            ),
            "prompt_shape": COOKBOOK_PROMPT_SHAPE,
            "scoring": "detection_only_semantic_fit_on_defect_summary",
            "semantic_fit_threshold": COOKBOOK_DETECTION_THRESHOLD,
            "calibration_report": "validation/reports/cookbook-semantic-fit-calibration.json",
            "severity_scored": False,
            "file_run_count": len(file_runs),
            "labeled_defect_count": len(instances),
            "inputs_path": str(args.inputs_output.relative_to(ROOT)),
            "model_dir": str(model_dir.relative_to(ROOT)),
            "summary": summary,
            "per_instance": instance_rows,
            "structured_baseline_reference": STRUCTURED_BASELINE_REF,
        }
    )

    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    summary_text = _format_summary_text(report)
    args.summary_output.write_text(summary_text, encoding="utf-8")

    print(summary_text)
    print(f"Wrote {args.output.relative_to(ROOT)}")
    print(f"Wrote {args.summary_output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
