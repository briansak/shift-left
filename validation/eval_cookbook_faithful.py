#!/usr/bin/env python3
"""Experiment H: cookbook-faithful config review via production chat inference path."""

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
FSEC = ROOT / "services" / "foundation-sec-server"
VALIDATION = ROOT / "validation"
for path in (SHARED, ORCH, FSEC, VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from cookbook_faithful_inputs import (  # noqa: E402
    FaithfulFileRun,
    FaithfulLabeledDefect,
    build_faithful_inputs,
)
from cookbook_faithful_prompt import COOKBOOK_FAITHFUL_PROMPT_SHAPE  # noqa: E402
from cookbook_prose_scoring import (  # noqa: E402
    COOKBOOK_DETECTION_THRESHOLD,
    defect_detected,
    score_detection_recall,
)
from eval_model import assert_llama_cpp, resolve_model_layout  # noqa: E402
from report_quant_stamping import merge_quant_metadata  # noqa: E402
from response_grounding import aggregate_grounding, score_grounding  # noqa: E402
from rcm_cwe_inference import LlamaCompleteEngine  # noqa: E402

REPORTS = ROOT / "validation" / "reports"
INPUTS_PATH = REPORTS / "cookbook-faithful-inputs.json"
RESPONSES_PATH = REPORTS / "cookbook-faithful-responses.json"
REPORT_PATH = REPORTS / "cookbook-faithful-eval.json"
SUMMARY_PATH = REPORTS / "cookbook-faithful-eval.txt"

STRUCTURED_BASELINE_REF = {
    "experiment": "baseline_structured_json",
    "rule_level_tp": 11,
    "labeled_defects": 108,
    "note": "Semantic-corrected best_fit_v1 TP from model-vs-handler-semantic-corrected.json",
}
EXPERIMENT_F_REF = {
    "experiment": "F_cookbook_prose",
    "rule_level_tp": 12,
    "labeled_defects": 108,
    "note": "Manual-adjudication-adjusted recall at semantic-fit threshold 0.70",
}
EXPERIMENT_G_GROUNDING_REF = {
    "experiment": "G_contextual_remediation",
    "metric": "manual_no_invented_refs_rate",
    "value": 0.40,
    "note": "20-defect sample; 60% fabrication on remediation prose",
}


def _inputs_payload(
    file_runs: list[FaithfulFileRun],
    instances: list[FaithfulLabeledDefect],
) -> dict[str, Any]:
    return merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "experiment": "H",
            "task": "cookbook_faithful_config_review",
            "prompt_shape": COOKBOOK_FAITHFUL_PROMPT_SHAPE,
            "inference_path": "foundation_sec_server.chat_inference.create_chat_completion",
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
    file_runs: list[FaithfulFileRun],
    *,
    cache: dict[str, str],
    max_tokens: int,
    temperature: float,
) -> dict[str, str]:
    responses: dict[str, str] = {}
    for index, file_run in enumerate(file_runs, start=1):
        if file_run.file_key in cache:
            responses[file_run.file_key] = cache[file_run.file_key]
            print(f"[file {index}/{len(file_runs)}] {file_run.file_key} (cached)", flush=True)
            continue
        response = engine.complete(
            file_run.prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            repeat_penalty=1.2,
        )
        cache[file_run.file_key] = response
        responses[file_run.file_key] = response
        print(f"[file {index}/{len(file_runs)}] {file_run.file_key} chars={len(response)}", flush=True)
    return responses


def _score_instances(
    instances: list[FaithfulLabeledDefect],
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


def _grounding_rows(
    file_runs: list[FaithfulFileRun],
    responses: dict[str, str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for file_run in file_runs:
        response = responses.get(file_run.file_key, "")
        grounding = score_grounding(response, file_run.config_content)
        rows.append(
            {
                "file_key": file_run.file_key,
                "corpus": file_run.corpus,
                "rel_path": file_run.rel_path,
                "target_type": file_run.target_type,
                **grounding,
            }
        )
    return rows


def _format_summary_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    grounding = report.get("grounding_summary") or {}
    fidelity = report.get("chat_template_fidelity") or {}
    lines = [
        "=== Experiment H: cookbook-faithful config review ===",
        (
            f"quant_evaluated={report.get('quant_evaluated')} "
            f"quant_intended={report.get('quant_intended')} "
            f"accuracy_only={report.get('accuracy_only')}"
        ),
        "",
        f"Inference path: {report.get('inference_path')}",
        f"llama.cpp chat_format: {fidelity.get('llama_cpp_chat_format')}",
        f"Model-specific Jinja template: {fidelity.get('uses_model_specific_jinja_template')}",
        f"Fidelity: {fidelity.get('fidelity_note')}",
        "",
        f"Prompt shape: {report['prompt_shape']}",
        f"Semantic-fit threshold: {report['semantic_fit_threshold']} (calibrated; not re-tuned)",
        "",
        f"Overall recall: {summary['detected']}/{summary['labeled_defects']} "
        f"({100 * float(summary['recall']):.1f}%)",
        "",
        "Grounding (identifiers / IPs / CIDRs not in supplied config):",
        (
            f"  ungrounded refs: {grounding.get('ungrounded_reference_count')}/"
            f"{grounding.get('total_reference_count')} "
            f"({100 * float(grounding.get('ungrounded_reference_rate') or 0):.1f}%)"
        ),
        (
            f"  files with any ungrounded: {grounding.get('files_with_ungrounded_references')}/"
            f"{grounding.get('file_count')} "
            f"({100 * float(grounding.get('files_with_ungrounded_rate') or 0):.1f}%)"
        ),
        "",
        "Comparison:",
        (
            f"  structured JSON baseline: {STRUCTURED_BASELINE_REF['rule_level_tp']}/"
            f"{STRUCTURED_BASELINE_REF['labeled_defects']}"
        ),
        (
            f"  Experiment F (prose, raw completion era): {EXPERIMENT_F_REF['rule_level_tp']}/"
            f"{EXPERIMENT_F_REF['labeled_defects']}"
        ),
        (
            f"  Experiment G fabrication check (manual): "
            f"{100 * float(EXPERIMENT_G_GROUNDING_REF['value']):.0f}% no-invented-refs"
        ),
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-output", type=Path, default=INPUTS_PATH)
    parser.add_argument("--responses", type=Path, default=RESPONSES_PATH)
    parser.add_argument("--output", type=Path, default=REPORT_PATH)
    parser.add_argument("--summary-output", type=Path, default=SUMMARY_PATH)
    parser.add_argument("--inputs-only", action="store_true")
    parser.add_argument("--run-inference", action="store_true")
    parser.add_argument("--allow-quant-mismatch", action="store_true")
    parser.add_argument("--max-tokens", type=int, default=1024)
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Cookbook instruct quickstart uses greedy decoding (temperature=0).",
    )
    args = parser.parse_args()

    file_runs, instances = build_faithful_inputs()
    if len(instances) != 108:
        print(f"ERROR: expected 108 labeled defects, built {len(instances)}", file=sys.stderr)
        return 1

    args.inputs_output.parent.mkdir(parents=True, exist_ok=True)
    args.inputs_output.write_text(
        json.dumps(_inputs_payload(file_runs, instances), indent=2),
        encoding="utf-8",
    )
    print(
        f"Wrote {args.inputs_output.relative_to(ROOT)} "
        f"({len(file_runs)} files, {len(instances)} labeled defects)"
    )

    if args.inputs_only:
        return 0

    cache: dict[str, str] = {}
    if args.responses.is_file():
        cache = json.loads(args.responses.read_text(encoding="utf-8"))

    missing = [run.file_key for run in file_runs if run.file_key not in cache]
    if missing and not args.run_inference:
        print(
            f"ERROR: missing responses for {len(missing)} files; use --run-inference",
            file=sys.stderr,
        )
        return 1

    fsec_python = ROOT / "services" / "foundation-sec-server" / ".venv" / "bin" / "python"
    if fsec_python.is_file():
        assert_llama_cpp(fsec_python)

    model_dir: Path | None = None
    chat_fidelity: dict[str, Any] = {}
    if missing and args.run_inference:
        model_dir, _, quant_label = resolve_model_layout(allow_quant_mismatch=args.allow_quant_mismatch)
        engine = LlamaCompleteEngine(model_dir, quant_label=quant_label)
        try:
            chat_fidelity = engine.chat_template_fidelity()
            responses = _run_inference(
                engine,
                file_runs,
                cache=cache,
                max_tokens=args.max_tokens,
                temperature=args.temperature,
            )
        finally:
            engine.unload()
        args.responses.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    else:
        responses = {run.file_key: cache[run.file_key] for run in file_runs}

    instance_rows = _score_instances(instances, responses)
    summary = score_detection_recall(instance_rows)
    grounding_rows = _grounding_rows(file_runs, responses)
    grounding_summary = aggregate_grounding(grounding_rows)

    report = merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "experiment": "H",
            "task": "cookbook_faithful_config_review",
            "purpose": (
                "Cookbook Configuration_Assessment prompt via production chat-template "
                "inference path; detection recall plus grounding rate."
            ),
            "prompt_shape": COOKBOOK_FAITHFUL_PROMPT_SHAPE,
            "inference_path": "foundation_sec_server.chat_inference.create_chat_completion",
            "chat_template_fidelity": chat_fidelity,
            "scoring": "detection_only_semantic_fit_on_defect_summary",
            "semantic_fit_threshold": COOKBOOK_DETECTION_THRESHOLD,
            "calibration_report": "validation/reports/cookbook-semantic-fit-calibration.json",
            "decoding": {
                "temperature": args.temperature,
                "repeat_penalty": 1.2,
                "max_tokens": args.max_tokens,
            },
            "file_run_count": len(file_runs),
            "labeled_defect_count": len(instances),
            "inputs_path": str(args.inputs_output.relative_to(ROOT)),
            "responses_path": str(args.responses.relative_to(ROOT)),
            "model_dir": str(model_dir.relative_to(ROOT)) if model_dir else None,
            "summary": summary,
            "grounding_summary": grounding_summary,
            "per_file_grounding": grounding_rows,
            "per_instance": instance_rows,
            "structured_baseline_reference": STRUCTURED_BASELINE_REF,
            "experiment_f_reference": EXPERIMENT_F_REF,
            "experiment_g_grounding_reference": EXPERIMENT_G_GROUNDING_REF,
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
