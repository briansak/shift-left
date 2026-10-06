#!/usr/bin/env python3
"""Experiment G: contextual remediation quality (no detection/classification)."""

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

from contextual_remediation_adjudication import (  # noqa: E402
    deterministic_sample,
    format_adjudication_worksheet,
    invented_reference_candidates,
)
from contextual_remediation_inputs import (  # noqa: E402
    RemediationInstance,
    build_remediation_instances,
)
from eval_model import assert_llama_cpp, resolve_model_layout  # noqa: E402
from report_quant_stamping import merge_quant_metadata  # noqa: E402
from rcm_cwe_inference import LlamaCompleteEngine  # noqa: E402

REPORTS = ROOT / "validation" / "reports"
INPUTS_PATH = REPORTS / "contextual-remediation-inputs.json"
RESPONSES_PATH = REPORTS / "contextual-remediation-responses.json"
REPORT_PATH = REPORTS / "contextual-remediation-eval.json"
SUMMARY_PATH = REPORTS / "contextual-remediation-eval.txt"
ADJUDICATION_PATH = REPORTS / "contextual-remediation-adjudication-sample.txt"
VERDICTS_PATH = REPORTS / "contextual-remediation-adjudication-verdicts.json"

SAMPLE_SIZE = 20


def _inputs_payload(instances: list[RemediationInstance]) -> dict[str, Any]:
    return merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "experiment": "G",
            "task": "contextual_remediation_quality",
            "instance_count": len(instances),
            "instances": [item.as_dict() for item in instances],
        }
    )


def _load_responses(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _run_inference(
    instances: list[RemediationInstance],
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
    engine = LlamaCompleteEngine(model_dir, quant_label=quant_label, n_ctx=8192)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        for index, instance in enumerate(instances, start=1):
            if instance.instance_id in cache:
                print(f"[infer {index}/{len(instances)}] {instance.instance_id} (cached)", flush=True)
                continue
            cache[instance.instance_id] = engine.complete(instance.prompt, max_tokens=max_tokens)
            cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
            print(f"[infer {index}/{len(instances)}] {instance.instance_id}", flush=True)
    finally:
        engine.unload()
    return cache


def _result_rows(
    instances: list[RemediationInstance],
    responses: dict[str, str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for instance in instances:
        response = responses.get(instance.instance_id, "")
        rows.append(
            {
                "instance_id": instance.instance_id,
                "corpus": instance.corpus,
                "rel_path": instance.rel_path,
                "target_type": instance.target_type,
                "rule_id": instance.rule_id,
                "cwe": instance.cwe,
                "defect_summary": instance.defect_summary,
                "registry_remediation": instance.registry_remediation,
                "known_identifiers": list(instance.known_identifiers),
                "invented_reference_candidates": invented_reference_candidates(
                    response,
                    instance.known_identifiers,
                ),
                "model_response": response,
            }
        )
    return rows


def _score_verdicts(sample: list[dict[str, Any]], verdicts: dict[str, dict[str, bool]]) -> dict[str, Any]:
    counts = {
        "a_no_invented_refs": 0,
        "b_resolves_defect": 0,
        "c_more_specific_than_registry": 0,
    }
    for row in sample:
        verdict = verdicts.get(row["instance_id"]) or {}
        if verdict.get("a_no_invented_refs"):
            counts["a_no_invented_refs"] += 1
        if verdict.get("b_resolves_defect"):
            counts["b_resolves_defect"] += 1
        if verdict.get("c_more_specific_than_registry"):
            counts["c_more_specific_than_registry"] += 1
    total = len(sample)
    return {
        "sample_size": total,
        **counts,
        "a_rate": round(counts["a_no_invented_refs"] / total, 4) if total else 0.0,
        "b_rate": round(counts["b_resolves_defect"] / total, 4) if total else 0.0,
        "c_rate": round(counts["c_more_specific_than_registry"] / total, 4) if total else 0.0,
    }


def _format_summary(report: dict[str, Any]) -> str:
    sample_scores = report.get("adjudication_scores") or {}
    lines = [
        "=== Experiment G: contextual remediation quality ===",
        (
            f"quant_evaluated={report.get('quant_evaluated')} "
            f"quant_intended={report.get('quant_intended')} "
            f"accuracy_only={report.get('accuracy_only')}"
        ),
        "",
        f"Instances: {report['instance_count']} labeled handler defects",
        f"Adjudication sample: {sample_scores.get('sample_size', SAMPLE_SIZE)}",
        "",
        "Manual adjudication counts (sample):",
        (
            f"  (a) no invented refs: {sample_scores.get('a_no_invented_refs')}/"
            f"{sample_scores.get('sample_size')} ({100 * float(sample_scores.get('a_rate') or 0):.1f}%)"
        ),
        (
            f"  (b) resolves defect: {sample_scores.get('b_resolves_defect')}/"
            f"{sample_scores.get('sample_size')} ({100 * float(sample_scores.get('b_rate') or 0):.1f}%)"
        ),
        (
            f"  (c) more specific than registry: {sample_scores.get('c_more_specific_than_registry')}/"
            f"{sample_scores.get('sample_size')} ({100 * float(sample_scores.get('c_rate') or 0):.1f}%)"
        ),
        "",
        "Criterion (a) is the fabrication check (analogous to invented evidence in quoting tasks).",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-output", type=Path, default=INPUTS_PATH)
    parser.add_argument("--responses", type=Path, default=RESPONSES_PATH)
    parser.add_argument("--output", type=Path, default=REPORT_PATH)
    parser.add_argument("--summary-output", type=Path, default=SUMMARY_PATH)
    parser.add_argument("--adjudication-output", type=Path, default=ADJUDICATION_PATH)
    parser.add_argument("--inputs-only", action="store_true")
    parser.add_argument("--run-inference", action="store_true")
    parser.add_argument("--allow-quant-mismatch", action="store_true")
    parser.add_argument("--max-tokens", type=int, default=768)
    parser.add_argument("--adjudication-verdicts", type=Path, default=VERDICTS_PATH)
    args = parser.parse_args()

    instances = build_remediation_instances()
    if len(instances) != 108:
        print(f"ERROR: expected 108 instances, built {len(instances)}", file=sys.stderr)
        return 1

    args.inputs_output.write_text(
        json.dumps(_inputs_payload(instances), indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {args.inputs_output.relative_to(ROOT)} ({len(instances)} instances)")

    if args.inputs_only:
        return 0

    responses = _load_responses(args.responses)
    missing = [item.instance_id for item in instances if item.instance_id not in responses]
    if missing and not args.run_inference:
        print(
            f"ERROR: missing responses for {len(missing)} instances; use --run-inference",
            file=sys.stderr,
        )
        return 1
    if missing and args.run_inference:
        responses = _run_inference(
            instances,
            cache_path=args.responses,
            allow_quant_mismatch=args.allow_quant_mismatch,
            max_tokens=args.max_tokens,
        )

    rows = _result_rows(instances, responses)
    sample = deterministic_sample(rows, sample_size=SAMPLE_SIZE)
    worksheet = format_adjudication_worksheet(sample)
    args.adjudication_output.write_text(worksheet, encoding="utf-8")

    verdicts: dict[str, dict[str, bool]] = {}
    if args.adjudication_verdicts.is_file():
        verdicts = json.loads(args.adjudication_verdicts.read_text(encoding="utf-8"))

    adjudication_scores = _score_verdicts(sample, verdicts) if verdicts else None

    report = merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "experiment": "G",
            "task": "contextual_remediation_quality",
            "instance_count": len(instances),
            "inputs_path": str(args.inputs_output.relative_to(ROOT)),
            "responses_path": str(args.responses.relative_to(ROOT)),
            "adjudication_sample_size": SAMPLE_SIZE,
            "adjudication_sample_path": str(args.adjudication_output.relative_to(ROOT)),
            "adjudication_scores": adjudication_scores,
            "per_instance": rows,
            "adjudication_sample": sample,
        }
    )
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if adjudication_scores:
        summary = _format_summary(report)
        args.summary_output.write_text(summary, encoding="utf-8")
        print(summary)
    else:
        print(
            f"Wrote adjudication worksheet {args.adjudication_output.relative_to(ROOT)}; "
            "manual verdicts pending."
        )

    print(f"Wrote {args.output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
