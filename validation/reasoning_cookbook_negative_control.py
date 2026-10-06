#!/usr/bin/env python3
"""Negative-control calibration for reasoning-model cookbook prose (whole completion scoring)."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FSEC = ROOT / "services" / "foundation-sec-server"
ORCH = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
VALIDATION = ROOT / "validation"
for path in (SHARED, ORCH, FSEC, VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from cookbook_prose_inputs import CookbookFileRun, build_cookbook_inputs  # noqa: E402
from cookbook_prose_scoring import prose_semantic_fit  # noqa: E402
from eval_model import RULE_SEMANTICS  # noqa: E402
from foundation_sec_server.model_profiles import (  # noqa: E402
    MODEL_VARIANT_REASONING,
    REASONING_MAX_TOKENS_DEFAULT,
    REASONING_N_CTX_DEFAULT,
)
from foundation_sec_server.reasoning_inference import (  # noqa: E402
    ReasoningModelClient,
    materialize_reasoning_chat_template,
    scoring_surface,
)
from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M  # noqa: E402

REPORTS = ROOT / "validation" / "reports"
DEFAULT_RESPONSES = REPORTS / "reasoning-cookbook-prose-responses.json"
DEFAULT_OUTPUT = REPORTS / "reasoning-cookbook-semantic-fit-calibration.json"
DEFAULT_SUMMARY = REPORTS / "reasoning-cookbook-semantic-fit-calibration.txt"

INSTRUCT_COOKBOOK_THRESHOLD = 0.70
NEGATIVE_SWEEP_THRESHOLDS = (0.60, 0.70, 0.80, 0.85)
MAX_FALSE_MATCH_RATE = 0.02
RAW_PATH_DROPPED = {
    "decision": "drop_raw_completion_scoring_path",
    "rationale": (
        "Raw completion hit max_tokens on 12/20 probe files (mean ~5014 answer tokens); "
        "template path is the only viable scoring path for corpus-scale experiments."
    ),
    "probe_report": str(REPORTS / "reasoning-split-path-probe.json"),
}


def _load_llm(model_dir: Path) -> Any:
    from llama_cpp import Llama

    gguf = model_dir / VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["gguf_filename"]
    n_gpu_layers = -1 if platform.system() == "Darwin" else 0
    return Llama(
        model_path=str(gguf),
        n_ctx=REASONING_N_CTX_DEFAULT,
        n_gpu_layers=n_gpu_layers,
        verbose=False,
    )


def _load_response_cache(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_cache_max_tokens(cache: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Confirm cached responses were not truncated at 1024."""
    token_counts: list[int] = []
    at_1024 = 0
    at_cap = 0
    missing_max_tokens = 0
    for row in cache.values():
        if not isinstance(row, dict):
            continue
        if row.get("max_tokens") is None:
            missing_max_tokens += 1
        else:
            if int(row["max_tokens"]) != REASONING_MAX_TOKENS_DEFAULT:
                return {
                    "valid": False,
                    "reason": f"unexpected max_tokens={row['max_tokens']}",
                }
        count = int(row.get("completion_token_count") or 0)
        if count:
            token_counts.append(count)
        if count in (1024, 1025):
            at_1024 += 1
        if count >= REASONING_MAX_TOKENS_DEFAULT:
            at_cap += 1
    if at_1024 >= max(1, len(token_counts) // 4):
        return {
            "valid": False,
            "reason": f"{at_1024}/{len(token_counts)} responses at ~1024 tokens (likely 1024 cap)",
        }
    return {
        "valid": True,
        "inferred_max_tokens": REASONING_MAX_TOKENS_DEFAULT,
        "client_default": REASONING_MAX_TOKENS_DEFAULT,
        "entries_missing_max_tokens_field": missing_max_tokens,
        "completion_token_min": min(token_counts) if token_counts else None,
        "completion_token_max": max(token_counts) if token_counts else None,
        "completion_token_mean": round(sum(token_counts) / len(token_counts), 1) if token_counts else None,
        "cap_hit_count": at_cap,
        "at_1024_count": at_1024,
        "note": (
            "ReasoningModelClient defaults to REASONING_MAX_TOKENS_DEFAULT (8192). "
            "Legacy cache rows without max_tokens are accepted when token distribution "
            "is inconsistent with a 1024 cap."
        ),
    }


def _run_inference(
    file_runs: list[CookbookFileRun],
    *,
    cache_path: Path,
    model_dir: Path,
) -> dict[str, dict[str, Any]]:
    materialize_reasoning_chat_template(model_dir)
    llm = _load_llm(model_dir)
    client = ReasoningModelClient(llm, model_dir=model_dir)
    cache = _load_response_cache(cache_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        for index, file_run in enumerate(file_runs, start=1):
            if file_run.file_key in cache:
                print(f"[infer {index}/{len(file_runs)}] {file_run.file_key} (cached)", flush=True)
                continue
            t0 = time.monotonic()
            completion = client.complete(file_run.prompt)
            inference_ms = int((time.monotonic() - t0) * 1000)
            cache[file_run.file_key] = {
                "scored_text": scoring_surface(completion),
                "raw_text": completion.raw_text,
                "split_method": completion.split_method,
                "split_failure": completion.split_failure,
                "reasoning_token_count": completion.reasoning_token_count,
                "answer_token_count": completion.answer_token_count,
                "completion_token_count": completion.completion_token_count,
                "cap_hit": (completion.completion_token_count or 0) >= REASONING_MAX_TOKENS_DEFAULT,
                "inference_ms": inference_ms,
                "inference_path": "chat_template",
                "scoring_policy": "whole_completion",
                "max_tokens": REASONING_MAX_TOKENS_DEFAULT,
            }
            cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
            print(
                f"[infer {index}/{len(file_runs)}] {file_run.file_key} "
                f"tokens={completion.completion_token_count} split={completion.split_method}",
                flush=True,
            )
    finally:
        del llm
    return cache


def _scored_text(cache_row: dict[str, Any] | str) -> str:
    if isinstance(cache_row, str):
        return cache_row
    return str(cache_row.get("scored_text") or cache_row.get("raw_text") or "")


def _negative_control(
    file_runs: list[CookbookFileRun],
    responses: dict[str, dict[str, Any]],
    threshold: float,
) -> dict[str, Any]:
    all_rule_ids = sorted(RULE_SEMANTICS)
    spurious: list[dict[str, Any]] = []
    total_pairs = 0
    for file_run in file_runs:
        prose = _scored_text(responses.get(file_run.file_key, {}))
        negative_rules = [rule_id for rule_id in all_rule_ids if rule_id not in file_run.expected_rule_ids]
        for rule_id in negative_rules:
            total_pairs += 1
            score = prose_semantic_fit(prose, RULE_SEMANTICS[rule_id])
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


def _choose_threshold(sweep: list[dict[str, Any]]) -> dict[str, Any]:
    at_instruct = next(row for row in sweep if row["threshold"] == INSTRUCT_COOKBOOK_THRESHOLD)
    if at_instruct["false_match_rate"] <= MAX_FALSE_MATCH_RATE:
        return {
            "chosen_threshold": INSTRUCT_COOKBOOK_THRESHOLD,
            "delta_from_instruct_threshold": 0.0,
            "justification": (
                f"False-match rate at instruct threshold {INSTRUCT_COOKBOOK_THRESHOLD} "
                f"({100 * at_instruct['false_match_rate']:.2f}%) is within "
                f"{100 * MAX_FALSE_MATCH_RATE:.0f}% ceiling."
            ),
            "false_match_rate_at_chosen": at_instruct["false_match_rate"],
        }

    for threshold in (0.80, 0.85):
        row = next(item for item in sweep if item["threshold"] == threshold)
        if row["false_match_rate"] <= MAX_FALSE_MATCH_RATE:
            return {
                "chosen_threshold": threshold,
                "delta_from_instruct_threshold": round(threshold - INSTRUCT_COOKBOOK_THRESHOLD, 2),
                "justification": (
                    f"False-match at {INSTRUCT_COOKBOOK_THRESHOLD} was "
                    f"{100 * at_instruct['false_match_rate']:.2f}% (> "
                    f"{100 * MAX_FALSE_MATCH_RATE:.0f}%); raised threshold to {threshold} "
                    f"({100 * row['false_match_rate']:.2f}% false-match)."
                ),
                "false_match_rate_at_chosen": row["false_match_rate"],
            }

    best = min(sweep, key=lambda row: row["false_match_rate"])
    return {
        "chosen_threshold": best["threshold"],
        "delta_from_instruct_threshold": round(best["threshold"] - INSTRUCT_COOKBOOK_THRESHOLD, 2),
        "justification": (
            f"No sweep threshold met the {100 * MAX_FALSE_MATCH_RATE:.0f}% ceiling; "
            f"chose {best['threshold']} (lowest false-match "
            f"{100 * best['false_match_rate']:.2f}%)."
        ),
        "false_match_rate_at_chosen": best["false_match_rate"],
    }


def _format_summary(report: dict[str, Any]) -> str:
    neg = report["negative_control_at_instruct_threshold"]
    lines = [
        "=== Reasoning cookbook semantic-fit calibration (whole completion) ===",
        "",
        f"Model: {report['model_variant']} ({report['quant']})",
        f"Scoring: {report['scoring_policy']}",
        f"Inference path: {report['inference_path']}",
        "",
        "Raw completion path:",
        f"  {report['raw_completion_path']['decision']}",
        f"  {report['raw_completion_path']['rationale']}",
        "",
        f"Negative control at instruct threshold {INSTRUCT_COOKBOOK_THRESHOLD}:",
        (
            f"  spurious {neg['spurious_matches']}/{neg['negative_pairs_total']} "
            f"({100 * neg['false_match_rate']:.2f}% false-match)"
        ),
        "",
        "Threshold sweep (false-match rate):",
        f"  {'threshold':>10} {'false_match%':>14} {'spurious':>10}",
    ]
    for row in report["negative_threshold_sweep"]:
        lines.append(
            f"  {row['threshold']:>10.2f} {100 * row['false_match_rate']:>12.2f}% "
            f"{row['spurious_matches']:>4}/{row['negative_pairs_total']}"
        )
    choice = report["threshold_choice"]
    lines.extend(
        [
            "",
            f"Chosen threshold: {choice['chosen_threshold']} "
            f"(delta from instruct {INSTRUCT_COOKBOOK_THRESHOLD}: "
            f"{choice['delta_from_instruct_threshold']:+.2f})",
            f"  {choice['justification']}",
        ]
    )
    return "\n".join(lines) + "\n"


def run(
    *,
    skip_inference: bool,
    cache_path: Path,
    output_path: Path,
    summary_path: Path,
) -> dict[str, Any]:
    file_runs, instances = build_cookbook_inputs()
    model_dir = ROOT / VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["local_path_default"]

    if skip_inference:
        responses = _load_response_cache(cache_path)
        if len(responses) < len(file_runs):
            missing = len(file_runs) - len(responses)
            raise SystemExit(
                f"Cache {cache_path} has {len(responses)}/{len(file_runs)} files; "
                f"{missing} missing — run without --skip-inference."
            )
    else:
        responses = _run_inference(file_runs, cache_path=cache_path, model_dir=model_dir)

    cache_validation = _validate_cache_max_tokens(responses)
    if not cache_validation.get("valid"):
        raise SystemExit(
            f"Cookbook cache invalid for calibration: {cache_validation.get('reason')}. "
            f"Re-run inference at max_tokens={REASONING_MAX_TOKENS_DEFAULT}."
        )

    sweep = [_negative_control(file_runs, responses, threshold) for threshold in NEGATIVE_SWEEP_THRESHOLDS]
    at_instruct = next(row for row in sweep if row["threshold"] == INSTRUCT_COOKBOOK_THRESHOLD)
    choice = _choose_threshold(sweep)

    split_failures = sum(
        1
        for key in file_runs
        for row in [responses.get(key.file_key, {})]
        if isinstance(row, dict) and row.get("split_failure")
    )

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "phase": "1c",
        "model_variant": MODEL_VARIANT_REASONING,
        "quant": "Q4_K_M",
        "n_ctx": REASONING_N_CTX_DEFAULT,
        "max_tokens": cache_validation["inferred_max_tokens"],
        "cache_validation": cache_validation,
        "inference_path": "chat_template",
        "scoring_policy": "whole_completion",
        "instruct_cookbook_threshold": INSTRUCT_COOKBOOK_THRESHOLD,
        "max_false_match_rate": MAX_FALSE_MATCH_RATE,
        "labeled_file_count": len(file_runs),
        "labeled_defect_count": len(instances),
        "responses_cache": str(cache_path.relative_to(ROOT)),
        "split_failure_files": split_failures,
        "raw_completion_path": RAW_PATH_DROPPED,
        "negative_control_at_instruct_threshold": at_instruct,
        "negative_threshold_sweep": sweep,
        "threshold_choice": choice,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    summary_path.write_text(_format_summary(report), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-inference", action="store_true")
    parser.add_argument("--responses", type=Path, default=DEFAULT_RESPONSES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    args = parser.parse_args()

    os.environ.setdefault("HF_HUB_OFFLINE", "0")
    report = run(
        skip_inference=args.skip_inference,
        cache_path=args.responses,
        output_path=args.output,
        summary_path=args.summary,
    )
    neg = report["negative_control_at_instruct_threshold"]
    print(
        f"False-match at {INSTRUCT_COOKBOOK_THRESHOLD}: "
        f"{100 * neg['false_match_rate']:.2f}% "
        f"({neg['spurious_matches']}/{neg['negative_pairs_total']})",
        flush=True,
    )
    print(f"Chosen threshold: {report['threshold_choice']['chosen_threshold']}", flush=True)
    print(f"Wrote {args.output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
