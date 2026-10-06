#!/usr/bin/env python3
"""Phase 3 reasoning-model experiments: cookbook prose, platform_specific JSON, RCM CWE."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from collections import defaultdict
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

from cookbook_prose_inputs import CookbookFileRun, LabeledDefect, build_cookbook_inputs  # noqa: E402
from cookbook_prose_prompt import COOKBOOK_PROMPT_SHAPE  # noqa: E402
from cookbook_prose_scoring import defect_detected, score_detection_recall  # noqa: E402
from eval_handlers import HOLDOUT_CORPUS_DIR, GENERATED_CORPUS_DIR, load_corpus  # noqa: E402
from eval_model import RULE_SEMANTICS, corpus_dirs  # noqa: E402
from foundation_sec_server.engine import _parse_json_findings  # noqa: E402
from foundation_sec_server.handlers.registry import DEFAULT_REGISTRY  # noqa: E402
from foundation_sec_server.model_profiles import (  # noqa: E402
    REASONING_MAX_TOKENS_DEFAULT,
    REASONING_N_CTX_DEFAULT,
)
from foundation_sec_server.preprocess import strip_inactive_lines  # noqa: E402
from foundation_sec_server.reasoning_inference import (  # noqa: E402
    ReasoningModelClient,
    materialize_reasoning_chat_template,
    scoring_surface,
)
from model_eval_matching import (  # noqa: E402
    MATCHER_BEST_FIT,
    MATCHER_METADATA,
    MetricCounts,
    ModelMetricCounts,
    is_model_originated,
    score_file,
)
from rcm_cwe_inputs import ZERO_SHOT_COMPLETION_STOP  # noqa: E402
from rcm_cwe_scoring import completion_token_stats, parse_predicted_cwe, score_predictions  # noqa: E402
from reasoning_report_stamping import (  # noqa: E402
    REASONING_COOKBOOK_THRESHOLD,
    reasoning_run_stamp,
)
from reasoning_suffix_probe import (  # noqa: E402
    _parse_findings,
    build_platform_prompt_with_suffix,
)
from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M  # noqa: E402

REPORTS = ROOT / "validation" / "reports"
COOKBOOK_CACHE = REPORTS / "reasoning-cookbook-prose-responses.json"
COOKBOOK_REPORT = REPORTS / "reasoning-cookbook-prose-eval.json"
PLATFORM_REPORT = REPORTS / "reasoning-platform-specific-eval.json"
RCM_INSTANCES = REPORTS / "rcm-cwe-instances.json"
RCM_REPORT = REPORTS / "reasoning-rcm-cwe-eval.json"
SUFFIX_PROBE = REPORTS / "reasoning-suffix-probe.json"


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


def _scored_text(row: dict[str, Any] | str) -> str:
    if isinstance(row, str):
        return row
    return str(row.get("scored_text") or row.get("raw_text") or "")


def _load_cookbook_cache(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        raise SystemExit(f"Missing cookbook cache: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def run_cookbook_prose(
    *,
    cache_path: Path,
    output_path: Path,
    threshold: float,
) -> dict[str, Any]:
    t0 = time.monotonic()
    file_runs, instances = build_cookbook_inputs()
    cache = _load_cookbook_cache(cache_path)

    missing = [fr.file_key for fr in file_runs if fr.file_key not in cache]
    if missing:
        raise SystemExit(f"Cookbook cache missing {len(missing)} files; run negative-control inference first.")

    split_failures = [
        fr.file_key
        for fr in file_runs
        if isinstance(cache.get(fr.file_key), dict) and cache[fr.file_key].get("split_failure")
    ]

    rows: list[dict[str, Any]] = []
    for instance in instances:
        prose = _scored_text(cache.get(instance.file_key, {}))
        detected, fit_score = defect_detected(
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
                "corpus": instance.corpus,
                "rel_path": instance.rel_path,
                "target_type": instance.target_type,
                "rule_id": instance.rule_id,
                "defect_summary": instance.defect_summary,
                "detected": detected,
                "semantic_fit": round(fit_score, 4),
                "split_failure": instance.file_key in split_failures,
                "model_response_excerpt": prose[:500],
            }
        )

    summary = score_detection_recall(rows)
    summary["semantic_fit_threshold"] = threshold
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    report = {
        **reasoning_run_stamp(threshold=threshold),
        "generated_at": datetime.now(UTC).isoformat(),
        "experiment": "F",
        "phase": "3a",
        "task": "reasoning_cookbook_prose_detection",
        "prompt_shape": COOKBOOK_PROMPT_SHAPE,
        "calibration_report": str(
            (REPORTS / "reasoning-cookbook-semantic-fit-calibration.json").relative_to(ROOT)
        ),
        "responses_cache": str(cache_path.relative_to(ROOT)),
        "file_run_count": len(file_runs),
        "labeled_defect_count": len(instances),
        "split_failure_files": split_failures,
        "split_failure_count": len(split_failures),
        "elapsed_ms": elapsed_ms,
        "summary": summary,
        "per_instance": rows,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _best_suffix_from_probe(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"Missing suffix probe report: {path}")
    probe = json.loads(path.read_text(encoding="utf-8"))
    if probe.get("max_tokens") != REASONING_MAX_TOKENS_DEFAULT:
        raise SystemExit(
            f"Suffix probe max_tokens={probe.get('max_tokens')}; "
            f"re-run reasoning_suffix_probe.py at {REASONING_MAX_TOKENS_DEFAULT}."
        )
    ranked: list[tuple[str, float, float, int]] = []
    for suffix_key, agg in (probe.get("by_suffix") or {}).items():
        parse_rate = float(agg.get("parseable_findings_rate") or 0.0)
        cap_rate = float(agg.get("cap_hit_rate") or 0.0)
        ranked.append((suffix_key, parse_rate, cap_rate, int(agg.get("parseable_findings_count") or 0)))
    ranked.sort(key=lambda item: (-item[1], item[2], -item[3]))
    return ranked[0][0]


def _normalize_findings(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        finding = dict(item)
        finding.setdefault("model_originated", True)
        normalized.append(finding)
    return normalized


def run_platform_specific(
    *,
    suffix_key: str,
    output_path: Path,
    cache_path: Path | None,
    max_tokens: int,
) -> dict[str, Any]:
    t0 = time.monotonic()
    model_dir = ROOT / VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["local_path_default"]
    materialize_reasoning_chat_template(model_dir)
    llm = _load_llm(model_dir)
    client = ReasoningModelClient(llm, model_dir=model_dir, max_tokens=max_tokens)

    cache: dict[str, dict[str, Any]] = {}
    if cache_path and cache_path.is_file():
        cache = json.loads(cache_path.read_text(encoding="utf-8"))

    handler_stats: dict[str, dict[str, MetricCounts]] = defaultdict(dict)
    model_stats: dict[str, dict[str, ModelMetricCounts]] = defaultdict(dict)
    unlabeled_model_findings: list[dict[str, Any]] = []
    file_runs: list[dict[str, Any]] = []
    split_failures: list[str] = []

    file_list: list[tuple[str, Path, Any]] = []
    for corpus_name, corpus_dir in corpus_dirs():
        for entry in load_corpus(corpus_dir):
            file_list.append((corpus_name, corpus_dir, entry))

    try:
        for index, (corpus_name, corpus_dir, entry) in enumerate(file_list, start=1):
            rel_key = f"{corpus_name}/{entry.rel_path}"
            content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")

            if rel_key in cache:
                row = cache[rel_key]
                completion_text = row.get("raw_text") or ""
                split_failure = bool(row.get("split_failure"))
                split_method = row.get("split_method")
                cap_hit = bool(row.get("cap_hit"))
                inference_ms = row.get("inference_ms")
            else:
                prompt = build_platform_prompt_with_suffix(
                    virtual_path=entry.virtual_path,
                    target_type=entry.target_type,
                    content=content,
                    suffix_key=suffix_key,
                )
                infer_t0 = time.monotonic()
                completion = client.complete(prompt)
                inference_ms = int((time.monotonic() - infer_t0) * 1000)
                completion_text = scoring_surface(completion)
                split_failure = completion.split_failure
                split_method = completion.split_method
                cap_hit = (completion.completion_token_count or 0) >= max_tokens
                row = {
                    "raw_text": completion_text,
                    "split_method": split_method,
                    "split_failure": split_failure,
                    "cap_hit": cap_hit,
                    "reasoning_token_count": completion.reasoning_token_count,
                    "answer_token_count": completion.answer_token_count,
                    "completion_token_count": completion.completion_token_count,
                    "inference_ms": inference_ms,
                    "suffix": suffix_key,
                    "max_tokens": max_tokens,
                }
                cache[rel_key] = row
                if cache_path:
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")

            if split_failure:
                split_failures.append(rel_key)
                model_findings: list[dict[str, Any]] = []
                outcome = "split_failure"
            else:
                parsed = _parse_findings(completion_text, entry.virtual_path, suffix_key=suffix_key)
                raw_findings = _parse_json_findings(
                    completion_text,
                    entry.virtual_path,
                    prepend_array_bracket=(suffix_key == "bracket"),
                )
                model_findings = [f for f in _normalize_findings(raw_findings) if is_model_originated(f)]
                outcome = "completed_with_findings" if model_findings else "completed_no_findings"
                if parsed.get("parseable") and not model_findings:
                    outcome = "parse_failed"

            score_file(
                matcher=MATCHER_BEST_FIT,
                entry=entry,
                corpus_name=corpus_name,
                content=content,
                model_findings=model_findings if not split_failure else None,
                handler_stats=handler_stats,
                model_stats=model_stats,
                unlabeled_model_findings=unlabeled_model_findings,
                rule_semantics=RULE_SEMANTICS,
            )

            file_runs.append(
                {
                    "index": index,
                    "corpus": corpus_name,
                    "rel_path": entry.rel_path,
                    "target_type": entry.target_type,
                    "model_outcome": outcome,
                    "split_failure": split_failure,
                    "split_method": split_method,
                    "cap_hit": cap_hit,
                    "model_finding_count": len(model_findings),
                    "inference_ms": inference_ms,
                }
            )
            print(
                f"[platform {index}/{len(file_list)}] {rel_key} "
                f"outcome={outcome} findings={len(model_findings)} split_failure={split_failure}",
                flush=True,
            )
    finally:
        del llm

    per_rule: dict[str, dict[str, dict[str, Any]]] = {}
    for target_type in sorted(set(handler_stats) | set(model_stats)):
        per_rule[target_type] = {}
        rule_ids = sorted(set(handler_stats.get(target_type, {})) | set(model_stats.get(target_type, {})))
        for rule_id in rule_ids:
            per_rule[target_type][rule_id] = {
                "handler": handler_stats.get(target_type, {}).get(rule_id, MetricCounts()).as_dict(),
                "model": model_stats.get(target_type, {}).get(rule_id, ModelMetricCounts()).as_dict(),
            }

    model_tp = sum(
        int(bucket["model"]["true_positives"])
        for rules in per_rule.values()
        for bucket in rules.values()
        if isinstance(bucket.get("model"), dict)
    )
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    report = {
        **reasoning_run_stamp(max_tokens=max_tokens),
        "generated_at": datetime.now(UTC).isoformat(),
        "phase": "3b",
        "experiment": "platform_specific",
        "task": "reasoning_platform_specific_json",
        "prompt_suffix": suffix_key,
        "suffix_probe_report": str(SUFFIX_PROBE.relative_to(ROOT)),
        "semantic_matcher": MATCHER_BEST_FIT,
        "semantic_matcher_metadata": MATCHER_METADATA[MATCHER_BEST_FIT],
        "file_count": len(file_list),
        "split_failure_files": split_failures,
        "split_failure_count": len(split_failures),
        "model_rule_level_tp": model_tp,
        "labeled_defect_reference": 149,
        "elapsed_ms": elapsed_ms,
        "per_target_type_per_rule": per_rule,
        "file_runs": file_runs,
        "responses_cache": str(cache_path.relative_to(ROOT)) if cache_path else None,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def run_rcm_cwe(
    *,
    instances_path: Path,
    output_path: Path,
    cache_path: Path | None,
    max_tokens: int,
) -> dict[str, Any]:
    t0 = time.monotonic()
    payload = json.loads(instances_path.read_text(encoding="utf-8"))
    instances = payload.get("instances") or []
    if len(instances) != 108:
        raise SystemExit(f"Expected 108 RCM instances, found {len(instances)}")

    model_dir = ROOT / VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["local_path_default"]
    materialize_reasoning_chat_template(model_dir)
    llm = _load_llm(model_dir)
    client = ReasoningModelClient(llm, model_dir=model_dir, max_tokens=max_tokens)

    cache: dict[str, str] = {}
    if cache_path and cache_path.is_file():
        cache = json.loads(cache_path.read_text(encoding="utf-8"))

    rows: list[dict[str, Any]] = []
    split_failures: list[str] = []
    try:
        for index, instance in enumerate(instances, start=1):
            instance_id = str(instance["instance_id"])
            if instance_id in cache:
                response = cache[instance_id]
                split_failure = False
                split_method = "cache"
            else:
                completion = client.complete(str(instance["prompt"]))
                response = scoring_surface(completion)
                split_failure = completion.split_failure
                split_method = completion.split_method
                cache[instance_id] = response
                if cache_path:
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")

            if split_failure:
                split_failures.append(instance_id)
                predicted = None
            else:
                predicted = parse_predicted_cwe(response, after_the_cwe_is=False)

            expected = str(instance["expected_cwe"])
            correct = predicted == expected if predicted else False
            rows.append(
                {
                    "instance_id": instance_id,
                    "corpus": instance["corpus"],
                    "rel_path": instance["rel_path"],
                    "target_type": instance["target_type"],
                    "rule_id": instance["rule_id"],
                    "expected_cwe": expected,
                    "predicted_cwe": predicted,
                    "correct": correct,
                    "split_failure": split_failure,
                    "split_method": split_method,
                    "model_response": response,
                }
            )
            print(
                f"[rcm {index}/{len(instances)}] {instance_id} "
                f"expected={expected} predicted={predicted or '—'} split_failure={split_failure}",
                flush=True,
            )
    finally:
        del llm

    summary = score_predictions(
        rows,
        parser=lambda response: parse_predicted_cwe(response, after_the_cwe_is=False),
    )
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    report = {
        **reasoning_run_stamp(max_tokens=max_tokens, scoring_surface="whole_completion"),
        "generated_at": datetime.now(UTC).isoformat(),
        "phase": "3c",
        "experiment": "D",
        "task": "reasoning_rcm_cwe_zero_shot",
        "matching": "exact_string_cwe_equality",
        "completion_stop": ZERO_SHOT_COMPLETION_STOP,
        "instance_count": len(instances),
        "split_failure_instances": split_failures,
        "split_failure_count": len(split_failures),
        "elapsed_ms": elapsed_ms,
        "summary": summary,
        "completion_token_stats": completion_token_stats(rows),
        "per_instance": rows,
        "instances_path": str(instances_path.relative_to(ROOT)),
        "responses_cache": str(cache_path.relative_to(ROOT)) if cache_path else None,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase",
        choices=("cookbook", "platform", "rcm", "all"),
        default="all",
    )
    parser.add_argument("--max-tokens", type=int, default=REASONING_MAX_TOKENS_DEFAULT)
    parser.add_argument("--threshold", type=float, default=REASONING_COOKBOOK_THRESHOLD)
    parser.add_argument("--suffix", help="platform_specific suffix key (colon|bracket|none)")
    args = parser.parse_args()

    os.environ.setdefault("HF_HUB_OFFLINE", "0")

    if args.phase in ("cookbook", "all"):
        report = run_cookbook_prose(
            cache_path=COOKBOOK_CACHE,
            output_path=COOKBOOK_REPORT,
            threshold=args.threshold,
        )
        print(
            f"Cookbook recall: {report['summary']['detected']}/{report['summary']['labeled_defects']} "
            f"({100 * float(report['summary']['recall']):.1f}%) elapsed={report['elapsed_ms']}ms",
            flush=True,
        )

    if args.phase in ("platform", "all"):
        suffix = args.suffix or _best_suffix_from_probe(SUFFIX_PROBE)
        report = run_platform_specific(
            suffix_key=suffix,
            output_path=PLATFORM_REPORT,
            cache_path=REPORTS / "reasoning-platform-specific-responses.json",
            max_tokens=args.max_tokens,
        )
        print(
            f"Platform TP={report['model_rule_level_tp']} suffix={suffix} "
            f"elapsed={report['elapsed_ms']}ms split_failures={report['split_failure_count']}",
            flush=True,
        )

    if args.phase in ("rcm", "all"):
        report = run_rcm_cwe(
            instances_path=RCM_INSTANCES,
            output_path=RCM_REPORT,
            cache_path=REPORTS / "reasoning-rcm-cwe-responses.json",
            max_tokens=args.max_tokens,
        )
        print(
            f"RCM accuracy={report['summary']['accuracy']:.1%} "
            f"elapsed={report['elapsed_ms']}ms split_failures={report['split_failure_count']}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
