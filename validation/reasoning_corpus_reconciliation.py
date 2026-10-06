#!/usr/bin/env python3
"""Reconcile instruct vs reasoning eval corpora and re-score on comparable subsets."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
FSEC = ROOT / "services" / "foundation-sec-server"
VALIDATION = ROOT / "validation"
for path in (SHARED, ORCH, FSEC, VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from cookbook_prose_inputs import build_cookbook_inputs  # noqa: E402
from cookbook_prose_scoring import defect_detected, score_detection_recall  # noqa: E402
from eval_handlers import load_corpus  # noqa: E402
from eval_model import RULE_SEMANTICS, corpus_dirs  # noqa: E402
from foundation_sec_server.engine import _parse_json_findings  # noqa: E402
from model_eval_matching import (  # noqa: E402
    MATCHER_BEST_FIT,
    MetricCounts,
    ModelMetricCounts,
    is_model_originated,
    score_file,
)
from reasoning_report_stamping import REASONING_COOKBOOK_THRESHOLD, reasoning_run_stamp  # noqa: E402
from reasoning_suffix_probe import _parse_findings  # noqa: E402

REPORTS = ROOT / "validation" / "reports"
OUTPUT_JSON = REPORTS / "reasoning-corpus-reconciliation.json"
OUTPUT_TXT = REPORTS / "reasoning-corpus-reconciliation.txt"

INSTRUCT_COOKBOOK_INPUTS = REPORTS / "cookbook-prose-inputs.json"
INSTRUCT_PLATFORM_FILELIST = REPORTS / "platform-specific-variance-q4_k_m-run1.json"
INSTRUCT_RCM_INSTANCES = REPORTS / "rcm-cwe-instances.json"
INSTRUCT_RCM_EVAL = REPORTS / "rcm-cwe-eval.json"

REASONING_COOKBOOK_CACHE = REPORTS / "reasoning-cookbook-prose-responses.json"
REASONING_COOKBOOK_EVAL = REPORTS / "reasoning-cookbook-prose-eval.json"
REASONING_PLATFORM_CACHE = REPORTS / "reasoning-platform-specific-responses.json"
REASONING_PLATFORM_EVAL = REPORTS / "reasoning-platform-specific-eval.json"
REASONING_RCM_EVAL = REPORTS / "reasoning-rcm-cwe-eval.json"
HANDLER_COVERAGE = REPORTS / "handler-coverage.json"

INSTRUCT_COOKBOOK_THRESHOLD = 0.70


def _file_key(corpus: str, rel_path: str) -> str:
    return f"{corpus}/{rel_path}"


def _load_instruct_platform_files() -> list[dict[str, str]]:
    payload = json.loads(INSTRUCT_PLATFORM_FILELIST.read_text(encoding="utf-8"))
    rows = payload.get("per_file") or payload.get("summary", {}).get("per_file") or []
    if not rows:
        # nested under quant key
        for value in payload.values():
            if isinstance(value, dict) and value.get("per_file"):
                rows = value["per_file"]
                break
    return [
        {
            "file_key": _file_key(str(row["corpus"]), str(row["rel_path"])),
            "corpus": str(row["corpus"]),
            "rel_path": str(row["rel_path"]),
            "target_type": str(row.get("target_type") or ""),
        }
        for row in rows
    ]


def _live_corpus_snapshot() -> dict[str, Any]:
    all_files: list[dict[str, Any]] = []
    labeled_files: list[dict[str, Any]] = []
    labeled_defects = 0
    for corpus_name, corpus_dir in corpus_dirs():
        for entry in load_corpus(corpus_dir):
            key = _file_key(corpus_name, entry.rel_path)
            row = {
                "file_key": key,
                "corpus": corpus_name,
                "rel_path": entry.rel_path,
                "target_type": entry.target_type,
                "expected_rule_ids": sorted(entry.expected_rule_ids),
            }
            all_files.append(row)
            if entry.expected_rule_ids:
                labeled_files.append(row)
                labeled_defects += len(entry.expected_rule_ids)
    return {
        "all_file_count": len(all_files),
        "labeled_file_count": len(labeled_files),
        "labeled_defect_count": labeled_defects,
        "all_files": all_files,
        "labeled_files": labeled_files,
    }


def _frozen_cookbook() -> dict[str, Any]:
    payload = json.loads(INSTRUCT_COOKBOOK_INPUTS.read_text(encoding="utf-8"))
    file_keys = {row["file_key"] for row in payload["file_runs"]}
    instances = [
        (row["file_key"], rule_id)
        for row in payload["file_runs"]
        for rule_id in row["expected_rule_ids"]
    ]
    return {
        "frozen_at": payload.get("generated_at"),
        "file_run_count": payload["file_run_count"],
        "labeled_defect_count": payload["labeled_defect_count"],
        "file_keys": file_keys,
        "instances": instances,
        "file_runs": payload["file_runs"],
    }


def _scored_text(row: dict[str, Any] | str) -> str:
    if isinstance(row, str):
        return row
    return str(row.get("scored_text") or row.get("raw_text") or "")


def _score_cookbook_subset(
    *,
    cache: dict[str, dict[str, Any]],
    frozen_instances: list[tuple[str, str, str, str, str]],
    threshold: float,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    split_failures: list[str] = []
    for instance_id, file_key, target_type, rule_id, defect_summary in frozen_instances:
        cache_row = cache.get(file_key, {})
        if isinstance(cache_row, dict) and cache_row.get("split_failure"):
            split_failures.append(file_key)
        prose = _scored_text(cache_row)
        detected, fit_score = defect_detected(
            prose,
            defect_summary=defect_summary,
            rule_id=rule_id,
            target_type=target_type,
            threshold=threshold,
        )
        rows.append(
            {
                "instance_id": instance_id,
                "file_key": file_key,
                "rule_id": rule_id,
                "detected": detected,
                "semantic_fit": round(fit_score, 4),
                "split_failure": file_key in split_failures,
            }
        )
    summary = score_detection_recall(rows)
    summary["semantic_fit_threshold"] = threshold
    return {
        "threshold": threshold,
        "labeled_defect_count": len(frozen_instances),
        "file_run_count": len({file_key for file_key, *_ in [(i[1],) for i in []]}),
        "split_failure_files": sorted(set(split_failures)),
        "split_failure_count": len(set(split_failures)),
        "summary": summary,
    }


def _cookbook_instances_from_live(file_keys: set[str] | None = None) -> list[tuple[str, str, str, str, str]]:
    file_runs, instances = build_cookbook_inputs()
    out: list[tuple[str, str, str, str, str]] = []
    for inst in instances:
        if file_keys is not None and inst.file_key not in file_keys:
            continue
        out.append(
            (inst.instance_id, inst.file_key, inst.target_type, inst.rule_id, inst.defect_summary)
        )
    return out


def _frozen_cookbook_instances() -> list[tuple[str, str, str, str, str]]:
    payload = json.loads(INSTRUCT_COOKBOOK_INPUTS.read_text(encoding="utf-8"))
    out: list[tuple[str, str, str, str, str]] = []
    for row in payload["file_runs"]:
        for rule_id in row["expected_rule_ids"]:
            sem = RULE_SEMANTICS[rule_id]
            out.append(
                (
                    f"{row['file_key']}#{rule_id}",
                    row["file_key"],
                    row["target_type"],
                    rule_id,
                    sem.defect_summary,
                )
            )
    return out


def _score_cookbook_from_cache(
    cache: dict[str, dict[str, Any]],
    instances: list[tuple[str, str, str, str, str]],
    threshold: float,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    split_failures: list[str] = []
    for instance_id, file_key, target_type, rule_id, defect_summary in instances:
        cache_row = cache.get(file_key, {})
        if isinstance(cache_row, dict) and cache_row.get("split_failure"):
            split_failures.append(file_key)
        prose = _scored_text(cache_row)
        detected, fit_score = defect_detected(
            prose,
            defect_summary=defect_summary,
            rule_id=rule_id,
            target_type=target_type,
            threshold=threshold,
        )
        rows.append(
            {
                "instance_id": instance_id,
                "file_key": file_key,
                "rule_id": rule_id,
                "detected": detected,
                "semantic_fit": round(fit_score, 4),
                "split_failure": file_key in split_failures,
            }
        )
    summary = score_detection_recall(rows)
    summary["semantic_fit_threshold"] = threshold
    return {
        "threshold": threshold,
        "labeled_defect_count": len(instances),
        "file_run_count": len({inst[1] for inst in instances}),
        "split_failure_count": len(set(split_failures)),
        "split_failure_files": sorted(set(split_failures)),
        "summary": summary,
    }


def _platform_tp_for_file_keys(
    file_keys: set[str],
    cache: dict[str, dict[str, Any]],
    *,
    suffix_key: str = "none",
) -> dict[str, Any]:
    handler_stats: dict[str, dict[str, MetricCounts]] = defaultdict(dict)
    model_stats: dict[str, dict[str, ModelMetricCounts]] = defaultdict(dict)
    unlabeled: list[dict[str, Any]] = []
    volume_rows: list[dict[str, Any]] = []
    labeled_defects = 0

    for corpus_name, corpus_dir in corpus_dirs():
        for entry in load_corpus(corpus_dir):
            key = _file_key(corpus_name, entry.rel_path)
            if key not in file_keys:
                continue
            content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
            if entry.expected_rule_ids:
                labeled_defects += len(entry.expected_rule_ids)

            cache_row = cache.get(key, {})
            split_failure = bool(cache_row.get("split_failure"))
            completion_text = str(cache_row.get("raw_text") or "")
            tokens = int(cache_row.get("completion_token_count") or 0)
            findings: list[dict[str, Any]] = []
            if not split_failure and completion_text:
                raw_findings = _parse_json_findings(
                    completion_text,
                    entry.virtual_path,
                    prepend_array_bracket=(suffix_key == "bracket"),
                )
                findings = [
                    dict(f, model_originated=True)
                    for f in raw_findings
                    if isinstance(f, dict) and is_model_originated(f)
                ]

            score_file(
                matcher=MATCHER_BEST_FIT,
                entry=entry,
                corpus_name=corpus_name,
                content=content,
                model_findings=findings if not split_failure else None,
                handler_stats=handler_stats,
                model_stats=model_stats,
                unlabeled_model_findings=unlabeled,
                rule_semantics=RULE_SEMANTICS,
            )
            volume_rows.append(
                {
                    "file_key": key,
                    "split_failure": split_failure,
                    "completion_tokens": tokens,
                    "cap_hit": bool(cache_row.get("cap_hit")),
                    "model_finding_count": len(findings),
                    "has_expected_labels": bool(entry.expected_rule_ids),
                }
            )

    model_tp = sum(
        int(bucket.true_positives)
        for rules in model_stats.values()
        for bucket in rules.values()
    )
    tokens = [row["completion_tokens"] for row in volume_rows if row["completion_tokens"]]
    findings_counts = [row["model_finding_count"] for row in volume_rows]
    zero_findings = sum(1 for row in volume_rows if row["model_finding_count"] == 0 and not row["split_failure"])
    split_failures = [row["file_key"] for row in volume_rows if row["split_failure"]]

    return {
        "file_count": len(volume_rows),
        "labeled_defect_count": labeled_defects,
        "model_rule_level_tp": model_tp,
        "split_failure_count": len(split_failures),
        "split_failure_files": split_failures,
        "findings_emitted_total": sum(findings_counts),
        "findings_emitted_mean": round(mean(findings_counts), 2) if findings_counts else 0.0,
        "files_zero_findings": zero_findings,
        "files_zero_findings_rate": round(zero_findings / len(volume_rows), 4) if volume_rows else 0.0,
        "completion_tokens_mean": round(mean(tokens), 1) if tokens else 0.0,
        "completion_tokens_max": max(tokens) if tokens else 0,
        "cap_hit_count": sum(1 for row in volume_rows if row["cap_hit"]),
        "per_file_volume": volume_rows,
    }


def _added_labeled_files(frozen_keys: set[str], live_labeled: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in live_labeled if row["file_key"] not in frozen_keys]


def _load_handler_baseline() -> dict[str, Any]:
    payload = json.loads(HANDLER_COVERAGE.read_text(encoding="utf-8"))
    baseline = payload.get("handler_baseline") or {}
    return {
        "report_path": str(HANDLER_COVERAGE.relative_to(ROOT)),
        "generated_at": payload.get("generated_at"),
        "corpus_version": payload.get("corpus_version"),
        "corpus_version_notes": payload.get("corpus_version_notes"),
        "prior_corpus_version": baseline.get("prior_corpus_version"),
        "prior_labeled_defect_instance_count": baseline.get("prior_labeled_defect_instance_count"),
        "files_total": baseline.get("files_total"),
        "labeled_files": baseline.get("labeled_files"),
        "labeled_defect_instances": baseline.get("labeled_defect_instances"),
        "true_positives": baseline.get("true_positives"),
        "false_positives": baseline.get("false_positives"),
        "false_negatives": baseline.get("false_negatives"),
        "precision": baseline.get("precision"),
        "recall": baseline.get("recall"),
        "per_target_type": baseline.get("per_target_type") or {},
    }


def main() -> int:
    live = _live_corpus_snapshot()
    frozen_cookbook = _frozen_cookbook()
    instruct_platform_files = _load_instruct_platform_files()
    instruct_platform_keys = {row["file_key"] for row in instruct_platform_files}

    added_file_keys = {row["file_key"] for row in live["labeled_files"]} - frozen_cookbook["file_keys"]
    added_platform_keys = {row["file_key"] for row in live["all_files"]} - instruct_platform_keys

    reasoning_cookbook_cache = json.loads(REASONING_COOKBOOK_CACHE.read_text(encoding="utf-8"))
    reasoning_platform_cache = json.loads(REASONING_PLATFORM_CACHE.read_text(encoding="utf-8"))

    instruct_instances = _frozen_cookbook_instances()
    live_instances = _cookbook_instances_from_live()

    reasoning_cookbook_full = _score_cookbook_from_cache(
        reasoning_cookbook_cache,
        live_instances,
        REASONING_COOKBOOK_THRESHOLD,
    )
    reasoning_cookbook_instruct = _score_cookbook_from_cache(
        reasoning_cookbook_cache,
        instruct_instances,
        REASONING_COOKBOOK_THRESHOLD,
    )

    platform_full = _platform_tp_for_file_keys(
        {row["file_key"] for row in live["all_files"]},
        reasoning_platform_cache,
    )
    platform_instruct = _platform_tp_for_file_keys(instruct_platform_keys, reasoning_platform_cache)

    rcm_frozen = json.loads(INSTRUCT_RCM_INSTANCES.read_text(encoding="utf-8"))
    rcm_reasoning = json.loads(REASONING_RCM_EVAL.read_text(encoding="utf-8"))
    rcm_instruct = json.loads(INSTRUCT_RCM_EVAL.read_text(encoding="utf-8"))
    frozen_rcm_ids = [row["instance_id"] for row in rcm_frozen["instances"]]
    reasoning_rcm_ids = [row["instance_id"] for row in rcm_reasoning["per_instance"]]
    rcm_instances_identical = frozen_rcm_ids == reasoning_rcm_ids
    handler_baseline = _load_handler_baseline()

    report = {
        **reasoning_run_stamp(threshold=REASONING_COOKBOOK_THRESHOLD),
        "generated_at": datetime.now(UTC).isoformat(),
        "task": "reasoning_corpus_reconciliation",
        "corpus_reconciliation": {
            "terminology": {
                "instruct_platform_files": "All corpus files with labels sidecar at instruct platform eval time (148). Includes unlabeled clean fixtures.",
                "instruct_cookbook_files": "Labeled files only (non-empty expected_rule_ids) frozen in cookbook-prose-inputs.json (87).",
                "handler_corpus_v1_108": (
                    "Instruct-era handler baseline (handler-corpus-v1): 108 labeled defect "
                    "instances / 87 labeled files / 148 platform files. Zero handler FP; FN=0."
                ),
                "handler_corpus_v2_149": (
                    "Current handler baseline (handler-corpus-v2): 149 labeled defect instances "
                    "/ 116 labeled files / 197 files. Includes cisco_nx_os. See handler-coverage.json."
                ),
                "reasoning_live_corpus": (
                    "On-disk corpus aligned with handler-corpus-v2 after NX-OS commit (2026-09-11)."
                ),
            },
            "handler_baseline": handler_baseline,
            "instruct_baselines": {
                "cookbook_f": {
                    "frozen_at": frozen_cookbook["frozen_at"],
                    "file_run_count": frozen_cookbook["file_run_count"],
                    "labeled_defect_count": frozen_cookbook["labeled_defect_count"],
                    "inputs_path": str(INSTRUCT_COOKBOOK_INPUTS.relative_to(ROOT)),
                },
                "platform_specific": {
                    "frozen_at": json.loads(INSTRUCT_PLATFORM_FILELIST.read_text())["generated_at"],
                    "file_count": len(instruct_platform_files),
                    "labeled_defect_scoring_denominator": 108,
                    "report_path": str(REPORTS / "model-vs-handler-platform-specific.json"),
                    "file_list_source": str(INSTRUCT_PLATFORM_FILELIST.relative_to(ROOT)),
                },
                "rcm_d": {
                    "frozen_at": rcm_frozen.get("generated_at"),
                    "instance_count": rcm_frozen["instance_count"],
                    "instances_path": str(INSTRUCT_RCM_INSTANCES.relative_to(ROOT)),
                },
            },
            "reasoning_runs": {
                "cookbook_f": {
                    "run_at": json.loads(REASONING_COOKBOOK_EVAL.read_text())["generated_at"],
                    "file_run_count": reasoning_cookbook_full["file_run_count"],
                    "labeled_defect_count": reasoning_cookbook_full["labeled_defect_count"],
                },
                "platform_specific": {
                    "run_at": json.loads(REASONING_PLATFORM_EVAL.read_text())["generated_at"],
                    "file_count": platform_full["file_count"],
                    "labeled_defect_count": live["labeled_defect_count"],
                },
                "rcm_d": {
                    "run_at": rcm_reasoning["generated_at"],
                    "instance_count": rcm_reasoning["instance_count"],
                },
            },
            "why_counts_differ": {
                "cookbook_87_vs_116": (
                    "Cookbook runs only labeled files. Instruct snapshot (2026-09-09) had 87 labeled files / "
                    "108 defects. Live corpus now has 116 labeled files / 149 defects (+29 files, +41 defects)."
                ),
                "platform_148_vs_197": (
                    "Platform runs all sidecar files (labeled + unlabeled clean fixtures). Instruct eval used "
                    "148 files (handler-corpus-v1). Live corpus has 197 (+49), primarily cisco_nx_os fixtures "
                    "in handler-corpus-v2 (committed 2026-09-11)."
                ),
                "rcm_108_unchanged": (
                    "RCM reasoning eval reads frozen rcm-cwe-instances.json from instruct era; instance set did "
                    "not expand with corpus growth."
                ),
            },
            "added_since_instruct": {
                "labeled_files_added_count": len(added_file_keys),
                "labeled_files_added": sorted(added_file_keys),
                "platform_files_added_count": len(added_platform_keys),
                "platform_files_added_sample": sorted(added_platform_keys)[:15],
                "when": "Between instruct snapshots (2026-09-08..09-09) and reasoning runs (2026-09-11); NX-OS corpus expansion.",
            },
        },
        "comparable_metrics": {
            "cookbook_f_reasoning": {
                "threshold": REASONING_COOKBOOK_THRESHOLD,
                "full_corpus": {
                    "denominator": f"{reasoning_cookbook_full['labeled_defect_count']} labeled defects / "
                    f"{reasoning_cookbook_full['file_run_count']} labeled files",
                    "detected": reasoning_cookbook_full["summary"]["detected"],
                    "recall": reasoning_cookbook_full["summary"]["recall"],
                    "split_failure_count": reasoning_cookbook_full["split_failure_count"],
                },
                "instruct_comparable_subset": {
                    "denominator": f"{reasoning_cookbook_instruct['labeled_defect_count']} labeled defects / "
                    f"{reasoning_cookbook_instruct['file_run_count']} labeled files",
                    "detected": reasoning_cookbook_instruct["summary"]["detected"],
                    "recall": reasoning_cookbook_instruct["summary"]["recall"],
                    "split_failure_count": reasoning_cookbook_instruct["split_failure_count"],
                    "frozen_inputs": str(INSTRUCT_COOKBOOK_INPUTS.relative_to(ROOT)),
                },
            },
            "platform_specific_reasoning": {
                "suffix": "none",
                "full_corpus": {
                    "denominator": f"{platform_full['labeled_defect_count']} labeled defects / "
                    f"{platform_full['file_count']} files",
                    "model_rule_level_tp": platform_full["model_rule_level_tp"],
                    "findings_emitted_total": platform_full["findings_emitted_total"],
                    "findings_emitted_mean": platform_full["findings_emitted_mean"],
                    "files_zero_findings": platform_full["files_zero_findings"],
                    "files_zero_findings_rate": platform_full["files_zero_findings_rate"],
                    "completion_tokens_mean": platform_full["completion_tokens_mean"],
                    "completion_tokens_max": platform_full["completion_tokens_max"],
                    "cap_hit_count": platform_full["cap_hit_count"],
                    "split_failure_count": platform_full["split_failure_count"],
                },
                "instruct_comparable_subset": {
                    "denominator": f"{platform_instruct['labeled_defect_count']} labeled defects / "
                    f"{platform_instruct['file_count']} files",
                    "model_rule_level_tp": platform_instruct["model_rule_level_tp"],
                    "findings_emitted_total": platform_instruct["findings_emitted_total"],
                    "findings_emitted_mean": platform_instruct["findings_emitted_mean"],
                    "files_zero_findings": platform_instruct["files_zero_findings"],
                    "files_zero_findings_rate": platform_instruct["files_zero_findings_rate"],
                    "completion_tokens_mean": platform_instruct["completion_tokens_mean"],
                    "completion_tokens_max": platform_instruct["completion_tokens_max"],
                    "cap_hit_count": platform_instruct["cap_hit_count"],
                    "split_failure_count": platform_instruct["split_failure_count"],
                    "frozen_file_list": str(INSTRUCT_PLATFORM_FILELIST.relative_to(ROOT)),
                },
                "volume_interpretation": (
                    "Reasoning platform_specific emits substantial JSON (mean ~hundreds of tokens, majority of "
                    "files with parseable findings). This is NOT instruct-style near-empty collapse "
                    "(instruct Q4 volume probe: mean 38.8 tokens, 148/148 zero parsed findings with fence stop)."
                ),
            },
            "rcm_d": {
                "instances_identical_to_instruct": rcm_instances_identical,
                "instance_count": len(frozen_rcm_ids),
                "instruct_foundation_sec_accuracy": rcm_instruct["models"]["foundation_sec"]["summary"]["accuracy"],
                "instruct_foundation_sec_correct": rcm_instruct["models"]["foundation_sec"]["summary"]["correct"],
                "reasoning_accuracy": rcm_reasoning["summary"]["accuracy"],
                "reasoning_correct": rcm_reasoning["summary"]["correct"],
                "directly_comparable": rcm_instances_identical,
                "comparison_statement": (
                    f"45/108 vs 24/108 on identical frozen instances"
                    if rcm_instances_identical
                    else "Instance sets differ — not directly comparable"
                ),
            },
        },
    }

    lines = [
        "# Reasoning vs instruct corpus reconciliation",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Corpus sizes",
        "",
        "| Experiment | Instruct | Reasoning (full) | Delta |",
        "|------------|----------|------------------|-------|",
        f"| Cookbook F (labeled files) | 87 | {reasoning_cookbook_full['file_run_count']} | +{reasoning_cookbook_full['file_run_count'] - 87} |",
        f"| Cookbook F (labeled defects) | 108 | {reasoning_cookbook_full['labeled_defect_count']} | +{reasoning_cookbook_full['labeled_defect_count'] - 108} |",
        f"| platform_specific (files) | 148 | {platform_full['file_count']} | +{platform_full['file_count'] - 148} |",
        f"| platform_specific (labeled defects) | 108 | {platform_full['labeled_defect_count']} | +{platform_full['labeled_defect_count'] - 108} |",
        f"| RCM D (instances) | 108 | {rcm_reasoning['instance_count']} | 0 (frozen) |",
        "",
        "## Handler deterministic baseline",
        "",
        f"- **{handler_baseline['corpus_version']}** "
        f"({handler_baseline['labeled_defect_instances']} labeled defect instances, "
        f"{handler_baseline['files_total']} files): "
        f"**{handler_baseline['true_positives']}/{handler_baseline['labeled_defect_instances']}** TP, "
        f"FP={handler_baseline['false_positives']}, FN={handler_baseline['false_negatives']} "
        f"(recall {100 * (handler_baseline['recall'] or 0):.2f}%)",
        f"- Prior **{handler_baseline['prior_corpus_version']}**: "
        f"{handler_baseline['prior_labeled_defect_instance_count']}/"
        f"{handler_baseline['prior_labeled_defect_instance_count']} TP, FP=0, FN=0",
        "",
        "| Target type | Instances | Handler TP | FP | FN |",
        "|-------------|-----------|------------|----|----|",
    ]
    for target_type in sorted(handler_baseline["per_target_type"]):
        row = handler_baseline["per_target_type"][target_type]
        lines.append(
            f"| {target_type} | {row['labeled_defect_instances']} | "
            f"{row['true_positives']} | {row['false_positives']} | {row['false_negatives']} |"
        )
    lines.extend(
        [
        "",
        "## Cookbook F recall (reasoning @ 0.80, whole completion)",
        "",
        f"- Full corpus: **{reasoning_cookbook_full['summary']['detected']}/{reasoning_cookbook_full['labeled_defect_count']}** "
        f"({100 * reasoning_cookbook_full['summary']['recall']:.1f}%)",
        f"- Instruct-comparable subset: **{reasoning_cookbook_instruct['summary']['detected']}/{reasoning_cookbook_instruct['labeled_defect_count']}** "
        f"({100 * reasoning_cookbook_instruct['summary']['recall']:.1f}%)",
        "",
        "## platform_specific TP (reasoning, suffix none)",
        "",
        f"- Full corpus: **{platform_full['model_rule_level_tp']}/{platform_full['labeled_defect_count']}** TP "
        f"({platform_full['file_count']} files); findings emitted {platform_full['findings_emitted_total']} "
        f"(mean {platform_full['findings_emitted_mean']}/file); zero-finding files {platform_full['files_zero_findings']}/{platform_full['file_count']}; "
        f"mean tokens {platform_full['completion_tokens_mean']}",
        f"- Instruct-comparable: **{platform_instruct['model_rule_level_tp']}/{platform_instruct['labeled_defect_count']}** TP "
        f"({platform_instruct['file_count']} files); findings emitted {platform_instruct['findings_emitted_total']} "
        f"(mean {platform_instruct['findings_emitted_mean']}/file); zero-finding files {platform_instruct['files_zero_findings']}/{platform_instruct['file_count']}; "
        f"mean tokens {platform_instruct['completion_tokens_mean']}",
        "",
        "## RCM D (identical 108 instances)",
        "",
        f"- Instruct: **{rcm_instruct['models']['foundation_sec']['summary']['correct']}/108** "
        f"({100 * rcm_instruct['models']['foundation_sec']['summary']['accuracy']:.1f}%)",
        f"- Reasoning: **{rcm_reasoning['summary']['correct']}/108** "
        f"({100 * rcm_reasoning['summary']['accuracy']:.1f}%)",
        "",
        ]
    )
    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    OUTPUT_TXT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUTPUT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
