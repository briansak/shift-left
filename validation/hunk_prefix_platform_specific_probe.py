#!/usr/bin/env python3
"""Paired colon-suffix run: clean corpus text vs production '+' hunk prefix.

Uses the defective `JSON array:` suffix that produced the published Q8_0 13/108
platform_specific TP. The production bracket suffix (`Findings JSON array:\\n[`)
emits 0 findings, so it cannot detect a prefix effect.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "validation" / "reports" / "hunk-prefix-platform-specific-colon-20.json"
SAMPLE_SIZE = 20
MAX_LINES = 80
PROMPT_VARIANT = "platform_specific_colon"
BASELINE_NOTE = (
    "Colon suffix `JSON array:` (no array-bracket prepend). Published platform_specific "
    "Q8_0 baseline on this suffix was 13 TP / 108 labeled defects (85 findings emitted). "
    "This probe reuses that suffix so the clean leg can emit findings; it is not the "
    "production bracket suffix."
)

from eval_model import (  # noqa: E402
    FOUNDATION_SEC_URL as _DEFAULT_FOUNDATION_SEC_URL,
    MODEL_MAX_CONTEXT_TOKENS,
    RULE_SEMANTICS,
    _line_count,
    analyze_file,
    collect_file_list,
)
import eval_model as _eval_model  # noqa: E402

FOUNDATION_SEC_URL = os.environ.get("FOUNDATION_SEC_URL", _DEFAULT_FOUNDATION_SEC_URL)
_eval_model.FOUNDATION_SEC_URL = FOUNDATION_SEC_URL
_IN_PROCESS_ANALYZER = None
from model_eval_matching import (  # noqa: E402
    MATCHER_BEST_FIT,
    MetricCounts,
    ModelMetricCounts,
    is_model_originated,
    score_file,
)


def _in_process_analyzer():
    global _IN_PROCESS_ANALYZER
    if _IN_PROCESS_ANALYZER is None:
        from foundation_sec_server.analyzer import ConfigAnalyzer
        from foundation_sec_server.engine import build_engine_from_env

        engine = build_engine_from_env()
        _IN_PROCESS_ANALYZER = ConfigAnalyzer(
            engine,
            max_context_tokens=int(os.environ.get("FOUNDATION_SEC_N_CTX", str(MODEL_MAX_CONTEXT_TOKENS))),
        )
    return _IN_PROCESS_ANALYZER


def analyze_one(
    client: httpx.Client | None,
    *,
    virtual_path: str,
    content: str,
    corpus_name: str,
    target_type: str,
) -> dict[str, Any]:
    if os.environ.get("FOUNDATION_SEC_IN_PROCESS", "").lower() in {"1", "true", "yes"}:
        analyzer = _in_process_analyzer()
        line_count = _line_count(content)
        return analyzer.analyze_files(
            [
                {
                    "path": virtual_path,
                    "target_type": target_type,
                    "hunks": [
                        {
                            "new_start": 1,
                            "new_end": line_count,
                            "content": content,
                        }
                    ],
                }
            ],
            prompt_variant=PROMPT_VARIANT,
        )
    assert client is not None
    return analyze_file(
        client,
        virtual_path=virtual_path,
        content=content,
        corpus_name=corpus_name,
        target_type=target_type,
        prompt_variant=PROMPT_VARIANT,
    )


def prefix_plus(content: str) -> str:
    lines = content.splitlines()
    if not lines:
        return "+"
    return "\n".join(f"+{line}" for line in lines)


def select_files() -> list[tuple[str, Path, Any]]:
    buckets: dict[str, list[tuple[int, str, Path, Any]]] = defaultdict(list)
    for corpus_name, corpus_dir, entry in collect_file_list():
        if not entry.expected_rule_ids:
            continue
        path = corpus_dir / entry.rel_path
        content = path.read_text(encoding="utf-8")
        lines = _line_count(content)
        if lines > MAX_LINES:
            continue
        buckets[entry.target_type].append((lines, corpus_name, corpus_dir, entry))
    for items in buckets.values():
        items.sort(key=lambda item: (item[0], item[1], item[3].rel_path))
    selected: list[tuple[str, Path, Any]] = []
    types = sorted(buckets)
    idx = {name: 0 for name in types}
    while len(selected) < SAMPLE_SIZE and types:
        progressed = False
        for name in list(types):
            cursor = idx[name]
            if cursor >= len(buckets[name]):
                types.remove(name)
                continue
            _lines, corpus_name, corpus_dir, entry = buckets[name][cursor]
            idx[name] = cursor + 1
            selected.append((corpus_name, corpus_dir, entry))
            progressed = True
            if len(selected) >= SAMPLE_SIZE:
                break
        if not progressed:
            break
    if len(selected) < SAMPLE_SIZE:
        raise SystemExit(f"Only selected {len(selected)} labeled files under {MAX_LINES} lines")
    return selected


def expected_tp(stats: dict[str, dict[str, ModelMetricCounts]]) -> tuple[int, int]:
    tp = 0
    labeled = 0
    for rules in stats.values():
        for counts in rules.values():
            labeled += counts.true_positives + counts.false_negatives
            tp += counts.true_positives
    return tp, labeled


def summarize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for finding in findings:
        rows.append(
            {
                "cwe": finding.get("model_asserted_cwe") or finding.get("cwe"),
                "title": finding.get("title"),
                "line_start": finding.get("line_start"),
                "line_end": finding.get("line_end"),
                "evidence": (finding.get("evidence") or "")[:160],
                "deterministic_only": bool(finding.get("deterministic_only")),
                "model_originated": is_model_originated(finding),
            }
        )
    return rows


def run_variant(
    client: httpx.Client | None,
    files: list[tuple[str, Path, Any]],
    *,
    prefix: bool,
) -> dict[str, Any]:
    model_stats: dict[str, dict[str, ModelMetricCounts]] = {}
    handler_stats: dict[str, dict[str, MetricCounts]] = {}
    unlabeled: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    emitted = 0
    empty = 0
    failed = 0
    completion_token_rows: list[int] = []
    for index, (corpus_name, corpus_dir, entry) in enumerate(files, start=1):
        clean = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
        content = prefix_plus(clean) if prefix else clean
        t0 = time.monotonic()
        try:
            result = analyze_one(
                client,
                virtual_path=entry.virtual_path,
                content=content,
                corpus_name=corpus_name,
                target_type=entry.target_type,
            )
            wall_ms = int((time.monotonic() - t0) * 1000)
            outcome = str(result.get("outcome") or "unknown")
            raw = list(result.get("findings") or [])
            model_findings = [item for item in raw if is_model_originated(item)]
            success = outcome in {"completed_no_findings", "completed_with_findings"}
        except Exception as exc:  # noqa: BLE001
            wall_ms = int((time.monotonic() - t0) * 1000)
            outcome = "failed"
            raw = []
            model_findings = []
            success = False
            result = {"failure_message": str(exc), "usage": {}}
        usage = result.get("usage") or {}
        try:
            file_tokens = int(usage.get("completion_tokens") or 0)
        except (TypeError, ValueError):
            file_tokens = 0
        completion_token_rows.append(file_tokens)
        if not success:
            failed += 1
        elif not model_findings:
            empty += 1
        emitted += len(model_findings)
        score_file(
            matcher=MATCHER_BEST_FIT,
            entry=entry,
            corpus_name=corpus_name,
            content=clean,
            model_findings=model_findings if success else None,
            handler_stats=handler_stats,
            model_stats=model_stats,
            unlabeled_model_findings=unlabeled,
            rule_semantics=RULE_SEMANTICS,
        )
        row = {
            "index": index,
            "corpus": corpus_name,
            "rel_path": entry.rel_path,
            "target_type": entry.target_type,
            "expected_rule_ids": sorted(entry.expected_rule_ids),
            "outcome": outcome,
            "wall_ms": wall_ms,
            "findings_all": len(raw),
            "findings_model": len(model_findings),
            "failure_message": result.get("failure_message"),
            "completion_tokens": file_tokens,
            "findings": summarize_findings(model_findings),
        }
        rows.append(row)
        label = "prefix+" if prefix else "clean"
        print(
            f"[{label} {index}/{len(files)}] {corpus_name}/{entry.rel_path} "
            f"{wall_ms}ms outcome={outcome} model_findings={len(model_findings)} "
            f"tokens={file_tokens}",
            flush=True,
        )
    tp, labeled = expected_tp(model_stats)
    return {
        "prefix": prefix,
        "files": rows,
        "model_findings_emitted": emitted,
        "files_empty_model_findings": empty,
        "files_failed": failed,
        "labeled_defects": labeled,
        "true_positives": tp,
        "completion_tokens_mean": (
            round(statistics.mean(completion_token_rows), 1) if completion_token_rows else 0.0
        ),
        "completion_tokens_sum": sum(completion_token_rows),
        "unlabeled_model_findings": unlabeled,
        "per_target_type": {
            target: {rule: counts.as_dict() for rule, counts in rules.items()}
            for target, rules in model_stats.items()
        },
    }


def main() -> int:
    files = select_files()
    print(f"Selected {len(files)} labeled files:", flush=True)
    for corpus_name, _dir, entry in files:
        print(
            f"  {entry.target_type:24} {corpus_name}/{entry.rel_path} "
            f"rules={sorted(entry.expected_rule_ids)}",
            flush=True,
        )
    started = time.monotonic()
    in_process = os.environ.get("FOUNDATION_SEC_IN_PROCESS", "").lower() in {"1", "true", "yes"}
    if in_process:
        analyzer = _in_process_analyzer()
        health = analyzer.status()
        print(
            f"In-process: {health.get('gguf_file')} loaded={health.get('loaded')}",
            flush=True,
        )
        clean = run_variant(None, files, prefix=False)
        prefixed = run_variant(None, files, prefix=True)
    else:
        with httpx.Client(timeout=600.0) as client:
            health = client.get(f"{FOUNDATION_SEC_URL}/health").json()
            print(f"Server: {health.get('gguf_file')} loaded={health.get('loaded')}", flush=True)
            clean = run_variant(client, files, prefix=False)
            prefixed = run_variant(client, files, prefix=True)
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "prompt_variant": PROMPT_VARIANT,
        "prompt_suffix": "JSON array:",
        "baseline": BASELINE_NOTE,
        "quant": health.get("gguf_file"),
        "n_ctx": health.get("n_ctx"),
        "sample_size": len(files),
        "max_lines": MAX_LINES,
        "scoring": (
            "best_fit_v1 against clean corpus text for both legs; "
            "prefixed leg feeds each line with a leading '+' as parse_unified_diff does for added lines"
        ),
        "elapsed_s": round(time.monotonic() - started, 1),
        "clean": clean,
        "prefixed": prefixed,
        "delta": {
            "model_findings_emitted": prefixed["model_findings_emitted"] - clean["model_findings_emitted"],
            "true_positives": prefixed["true_positives"] - clean["true_positives"],
            "completion_tokens_mean": round(
                prefixed["completion_tokens_mean"] - clean["completion_tokens_mean"], 1
            ),
            "files_empty_model_findings": (
                prefixed["files_empty_model_findings"] - clean["files_empty_model_findings"]
            ),
            "files_failed": prefixed["files_failed"] - clean["files_failed"],
        },
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("quant", "elapsed_s", "clean", "prefixed", "delta") if k != "clean"}, indent=2))
    print(
        f"clean TP {clean['true_positives']}/{clean['labeled_defects']} "
        f"emitted={clean['model_findings_emitted']} empty={clean['files_empty_model_findings']} "
        f"mean_tokens={clean['completion_tokens_mean']}",
        flush=True,
    )
    print(
        f"prefixed TP {prefixed['true_positives']}/{prefixed['labeled_defects']} "
        f"emitted={prefixed['model_findings_emitted']} empty={prefixed['files_empty_model_findings']} "
        f"mean_tokens={prefixed['completion_tokens_mean']}",
        flush=True,
    )
    print(f"Wrote {REPORT_PATH}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
