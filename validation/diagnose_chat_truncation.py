#!/usr/bin/env python3
"""Diagnose truncation vs under-detection on the Foundation-Sec chat-template path."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FSEC = ROOT / "services" / "foundation-sec-server"
ORCH = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
VALIDATION = ROOT / "validation"
for path in (SHARED, ORCH, FSEC, VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from eval_model import collect_file_list, resolve_model_layout  # noqa: E402
from foundation_sec_server.chat_inference import (  # noqa: E402
    FOUNDATION_SEC_CHAT_STOP_TOKENS,
    _merge_stop_tokens,
    build_foundation_sec_chat_handler,
    build_instruct_messages,
    create_chat_completion,
)
from foundation_sec_server.engine import LlamaCppEvalEngine, _parse_json_findings  # noqa: E402
from foundation_sec_server.handlers.registry import DEFAULT_REGISTRY  # noqa: E402
from foundation_sec_server.preprocess import strip_inactive_lines  # noqa: E402
from foundation_sec_server.prompts import (  # noqa: E402
    PROMPT_VARIANT_PLATFORM_SPECIFIC,
    build_platform_specific_prompt,
)

REPORTS = ROOT / "validation" / "reports"
RAW_CACHE = REPORTS / "findings-cache" / "platform_specific.findings.json"
CORRECT_CACHE = REPORTS / "findings-cache" / "platform_specific.foundation_sec_template.findings.json"
OUTPUT_JSON = REPORTS / "chat-truncation-diagnostic.json"
OUTPUT_TXT = REPORTS / "chat-truncation-diagnostic.txt"

SAMPLE_SIZE = 10
MAX_OUTPUT_TOKENS = 1024
CALLER_STOP_FENCE = "```"


@dataclass(frozen=True)
class FileRun:
    corpus: str
    rel_path: str
    virtual_path: str
    target_type: str
    content: str


def _load_caches() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    raw = json.loads(RAW_CACHE.read_text(encoding="utf-8"))
    correct = json.loads(CORRECT_CACHE.read_text(encoding="utf-8"))
    return (
        {item["virtual_path"]: item for item in raw.get("files") or []},
        {item["virtual_path"]: item for item in correct.get("files") or []},
    )


def _select_sample_files(
    raw_map: dict[str, dict[str, Any]],
    correct_map: dict[str, dict[str, Any]],
    *,
    limit: int,
) -> list[str]:
    raw_only: list[str] = []
    correct_only: list[str] = []
    for virtual_path in raw_map:
        raw_count = len(raw_map[virtual_path].get("model_findings") or [])
        correct_count = len(correct_map.get(virtual_path, {}).get("model_findings") or [])
        if raw_count and not correct_count:
            raw_only.append(virtual_path)
        elif correct_count and not raw_count:
            correct_only.append(virtual_path)
    picks: list[str] = []
    picks.extend(raw_only[:6])
    picks.extend(correct_only[:2])
    for virtual_path in raw_only[6:]:
        if virtual_path not in picks and len(picks) < limit:
            picks.append(virtual_path)
    for virtual_path in correct_only[2:]:
        if virtual_path not in picks and len(picks) < limit:
            picks.append(virtual_path)
    return picks[:limit]


def _build_file_runs() -> dict[str, FileRun]:
    runs: dict[str, FileRun] = {}
    for corpus_name, corpus_dir, entry in collect_file_list():
        content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
        runs[entry.virtual_path] = FileRun(
            corpus=corpus_name,
            rel_path=entry.rel_path,
            virtual_path=entry.virtual_path,
            target_type=entry.target_type,
            content=content,
        )
    return runs


def _platform_prompt(file_run: FileRun) -> str:
    handler = DEFAULT_REGISTRY.resolve(file_run.virtual_path)
    active_content, _ = strip_inactive_lines(file_run.content, handler)
    line_count = max(1, file_run.content.count("\n") + 1)
    return build_platform_specific_prompt(
        handler=handler,
        target_type=file_run.target_type,
        file_path=file_run.virtual_path,
        line_start=1,
        line_end=line_count,
        content=active_content,
    )


def _classify_output(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return "empty"
    if re.search(r"```", stripped):
        if re.search(r"\[.*\]", stripped, re.DOTALL):
            return "fenced_json"
        return "fenced_non_json"
    if "[" in stripped:
        if re.search(r"\[.*\]", stripped, re.DOTALL):
            return "bare_json"
        return "json_cut_mid_array"
    return "prose"


def _completion_call(
    llm: Any,
    prompt: str,
    *,
    include_fence_stop: bool,
) -> dict[str, Any]:
    caller_stops = [CALLER_STOP_FENCE] if include_fence_stop else []
    output = llm.create_chat_completion(
        messages=build_instruct_messages(prompt),
        max_tokens=MAX_OUTPUT_TOKENS,
        temperature=0.1,
        repeat_penalty=1.2,
        stop=_merge_stop_tokens(caller_stops),
    )
    choice = output["choices"][0]
    text = str((choice.get("message") or {}).get("content") or "")
    usage = output.get("usage") or {}
    completion_tokens = int(usage.get("completion_tokens") or 0)
    return {
        "raw_text": text,
        "completion_tokens": completion_tokens,
        "finish_reason": str(choice.get("finish_reason") or ""),
        "parsed_findings": len(_parse_json_findings(text, "diagnostic")),
        "output_class": _classify_output(text),
    }


def _raw_completion_call(llm: Any, prompt: str) -> dict[str, Any]:
    output = llm(
        prompt,
        max_tokens=MAX_OUTPUT_TOKENS,
        temperature=0.1,
        stop=[CALLER_STOP_FENCE],
    )
    choice = output["choices"][0]
    text = str(choice.get("text") or "")
    usage = output.get("usage") or {}
    return {
        "raw_text": text,
        "completion_tokens": int(usage.get("completion_tokens") or 0),
        "finish_reason": str(choice.get("finish_reason") or ""),
        "parsed_findings": len(_parse_json_findings(text, "diagnostic")),
        "output_class": _classify_output(text),
    }


def _infer_stop_sequence(
    with_fence: dict[str, Any],
    without_fence: dict[str, Any],
) -> str:
    if with_fence["completion_tokens"] >= MAX_OUTPUT_TOKENS:
        return "max_tokens"
    if with_fence["finish_reason"] == "length":
        return "max_tokens"
    if without_fence["completion_tokens"] > with_fence["completion_tokens"]:
        fence_pos = without_fence["raw_text"].find(CALLER_STOP_FENCE)
        if fence_pos >= 0:
            prefix = without_fence["raw_text"][:fence_pos]
            if prefix.rstrip() == with_fence["raw_text"].rstrip():
                return CALLER_STOP_FENCE
    for marker in FOUNDATION_SEC_CHAT_STOP_TOKENS:
        if with_fence["raw_text"].rstrip().endswith(marker.rstrip()):
            return marker
    if with_fence["finish_reason"] == "stop":
        return "role_or_eos_stop"
    if not with_fence["raw_text"].strip():
        return "empty_immediate"
    return "unknown_stop"


def _token_stats(rows: list[dict[str, Any]], key: str) -> dict[str, float | int]:
    values = [int(row[key]) for row in rows if row.get(key) is not None]
    if not values:
        return {"count": 0, "mean": 0.0, "max": 0}
    return {
        "count": len(values),
        "mean": round(mean(values), 1),
        "max": max(values),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-quant-mismatch", action="store_true")
    parser.add_argument("--sample-size", type=int, default=SAMPLE_SIZE)
    args = parser.parse_args()

    raw_map, correct_map = _load_caches()
    file_runs = _build_file_runs()
    sample_paths = _select_sample_files(raw_map, correct_map, limit=args.sample_size)

    model_dir, _, quant_label = resolve_model_layout(allow_quant_mismatch=args.allow_quant_mismatch)
    print(f"Loading model from {model_dir} ({quant_label}) …", flush=True)
    engine = LlamaCppEvalEngine(
        model_dir,
        gguf_glob="*.gguf",
        quant_label=quant_label,
        load_strategy="eager",
        n_ctx=4096,
    )
    engine.load()
    llm = engine._llm  # noqa: SLF001 — diagnostic access to production llama instance
    assert llm is not None
    print("Model loaded.", flush=True)

    sample_rows: list[dict[str, Any]] = []
    print(f"Sample deep-dive on {len(sample_paths)} files …", flush=True)
    for index, virtual_path in enumerate(sample_paths, start=1):
        print(f"  sample {index}/{len(sample_paths)}: {virtual_path}", flush=True)
        file_run = file_runs[virtual_path]
        prompt = _platform_prompt(file_run)
        with_fence = _completion_call(llm, prompt, include_fence_stop=True)
        without_fence = _completion_call(llm, prompt, include_fence_stop=False)
        raw_completion = _raw_completion_call(llm, prompt)
        sample_rows.append(
            {
                "virtual_path": virtual_path,
                "corpus": file_run.corpus,
                "rel_path": file_run.rel_path,
                "raw_cache_findings": len(raw_map.get(virtual_path, {}).get("model_findings") or []),
                "correct_cache_findings": len(
                    correct_map.get(virtual_path, {}).get("model_findings") or []
                ),
                "with_fence_stop": with_fence,
                "without_fence_stop": without_fence,
                "fence_stop_delta_tokens": (
                    without_fence["completion_tokens"] - with_fence["completion_tokens"]
                ),
                "findings_recovered_without_fence": (
                    without_fence["parsed_findings"] > with_fence["parsed_findings"]
                ),
                "inferred_stop_with_fence": _infer_stop_sequence(with_fence, without_fence),
                "raw_completion": raw_completion,
            }
        )

    labeled_paths = [
        virtual_path
        for virtual_path, record in raw_map.items()
        if record.get("expected_rule_ids")
    ]
    stop_rows: list[dict[str, Any]] = []
    correct_token_rows: list[dict[str, Any]] = []
    raw_token_rows: list[dict[str, Any]] = []

    total_files = len(raw_map)
    print(f"Corpus pass on {total_files} eval files (stop stats on labeled subset) …", flush=True)
    for file_index, (virtual_path, record) in enumerate(raw_map.items(), start=1):
        if file_index % 10 == 0 or file_index == total_files:
            print(f"  corpus {file_index}/{total_files}", flush=True)
        file_run = file_runs[virtual_path]
        prompt = _platform_prompt(file_run)
        with_fence = _completion_call(llm, prompt, include_fence_stop=True)
        correct_token_rows.append(
            {
                "virtual_path": virtual_path,
                "completion_tokens": with_fence["completion_tokens"],
            }
        )
        raw_completion = _raw_completion_call(llm, prompt)
        raw_token_rows.append(
            {
                "virtual_path": virtual_path,
                "completion_tokens": raw_completion["completion_tokens"],
            }
        )
        labeled = bool(record.get("expected_rule_ids"))
        without_fence: dict[str, Any] | None = None
        inferred = "not_measured"
        if labeled:
            without_fence = _completion_call(llm, prompt, include_fence_stop=False)
            inferred = _infer_stop_sequence(with_fence, without_fence)
        stop_rows.append(
            {
                "virtual_path": virtual_path,
                "labeled": labeled,
                "completion_tokens_with_fence": with_fence["completion_tokens"],
                "completion_tokens_without_fence": (
                    without_fence["completion_tokens"] if without_fence else None
                ),
                "inferred_stop": inferred,
                "output_class": with_fence["output_class"],
                "fence_stop_delta_tokens": (
                    (without_fence["completion_tokens"] - with_fence["completion_tokens"])
                    if without_fence
                    else None
                ),
            }
        )

    labeled_stop_rows = [row for row in stop_rows if row["labeled"]]
    stop_histogram = {}
    for row in labeled_stop_rows:
        stop_histogram[row["inferred_stop"]] = stop_histogram.get(row["inferred_stop"], 0) + 1
    fence_hits = sum(1 for row in labeled_stop_rows if row["inferred_stop"] == CALLER_STOP_FENCE)
    output_class_hist = {}
    for row in labeled_stop_rows:
        output_class_hist[row["output_class"]] = output_class_hist.get(row["output_class"], 0) + 1

    sample_recovered = sum(
        1 for row in sample_rows if row["findings_recovered_without_fence"]
    )
    sample_fence_deltas = [row["fence_stop_delta_tokens"] for row in sample_rows]

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "task": "chat_truncation_diagnostic",
        "prompt_variant": PROMPT_VARIANT_PLATFORM_SPECIFIC,
        "labeled_file_count": len(labeled_paths),
        "labeled_rule_count": 108,
        "eval_file_count": len(stop_rows),
        "sample_files": sample_paths,
        "sample_details": sample_rows,
        "labeled_stop_summary": {
            "files": len(labeled_stop_rows),
            "stop_histogram": stop_histogram,
            "fence_stop_hits": fence_hits,
            "fence_stop_rate": round(fence_hits / len(labeled_stop_rows), 3) if labeled_stop_rows else 0.0,
            "output_class_histogram": output_class_hist,
        },
        "sample_without_fence_recovery": {
            "files_with_more_findings": sample_recovered,
            "files_sampled": len(sample_rows),
        },
        "completion_token_stats": {
            "correct_template_with_fence": _token_stats(correct_token_rows, "completion_tokens"),
            "raw_completion": _token_stats(raw_token_rows, "completion_tokens"),
        },
        "interpretation": {
            "truncation_likely_if": (
                "fence_stop_hits are high, sample_without_fence_recovery > 0, "
                "or correct_template mean/max tokens are much lower than raw_completion"
            ),
        },
    }

    lines = [
        "=== chat-template truncation diagnostic (platform_specific) ===",
        "",
        f"Sample files ({len(sample_rows)}):",
    ]
    for row in sample_rows:
        wf = row["with_fence_stop"]
        wof = row["without_fence_stop"]
        lines.extend(
            [
                f"- {row['virtual_path']}",
                f"    cache findings: raw={row['raw_cache_findings']} correct={row['correct_cache_findings']}",
                f"    with ``` stop: class={wf['output_class']} tokens={wf['completion_tokens']} "
                f"parsed={wf['parsed_findings']} inferred_stop={row['inferred_stop_with_fence']}",
                f"    without ``` stop: class={wof['output_class']} tokens={wof['completion_tokens']} "
                f"parsed={wof['parsed_findings']} recovered={row['findings_recovered_without_fence']}",
                f"    raw completion: class={row['raw_completion']['output_class']} "
                f"tokens={row['raw_completion']['completion_tokens']} "
                f"parsed={row['raw_completion']['parsed_findings']}",
                f"    raw text (with ``` stop, pre-parse):",
                "    ---",
                *(f"    {line}" for line in wf["raw_text"].splitlines()[:20]),
                "    ---",
            ]
        )
    lines.extend(
        [
            "",
            f"Labeled eval files: {len(labeled_stop_rows)} (108 expected rules)",
            f"Stop histogram (labeled files): {stop_histogram}",
            f"``` stop inferred: {fence_hits}/{len(labeled_stop_rows)} labeled files",
            f"Output class histogram (labeled): {output_class_hist}",
            "",
            "Completion tokens:",
            (
                f"  correct template (with ```): mean={report['completion_token_stats']['correct_template_with_fence']['mean']} "
                f"max={report['completion_token_stats']['correct_template_with_fence']['max']}"
            ),
            (
                f"  raw completion: mean={report['completion_token_stats']['raw_completion']['mean']} "
                f"max={report['completion_token_stats']['raw_completion']['max']}"
            ),
            "",
            (
                f"Sample without ```: findings recovered on "
                f"{sample_recovered}/{len(sample_rows)} files"
            ),
        ]
    )

    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    OUTPUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"Wrote {OUTPUT_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
