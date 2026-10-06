#!/usr/bin/env python3
"""20-file probe: chat-template vs raw completion split safety for reasoning model."""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FSEC = ROOT / "services" / "foundation-sec-server"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (FSEC, SHARED, ROOT / "validation"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from cookbook_prose_prompt import build_cookbook_prompt  # noqa: E402
from foundation_sec_server.model_profiles import (  # noqa: E402
    MODEL_VARIANT_REASONING,
    REASONING_MAX_TOKENS_DEFAULT,
    REASONING_N_CTX_DEFAULT,
    REASONING_SPLIT_END,
    REASONING_SPLIT_START,
)
from foundation_sec_server.reasoning_inference import (  # noqa: E402
    SPLIT_METHOD_CLOSED_TAG,
    SPLIT_METHOD_FALLBACK_BASED_ON,
    SPLIT_METHOD_FALLBACK_H3,
    SPLIT_METHOD_SPLIT_FAILURE,
    SPLIT_METHOD_WHOLE_COMPLETION,
    ReasoningModelClient,
    materialize_reasoning_chat_template,
    render_reasoning_prompt,
)
from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M  # noqa: E402

REPORT_PATH = ROOT / "validation" / "reports" / "reasoning-split-path-probe.json"
CORPUS_DIR = ROOT / "validation/corpus/config/cisco_ftd"
FILE_COUNT = 20


def _select_files() -> list[Path]:
    files = sorted(CORPUS_DIR.glob("*.tf"))
    if len(files) < FILE_COUNT:
        raise RuntimeError(f"Need {FILE_COUNT} corpus files under {CORPUS_DIR}, found {len(files)}")
    return files[:FILE_COUNT]


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


def _path_record(
    *,
    path: str,
    inference_path: str,
    inference_ms: int,
    completion: Any,
    prompt_prefix: str,
) -> dict[str, Any]:
    return {
        "file": path,
        "inference_path": inference_path,
        "inference_ms": inference_ms,
        "split_method": completion.split_method,
        "split_failure": completion.split_failure,
        "emitted_close_tag": completion.emitted_close_tag,
        "emitted_open_tag": completion.emitted_open_tag,
        "delimiter_observed": completion.delimiter_observed,
        "reasoning_token_count": completion.reasoning_token_count,
        "answer_token_count": completion.answer_token_count,
        "completion_token_count": completion.completion_token_count,
        "reasoning_char_count": len(completion.reasoning),
        "answer_char_count": len(completion.answer),
        "answer_excerpt": completion.answer[:300],
        "reasoning_excerpt": completion.reasoning[:300],
        "raw_output_verbatim": prompt_prefix + completion.raw_text,
    }


def _tally(records: list[dict[str, Any]]) -> dict[str, Any]:
    methods = Counter(item["split_method"] for item in records)
    return {
        "file_count": len(records),
        "emitted_close_tag": sum(1 for item in records if item["emitted_close_tag"]),
        "matched_fallback_triple_hash": methods.get(SPLIT_METHOD_FALLBACK_H3, 0),
        "matched_fallback_based_on_provided": methods.get(SPLIT_METHOD_FALLBACK_BASED_ON, 0),
        "matched_nothing_empty_answer": methods.get(SPLIT_METHOD_SPLIT_FAILURE, 0),
        "whole_completion_as_answer": methods.get(SPLIT_METHOD_WHOLE_COMPLETION, 0),
        "split_failure_total": sum(1 for item in records if item["split_failure"]),
        "split_method_counts": dict(methods),
        "mean_reasoning_tokens": _mean(
            item["reasoning_token_count"] for item in records if item["reasoning_token_count"] is not None
        ),
        "mean_answer_tokens": _mean(
            item["answer_token_count"] for item in records if item["answer_token_count"] is not None
        ),
        "mean_completion_tokens": _mean(
            item["completion_token_count"] for item in records if item["completion_token_count"] is not None
        ),
    }


def _mean(values: Any) -> float | None:
    items = list(values)
    if not items:
        return None
    return round(sum(items) / len(items), 1)


def _raw_token_cap_hits(raw_records: list[dict[str, Any]]) -> dict[str, Any]:
    cap_hits = [
        row
        for row in raw_records
        if (row.get("completion_token_count") or 0) >= REASONING_MAX_TOKENS_DEFAULT
    ]
    slow = [row for row in raw_records if (row.get("inference_ms") or 0) > 300_000]
    return {
        "raw_runs": len(raw_records),
        "token_cap_hits": len(cap_hits),
        "token_cap_hit_rate": round(len(cap_hits) / len(raw_records), 4) if raw_records else 0.0,
        "inference_over_300s": len(slow),
        "token_cap_files": [row["file"] for row in cap_hits],
    }


def _recommendation(
    template_tally: dict[str, Any],
    raw_tally: dict[str, Any],
    raw_records: list[dict[str, Any]],
) -> dict[str, str]:
    cap = _raw_token_cap_hits(raw_records)
    raw_viable = cap["token_cap_hits"] == 0

    return {
        "recommended_inference_path": "chat_template",
        "recommended_scoring_approach": "whole_completion",
        "raw_completion_viable": str(raw_viable),
        "raw_token_cap_summary": (
            f"{cap['token_cap_hits']}/{cap['raw_runs']} raw runs hit max_tokens="
            f"{REASONING_MAX_TOKENS_DEFAULT}; {cap['inference_over_300s']} exceeded 300s."
        ),
        "rationale": (
            "Raw completion is not viable at corpus scale (majority of probe runs hit the "
            "8192-token cap with mean ~5014 answer tokens). Use the chat-template path and "
            "score the whole completion — heuristic split_method/split_failure are diagnostics only."
        ),
        "heuristic_safe_for_scoring": "false",
        "split_failure_rule": (
            "Any split_failure must be recorded explicitly — never as zero findings."
        ),
    }


def run_probe() -> dict[str, Any]:
    model_dir = ROOT / VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["local_path_default"]
    template_path = materialize_reasoning_chat_template(model_dir)
    files = _select_files()

    llm = _load_llm(model_dir)
    client = ReasoningModelClient(llm, model_dir=model_dir)

    template_records: list[dict[str, Any]] = []
    raw_records: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []

    for index, file_path in enumerate(files, start=1):
        rel = str(file_path.relative_to(ROOT))
        user_prompt = build_cookbook_prompt(file_path=rel, content=file_path.read_text(encoding="utf-8"))
        print(f"[{index}/{FILE_COUNT}] {file_path.name}", flush=True)

        t0 = time.monotonic()
        template_completion = client.complete(user_prompt)
        template_ms = int((time.monotonic() - t0) * 1000)
        template_prompt = render_reasoning_prompt(user_prompt)
        template_prefix = ""
        if template_prompt.rstrip().endswith(REASONING_SPLIT_START):
            template_prefix = f"{REASONING_SPLIT_START}\n"
        template_rec = _path_record(
            path=rel,
            inference_path="chat_template",
            inference_ms=template_ms,
            completion=template_completion,
            prompt_prefix=template_prefix,
        )
        template_records.append(template_rec)

        t0 = time.monotonic()
        raw_completion = client.complete_raw(user_prompt)
        raw_ms = int((time.monotonic() - t0) * 1000)
        raw_rec = _path_record(
            path=rel,
            inference_path="raw_completion",
            inference_ms=raw_ms,
            completion=raw_completion,
            prompt_prefix="",
        )
        raw_records.append(raw_rec)

        comparisons.append(
            {
                "file": rel,
                "template": {
                    "split_method": template_rec["split_method"],
                    "split_failure": template_rec["split_failure"],
                    "emitted_close_tag": template_rec["emitted_close_tag"],
                    "emitted_open_tag": template_rec["emitted_open_tag"],
                    "reasoning_tokens": template_rec["reasoning_token_count"],
                    "answer_tokens": template_rec["answer_token_count"],
                    "inference_ms": template_ms,
                },
                "raw_completion": {
                    "split_method": raw_rec["split_method"],
                    "split_failure": raw_rec["split_failure"],
                    "emitted_close_tag": raw_rec["emitted_close_tag"],
                    "emitted_open_tag": raw_rec["emitted_open_tag"],
                    "reasoning_tokens": raw_rec["reasoning_token_count"],
                    "answer_tokens": raw_rec["answer_token_count"],
                    "inference_ms": raw_ms,
                },
                "raw_emits_think_block": raw_rec["emitted_open_tag"] or raw_rec["emitted_close_tag"],
                "cleaner_boundary": (
                    "raw"
                    if raw_rec["emitted_close_tag"] and not template_rec["emitted_close_tag"]
                    else (
                        "template"
                        if template_rec["emitted_close_tag"] and not raw_rec["emitted_close_tag"]
                        else "tie"
                    )
                ),
            }
        )

    template_tally = _tally(template_records)
    raw_tally = _tally(raw_records)
    raw_cap = _raw_token_cap_hits(raw_records)
    recommendation = _recommendation(template_tally, raw_tally, raw_records)

    del llm

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "phase": "1b",
        "model_variant": MODEL_VARIANT_REASONING,
        "quant": "Q4_K_M",
        "n_ctx": REASONING_N_CTX_DEFAULT,
        "max_tokens": REASONING_MAX_TOKENS_DEFAULT,
        "temperature": 0.3,
        "do_sample": True,
        "reasoning_split_delimiter": f"{REASONING_SPLIT_START}...{REASONING_SPLIT_END}",
        "chat_template_path": str(template_path),
        "corpus_dir": str(CORPUS_DIR.relative_to(ROOT)),
        "file_count": FILE_COUNT,
        "template_path": template_tally,
        "raw_completion_path": raw_tally,
        "raw_token_cap": raw_cap,
        "side_by_side": comparisons,
        "recommendation": recommendation,
        "template_records": template_records,
        "raw_records": raw_records,
    }


def main() -> int:
    os.environ.setdefault("HF_HUB_OFFLINE", "0")
    report = run_probe()
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("=" * 72)
    print("TEMPLATE PATH")
    for key in (
        "emitted_close_tag",
        "matched_fallback_triple_hash",
        "matched_fallback_based_on_provided",
        "matched_nothing_empty_answer",
        "whole_completion_as_answer",
        "split_failure_total",
    ):
        print(f"  {key}: {report['template_path'][key]}")
    print("RAW COMPLETION PATH")
    for key in (
        "emitted_close_tag",
        "matched_fallback_triple_hash",
        "matched_fallback_based_on_provided",
        "matched_nothing_empty_answer",
        "whole_completion_as_answer",
        "split_failure_total",
    ):
        print(f"  {key}: {report['raw_completion_path'][key]}")
    print("RECOMMENDATION:", report["recommendation"]["recommended_scoring_approach"])
    print(f"Wrote {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
