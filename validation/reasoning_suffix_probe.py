#!/usr/bin/env python3
"""Phase 2: platform_specific prompt-suffix probe on reasoning model (template path only)."""

from __future__ import annotations

import json
import os
import platform
import re
import sys
import time
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

from eval_model import collect_file_list  # noqa: E402
from foundation_sec_server.engine import _parse_json_findings  # noqa: E402
from foundation_sec_server.handlers.registry import DEFAULT_REGISTRY  # noqa: E402
from foundation_sec_server.model_profiles import (  # noqa: E402
    MODEL_VARIANT_REASONING,
    REASONING_MAX_TOKENS_DEFAULT,
    REASONING_N_CTX_DEFAULT,
)
from foundation_sec_server.preprocess import strip_inactive_lines  # noqa: E402
from foundation_sec_server.prompts import build_platform_specific_prompt  # noqa: E402
from foundation_sec_server.reasoning_inference import (  # noqa: E402
    ReasoningModelClient,
    diagnostic_token_split,
    materialize_reasoning_chat_template,
    scoring_surface,
)
from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M  # noqa: E402

SAMPLE_MANIFEST = ROOT / "validation" / "reports" / "chat-truncation-diagnostic.json"
OUTPUT_JSON = ROOT / "validation" / "reports" / "reasoning-suffix-probe.json"
OUTPUT_TXT = ROOT / "validation" / "reports" / "reasoning-suffix-probe.txt"

MAX_OUTPUT_TOKENS = REASONING_MAX_TOKENS_DEFAULT
TEMPERATURE = 0.3

_SUFFIX_VARIANTS = {
    "colon": "JSON array:",
    "bracket": "Findings JSON array:\n[",
    "none": "",
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


def _completion_tokens(llm: Any, text: str) -> int:
    tokenize = getattr(llm, "tokenize", None)
    if not callable(tokenize):
        return 0
    return len(tokenize((text or "").encode("utf-8")))


def _first_tokens(llm: Any, text: str, count: int = 5) -> list[str]:
    detokenize = getattr(llm, "detokenize", None)
    tokenize = getattr(llm, "tokenize", None)
    if not callable(tokenize) or not callable(detokenize):
        return []
    ids = tokenize((text or "").encode("utf-8"))[:count]
    return [str(detokenize([token_id])) for token_id in ids]


def build_platform_prompt_with_suffix(
    *,
    virtual_path: str,
    target_type: str,
    content: str,
    suffix_key: str,
) -> str:
    handler = DEFAULT_REGISTRY.resolve(virtual_path)
    active_content, _ = strip_inactive_lines(content, handler)
    line_count = max(1, content.count("\n") + 1)
    base = build_platform_specific_prompt(
        handler=handler,
        target_type=target_type,
        file_path=virtual_path,
        line_start=1,
        line_end=line_count,
        content=active_content,
    )
    tail = _SUFFIX_VARIANTS[suffix_key]
    if suffix_key == "bracket":
        return base
    if suffix_key == "colon":
        marker = "\nFindings JSON array:\n["
        if marker in base:
            return base.rsplit(marker, 1)[0] + "\n" + tail
        return base.rstrip() + "\n" + tail
    if suffix_key == "none":
        marker = "\nFindings JSON array:\n["
        if marker in base:
            return base.rsplit(marker, 1)[0].rstrip() + "\n"
        return base.rstrip() + "\n"
    raise KeyError(suffix_key)


def _classify_degenerate(text: str, *, suffix_key: str) -> list[str]:
    stripped = (text or "").strip()
    lead = (text or "").lstrip()
    labels: list[str] = []
    if stripped == "]":
        labels.append("single_close_bracket")
    if stripped == "[]" or lead.startswith("[]"):
        labels.append("empty_array_literal")
    if lead.startswith("://") or re.match(r"^://json\b", stripped):
        labels.append("url_prefix")
    if lead.startswith("```diff") or lead.startswith("```\ndiff"):
        labels.append("continues_diff_fence")
    if "```json" in (text or "")[:120] or lead.startswith("```json"):
        labels.append("markdown_json_fence")
    if suffix_key == "bracket" and lead.startswith("{"):
        labels.append("object_continuation_after_open_bracket")
    if suffix_key == "none" and lead.startswith("```"):
        labels.append("continues_markdown_fence")
    return labels


def _cap_hit(completion_tokens: int, *, max_tokens: int) -> bool:
    return completion_tokens >= max_tokens


def _parse_findings(text: str, file_path: str, *, suffix_key: str) -> dict[str, Any]:
    attempts: list[tuple[str, str]] = [("raw", text or "")]
    if suffix_key == "bracket":
        stripped = (text or "").lstrip()
        if stripped and not stripped.startswith("["):
            attempts.append(("prepend_bracket", "[" + text))
    for label, payload in attempts:
        findings = _parse_json_findings(
            payload,
            file_path,
            prepend_array_bracket=(suffix_key == "bracket"),
        )
        if findings:
            return {
                "parse_path": label,
                "parseable": True,
                "findings_count": len(findings),
            }
    return {
        "parse_path": "raw",
        "parseable": False,
        "findings_count": 0,
    }


def _load_sample_entries() -> list[dict[str, Any]]:
    manifest = json.loads(SAMPLE_MANIFEST.read_text(encoding="utf-8"))
    details = {row["rel_path"]: row for row in manifest.get("sample_details") or []}
    rel_paths = list(manifest.get("sample_files") or [])
    if not rel_paths:
        raise RuntimeError(f"No sample_files in {SAMPLE_MANIFEST}")

    by_rel = {}
    for corpus_name, corpus_dir, entry in collect_file_list():
        by_rel[entry.rel_path] = (corpus_name, corpus_dir, entry)

    samples: list[dict[str, Any]] = []
    for virtual_path in rel_paths:
        detail = next(
            (row for row in manifest.get("sample_details") or [] if row.get("virtual_path") == virtual_path),
            None,
        )
        if detail is None:
            raise RuntimeError(f"No sample_details for virtual_path {virtual_path}")
        rel_path = detail["rel_path"]
        corpus_name, corpus_dir, entry = by_rel[rel_path]
        samples.append(
            {
                "virtual_path": entry.virtual_path,
                "rel_path": rel_path,
                "corpus": corpus_name,
                "target_type": entry.target_type,
                "corpus_dir": corpus_dir,
            }
        )
    return samples


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tokens = [row["completion_tokens"] for row in rows]
    answer_tokens = [row["answer_tokens"] for row in rows]
    reasoning_tokens = [row["reasoning_tokens"] for row in rows]
    degenerate_rows = [row for row in rows if row["degenerate_labels"]]
    cap_hit_rows = [row for row in rows if row["cap_hit"]]
    parseable_rows = [row for row in rows if row["parseable"]]
    return {
        "files": len(rows),
        "completion_tokens_mean": round(mean(tokens), 1) if tokens else 0.0,
        "completion_tokens_max": max(tokens) if tokens else 0,
        "reasoning_tokens_mean": round(mean(reasoning_tokens), 1) if reasoning_tokens else 0.0,
        "reasoning_tokens_max": max(reasoning_tokens) if reasoning_tokens else 0,
        "answer_tokens_mean": round(mean(answer_tokens), 1) if answer_tokens else 0.0,
        "answer_tokens_max": max(answer_tokens) if answer_tokens else 0,
        "cap_hit_count": len(cap_hit_rows),
        "cap_hit_rate": round(len(cap_hit_rows) / len(rows), 4) if rows else 0.0,
        "degenerate_count": len(degenerate_rows),
        "degenerate_rate": round(len(degenerate_rows) / len(rows), 4) if rows else 0.0,
        "parseable_findings_count": len(parseable_rows),
        "parseable_findings_rate": round(len(parseable_rows) / len(rows), 4) if rows else 0.0,
        "degenerate_breakdown": {
            label: sum(1 for row in rows if label in row["degenerate_labels"])
            for label in (
                "single_close_bracket",
                "empty_array_literal",
                "url_prefix",
                "continues_diff_fence",
                "continues_markdown_fence",
                "markdown_json_fence",
                "object_continuation_after_open_bracket",
            )
        },
        "per_file": rows,
    }


def run_probe() -> dict[str, Any]:
    model_dir = ROOT / VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["local_path_default"]
    template_path = materialize_reasoning_chat_template(model_dir)
    samples = _load_sample_entries()

    llm = _load_llm(model_dir)
    client = ReasoningModelClient(
        llm,
        model_dir=model_dir,
        max_tokens=MAX_OUTPUT_TOKENS,
    )

    by_suffix: dict[str, list[dict[str, Any]]] = {key: [] for key in _SUFFIX_VARIANTS}
    total = len(samples) * len(_SUFFIX_VARIANTS)
    step = 0

    try:
        for suffix_key in _SUFFIX_VARIANTS:
            for sample in samples:
                step += 1
                content = (sample["corpus_dir"] / sample["rel_path"]).read_text(encoding="utf-8")
                prompt = build_platform_prompt_with_suffix(
                    virtual_path=sample["virtual_path"],
                    target_type=sample["target_type"],
                    content=content,
                    suffix_key=suffix_key,
                )
                t0 = time.monotonic()
                completion = client.complete(prompt)
                inference_ms = int((time.monotonic() - t0) * 1000)
                scored = scoring_surface(completion)
                diag = diagnostic_token_split(scored, token_counter=llm)
                tokens = (
                    completion.completion_token_count
                    or diag["completion_token_count"]
                    or _completion_tokens(llm, scored)
                )
                reasoning_tokens = diag["reasoning_token_count"] or 0
                answer_tokens = diag["answer_token_count"] or 0
                hit_cap = _cap_hit(tokens, max_tokens=MAX_OUTPUT_TOKENS)
                degenerate = _classify_degenerate(scored, suffix_key=suffix_key)
                parsed = _parse_findings(scored, sample["virtual_path"], suffix_key=suffix_key)
                row = {
                    "rel_path": sample["rel_path"],
                    "virtual_path": sample["virtual_path"],
                    "corpus": sample["corpus"],
                    "target_type": sample["target_type"],
                    "suffix": suffix_key,
                    "prompt_tail_repr": repr(prompt[-24:]),
                    "inference_ms": inference_ms,
                    "split_method": completion.split_method,
                    "diagnostic_split_method": diag["diagnostic_split_method"],
                    "split_failure": completion.split_failure,
                    "raw_completion": scored,
                    "raw_completion_repr": repr(scored[:240]),
                    "completion_tokens": tokens,
                    "reasoning_tokens": reasoning_tokens,
                    "answer_tokens": answer_tokens,
                    "cap_hit": hit_cap,
                    "first_5_tokens": _first_tokens(llm, scored, 5),
                    "degenerate_labels": degenerate,
                    **parsed,
                }
                by_suffix[suffix_key].append(row)
                print(
                    f"[{step}/{total}] {suffix_key} {sample['rel_path']} "
                    f"tokens={tokens} cap_hit={hit_cap} degenerate={degenerate or '-'} "
                    f"parseable={parsed['parseable']}",
                    flush=True,
                )
    finally:
        del llm

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "phase": "2b",
        "task": "reasoning_suffix_probe",
        "model_variant": MODEL_VARIANT_REASONING,
        "quant": "Q4_K_M",
        "n_ctx": REASONING_N_CTX_DEFAULT,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "threshold": None,
        "scoring_surface": "whole_completion",
        "inference_path": "chat_template",
        "raw_completion_path": "dropped",
        "truncation_label": "cap_hit",
        "chat_template_path": str(template_path),
        "sample_manifest": str(SAMPLE_MANIFEST.relative_to(ROOT)),
        "sample_file_count": len(samples),
        "inference": {
            "temperature": TEMPERATURE,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "do_sample": True,
        },
        "suffix_variants": _SUFFIX_VARIANTS,
        "by_suffix": {key: _aggregate(rows) for key, rows in by_suffix.items()},
    }


def _write_summary(report: dict[str, Any]) -> str:
    lines = [
        "# Reasoning model prompt-suffix probe (Phase 2b @ max_tokens=8192)",
        "",
        f"Generated: {report['generated_at']}",
        "",
        f"- Model: {report['model_variant']} ({report['quant']})",
        f"- n_ctx: {report['n_ctx']}  max_tokens: {report['max_tokens']}",
        f"- Path: chat template only (raw completion dropped)",
        f"- Truncation: reported as cap_hit (not degenerate)",
        f"- Sample files: {report['sample_file_count']} (from chat-truncation-diagnostic)",
        "",
        "## Summary by suffix",
        "",
        "| Suffix | Mean completion | Max | Mean reasoning | Mean answer | cap_hit | Parseable |",
        "|--------|-----------------|-----|----------------|-------------|---------|-----------|",
    ]
    for suffix_key, label in (
        ("colon", "`JSON array:`"),
        ("bracket", "`Findings JSON array:\\n[`"),
        ("none", "no trailing punctuation"),
    ):
        agg = report["by_suffix"][suffix_key]
        lines.append(
            f"| {label} | {agg['completion_tokens_mean']} | {agg['completion_tokens_max']} | "
            f"{agg['reasoning_tokens_mean']} | {agg['answer_tokens_mean']} | "
            f"{agg['cap_hit_count']}/{agg['files']} | "
            f"{agg['parseable_findings_count']}/{agg['files']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    os.environ.setdefault("HF_HUB_OFFLINE", "0")
    report = run_probe()
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    OUTPUT_TXT.write_text(_write_summary(report), encoding="utf-8")
    print(f"Wrote {OUTPUT_JSON}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
