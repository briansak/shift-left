#!/usr/bin/env python3
"""Measure platform_specific raw-completion output volume and tokens (Q4 vs Q8)."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[1]
FSEC = ROOT / "services" / "foundation-sec-server"
ORCH = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
VALIDATION = ROOT / "validation"
for path in (SHARED, ORCH, FSEC, VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from eval_model import Q4_MODEL_DIR, Q8_MODEL_DIR, collect_file_list  # noqa: E402
from shift_left_shared.weights import (  # noqa: E402
    VERIFIED_FOUNDATION_SEC_Q4_K_M,
    VERIFIED_FOUNDATION_SEC_Q8_0,
)
from foundation_sec_server.engine import LlamaCppEvalEngine, _parse_json_findings  # noqa: E402
from foundation_sec_server.handlers.registry import DEFAULT_REGISTRY  # noqa: E402
from foundation_sec_server.preprocess import strip_inactive_lines  # noqa: E402
from foundation_sec_server.prompts import build_platform_specific_prompt  # noqa: E402

OUTPUT_JSON = ROOT / "validation" / "reports" / "platform-specific-output-volume.json"
OUTPUT_TXT = ROOT / "validation" / "reports" / "platform-specific-output-volume.txt"

MAX_OUTPUT_TOKENS = 1024
TEMPERATURE = 0.1
STOP = ["```"]


def _platform_prompt(virtual_path: str, target_type: str, content: str) -> str:
    handler = DEFAULT_REGISTRY.resolve(virtual_path)
    active_content, _ = strip_inactive_lines(content, handler)
    line_count = max(1, content.count("\n") + 1)
    return build_platform_specific_prompt(
        handler=handler,
        target_type=target_type,
        file_path=virtual_path,
        line_start=1,
        line_end=line_count,
        content=active_content,
    )


def _measure_quant(model_dir: Path, quant_label: str, *, verified: dict) -> dict:
    engine = LlamaCppEvalEngine(
        model_dir,
        gguf_glob=verified["gguf_glob"],
        quant_label=quant_label,
        load_strategy="eager",
        n_ctx=4096,
        manifest_key=verified["manifest_key"],
    )
    engine.load()
    llm = engine._llm  # noqa: SLF001
    assert llm is not None

    rows: list[dict] = []
    for corpus_name, corpus_dir, entry in collect_file_list():
        content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
        prompt = _platform_prompt(entry.virtual_path, entry.target_type, content)
        output = llm(
            prompt,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=TEMPERATURE,
            stop=STOP,
        )
        choice = output["choices"][0]
        text = str(choice.get("text") or "")
        usage = output.get("usage") or {}
        tokens = int(usage.get("completion_tokens") or 0)
        parsed = len(
            _parse_json_findings(text, entry.virtual_path, prepend_array_bracket=True)
        )
        starts_colon_slash = text.lstrip().startswith("://")
        rows.append(
            {
                "corpus": corpus_name,
                "rel_path": entry.rel_path,
                "virtual_path": entry.virtual_path,
                "completion_tokens": tokens,
                "parsed_findings": parsed,
                "starts_with_colon_slash": starts_colon_slash,
                "finish_reason": str(choice.get("finish_reason") or ""),
                "raw_prefix": text[:120],
            }
        )
        print(
            f"[{quant_label} {len(rows)}/148] {entry.rel_path} "
            f"tokens={tokens} parsed={parsed}",
            flush=True,
        )

    engine.unload()
    tokens = [row["completion_tokens"] for row in rows]
    parsed_total = sum(row["parsed_findings"] for row in rows)
    zero_parsed = sum(1 for row in rows if row["parsed_findings"] == 0)
    one_token = sum(1 for row in rows if row["completion_tokens"] == 1)
    colon_slash = sum(1 for row in rows if row["starts_with_colon_slash"])
    return {
        "quant": quant_label,
        "model_dir": str(model_dir),
        "temperature": TEMPERATURE,
        "max_output_tokens": MAX_OUTPUT_TOKENS,
        "stop": STOP,
        "inference_path": "raw_completion",
        "prompt_variant": "platform_specific",
        "files": len(rows),
        "parsed_findings_total": parsed_total,
        "files_zero_parsed_findings": zero_parsed,
        "files_one_completion_token": one_token,
        "files_starting_with_colon_slash": colon_slash,
        "colon_slash_rate": round(colon_slash / len(rows), 4) if rows else 0.0,
        "completion_tokens_mean": round(mean(tokens), 1) if tokens else 0.0,
        "completion_tokens_max": max(tokens) if tokens else 0,
        "per_file": rows,
    }


def main() -> int:
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "task": "platform_specific_output_volume",
        "q4_k_m": _measure_quant(Q4_MODEL_DIR, "Q4_K_M", verified=VERIFIED_FOUNDATION_SEC_Q4_K_M),
        "q8_0": _measure_quant(Q8_MODEL_DIR, "Q8_0", verified=VERIFIED_FOUNDATION_SEC_Q8_0),
    }
    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = [
        "=== platform_specific output volume (raw completion, temperature=0.1) ===",
        "",
    ]
    for key in ("q4_k_m", "q8_0"):
        block = report[key]
        lines.extend(
            [
                f"{block['quant']}:",
                f"  parsed findings total: {block['parsed_findings_total']}",
                f"  files zero parsed findings: {block['files_zero_parsed_findings']}/148",
                f"  files with 1 completion token: {block['files_one_completion_token']}/148",
                f"  completions starting with ://: {block['files_starting_with_colon_slash']}/148",
                f"  completion tokens mean/max: {block['completion_tokens_mean']}/{block['completion_tokens_max']}",
                "",
            ]
        )
    OUTPUT_TXT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"Wrote {OUTPUT_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
