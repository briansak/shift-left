#!/usr/bin/env python3
"""Phase 1 smoke test — Foundation-Sec-8B-Reasoning inference path (3 files, no corpus eval)."""

from __future__ import annotations

import json
import os
import platform
import resource
import sys
import time
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
    ReasoningModelClient,
    answer_is_parseable,
    materialize_reasoning_chat_template,
    render_reasoning_prompt,
    split_reasoning_answer,
)
from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M  # noqa: E402

REPORT_PATH = ROOT / "validation" / "reports" / "reasoning-phase1-smoke.json"
SMOKE_FILES = (
    ROOT / "validation/corpus/config/cisco_ftd/branch-policy-insecure.tf",
    ROOT / "validation/corpus/config/cisco_ftd/dcloud-baseline.tf",
    ROOT / "validation/corpus/config/cisco_ftd/broad-source-any.tf",
)


def _rss_mib() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_maxrss / (1024 * 1024)


def _swap_mib() -> float | None:
    try:
        import psutil  # type: ignore

        return psutil.swap_memory().used / (1024 * 1024)
    except Exception:
        return None


def _load_llm(model_dir: Path) -> Any:
    from llama_cpp import Llama

    gguf = model_dir / VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["gguf_filename"]
    if not gguf.is_file():
        raise FileNotFoundError(f"Reasoning GGUF missing: {gguf}")
    n_gpu_layers = -1 if platform.system() == "Darwin" else 0
    return Llama(
        model_path=str(gguf),
        n_ctx=REASONING_N_CTX_DEFAULT,
        n_gpu_layers=n_gpu_layers,
        verbose=False,
    )


def _full_raw_output(prompt: str, completion_text: str) -> str:
    if completion_text.startswith(REASONING_SPLIT_START):
        return completion_text
    if prompt.rstrip().endswith(REASONING_SPLIT_START):
        return f"{REASONING_SPLIT_START}\n{completion_text}"
    return completion_text


def run_smoke() -> dict[str, Any]:
    model_dir = ROOT / VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M["local_path_default"]
    template_path = materialize_reasoning_chat_template(model_dir)

    baseline_rss = _rss_mib()
    baseline_swap = _swap_mib()
    load_started = time.monotonic()
    llm = _load_llm(model_dir)
    load_ms = int((time.monotonic() - load_started) * 1000)
    after_load_rss = _rss_mib()
    after_load_swap = _swap_mib()

    client = ReasoningModelClient(llm, model_dir=model_dir)
    peak_rss = after_load_rss
    peak_swap = after_load_swap or 0.0

    file_results: list[dict[str, Any]] = []
    for path in SMOKE_FILES:
        content = path.read_text(encoding="utf-8")
        user_prompt = build_cookbook_prompt(file_path=str(path.relative_to(ROOT)), content=content)
        prompt = render_reasoning_prompt(user_prompt)
        infer_started = time.monotonic()
        completion = client.complete(user_prompt)
        infer_ms = int((time.monotonic() - infer_started) * 1000)
        peak_rss = max(peak_rss, _rss_mib())
        swap_now = _swap_mib()
        if swap_now is not None:
            peak_swap = max(peak_swap, swap_now)

        full_raw = _full_raw_output(prompt, completion.raw_text)
        parseable, parse_reason = answer_is_parseable(completion.answer, mode="prose")
        file_results.append(
            {
                "file": str(path.relative_to(ROOT)),
                "inference_ms": infer_ms,
                "reasoning_token_count": completion.reasoning_token_count,
                "answer_token_count": completion.answer_token_count,
                "completion_token_count": completion.completion_token_count,
                "delimiter_observed": completion.delimiter_observed,
                "answer_parseable": parseable,
                "answer_parse_reason": parse_reason,
                "full_raw_output_verbatim": full_raw,
                "reasoning_excerpt": completion.reasoning[:500],
                "answer_excerpt": completion.answer[:500],
            }
        )
        print("=" * 72)
        print(f"FILE: {path.name}")
        print("FULL RAW OUTPUT (verbatim, including reasoning block):")
        print(full_raw)
        print("-" * 72)
        print(f"reasoning_token_count: {completion.reasoning_token_count}")
        print(f"answer_token_count:    {completion.answer_token_count}")
        print(f"delimiter_observed:      {completion.delimiter_observed}")
        print(f"answer_parseable:        {parseable} ({parse_reason})")

    del llm
    after_unload_rss = _rss_mib()

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "phase": "1",
        "model_variant": MODEL_VARIANT_REASONING,
        "quant": "Q4_K_M",
        "n_ctx": REASONING_N_CTX_DEFAULT,
        "max_tokens": REASONING_MAX_TOKENS_DEFAULT,
        "temperature": 0.3,
        "do_sample": True,
        "reasoning_split_delimiter": f"{REASONING_SPLIT_START}...{REASONING_SPLIT_END}",
        "chat_template_path": str(template_path),
        "memory": {
            "baseline_rss_mib": round(baseline_rss, 1),
            "after_load_rss_mib": round(after_load_rss, 1),
            "peak_rss_mib": round(peak_rss, 1),
            "after_unload_rss_mib": round(after_unload_rss, 1),
            "baseline_swap_mib": round(baseline_swap or 0.0, 1) if baseline_swap else None,
            "peak_swap_mib": round(peak_swap, 1) if peak_swap else None,
            "model_load_ms": load_ms,
            "host_note": "Q4_K_M weights ~4.9 GB; KV cache at n_ctx=16384 is material on 24 GB hosts.",
        },
        "files": file_results,
        "all_answers_parseable": all(item["answer_parseable"] for item in file_results),
    }


def main() -> int:
    os.environ.setdefault("HF_HUB_OFFLINE", "0")
    report = run_smoke()
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("=" * 72)
    print(f"Wrote {REPORT_PATH}")
    print(
        f"peak_rss_mib={report['memory']['peak_rss_mib']} "
        f"peak_swap_mib={report['memory'].get('peak_swap_mib')}"
    )
    print(f"all_answers_parseable={report['all_answers_parseable']}")
    return 0 if report["all_answers_parseable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
