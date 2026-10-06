#!/usr/bin/env python3
"""Diff Foundation-Sec instruct vs reasoning chat templates."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FSEC = ROOT / "services" / "foundation-sec-server"
REPORTS = ROOT / "validation" / "reports"
if str(FSEC) not in sys.path:
    sys.path.insert(0, str(FSEC))

from foundation_sec_server.chat_inference import load_chat_template_source  # noqa: E402
from foundation_sec_server.reasoning_inference import (  # noqa: E402
    REASONING_SPLIT_START,
    fetch_reasoning_chat_template_source,
    materialize_reasoning_chat_template,
)

INSTRUCT_HF_URL = (
    "https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct/raw/main/chat_template.jinja"
)
REASONING_TOKENIZER_URL = (
    "https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF/"
    "raw/main/tokenizer_config.json"
)
OUTPUT_JSON = REPORTS / "reasoning-chat-template-diff.json"
OUTPUT_TXT = REPORTS / "reasoning-chat-template-diff.txt"


def _fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8")


def _load_instruct_template() -> tuple[str, str]:
    path = ROOT / "models" / "foundation-sec-chat-template.jinja"
    if path.is_file():
        return path.read_text(encoding="utf-8"), str(path)
    try:
        return _fetch(INSTRUCT_HF_URL), INSTRUCT_HF_URL
    except Exception:
        return load_chat_template_source(), str(path)


def main() -> int:
    reasoning_path = materialize_reasoning_chat_template()
    reasoning_template = reasoning_path.read_text(encoding="utf-8")
    instruct_template, instruct_source = _load_instruct_template()

    gen_reasoning = reasoning_template[reasoning_template.find("add_generation_prompt") :][:120]
    gen_instruct = instruct_template[instruct_template.find("add_generation_prompt") :][:120] if instruct_template else ""

    report = {
        "instruct_source": instruct_source,
        "reasoning_source": str(reasoning_path),
        "instruct_len": len(instruct_template),
        "reasoning_len": len(reasoning_template),
        "instruct_has_redacted_thinking": REASONING_SPLIT_START in instruct_template,
        "reasoning_has_redacted_thinking": REASONING_SPLIT_START in reasoning_template,
        "reasoning_generation_prompt_snippet": gen_reasoning,
        "instruct_generation_prompt_snippet": gen_instruct,
        "template_injects_thinking_prefix": REASONING_SPLIT_START in gen_reasoning,
        "cookbook_manual_prefix_note": (
            "Cookbook ReasoningModelClient may force <think> when not using "
            "the HF chat template; the reasoning tokenizer template injects "
            "<|assistant|>\\n<think>\\n at add_generation_prompt."
        ),
        "templates_identical": instruct_template == reasoning_template,
    }

    lines = [
        "Foundation-Sec instruct vs reasoning chat template diff",
        f"instruct source: {instruct_source} ({report['instruct_len']} chars)",
        f"reasoning source: {reasoning_path} ({report['reasoning_len']} chars)",
        f"reasoning injects {REASONING_SPLIT_START} at generation: {report['template_injects_thinking_prefix']}",
        f"instruct has thinking delimiter: {report['instruct_has_redacted_thinking']}",
        "",
        report["cookbook_manual_prefix_note"],
        "",
    ]
    if instruct_template == reasoning_template:
        lines.append("Templates are byte-identical.")
    else:
        lines.append("Templates differ (see JSON for snippets).")

    REPORTS.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    OUTPUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
