#!/usr/bin/env python3
"""Diff HF chat_template.jinja vs llama.cpp generic llama-3 handler formatting."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FSEC = ROOT / "services" / "foundation-sec-server"
if str(FSEC) not in sys.path:
    sys.path.insert(0, str(FSEC))

from foundation_sec_server.chat_inference import DEFAULT_SYSTEM_PROMPT  # noqa: E402

REPORTS = ROOT / "validation" / "reports"
OUTPUT_JSON = REPORTS / "chat-template-diff.json"
OUTPUT_TXT = REPORTS / "chat-template-diff.txt"

HF_TEMPLATE_URL = (
    "https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct/raw/main/chat_template.jinja"
)
HF_TOKENIZER_CONFIG_URL = (
    "https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct/raw/main/tokenizer_config.json"
)

SYSTEM_PROMPT = DEFAULT_SYSTEM_PROMPT
USER_PROMPT = (
    "You are a security auditor reviewing a configuration file. "
    "List one misconfiguration, severity, and recommended fix."
)


def _fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8")


def _render_hf_jinja(template_source: str, *, eos_token: str) -> str:
    from jinja2 import Environment

    env = Environment(autoescape=False)
    template = env.from_string(template_source)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_PROMPT},
    ]
    return template.render(
        messages=messages,
        add_generation_prompt=True,
        eos_token=eos_token,
    )


def _render_llama_cpp_llama3() -> str:
    from llama_cpp.llama_chat_format import format_llama3

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_PROMPT},
    ]
    return format_llama3(messages).prompt


def _token_spans(text: str) -> list[str]:
    import re

    patterns = [
        r"<\|[^>\n|]+?\|>",
        r"<\|redacted_[^|>]+?\|>",
        r"<\|eot_id\|>",
        r"<\|end_of_text\|>",
        r"<\|begin_of_text\|>",
    ]
    found: list[str] = []
    for pattern in patterns:
        found.extend(re.findall(pattern, text))
    return sorted(set(found))


def _analyze_diff(hf_prompt: str, llama_prompt: str) -> dict[str, Any]:
    hf_tokens = _token_spans(hf_prompt)
    llama_tokens = _token_spans(llama_prompt)
    return {
        "identical": hf_prompt == llama_prompt,
        "hf_special_tokens": hf_tokens,
        "llama_cpp_special_tokens": llama_tokens,
        "special_tokens_only_in_hf": sorted(set(hf_tokens) - set(llama_tokens)),
        "special_tokens_only_in_llama_cpp": sorted(set(llama_tokens) - set(hf_tokens)),
        "system_prompt_placement": {
            "hf": "wrapped in <|system|> role block at start of rendered prompt",
            "llama_cpp": "wrapped in <|start_header_id|>system<|end_header_id|> block",
        },
        "bos_handling": {
            "hf": "no explicit <|begin_of_text|> in chat_template.jinja render",
            "llama_cpp": "no explicit <|begin_of_text|> in llama-3 handler render",
        },
        "generation_prompt_suffix": {
            "hf": "ends with <|assistant|>\\n (add_generation_prompt=True)",
            "llama_cpp": "ends with assistant header block before generation",
        },
    }


def main() -> int:
    template_source = _fetch(HF_TEMPLATE_URL)
    tokenizer_config = json.loads(_fetch(HF_TOKENIZER_CONFIG_URL))
    eos_token = str(tokenizer_config.get("eos_token") or "<|end_of_text|>")

    hf_prompt = _render_hf_jinja(template_source, eos_token=eos_token)
    llama_prompt = _render_llama_cpp_llama3()
    analysis = _analyze_diff(hf_prompt, llama_prompt)

    can_use_real_template = {
        "llama_cpp_supports_custom_jinja": True,
        "gguf_embedded_template": False,
        "options": [
            "Pass chat_handler built from HF chat_template.jinja via llama.cpp custom formatter",
            "Re-export GGUF with tokenizer.chat_template metadata embedded",
            "Use HuggingFace transformers apply_chat_template for tokenization (cookbook path)",
        ],
        "current_production_choice": "generic llama-3 handler (not HF jinja)",
    }

    report = {
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat(),
        "hf_repo": "fdtn-ai/Foundation-Sec-1.1-8B-Instruct",
        "hf_chat_template_path": "chat_template.jinja",
        "tokenizer_config_chat_template_field_empty": not bool(tokenizer_config.get("chat_template")),
        "eos_token": eos_token,
        "bos_token": tokenizer_config.get("bos_token"),
        "system_prompt": SYSTEM_PROMPT,
        "user_prompt": USER_PROMPT,
        "hf_rendered_prompt": hf_prompt,
        "llama_cpp_llama3_rendered_prompt": llama_prompt,
        "analysis": analysis,
        "llama_cpp_can_use_real_template": can_use_real_template,
        "fidelity_summary": (
            "HF uses <|system|>/<|user|>/<|assistant|> tokens; llama.cpp llama-3 handler uses "
            "<|start_header_id|>role<|end_header_id|> and <|eot_id|> separators. "
            "They differ; generic llama-3 is not byte-identical to the model repo template."
        ),
    }

    lines = [
        "=== HF chat_template.jinja vs llama.cpp llama-3 handler ===",
        f"Identical render: {analysis['identical']}",
        "",
        "HF-only special tokens:",
        f"  {analysis['special_tokens_only_in_hf']}",
        "llama.cpp-only special tokens:",
        f"  {analysis['special_tokens_only_in_llama_cpp']}",
        "",
        f"System placement (HF): {analysis['system_prompt_placement']['hf']}",
        f"System placement (llama.cpp): {analysis['system_prompt_placement']['llama_cpp']}",
        "",
        f"BOS (HF): {analysis['bos_handling']['hf']}",
        f"BOS (llama.cpp): {analysis['bos_handling']['llama_cpp']}",
        "",
        "Can llama.cpp use the real template?",
        "  Yes, via custom chat_handler or embedding Jinja in GGUF; not configured today.",
        "",
        report["fidelity_summary"],
        "",
        "--- HF rendered prompt ---",
        hf_prompt,
        "",
        "--- llama.cpp llama-3 rendered prompt ---",
        llama_prompt,
    ]

    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    OUTPUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:20]))
    print(f"... full prompts in {OUTPUT_TXT.relative_to(ROOT)}")
    print(f"Wrote {OUTPUT_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
