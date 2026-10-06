#!/usr/bin/env python3
"""Compare shift-left agent_loop prompt vs shipped chat template tokenization."""

from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANTARES_SERVER = ROOT / "services" / "antares-server"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ANTARES_SERVER):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from transformers import AutoTokenizer

from antares_server.agent_loop import default_cwe_description
from antares_server.chat_prompt import _SYSTEM_PROMPT, build_initial_messages

MODEL_PATH = ROOT / "models" / "1b"
OUT = ROOT / "validation" / "reports" / "antares-prompt-equivalence.json"

# Official Antares CLI tool schema (from bundled antares-cli.zip model_adapter.py)
ANTARES_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "terminal",
            "description": "Execute a read-only terminal command in the repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "max_chars": {"type": "integer", "default": 2000},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_vulnerable_files",
            "description": "Submit ranked vulnerable file paths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ranked_files": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["ranked_files"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_no_vulnerability_found",
            "description": "Declare no matching vulnerability.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]

_ASSISTANT_PREFILL = "<|start_of_role|>assistant<|end_of_role|><think>\n"


def shift_left_turn1_prompt() -> str:
    from antares_server.chat_prompt import ChatPromptRenderer

    messages = build_initial_messages(
        max_calls=15,
        task_cwe="CWE-89",
        task_cwe_description=default_cwe_description("CWE-89"),
        repo_root="/workspace/repo",
        changed_paths="app/db.py",
    )
    return ChatPromptRenderer.from_model_path(MODEL_PATH).render(messages)


def hf_chat_template_prompt(messages: list[dict], tools: list | None = None) -> str:
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_PATH), local_files_only=True)
    kwargs: dict = {
        "tokenize": False,
        "add_generation_prompt": True,
    }
    if tools is not None:
        kwargs["tools"] = tools
    return tokenizer.apply_chat_template(messages, **kwargs)


def granite_cli_prompt(messages: list[dict[str, str]]) -> str:
    """Mirror antares_cli.inference.granite.apply_granite_chat_template."""
    parts: list[str] = []
    for message in messages:
        role = message["role"]
        content = message["content"]
        if role == "assistant":
            prefixed = (
                content
                if content.startswith("<think>")
                else f"<think>\n{content}"
            )
            parts.append(
                f"<|start_of_role|>assistant<|end_of_role|>{prefixed}<|end_of_text|>"
            )
        elif role == "tool_response":
            parts.append(
                "<|start_of_role|>user<|end_of_role|>\n<tool_response>\n"
                f"{content}\n</tool_response><|end_of_text|>"
            )
        else:
            parts.append(f"<|start_of_role|>{role}<|end_of_role|>{content}<|end_of_text|>")
    parts.append(_ASSISTANT_PREFILL)
    return "\n".join(parts)


def token_ids(text: str) -> list[int]:
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_PATH), local_files_only=True)
    return tokenizer.encode(text, add_special_tokens=False)


def unified_diff(a: str, b: str, a_name: str, b_name: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            a.splitlines(),
            b.splitlines(),
            fromfile=a_name,
            tofile=b_name,
            lineterm="",
        )
    )


def compare(label: str, runtime: str, templated: str) -> dict:
    ids_runtime = token_ids(runtime)
    ids_template = token_ids(templated)
    first_mismatch = None
    for index, (a, b) in enumerate(zip(ids_runtime, ids_template, strict=False)):
        if a != b:
            first_mismatch = index
            break
    if first_mismatch is None and len(ids_runtime) != len(ids_template):
        first_mismatch = min(len(ids_runtime), len(ids_template))
    return {
        "label": label,
        "runtime_chars": len(runtime),
        "template_chars": len(templated),
        "runtime_tokens": len(ids_runtime),
        "template_tokens": len(ids_template),
        "token_ids_identical": ids_runtime == ids_template,
        "first_token_mismatch_index": first_mismatch,
        "runtime_text": runtime,
        "template_text": templated,
        "unified_diff": unified_diff(runtime, templated, "runtime_raw", "chat_template"),
    }


def main() -> int:
    runtime = shift_left_turn1_prompt()
    system_only = [
        {"role": "system", "content": runtime},
    ]
    system_user = [
        {
            "role": "system",
            "content": _SYSTEM_PROMPT.format(
                max_calls=15,
                task_cwe="CWE-89",
                task_cwe_description=default_cwe_description("CWE-89"),
                repo_root="/workspace/repo",
                changed_paths="app/db.py",
            ),
        },
        {
            "role": "user",
            "content": (
                "Search this repository for vulnerabilities matching: CWE-89. "
                "Read source files, identify vulnerable code patterns, and submit "
                "ranked vulnerable file paths only."
            ),
        },
    ]

    comparisons = [
        compare(
            "turn1_runtime_vs_hf_system_only_no_tools",
            runtime,
            hf_chat_template_prompt(system_only, tools=None),
        ),
        compare(
            "turn1_runtime_vs_hf_system_only_with_tools",
            runtime,
            hf_chat_template_prompt(system_only, tools=ANTARES_TOOLS),
        ),
        compare(
            "turn1_runtime_vs_hf_system_user_with_tools",
            runtime,
            hf_chat_template_prompt(system_user, tools=ANTARES_TOOLS),
        ),
        compare(
            "turn1_runtime_vs_official_granite_cli_system_user",
            runtime,
            granite_cli_prompt(system_user),
        ),
    ]

    report = {
        "verdict": "not_equivalent",
        "note": (
            "shift-left agent_loop turn-1 sends only the formatted _SYSTEM_PROMPT with no user "
            "turn, no Granite role markers, no assistant prefill, and no <tools> block."
        ),
        "comparisons": comparisons,
    }
    report["any_token_identical"] = any(item["token_ids_identical"] for item in comparisons)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k != "comparisons"}, indent=2))
    for item in comparisons:
        print("\n" + "=" * 80)
        print(item["label"])
        print(
            f"tokens runtime={item['runtime_tokens']} template={item['template_tokens']} "
            f"identical={item['token_ids_identical']} first_mismatch={item['first_token_mismatch_index']}"
        )
        print(item["unified_diff"][:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
