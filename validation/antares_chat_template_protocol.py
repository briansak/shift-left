#!/usr/bin/env python3
"""Protocol checks after chat-template wiring in the Antares agent loop."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANTARES_SERVER = ROOT / "services" / "antares-server"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ANTARES_SERVER):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import torch
from transformers import AutoModelForCausalLM

from antares_server.agent_loop import default_cwe_description
from antares_server.agent_tools import TerminalToolCall, parse_agent_action
from antares_server.chat_prompt import (
    ANTARES_TOOLS,
    TOOL_RESPONSE_ROLE,
    ChatPromptRenderer,
    build_assistant_tool_message,
    build_initial_messages,
    build_tool_message,
    default_model_path,
)

OUT = ROOT / "validation" / "reports" / "antares-chat-template-protocol.json"


def load_engine():
    model_path = default_model_path()
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    dtype = torch.bfloat16 if device == "mps" else torch.float32
    renderer = ChatPromptRenderer.from_model_path(model_path)
    tokenizer = renderer._tokenizer
    model = AutoModelForCausalLM.from_pretrained(
        str(model_path),
        local_files_only=True,
        torch_dtype=dtype,
        trust_remote_code=False,
    ).to(device)
    model.eval()
    return renderer, tokenizer, model, device


def generate(renderer: ChatPromptRenderer, tokenizer, model, device: str, messages: list) -> str:
    prompt = renderer.render(messages)
    inputs = tokenizer(prompt, return_tensors="pt").to(device)
    with torch.no_grad():
        output = model.generate(
            **inputs,
            max_new_tokens=512,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
        )
    return tokenizer.decode(output[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=False)


def base_messages() -> list:
    return build_initial_messages(
        max_calls=15,
        task_cwe="CWE-89",
        task_cwe_description=default_cwe_description("CWE-89"),
        repo_root="/workspace/repo",
        changed_paths="app/db.py",
    )


def main() -> int:
    renderer, tokenizer, model, device = load_engine()
    messages = base_messages()

    turn1_prompt = renderer.render(messages)
    messages.append(
        build_assistant_tool_message(TerminalToolCall(command="ls", max_chars=2000))
    )
    messages.append(build_tool_message(exit_code=0, output="app/\ndb.py\nREADME.md\n"))
    turn2_prompt = renderer.render(messages)

    single_raw = generate(renderer, tokenizer, model, device, base_messages())
    single_action = parse_agent_action(single_raw)

    three_turn = base_messages()
    turn_outputs: list[dict] = []
    for turn_index in range(3):
        raw = generate(renderer, tokenizer, model, device, three_turn)
        action = parse_agent_action(raw)
        turn_outputs.append(
            {
                "turn": turn_index + 1,
                "raw": raw,
                "parse_ok": action is not None,
                "action": None
                if action is None
                else {
                    "type": type(action).__name__,
                    "command": getattr(action, "command", None),
                },
            }
        )
        if not isinstance(action, TerminalToolCall):
            break
        three_turn.append(build_assistant_tool_message(action))
        synthetic_output = f"synthetic-output-turn-{turn_index + 1}"
        three_turn.append(build_tool_message(exit_code=0, output=synthetic_output))

    continued = (
        len(turn_outputs) >= 2
        and turn_outputs[0]["parse_ok"]
        and turn_outputs[1]["parse_ok"]
        and turn_outputs[0]["action"]["command"] != turn_outputs[1]["action"]["command"]
    )

    report = {
        "tool_response_role": TOOL_RESPONSE_ROLE,
        "tool_schema": ANTARES_TOOLS,
        "turn1_prompt": turn1_prompt,
        "turn2_prompt": turn2_prompt,
        "assistant_history_strips_thinking": not renderer.assistant_history_includes_thinking(
            messages
        ),
        "single_turn": {
            "raw_completion": single_raw,
            "parse_ok": single_action is not None,
            "action": None
            if single_action is None
            else {
                "type": type(single_action).__name__,
                "command": getattr(single_action, "command", None),
            },
        },
        "three_turn": {
            "turns": turn_outputs,
            "continued_exploring": continued,
        },
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2))

    print("TOOL_RESPONSE_ROLE:", TOOL_RESPONSE_ROLE)
    print("\n=== TURN 1 PROMPT ===\n")
    print(turn1_prompt)
    print("\n=== TURN 2 PROMPT ===\n")
    print(turn2_prompt)
    print("\n=== SINGLE-TURN RAW ===\n")
    print(single_raw)
    print("\nparse_agent_action:", single_action)
    print("\n=== THREE-TURN ===")
    print(json.dumps(report["three_turn"], indent=2))
    ok = report["single_turn"]["parse_ok"] and report["three_turn"]["continued_exploring"]
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
