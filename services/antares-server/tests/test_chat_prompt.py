"""Chat-template prompt rendering for the Antares agent loop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from antares_server.agent_tools import TerminalToolCall
from antares_server.agent_loop import default_cwe_description
from antares_server.chat_prompt import (
    ANTARES_TOOLS,
    TOOL_RESPONSE_ROLE,
    ChatPromptRenderer,
    build_assistant_tool_message,
    build_initial_messages,
    build_tool_message,
    strip_thinking_blocks,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
MODEL_PATH = REPO_ROOT / "models" / "1b"


@pytest.fixture(scope="module")
def renderer() -> ChatPromptRenderer:
    if not (MODEL_PATH / "tokenizer.json").exists():
        pytest.skip("Antares tokenizer not staged under models/1b")
    return ChatPromptRenderer.from_model_path(MODEL_PATH)


def test_tool_response_role_is_tool() -> None:
    assert TOOL_RESPONSE_ROLE == "tool"


def test_turn1_prompt_uses_template_markers(renderer: ChatPromptRenderer) -> None:
    messages = build_initial_messages(
        max_calls=15,
        task_cwe="CWE-89",
        task_cwe_description=default_cwe_description("CWE-89"),
        repo_root="/workspace/repo",
        changed_paths="app/db.py",
    )
    prompt = renderer.render(messages)
    assert "<|start_of_role|>system<|end_of_role|>" in prompt
    assert "<tools>" in prompt
    assert '"name": "terminal"' in prompt
    assert "<|start_of_role|>user<|end_of_role|>" in prompt
    assert prompt.endswith("<|start_of_role|>assistant<|end_of_role|><think>\n")


def test_turn2_prompt_accumulates_tool_response(renderer: ChatPromptRenderer) -> None:
    messages = build_initial_messages(
        max_calls=15,
        task_cwe="CWE-89",
        task_cwe_description=default_cwe_description("CWE-89"),
        repo_root="/workspace/repo",
        changed_paths="app/db.py",
    )
    messages.append(
        build_assistant_tool_message(
            TerminalToolCall(command="ls", max_chars=2000),
        )
    )
    messages.append(build_tool_message(exit_code=0, output="app\n"))
    prompt = renderer.render(messages)
    assert "<tool_call>" in prompt
    assert "exit=0" in prompt
    assert "app" in prompt
    assert "<tool_response>" in prompt and "</tool_response>" in prompt
    assert prompt.count("<think>") == 1


def test_assistant_history_omits_prior_thinking(renderer: ChatPromptRenderer) -> None:
    messages = build_initial_messages(
        max_calls=15,
        task_cwe="CWE-89",
        task_cwe_description=default_cwe_description("CWE-89"),
        repo_root="/workspace/repo",
        changed_paths="app/db.py",
    )
    messages.append(
        build_assistant_tool_message(
            TerminalToolCall(command="ls", max_chars=2000),
        )
    )
    assert not renderer.assistant_history_includes_thinking(messages)


def test_strip_thinking_blocks() -> None:
    raw = "<think>\nsecret\n</think>\nleftover"
    assert strip_thinking_blocks(raw) == "leftover"


def test_chat_template_loads_from_config_first() -> None:
    from antares_server.chat_prompt import chat_template_path, repo_root

    path = chat_template_path(MODEL_PATH)
    assert path == repo_root() / "config" / "antares-chat-template.jinja"


def test_tool_schema_matches_expected_names() -> None:
    names = {tool["function"]["name"] for tool in ANTARES_TOOLS}
    assert names == {
        "terminal",
        "submit_vulnerable_files",
        "submit_no_vulnerability_found",
    }
    assert json.loads(json.dumps(ANTARES_TOOLS))
