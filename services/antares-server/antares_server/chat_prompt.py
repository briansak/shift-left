"""Render Antares agent transcripts with the shipped Granite chat template."""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from antares_server.agent_tools import (
    AgentAction,
    SubmitNoVulnerabilityFound,
    SubmitVulnerableFiles,
    TerminalToolCall,
)

ANTARES_CHAT_TEMPLATE_FILENAME = "antares-chat-template.jinja"

# Role used for chat_template.jinja sandbox output (rendered as user + <tool_response>).
TOOL_RESPONSE_ROLE = "tool"

_THINKING_BLOCK = re.compile(
    r"<think>.*?</think>",
    re.DOTALL | re.IGNORECASE,
)

ANTARES_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "terminal",
            "description": (
                "Execute a read-only terminal command in the repository. Allowed: ls, tree, find, "
                "cat, head, tail, sed, grep, rg, wc, sort, uniq, cut, file, stat, du, pwd, nl, "
                "basename, dirname, realpath, diff, echo, true, false. Pipes and read-only &&, ||, "
                "and ; chains are OK. No interpreters, writes, redirects, or network commands."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to run",
                    },
                    "max_chars": {
                        "type": "integer",
                        "description": "Max output chars (default 2000)",
                        "default": 2000,
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_vulnerable_files",
            "description": (
                "Submit your answer: a ranked list of file paths you believe contain the "
                "vulnerability. Most likely vulnerable file first. Paths relative to repository root."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ranked_files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Ordered list of file paths, most vulnerable first",
                    }
                },
                "required": ["ranked_files"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_no_vulnerability_found",
            "description": (
                "Declare that no vulnerability matching the CWE description was found in this codebase."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]

_SYSTEM_PROMPT = """You are {model_name}, a security agent that localizes vulnerabilities in source code.
You receive a CWE identifier and description, then explore a read-only repository snapshot using terminal tools.

Rules:
- Issue up to {max_calls} read-only terminal commands (ls, find, cat, head, tail, grep, rg, tree, wc, pwd).
- After exploration, submit exactly one final answer:
  - submit_vulnerable_files with ranked_files (repo-relative paths), OR
  - submit_no_vulnerability_found

Task CWE: {task_cwe}
CWE description: {task_cwe_description}

Repository root: {repo_root}
Changed paths in this review (prefer these when ranking): {changed_paths}
"""


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def default_model_path() -> Path:
    env_path = os.environ.get("ANTARES_MODEL_PATH")
    if env_path:
        return Path(env_path)
    return repo_root() / "models" / "1b"


def chat_template_path(model_dir: Path | None = None) -> Path:
    """Bundled config template first, then staged model directory fallback."""
    bundled = repo_root() / "config" / ANTARES_CHAT_TEMPLATE_FILENAME
    if bundled.is_file():
        return bundled
    staged = (model_dir or default_model_path()) / "chat_template.jinja"
    if staged.is_file():
        return staged
    raise FileNotFoundError(
        f"Antares chat template missing: expected {bundled} or {staged}. "
        "Copy models/1b/chat_template.jinja to config/antares-chat-template.jinja."
    )


def load_chat_template_source(model_dir: Path | None = None) -> str:
    return chat_template_path(model_dir).read_text(encoding="utf-8")


def strip_thinking_blocks(text: str) -> str:
    return _THINKING_BLOCK.sub("", text).strip()


def build_system_message(
    *,
    model_name: str = "Antares",
    max_calls: int,
    task_cwe: str,
    task_cwe_description: str,
    repo_root: str,
    changed_paths: str,
) -> dict[str, str]:
    return {
        "role": "system",
        "content": _SYSTEM_PROMPT.format(
            model_name=model_name,
            max_calls=max_calls,
            task_cwe=task_cwe,
            task_cwe_description=task_cwe_description,
            repo_root=repo_root,
            changed_paths=changed_paths,
        ),
    }


def build_user_message(task_cwe: str) -> dict[str, str]:
    return {
        "role": "user",
        "content": (
            f"Search this repository for vulnerabilities matching: {task_cwe}. "
            "Read source files, identify vulnerable code patterns, and submit "
            "ranked vulnerable file paths only."
        ),
    }


def build_initial_messages(
    *,
    model_name: str = "Antares",
    max_calls: int,
    task_cwe: str,
    task_cwe_description: str,
    repo_root: str,
    changed_paths: str,
) -> list[dict[str, Any]]:
    return [
        build_system_message(
            model_name=model_name,
            max_calls=max_calls,
            task_cwe=task_cwe,
            task_cwe_description=task_cwe_description,
            repo_root=repo_root,
            changed_paths=changed_paths,
        ),
        build_user_message(task_cwe),
    ]


def build_assistant_tool_message(action: AgentAction) -> dict[str, Any]:
    if isinstance(action, TerminalToolCall):
        name = "terminal"
        arguments = {"command": action.command, "max_chars": action.max_chars}
    elif isinstance(action, SubmitVulnerableFiles):
        name = "submit_vulnerable_files"
        arguments = {"ranked_files": action.ranked_files}
    elif isinstance(action, SubmitNoVulnerabilityFound):
        name = "submit_no_vulnerability_found"
        arguments = {}
    else:
        raise TypeError(f"Unsupported action type: {type(action)!r}")

    return {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(arguments),
                },
            }
        ],
    }


def build_assistant_parse_failure_message(raw: str) -> dict[str, str]:
    """Keep non-tool assistant text without re-sending prior reasoning blocks."""
    return {"role": "assistant", "content": strip_thinking_blocks(raw)}


def build_tool_message(*, exit_code: int, output: str) -> dict[str, str]:
    return {
        "role": TOOL_RESPONSE_ROLE,
        "content": f"exit={exit_code}\n{output}",
    }


def format_tool_response_trace(*, exit_code: int, output: str) -> str:
    return f"<tool_response>\nexit={exit_code}\n{output}\n</tool_response>"


def duplicate_command_notice(*, prior_turn: int) -> str:
    return (
        f"note: this command was already run at turn {prior_turn} with the same output; "
        "this turn was not charged against the terminal budget."
    )


def malformed_command_notice() -> str:
    from antares_server.loop_control import MALFORMED_COMMAND_REJECTED_NOTICE

    return MALFORMED_COMMAND_REJECTED_NOTICE


def build_duplicate_tool_message(
    *,
    prior_turn: int,
    exit_code: int,
    output: str,
    extra_notice: str = "",
) -> dict[str, str]:
    notice = duplicate_command_notice(prior_turn=prior_turn)
    body = f"{notice}\nexit={exit_code}\n{output}"
    if extra_notice:
        body = f"{body}\n\n{extra_notice}"
    return {
        "role": TOOL_RESPONSE_ROLE,
        "content": body,
    }


def build_malformed_tool_message() -> dict[str, str]:
    return {
        "role": TOOL_RESPONSE_ROLE,
        "content": malformed_command_notice(),
    }


def format_malformed_tool_response_trace(
    *,
    trace_marker: str = "[malformed-command rejected]",
) -> str:
    return f"{trace_marker}\n<tool_response>\nexit=1\n{malformed_command_notice()}\n</tool_response>"


def format_duplicate_tool_response_trace(
    *,
    prior_turn: int,
    exit_code: int,
    output: str,
    extra_notice: str = "",
    trace_marker: str = "[duplicate-command suppressed]",
) -> str:
    notice = duplicate_command_notice(prior_turn=prior_turn)
    body = f"{notice}\nexit={exit_code}\n{output}"
    if extra_notice:
        body = f"{body}\n\n{extra_notice}"
    return f"{trace_marker}\n<tool_response>\n{body}\n</tool_response>"


def build_harness_notice_tool_message(*, exit_code: int, output: str) -> dict[str, str]:
    return {
        "role": TOOL_RESPONSE_ROLE,
        "content": f"exit={exit_code}\n{output}",
    }


def format_harness_notice_tool_response_trace(
    *,
    marker: str,
    exit_code: int,
    output: str,
) -> str:
    return f"{marker}\n<tool_response>\nexit={exit_code}\n{output}\n</tool_response>"


class ChatPromptRenderer:
    """Apply config/antares-chat-template.jinja via the staged tokenizer."""

    def __init__(self, tokenizer: Any, *, model_path: Path, chat_template: str) -> None:
        self._tokenizer = tokenizer
        self._model_path = model_path
        self._chat_template = chat_template

    @classmethod
    def from_model_path(cls, model_path: Path | None = None) -> ChatPromptRenderer:
        from transformers import AutoTokenizer

        path = (model_path or default_model_path()).resolve()
        tokenizer = AutoTokenizer.from_pretrained(str(path), local_files_only=True)
        template = load_chat_template_source(path)
        return cls(tokenizer, model_path=path, chat_template=template)

    @classmethod
    @lru_cache(maxsize=1)
    def from_env(cls) -> ChatPromptRenderer:
        return cls.from_model_path()

    def render(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
    ) -> str:
        return self._tokenizer.apply_chat_template(
            messages,
            chat_template=self._chat_template,
            tools=tools if tools is not None else ANTARES_TOOLS,
            add_generation_prompt=True,
            tokenize=False,
        )

    def assistant_history_includes_thinking(self, messages: list[dict[str, Any]]) -> bool:
        """Return True when a prior assistant turn would re-send redacted_thinking content."""
        for message in messages:
            if message.get("role") != "assistant":
                continue
            content = str(message.get("content") or "")
            if "<think>" in content.lower():
                return True
        return False
