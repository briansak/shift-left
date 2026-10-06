"""Parse Antares agent tool calls and submissions from model text."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

_TOOL_CALL_PATTERN = re.compile(
    r"<tool_call>\s*(\{.*?\})\s*</tool_call>",
    re.DOTALL,
)
_SUBMIT_FILES_PATTERN = re.compile(
    r"<tool_call>\s*(\{.*?\"name\"\s*:\s*\"submit_vulnerable_files\".*?\})\s*</tool_call>",
    re.DOTALL,
)
_SUBMIT_CLEAN_PATTERN = re.compile(
    r"<tool_call>\s*(\{.*?\"name\"\s*:\s*\"submit_no_vulnerability_found\".*?\})\s*</tool_call>",
    re.DOTALL,
)


@dataclass(frozen=True)
class TerminalToolCall:
    command: str
    max_chars: int = 2000


@dataclass(frozen=True)
class SubmitVulnerableFiles:
    ranked_files: list[str]


@dataclass(frozen=True)
class SubmitNoVulnerabilityFound:
    pass


AgentAction = TerminalToolCall | SubmitVulnerableFiles | SubmitNoVulnerabilityFound


def _parse_tool_json(raw: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


_RANKED_FILES_PREFIX = re.compile(r'"ranked_files"\s*:\s*\[')
_QUOTED_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def salvage_submit_vulnerable_files(text: str) -> SubmitVulnerableFiles | None:
    """Recover well-formed ranked_files prefixes from truncated submit JSON."""
    if "submit_vulnerable_files" not in text:
        return None
    match = _RANKED_FILES_PREFIX.search(text)
    if not match:
        return None
    files: list[str] = []
    seen: set[str] = set()
    for item in _QUOTED_STRING.finditer(text[match.end() :]):
        path = item.group(1).strip()
        if not path or path in seen:
            continue
        seen.add(path)
        files.append(path)
    if not files:
        return None
    return SubmitVulnerableFiles(ranked_files=files)


def parse_agent_action(text: str) -> AgentAction | None:
    """Extract the first actionable tool call or submission from model output."""
    action, _ = parse_agent_action_with_salvage(text)
    return action


def parse_agent_action_with_salvage(text: str) -> tuple[AgentAction | None, bool]:
    """Parse model output; salvage truncated submit_vulnerable_files when JSON is incomplete."""
    for pattern in (_SUBMIT_CLEAN_PATTERN, _SUBMIT_FILES_PATTERN, _TOOL_CALL_PATTERN):
        match = pattern.search(text)
        if not match:
            continue
        payload = _parse_tool_json(match.group(1))
        if not payload:
            continue
        name = str(payload.get("name", "")).strip()
        arguments = payload.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {}

        if name == "submit_no_vulnerability_found":
            return SubmitNoVulnerabilityFound(), False
        if name == "submit_vulnerable_files":
            ranked = arguments.get("ranked_files") or []
            if isinstance(ranked, list):
                files = [str(item) for item in ranked if str(item).strip()]
                return SubmitVulnerableFiles(ranked_files=files), False
            return None, False
        if name == "terminal":
            command = str(arguments.get("command", "")).strip()
            if not command:
                return None, False
            max_chars = int(arguments.get("max_chars") or 2000)
            return TerminalToolCall(command=command, max_chars=max_chars), False
    salvaged = salvage_submit_vulnerable_files(text)
    if salvaged is not None:
        return salvaged, True
    return None, False
