#!/usr/bin/env python3
"""Parse Antares exploration_trace into per-turn command/response/reasoning records."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def parse_exploration_trace(trace: str) -> list[dict[str, object]]:
    turns: list[dict[str, object]] = []
    chunks = re.split(r"\n\n(?=Assistant:)", trace.strip())
    for chunk in chunks:
        if not chunk.startswith("Assistant:"):
            continue
        body = chunk[len("Assistant:") :].strip()
        thinking_match = re.search(
            r"^(.*?)(</think>\s*)?<tool_call>",
            body,
            re.DOTALL,
        )
        reasoning = ""
        remainder = body
        if thinking_match:
            reasoning = thinking_match.group(1).strip()
            remainder = body[thinking_match.end() :]
        tool_call_match = re.search(
            r"<tool_call>\s*(\{.*?\})\s*</tool_call>",
            remainder,
            re.DOTALL,
        )
        command = None
        tool_name = None
        if tool_call_match:
            payload = json.loads(tool_call_match.group(1))
            tool_name = payload.get("name")
            if tool_name == "terminal":
                command = payload.get("arguments", {}).get("command")
        response_match = re.search(
            r"(?:\[duplicate-command suppressed\]\s*)?<tool_response>\s*(.*?)\s*</tool_response>",
            remainder,
            re.DOTALL,
        )
        response_text = response_match.group(1).strip() if response_match else None
        duplicate_suppressed = "[duplicate-command suppressed]" in remainder
        exit_code = None
        output = None
        if response_text:
            lines = response_text.splitlines()
            if lines and lines[0].startswith("exit="):
                exit_code = int(lines[0].split("=", 1)[1])
                output = "\n".join(lines[1:]).strip()
            else:
                output = response_text
        turns.append(
            {
                "reasoning": reasoning,
                "tool_name": tool_name,
                "command": command,
                "duplicate_suppressed": duplicate_suppressed,
                "exit_code": exit_code,
                "output": output,
            }
        )
    return turns


def main() -> int:
    path = Path(sys.argv[1])
    data = json.loads(path.read_text())
    turns = parse_exploration_trace(data.get("exploration_trace", ""))
    print(json.dumps(turns, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
