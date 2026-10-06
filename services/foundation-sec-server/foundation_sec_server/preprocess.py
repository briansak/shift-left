"""Format-aware preprocessing before model evaluation."""

from __future__ import annotations

import re

from foundation_sec_server.handlers.registry import ConfigFormatHandler

_HASH_COMMENT = re.compile(r"^\s*#")
_SLASH_COMMENT = re.compile(r"^\s*//")


def strip_inactive_lines(content: str, handler: ConfigFormatHandler) -> tuple[str, int]:
    """
    Remove comment-only lines that are not active configuration.

    Returns (active_content, stripped_line_count).
    """
    if handler.name not in {"terraform", "nginx", "device", "ansible", "kubernetes"}:
        return content, 0

    kept: list[str] = []
    stripped = 0
    for line in content.splitlines():
        if handler.name == "kubernetes" and line.strip() == "---":
            kept.append(line)
            continue
        if _HASH_COMMENT.match(line) or _SLASH_COMMENT.match(line):
            stripped += 1
            continue
        kept.append(line)
    return "\n".join(kept), stripped
