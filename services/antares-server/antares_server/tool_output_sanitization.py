"""Quarantine untrusted tool output so it cannot be interpreted as agent protocol."""

from __future__ import annotations

import re

_PROTOCOL_MARKERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"</?\s*tool_call\s*>", re.IGNORECASE), "[quarantined:tool_call]"),
    (re.compile(r"</?\s*tool_response\s*>", re.IGNORECASE), "[quarantined:tool_response]"),
    (re.compile(r"submit_vulnerable_files", re.IGNORECASE), "[quarantined:submit_vulnerable_files]"),
    (
        re.compile(r"submit_no_vulnerability_found", re.IGNORECASE),
        "[quarantined:submit_no_vulnerability_found]",
    ),
)


def sanitize_tool_output(text: str) -> str:
    """Strip or escape protocol-like markers from command output before transcript append."""
    sanitized = text
    for pattern, replacement in _PROTOCOL_MARKERS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized
