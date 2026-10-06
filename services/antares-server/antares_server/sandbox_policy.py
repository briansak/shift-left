"""Read-only command allowlist — defense in depth inside the investigation container."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

_ALLOWED_COMMANDS = frozenset(
    {
        "ls",
        "tree",
        "find",
        "cat",
        "head",
        "tail",
        "sed",
        "grep",
        "rg",
        "wc",
        "sort",
        "uniq",
        "cut",
        "file",
        "stat",
        "du",
        "pwd",
        "nl",
        "basename",
        "dirname",
        "realpath",
        "diff",
        "echo",
        "true",
        "false",
    }
)
# Longest operators first so "||" is not parsed as two "|" segments.
_SHELL_CHAIN_OPS = ("||", "&&", "|", ";")
_REDIRECT_CHARS = frozenset("<>")
_BLOCKED_TOKENS = re.compile(
    r"(^|[\s|;&])("
    r"rm|rmdir|mv|cp|chmod|chown|curl|wget|python|python3|perl|ruby|node|bash|sh|zsh|"
    r"exec|eval|source|sudo|ssh|scp|nc|netcat|dd|tee|touch|chmod|"
    r"\./|\../"
    r")([\s|;&]|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CommandValidation:
    ok: bool
    error: str = ""
    shell_command: str = ""
    argv_command: list[str] | None = None


def validate_command(command: str) -> CommandValidation:
    """Validate a terminal command against the read-only allowlist."""
    command = command.strip()
    if not command:
        return CommandValidation(ok=False, error="error: empty command")

    if _has_redirection_outside_quotes(command) or _has_lone_ampersand_outside_quotes(
        command
    ):
        return CommandValidation(
            ok=False,
            error="error: shell chaining/redirection blocked by sandbox policy",
        )

    segments = _split_shell_chain(command)
    if segments is None:
        return CommandValidation(
            ok=False,
            error="error: shell chaining/redirection blocked by sandbox policy",
        )

    if len(segments) > 1:
        chain_error = _validate_chain_segments(segments)
        if chain_error is not None:
            return chain_error
        if _BLOCKED_TOKENS.search(command):
            return CommandValidation(
                ok=False,
                error="error: command blocked by sandbox policy (read-only allowlist)",
            )
        return CommandValidation(ok=True, shell_command=command)

    if _BLOCKED_TOKENS.search(command):
        return CommandValidation(
            ok=False,
            error="error: command blocked by sandbox policy (read-only allowlist)",
        )

    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return CommandValidation(ok=False, error=f"error: invalid shell syntax: {exc}")

    if not parts or parts[0] not in _ALLOWED_COMMANDS:
        allowed = ", ".join(sorted(_ALLOWED_COMMANDS))
        return CommandValidation(
            ok=False,
            error=f"error: command not allowlisted ({allowed})",
        )

    return CommandValidation(ok=True, argv_command=parts)


def _split_shell_chain(command: str) -> list[str] | None:
    """Split on |, ||, &&, and ; that appear outside single/double quotes."""
    segments: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    while i < len(command):
        ch = command[i]
        if in_single:
            current.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            current.append(ch)
            if ch == "\\" and i + 1 < len(command):
                current.append(command[i + 1])
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            current.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            current.append(ch)
            i += 1
            continue

        matched = False
        for op in _SHELL_CHAIN_OPS:
            if command.startswith(op, i):
                segment = "".join(current).strip()
                if not segment:
                    return None
                segments.append(segment)
                current = []
                i += len(op)
                matched = True
                break
        if matched:
            continue

        current.append(ch)
        i += 1

    segment = "".join(current).strip()
    if not segment:
        return None if segments else [""]
    segments.append(segment)
    return segments


def _has_redirection_outside_quotes(command: str) -> bool:
    in_single = False
    in_double = False
    i = 0
    while i < len(command):
        ch = command[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < len(command):
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        if ch in _REDIRECT_CHARS:
            return True
        i += 1
    return False


def _has_lone_ampersand_outside_quotes(command: str) -> bool:
    """Reject background operators (&) that are not part of &&."""
    in_single = False
    in_double = False
    i = 0
    while i < len(command):
        ch = command[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < len(command):
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        if ch == "&":
            if i + 1 < len(command) and command[i + 1] == "&":
                i += 2
                continue
            return True
        i += 1
    return False


def _validate_chain_segments(segments: list[str]) -> CommandValidation | None:
    for segment in segments:
        try:
            parts = shlex.split(segment)
        except ValueError as exc:
            return CommandValidation(ok=False, error=f"error: invalid shell syntax: {exc}")
        if not parts or parts[0] not in _ALLOWED_COMMANDS:
            allowed = ", ".join(sorted(_ALLOWED_COMMANDS))
            return CommandValidation(
                ok=False,
                error=f"error: command not allowlisted ({allowed})",
            )
    return None


def allowed_commands() -> frozenset[str]:
    return _ALLOWED_COMMANDS
