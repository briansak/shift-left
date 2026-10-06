"""Harness loop-control helpers — not model prompts and not answer hints."""

from __future__ import annotations

import math
import re
import shlex
from dataclasses import dataclass, field

# Total terminal attempts (charged + duplicate suppressions) before the harness stops.
DEFAULT_MAX_TERMINAL_ATTEMPTS = 20

# Consecutive suppressed duplicates before the harness enters forced submission.
CONSECUTIVE_DUPLICATE_HARD_STOP_THRESHOLD = 3

# Model generations allowed after forced submission begins (submit-only phase).
MAX_FORCED_SUBMISSION_GENERATIONS = 3

# Consecutive unparseable generations before the harness terminates.
CONSECUTIVE_UNPARSEABLE_HARD_STOP_THRESHOLD = 3

# Degenerate repetition: token subsequence length and consecutive repeat count.
DEGENERATE_MIN_TOKEN_SEQUENCE_LENGTH = 8
DEGENERATE_MIN_CONSECUTIVE_REPEATS = 11  # more than 10 consecutive repeats

# Consecutive degenerate-repetition rejections before the harness terminates.
CONSECUTIVE_DEGENERATE_HARD_STOP_THRESHOLD = 3

# Default per-investigation wall-clock limit (seconds).
DEFAULT_INVESTIGATION_WALL_CLOCK_SECONDS = 300

BUDGET_ESCALATION_NOTICE = (
    "note: the terminal budget is nearly exhausted; you must call submit_vulnerable_files "
    "or submit_no_vulnerability_found before charged commands are exhausted. "
    "Files you have already inspected are candidates for your final submission."
)

DUPLICATE_LOOP_FORCED_SUBMISSION_NOTICE = (
    "note: the terminal budget is closed; call submit_vulnerable_files or "
    "submit_no_vulnerability_found now. No further terminal commands will be executed."
)

# Do not name files or suggest queries — the model already has hits in context.
UNREAD_SEARCH_HIT_NOTICE = (
    "note: search results include files that have not yet been inspected or ranked."
)

FORCED_SUBMISSION_TERMINAL_REJECTED_NOTICE = (
    "error: the terminal is closed; only submit_vulnerable_files or "
    "submit_no_vulnerability_found are available."
)

MALFORMED_COMMAND_REJECTED_NOTICE = (
    "error: the terminal command was malformed and rejected due to degenerate "
    "repetition; this turn was not charged against the terminal budget."
)

_RG_LINE = re.compile(r"^(?:\./)?([^:]+):\d+:")
_SEARCH_COMMANDS = frozenset({"rg", "grep"})


@dataclass
class LoopControlState:
    enabled: bool = True
    terminal_budget: int = 0
    adapter_identity: dict[str, str] = field(default_factory=dict)
    generation_params: dict[str, object] = field(default_factory=dict)
    total_terminal_attempts: int = 0
    consecutive_duplicate_suppressions: int = 0
    duplicate_loop_hard_stop_fired: bool = False
    forced_submission_mode: bool = False
    forced_submission_generations: int = 0
    consecutive_unparseable_generations: int = 0
    degenerate_repetition_rejections: int = 0
    consecutive_degenerate_rejections: int = 0
    budget_escalation_fired: bool = False
    attempt_cap_reached: bool = False
    inspected_files: set[str] = field(default_factory=set)
    search_hit_files: set[str] = field(default_factory=set)


def budget_escalation_threshold(max_terminal_calls: int) -> int:
    return math.ceil(max_terminal_calls * 0.8)


def append_harness_notice(output: str, notice: str) -> str:
    text = output.strip()
    if not text:
        return notice
    return f"{text}\n\n{notice}"


def unread_search_hit_files(loop_control: LoopControlState) -> set[str]:
    """Search hits that have not been inspected (and therefore not ranked from inspection)."""
    return set(loop_control.search_hit_files) - set(loop_control.inspected_files)


def with_unread_search_hit_pressure(output: str, loop_control: LoopControlState) -> str:
    if unread_search_hit_files(loop_control):
        return append_harness_notice(output, UNREAD_SEARCH_HIT_NOTICE)
    return output


def inspected_paths_from_command(command: str, snapshot_paths: set[str]) -> list[str]:
    try:
        parts = shlex.split(command)
    except ValueError:
        return []
    if not parts or parts[0] != "cat":
        return []
    paths: list[str] = []
    for raw in parts[1:]:
        path = raw.strip().lstrip("./")
        if path in snapshot_paths:
            paths.append(path)
    return paths


def search_hit_paths_from_output(output: str, snapshot_paths: set[str]) -> list[str]:
    hits: set[str] = set()
    for line in output.splitlines():
        match = _RG_LINE.match(line.strip())
        if match:
            path = match.group(1).lstrip("./")
            if path in snapshot_paths:
                hits.add(path)
            continue
        candidate = line.strip().lstrip("./")
        if candidate in snapshot_paths:
            hits.add(candidate)
    return sorted(hits)


def search_targets_from_command(command: str, snapshot_paths: set[str]) -> list[str]:
    try:
        parts = shlex.split(command)
    except ValueError:
        return []
    if not parts or parts[0] not in _SEARCH_COMMANDS:
        return []
    targets: list[str] = []
    for raw in parts[1:]:
        if raw.startswith("-") or raw in {"|", "||", "&&", ";"}:
            continue
        path = raw.strip().lstrip("./")
        if path in snapshot_paths:
            targets.append(path)
    return targets


def record_search_hits_from_command(
    *,
    command: str,
    exit_code: int,
    output: str,
    snapshot_paths: set[str],
    search_hit_files: set[str],
) -> None:
    if exit_code != 0 or not output.strip():
        return
    try:
        parts = shlex.split(command)
    except ValueError:
        return
    if not parts or parts[0] not in _SEARCH_COMMANDS:
        return
    hits = set(search_hit_paths_from_output(output, snapshot_paths))
    if hits:
        search_hit_files.update(hits)
        return
    # rg emits line-only output when the search scope is a single file path.
    search_hit_files.update(search_targets_from_command(command, snapshot_paths))


def _has_consecutive_unit_repeat(text: str, min_unit: int, min_repeats: int) -> bool:
    length = len(text)
    if length < min_unit * min_repeats:
        return False
    max_unit = length // min_repeats
    for unit_len in range(min_unit, max_unit + 1):
        limit = length - unit_len * min_repeats + 1
        for start in range(limit):
            unit = text[start : start + unit_len]
            repeats = 1
            pos = start + unit_len
            while pos + unit_len <= length and text[pos : pos + unit_len] == unit:
                repeats += 1
                pos += unit_len
            if repeats >= min_repeats:
                return True
    return False


def _tokenize_for_degeneracy(text: str) -> list[str]:
    return re.findall(r"\S+", text)


def _has_consecutive_token_sequence_repeat(
    tokens: list[str],
    min_seq_len: int,
    min_repeats: int,
) -> bool:
    count = len(tokens)
    if count < min_seq_len * min_repeats:
        return False
    max_seq = count // min_repeats
    for seq_len in range(min_seq_len, max_seq + 1):
        limit = count - seq_len * min_repeats + 1
        for start in range(limit):
            pattern = tokens[start : start + seq_len]
            repeats = 1
            pos = start + seq_len
            while pos + seq_len <= count and tokens[pos : pos + seq_len] == pattern:
                repeats += 1
                pos += seq_len
            if repeats >= min_repeats:
                return True
    return False


def detect_degenerate_repetition(
    text: str,
    *,
    min_token_seq_len: int = DEGENERATE_MIN_TOKEN_SEQUENCE_LENGTH,
    min_repeats: int = DEGENERATE_MIN_CONSECUTIVE_REPEATS,
    min_char_unit: int = DEGENERATE_MIN_TOKEN_SEQUENCE_LENGTH,
) -> bool:
    """Return True when output contains a runaway repeated substring or token run."""
    if not text:
        return False
    if _has_consecutive_unit_repeat(text, min_char_unit, min_repeats):
        return True
    tokens = _tokenize_for_degeneracy(text)
    return _has_consecutive_token_sequence_repeat(tokens, min_token_seq_len, min_repeats)


def classify_duplicate_loop_failure(
    loop_control: LoopControlState,
    *,
    failed_outcome: str,
    failed_unsubmitted_outcome: str,
) -> tuple[str, str, str]:
    if loop_control.inspected_files:
        return (
            failed_unsubmitted_outcome,
            "duplicate_loop_after_inspection",
            "Investigation terminated after repeated identical commands following file inspection",
        )
    if loop_control.search_hit_files:
        return (
            failed_outcome,
            "duplicate_loop_search_unread",
            "Investigation terminated after repeated identical commands with unread search hits",
        )
    return (
        failed_outcome,
        "duplicate_loop_no_progress",
        "Investigation terminated after repeated identical commands without progress",
    )
