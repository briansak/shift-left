"""Classify pull-request diffs against configured code vs config globs."""

from __future__ import annotations

from shift_left.config import RoutingConfig
from shift_left.routing.globmatch import matches_any


def classify_paths(paths: list[str], routing: RoutingConfig) -> str:
    """
    Return config_scope for a PR: config | non_config | mixed.

    Paths matching ignore_globs are excluded from classification.
    """
    config_hits = 0
    code_hits = 0
    other_hits = 0
    for path in paths:
        if matches_any(path, routing.ignore_globs):
            continue
        is_config = matches_any(path, routing.config_globs)
        is_code = matches_any(path, routing.code_globs)
        if is_config:
            config_hits += 1
        elif is_code:
            code_hits += 1
        elif path:
            other_hits += 1
    if config_hits == 0 and (code_hits > 0 or other_hits > 0):
        return "non_config"
    if config_hits > 0 and code_hits == 0 and other_hits == 0:
        return "config"
    if config_hits > 0:
        return "mixed"
    return "non_config"


def paths_from_unified_diff(diff_text: str) -> list[str]:
    paths: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            paths.append(line.removeprefix("+++ b/").strip())
        elif line.startswith("--- a/"):
            # Deleted-only files may only appear on --- line
            candidate = line.removeprefix("--- a/").strip()
            if candidate and candidate != "/dev/null" and candidate not in paths:
                paths.append(candidate)
    return paths
