"""Glob matching with ** support for config handler selection."""

from __future__ import annotations

import fnmatch
import re


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    escaped = fnmatch.translate(pattern)
    escaped = escaped.replace(r"\*\*", "§§")
    escaped = escaped.replace(r"\*", "[^/]*")
    escaped = escaped.replace("§§", ".*")
    return re.compile(f"^{escaped}$")


def path_matches_glob(path: str, pattern: str) -> bool:
    normalized = path[2:] if path.startswith("./") else path
    if _glob_to_regex(pattern).match(normalized):
        return True
    # ``**/segment/**`` must also match ``segment/...`` at repository root.
    if pattern.startswith("**/") and pattern.endswith("/**"):
        root_pattern = pattern[3:]
        if _glob_to_regex(root_pattern).match(normalized):
            return True
    if "/" not in pattern:
        basename = normalized.rsplit("/", 1)[-1]
        return fnmatch.fnmatch(basename, pattern)
    return False


def matches_any(path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    return any(path_matches_glob(path, pattern) for pattern in patterns)
