"""Configurable test/fixture path exclusions (profiler + investigation snapshots)."""

from __future__ import annotations

import fnmatch
import json
import os
from functools import lru_cache
from pathlib import Path

_EXCLUSIONS_REL = Path("data") / "profiler" / "test-path-exclusions.json"


def test_path_exclusions_path(repo_root: Path | None = None) -> Path:
    if repo_root is not None:
        return repo_root / _EXCLUSIONS_REL
    env_root = os.environ.get("SHIFT_LEFT_REPO_ROOT", "").strip()
    if env_root:
        return Path(env_root) / _EXCLUSIONS_REL
    return _EXCLUSIONS_REL


@lru_cache(maxsize=1)
def load_test_path_exclusions(repo_root: str | None = None) -> dict:
    path = test_path_exclusions_path(Path(repo_root) if repo_root else None)
    if not path.is_file():
        return {"enabled": False}
    return json.loads(path.read_text(encoding="utf-8"))


def is_excluded_test_path(rel_path: str, exclusions: dict | None = None) -> bool:
    """Return True when ``rel_path`` matches configured test/fixture exclusion rules."""
    rules = exclusions if exclusions is not None else load_test_path_exclusions()
    if not rules.get("enabled", True):
        return False
    normalized = rel_path.replace("\\", "/").lstrip("./")
    parts = Path(normalized).parts
    excluded_dirs = {str(segment) for segment in rules.get("directory_segments", [])}
    if excluded_dirs.intersection(parts):
        return True
    name = Path(normalized).name
    if name in {str(value) for value in rules.get("file_names", [])}:
        return True
    for pattern in rules.get("file_globs", []):
        if fnmatch.fnmatch(name, str(pattern)):
            return True
    return False
