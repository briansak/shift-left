"""Configurable test/fixture path exclusions for profiler evidence."""

from __future__ import annotations

from pathlib import Path

from shift_left.config import resolve_repo_root
from shift_left_shared.path_exclusions import (
    is_excluded_test_path,
    load_test_path_exclusions as _shared_load_test_path_exclusions,
    test_path_exclusions_path as _shared_test_path_exclusions_path,
)


def load_test_path_exclusions() -> dict:
    return _shared_load_test_path_exclusions(str(resolve_repo_root()))

__all__ = [
    "is_excluded_test_path",
    "load_test_path_exclusions",
    "test_path_exclusions_path",
]


def test_path_exclusions_path() -> Path:
    return _shared_test_path_exclusions_path(resolve_repo_root())
