"""VLoc Bench-style ground truth extraction from security fix commits."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

# VLoc Bench excludes tests, docs, changelogs, and version bumps from ground truth.
_EXCLUDE_DIR_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "t",
        "spec",
        "specs",
        "fixtures",
        "__tests__",
        "docs",
        "doc",
        "changes",
        "changelog",
        "changelog.d",
        ".github",
        "ci",
    }
)
_EXCLUDE_FILE_NAMES = frozenset(
    {
        "changes.rst",
        "history.md",
        "readme.md",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "tox.ini",
        ".bumpversion.cfg",
    }
)
_EXCLUDE_EXTENSIONS = frozenset(
    {
        ".rst",
        ".md",
        ".txt",
        ".yml",
        ".yaml",
        ".cfg",
        ".toml",
        ".in",
    }
)
_CODE_EXTENSIONS = frozenset(
    {
        ".py",
        ".pyx",
        ".pxd",
        ".c",
        ".h",
        ".cpp",
        ".cc",
        ".cxx",
        ".hpp",
        ".js",
        ".ts",
        ".go",
        ".rs",
        ".java",
        ".rb",
        ".sh",
    }
)
_EXCLUDE_PATTERNS = (
    re.compile(r"(^|/)(_version|__version__|version)\.py$", re.I),
    re.compile(r"(^|/)changes/.*", re.I),
    re.compile(r"(^|/)changelog(\.d)?/.*", re.I),
    re.compile(r"\.(md|rst|txt|ya?ml|cfg|toml|in)$", re.I),
    re.compile(r"(^|/)(changes|changelog|changelog\.d)(/|$)", re.I),
    re.compile(r"(^|/)docs(/|$)", re.I),
)


def _has_code_extension(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in _CODE_EXTENSIONS


def is_non_code_ground_truth_path(path: str) -> bool:
    rel = path.replace("\\", "/").lstrip("./")
    name = Path(rel).name
    upper = name.upper()
    if upper.startswith("CHANGES") or upper.startswith("CHANGELOG"):
        return True
    suffix = Path(rel).suffix.lower()
    if suffix in _EXCLUDE_EXTENSIONS:
        return True
    return not _has_code_extension(rel)


def is_excluded_ground_truth_path(path: str) -> bool:
    rel = path.replace("\\", "/").lstrip("./")
    parts = [part.lower() for part in rel.split("/")]
    if any(part in _EXCLUDE_DIR_SEGMENTS for part in parts):
        return True
    name = parts[-1] if parts else rel.lower()
    if name in _EXCLUDE_FILE_NAMES:
        return True
    for pattern in _EXCLUDE_PATTERNS:
        if pattern.search(rel):
            return True
    if name.startswith("test_") or name.endswith("_test.py") or name.endswith("_spec.py"):
        return True
    if is_non_code_ground_truth_path(rel):
        return True
    return False


def filter_ground_truth_files(paths: list[str]) -> list[str]:
    return sorted({path for path in paths if path and not is_excluded_ground_truth_path(path)})


def _changed_files(repo_dir: Path, parent_commit: str, fix_commit: str) -> list[str]:
    output = subprocess.check_output(
        ["git", "-C", str(repo_dir), "diff", "--name-only", parent_commit, fix_commit],
        text=True,
    )
    return [line.strip() for line in output.splitlines() if line.strip()]


def ground_truth_from_fix(repo_dir: Path, *, parent_commit: str, fix_commit: str) -> list[str]:
    return filter_ground_truth_files(_changed_files(repo_dir, parent_commit, fix_commit))


def resolve_effective_fix_commit(
    repo_dir: Path,
    osv_fix_commit: str,
    *,
    max_walk: int = 30,
) -> tuple[str, str, list[str]]:
    """Walk back from an OSV fix tag to the nearest substantive source fix commit."""
    commits = subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-list", "--max-count", str(max_walk), osv_fix_commit],
        text=True,
    ).splitlines()
    fallback: tuple[str, str, list[str]] | None = None
    for commit in commits:
        parent = subprocess.check_output(
            ["git", "-C", str(repo_dir), "rev-parse", f"{commit}^"],
            text=True,
        ).strip()
        ground_truth = ground_truth_from_fix(repo_dir, parent_commit=parent, fix_commit=commit)
        if not ground_truth:
            continue
        substantive = [path for path in ground_truth if not path.endswith("__init__.py")]
        if substantive:
            return commit, parent, substantive
        fallback = (commit, parent, ground_truth)
    if fallback is not None:
        return fallback
    raise RuntimeError(f"No substantive fix commit found near {osv_fix_commit}")
