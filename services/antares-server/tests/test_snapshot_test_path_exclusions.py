"""Test and fixture paths are omitted from investigation snapshots by default."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from antares_server.snapshot_materialize import materialize_tree_snapshot, remove_snapshot


@pytest.fixture
def repo_with_tests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    rules = {
        "enabled": True,
        "directory_segments": ["t", "tests"],
        "file_names": ["conftest.py"],
        "file_globs": ["test_*.py"],
    }
    rules_path = tmp_path / "data" / "profiler" / "test-path-exclusions.json"
    rules_path.parent.mkdir(parents=True)
    rules_path.write_text(json.dumps(rules), encoding="utf-8")
    monkeypatch.setenv("SHIFT_LEFT_REPO_ROOT", str(tmp_path))

    repo = tmp_path / "repo"
    (repo / "celery").mkdir(parents=True)
    (repo / "celery" / "app.py").write_text("app = 1\n", encoding="utf-8")
    (repo / "t" / "unit").mkdir(parents=True)
    (repo / "t" / "unit" / "test_app.py").write_text("def test_x(): pass\n", encoding="utf-8")
    return repo


def test_materialize_tree_snapshot_excludes_test_paths_by_default(repo_with_tests: Path) -> None:
    snapshot = materialize_tree_snapshot(repo_with_tests, max_bytes=1_000_000, exclude_test_paths=True)
    try:
        rel_paths = {path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*") if path.is_file()}
        assert "celery/app.py" in rel_paths
        assert not any(path.startswith("t/") for path in rel_paths)
    finally:
        remove_snapshot(snapshot)


def test_materialize_tree_snapshot_includes_test_paths_when_opted_in(repo_with_tests: Path) -> None:
    snapshot = materialize_tree_snapshot(repo_with_tests, max_bytes=1_000_000, exclude_test_paths=False)
    try:
        rel_paths = {path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*") if path.is_file()}
        assert "t/unit/test_app.py" in rel_paths
    finally:
        remove_snapshot(snapshot)


def test_materialize_tree_snapshot_excludes_git_unconditionally(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "celery").mkdir(parents=True)
    (repo / "celery" / "app.py").write_text("app = 1\n", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (repo / ".git" / "objects").mkdir()
    (repo / ".git" / "objects" / "ab" / "cdef").mkdir(parents=True)
    (repo / ".git" / "objects" / "ab" / "cdef" / "pack").write_text("pack", encoding="utf-8")

    for exclude_test_paths in (True, False):
        snapshot = materialize_tree_snapshot(
            repo,
            max_bytes=1_000_000,
            exclude_test_paths=exclude_test_paths,
        )
        try:
            rel_paths = {path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*") if path.is_file()}
            assert "celery/app.py" in rel_paths
            assert not any(path == ".git" or path.startswith(".git/") for path in rel_paths)
        finally:
            remove_snapshot(snapshot)
