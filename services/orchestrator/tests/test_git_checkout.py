"""Git checkout helpers — archive materialization on read-only repos."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from shift_left.investigations.git_checkout import (
    materialize_worktree_at_sha,
    remove_worktree,
)


def _init_git_repo(path: Path, files: dict[str, str]) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=path, check=True)
    for rel, content in files.items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, check=True)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


def test_materialize_worktree_uses_archive_on_read_only_git_dir(tmp_path: Path) -> None:
    checkout = tmp_path / "repo"
    sha = _init_git_repo(checkout, {"README.md": "hello\n"})
    git_dir = checkout / ".git"
    os.chmod(git_dir, stat.S_IREAD | stat.S_IEXEC)
    for child in git_dir.rglob("*"):
        if child.is_file():
            os.chmod(child, stat.S_IREAD)
        elif child.is_dir():
            os.chmod(child, stat.S_IREAD | stat.S_IEXEC)

    dest = tmp_path / "tree"
    size = materialize_worktree_at_sha(checkout, sha, dest)
    assert size > 0
    assert (dest / "README.md").read_text(encoding="utf-8") == "hello\n"

    remove_worktree(checkout, dest)
    assert not dest.exists()


def test_pr_changed_files_scope_lists_and_materializes_only_delta(tmp_path: Path) -> None:
    checkout = tmp_path / "repo"
    _init_git_repo(checkout, {"README.md": "hello\n" * 2000, "keep.py": "x = 1\n"})
    subprocess.run(["git", "checkout", "-b", "feature"], cwd=checkout, check=True, capture_output=True)
    (checkout / "keep.py").write_text("x = 2\n", encoding="utf-8")
    (checkout / "new.py").write_text("print(1)\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=checkout, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "change"], cwd=checkout, check=True, capture_output=True)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    from shift_left.investigations.git_checkout import (
        estimate_launch_snapshot_bytes,
        list_changed_paths_at_sha,
        materialize_worktree_at_sha,
    )

    paths = list_changed_paths_at_sha(checkout, sha, base_ref="main")
    assert "keep.py" in paths
    assert "new.py" in paths
    assert "README.md" not in paths
    full, _ = estimate_launch_snapshot_bytes(checkout, sha, snapshot_scope="full")
    pr_bytes, pr_paths = estimate_launch_snapshot_bytes(
        checkout, sha, snapshot_scope="pr_changed", base_ref="main"
    )
    assert pr_paths is not None
    assert pr_bytes < full
    dest = tmp_path / "pr-tree"
    materialize_worktree_at_sha(checkout, sha, dest, paths=pr_paths)
    assert (dest / "new.py").is_file()
    assert not (dest / "README.md").exists()
