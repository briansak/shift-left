"""Git checkout helpers for investigation launch and pinned snapshots."""

from __future__ import annotations

import io
import shutil
import subprocess
import tarfile
from pathlib import Path


class GitCheckoutError(ValueError):
    """Raised when a local checkout cannot satisfy a ref or SHA request."""


def resolve_ref_to_sha(checkout: Path, ref: str) -> str:
    if not checkout.is_dir():
        raise GitCheckoutError(f"Repo checkout not found at {checkout}")
    result = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "--verify", ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise GitCheckoutError(f"Ref {ref!r} does not resolve in local checkout {checkout}")
    sha = result.stdout.strip()
    if not sha:
        raise GitCheckoutError(f"Ref {ref!r} does not resolve in local checkout {checkout}")
    return sha


def materialize_worktree_at_sha(
    checkout: Path,
    commit_sha: str,
    dest: Path,
    *,
    paths: list[str] | None = None,
) -> int:
    """Materialize a detached tree at ``commit_sha`` into ``dest`` and return byte size.

    Uses ``git archive`` rather than ``git worktree add`` so read-only repository
    mounts (e.g. orchestrator bind-mounting the monorepo at /shift-left:ro while
    repos_checkout_dir points inside it) do not require writes under ``.git/worktrees``.
    When ``paths`` is set, only those pathspecs are archived (PR changed-files scope).
    """
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    verify = subprocess.run(
        ["git", "-C", str(checkout), "cat-file", "-e", f"{commit_sha}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if verify.returncode != 0:
        raise GitCheckoutError(f"Commit {commit_sha!r} is not available in checkout {checkout}")
    archive_cmd = ["git", "-C", str(checkout), "archive", "--format=tar", commit_sha]
    if paths:
        archive_cmd.extend(paths)
    archive = subprocess.run(
        archive_cmd,
        capture_output=True,
        check=False,
    )
    if archive.returncode != 0:
        stderr = (archive.stderr or b"").decode("utf-8", errors="replace").strip()
        raise GitCheckoutError(
            f"Failed to materialize tree at {commit_sha}: {stderr or 'git archive failed'}"
        )
    extract_kwargs: dict[str, object] = {"path": dest}
    if hasattr(tarfile, "data_filter"):
        extract_kwargs["filter"] = "data"
    with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as tar:
        tar.extractall(**extract_kwargs)
    return _directory_size(dest)


def remove_worktree(checkout: Path, dest: Path) -> None:
    if not dest.exists():
        return
    subprocess.run(
        ["git", "-C", str(checkout), "worktree", "remove", "--force", str(dest)],
        capture_output=True,
        text=True,
        check=False,
    )
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)


def estimate_snapshot_bytes_at_sha(
    checkout: Path,
    commit_sha: str,
    *,
    paths: list[str] | None = None,
) -> int:
    """Estimate tree size at ``commit_sha`` without leaving a persistent worktree."""
    cmd = ["git", "-C", str(checkout), "archive", "--format=tar", commit_sha]
    if paths:
        cmd.extend(paths)
    result = subprocess.run(cmd, capture_output=True, check=False)
    if result.returncode != 0:
        raise GitCheckoutError(f"Cannot estimate snapshot size for commit {commit_sha!r}")
    return len(result.stdout)


def list_changed_paths_at_sha(
    checkout: Path,
    commit_sha: str,
    *,
    base_ref: str,
) -> list[str]:
    """Repo-relative paths changed between ``base_ref`` and ``commit_sha`` (PR scope)."""
    if not checkout.is_dir():
        raise GitCheckoutError(f"Repo checkout not found at {checkout}")
    base = (base_ref or "main").strip() or "main"
    result = subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            f"{base}...{commit_sha}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise GitCheckoutError(
            f"Cannot list changed files for {base!r}...{commit_sha}: "
            f"{stderr or 'git diff failed'}"
        )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def estimate_launch_snapshot_bytes(
    checkout: Path,
    commit_sha: str,
    *,
    snapshot_scope: str = "full",
    base_ref: str = "main",
) -> tuple[int, list[str] | None]:
    """Return (byte estimate, changed paths or None for full checkout)."""
    if snapshot_scope == "pr_changed":
        paths = list_changed_paths_at_sha(checkout, commit_sha, base_ref=base_ref)
        if not paths:
            raise GitCheckoutError(
                f"PR changed-files scope has no files between {base_ref!r} and {commit_sha[:12]}"
            )
        return estimate_snapshot_bytes_at_sha(checkout, commit_sha, paths=paths), paths
    return estimate_snapshot_bytes_at_sha(checkout, commit_sha), None


def _directory_size(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        if path.is_file():
            try:
                total += path.stat().st_size
            except OSError:
                continue
    return total
