"""Hardened snapshot materialization — no symlinks, no path escape, no external hardlinks."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from shift_left_shared.path_exclusions import is_excluded_test_path

_SNAPSHOT_SUBDIR = Path("data") / "findings" / "antares-snapshots"


def snapshot_staging_dir() -> Path:
    """Directory for ephemeral investigation snapshots.

    On macOS with host-native ``antares-server`` and Docker sandboxes, snapshots must
    live on a path the Docker VM can bind-mount (not ``/var/folders/...`` temp).
    """
    explicit = os.environ.get("ANTARES_SNAPSHOT_DIR", "").strip()
    if explicit:
        candidate = Path(explicit)
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate

    repo_root = os.environ.get("SHIFT_LEFT_REPO_ROOT", "").strip()
    if repo_root:
        candidate = Path(repo_root) / _SNAPSHOT_SUBDIR
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate

    return Path(tempfile.gettempdir())


def _make_snapshot_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="antares-snapshot-", dir=str(snapshot_staging_dir())))


def safe_repo_relative_path(path: str) -> str | None:
    cleaned = path.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if not cleaned or cleaned.startswith("/"):
        return None
    parts = Path(cleaned).parts
    if not parts or any(part == ".." for part in parts):
        return None
    return Path(*parts).as_posix()


def resolve_under_root(root: Path, relative: str) -> Path | None:
    """Return resolved path only when it stays inside ``root``."""
    rel = safe_repo_relative_path(relative)
    if not rel:
        return None
    root_resolved = root.resolve()
    try:
        target = (root_resolved / rel).resolve()
        target.relative_to(root_resolved)
    except ValueError:
        return None
    return target


def materialize_snapshot(snapshot_files: list[dict[str, str]], *, max_bytes: int) -> Path:
    """Materialize explicit path/content pairs into an isolated directory tree."""
    total = sum(len(str(item.get("content", "")).encode("utf-8")) for item in snapshot_files)
    if total > max_bytes:
        raise ValueError(f"Snapshot exceeds max_snapshot_bytes ({max_bytes})")

    root = _make_snapshot_dir()
    for item in snapshot_files:
        rel = safe_repo_relative_path(str(item.get("path", "")))
        if not rel:
            continue
        target = resolve_under_root(root, rel)
        if target is None:
            continue
        if target.exists() and (target.is_symlink() or not target.is_file()):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = str(item.get("content", "")).encode("utf-8")
        if len(payload) > max_bytes:
            raise ValueError(f"Snapshot exceeds max_snapshot_bytes ({max_bytes})")
        target.write_bytes(payload)
    return root


def materialize_tree_snapshot(
    source: Path,
    *,
    max_bytes: int,
    exclude_test_paths: bool = True,
) -> Path:
    """Copy a checkout tree into an isolated snapshot, discarding unsafe entries."""
    source_root = source.resolve()
    if not source_root.is_dir():
        raise FileNotFoundError(f"Snapshot source is not a directory: {source_root}")

    dest_root = _make_snapshot_dir()
    total_bytes = 0

    for dirpath, dirnames, filenames in os.walk(source_root, topdown=True, followlinks=False):
        current = Path(dirpath)
        try:
            rel_dir = current.relative_to(source_root)
        except ValueError:
            continue

        dirnames[:] = [
            name
            for name in dirnames
            if _include_directory_entry(current / name, source_root=source_root)
            and _include_snapshot_path(
                _relative_posix(rel_dir, name),
                exclude_test_paths=exclude_test_paths,
            )
            and not _is_excluded_vcs_path(_relative_posix(rel_dir, name))
        ]

        dest_dir = dest_root / rel_dir
        dest_dir.mkdir(parents=True, exist_ok=True)

        for name in filenames:
            rel_posix = _relative_posix(rel_dir, name)
            if not _include_snapshot_path(rel_posix, exclude_test_paths=exclude_test_paths):
                continue
            entry = current / name
            rel_file = rel_dir / name
            copied = _copy_regular_file(
                entry,
                dest_root / rel_file,
                source_root=source_root,
                max_bytes=max_bytes,
                total_bytes=total_bytes,
            )
            if copied is None:
                continue
            total_bytes = copied

    return dest_root


def _relative_posix(rel_dir: Path, name: str) -> str:
    if rel_dir == Path("."):
        return name
    return f"{rel_dir.as_posix()}/{name}"


def _is_excluded_vcs_path(rel_posix: str) -> bool:
    """VCS metadata has no localization value and must never enter investigation snapshots."""
    normalized = rel_posix.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized == ".git" or normalized.startswith(".git/")


def _include_snapshot_path(rel_posix: str, *, exclude_test_paths: bool) -> bool:
    if _is_excluded_vcs_path(rel_posix):
        return False
    if not exclude_test_paths:
        return True
    return not is_excluded_test_path(rel_posix)


def _include_directory_entry(entry: Path, *, source_root: Path) -> bool:
    if entry.is_symlink():
        return False
    if not entry.is_dir():
        return False
    resolved = _resolved_entry_path(entry, source_root=source_root)
    return resolved is not None


def _copy_regular_file(
    entry: Path,
    dest: Path,
    *,
    source_root: Path,
    max_bytes: int,
    total_bytes: int,
) -> int | None:
    if entry.is_symlink():
        return None
    if not entry.is_file():
        return None
    resolved = _resolved_entry_path(entry, source_root=source_root)
    if resolved is None:
        return None
    if _is_hardlink_to_outside(entry, source_root=source_root):
        return None

    try:
        payload = entry.read_bytes()
    except OSError:
        return None

    next_total = total_bytes + len(payload)
    if next_total > max_bytes:
        raise ValueError(f"Snapshot exceeds max_snapshot_bytes ({max_bytes})")

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(payload)
    return next_total


def _resolved_entry_path(entry: Path, *, source_root: Path) -> Path | None:
    root = source_root.resolve()
    try:
        resolved = entry.resolve()
        resolved.relative_to(root)
    except (ValueError, OSError):
        return None
    return resolved


def _is_hardlink_to_outside(entry: Path, *, source_root: Path) -> bool:
    try:
        stat = entry.stat(follow_symlinks=False)
    except OSError:
        return True
    if stat.st_nlink <= 1:
        return False
    links_in_source = _count_inode_links_under(source_root.resolve(), stat.st_dev, stat.st_ino)
    return links_in_source < stat.st_nlink


def _count_inode_links_under(source: Path, device: int, inode: int) -> int:
    count = 0
    for path in source.rglob("*"):
        if path.is_symlink():
            continue
        try:
            stat = path.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.st_dev == device and stat.st_ino == inode:
            count += 1
    return count


def remove_snapshot(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
