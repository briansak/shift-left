"""Map investigation repo paths for host-native Antares when orchestrator runs in Docker."""

from __future__ import annotations

import json
import os
import subprocess
from functools import lru_cache
from pathlib import Path

from shift_left.config import AppConfig, resolve_repo_root

_CONTAINER_FINDINGS_MOUNT = Path("/data/findings")
_DOCKER_SOCKET = Path("/var/run/docker.sock")


def investigation_worktree_root(config: AppConfig) -> Path:
    """Writable directory for pinned investigation trees (shared with host via bind mount)."""
    sqlite_path = Path(config.investigations.sqlite_path)
    if not sqlite_path.is_absolute():
        sqlite_path = resolve_repo_root() / sqlite_path
    return sqlite_path.parent / "investigation-worktrees"


def investigation_worktree_path(config: AppConfig, investigation_id: str) -> Path:
    return investigation_worktree_root(config) / investigation_id / "tree"


def _host_repo_root_from_docker_inspect() -> Path | None:
    """Resolve the host repo root via the container's own bind mounts (Colima/Lima-safe)."""
    hostname = os.environ.get("HOSTNAME", "").strip()
    if not hostname or not _DOCKER_SOCKET.is_socket():
        return None
    result = subprocess.run(
        ["docker", "inspect", hostname, "--format", "{{json .Mounts}}"],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    if result.returncode != 0:
        return None
    try:
        mounts = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(mounts, list):
        return None

    for entry in mounts:
        if not isinstance(entry, dict):
            continue
        destination = entry.get("Destination")
        source = entry.get("Source")
        if not source:
            continue
        if destination == "/shift-left":
            # Host bind-mount source is not visible inside the container namespace.
            return Path(str(source))
        if destination == "/data/findings":
            candidate = Path(str(source))
            if candidate.name == "findings" and candidate.parent.name == "data":
                return candidate.parent.parent
    return None


def _host_repo_root_from_mountinfo() -> Path | None:
    mountinfo = Path("/proc/self/mountinfo")
    if not mountinfo.is_file():
        return None

    for line in mountinfo.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            separator = parts.index("-")
        except ValueError:
            continue
        if separator + 2 >= len(parts):
            continue
        mount_root = parts[3]
        mountpoint = parts[4]
        source = parts[separator + 2]
        if mountpoint != "/shift-left":
            continue
        host_root = Path(source)
        if mount_root not in {"", "/"}:
            host_root = host_root / mount_root.lstrip("/")
        if host_root.is_dir():
            return host_root.resolve()
    return None


@lru_cache(maxsize=1)
def _host_repo_root() -> Path | None:
    explicit = os.environ.get("SHIFT_LEFT_HOST_REPO_ROOT", "").strip()
    if explicit:
        candidate = Path(explicit)
        if candidate.is_dir():
            return candidate.resolve()

    from_docker = _host_repo_root_from_docker_inspect()
    if from_docker is not None:
        return from_docker

    return _host_repo_root_from_mountinfo()


def antares_visible_repo_root(local_path: Path) -> str:
    """Return a ``repo_root`` path readable by host-native ``antares-server``."""
    resolved = local_path.resolve()
    host_root = _host_repo_root()
    if host_root is None:
        return str(resolved)

    container_root = os.environ.get("SHIFT_LEFT_REPO_ROOT", "/shift-left").strip()
    if container_root:
        try:
            relative = resolved.relative_to(Path(container_root))
            return str(host_root / relative)
        except ValueError:
            pass

    try:
        relative = resolved.relative_to(_CONTAINER_FINDINGS_MOUNT)
        return str(host_root / "data" / "findings" / relative)
    except ValueError:
        pass

    return str(resolved)
