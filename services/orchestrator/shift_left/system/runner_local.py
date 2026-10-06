"""Local Forgejo Actions runner registration markers (when list API is unavailable)."""

from __future__ import annotations

from pathlib import Path

from shift_left.config import resolve_repo_root

RUNNER_MARKER_CONTAINER = Path("/var/lib/shift-left/forgejo-runner.registered")


def runner_registration_present() -> bool:
    """True when the host or container has completed runner registration."""
    root = resolve_repo_root()
    host_file = root / "data" / "forgejo-runner" / ".runner"
    if host_file.is_file():
        return True
    return RUNNER_MARKER_CONTAINER.is_file()
