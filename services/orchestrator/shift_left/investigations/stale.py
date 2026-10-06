"""Informational stale binding when checkout HEAD diverges from investigated SHA."""

from __future__ import annotations


def is_investigation_stale(resolved_commit_sha: str, current_head_sha: str) -> bool:
    """Return True when checkout HEAD is not the SHA the investigation was bound to.

    Callers resolve ``current_head_sha`` from the live checkout at read time.
    This is informational only — not used by policy or the merge gate.
    """
    if not resolved_commit_sha or not current_head_sha:
        return False
    return resolved_commit_sha.strip() != current_head_sha.strip()
