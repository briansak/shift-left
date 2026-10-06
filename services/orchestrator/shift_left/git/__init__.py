"""Pluggable git hosting backends for PR diffs and review comments."""

from shift_left.git.protocol import GitBackend, GitBackendKind

__all__ = ["GitBackend", "GitBackendKind"]
