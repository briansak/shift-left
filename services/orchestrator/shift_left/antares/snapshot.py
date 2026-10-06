"""Build read-only PR snapshot payloads for Antares agent queries."""

from __future__ import annotations

from shift_left.diff.extractor import ChangedFile


def reconstruct_file_content(changed: ChangedFile) -> str:
    """Reconstruct post-change file content from diff hunks (Option E snapshot)."""
    lines: list[str] = []
    for hunk in changed.hunks:
        for raw in hunk.content.splitlines():
            if raw.startswith("+") and not raw.startswith("+++"):
                lines.append(raw[1:])
            elif raw.startswith(" ") and not raw.startswith("---"):
                lines.append(raw[1:])
    return "\n".join(lines)


def build_snapshot_payload(files: list[ChangedFile]) -> tuple[list[dict[str, str]], list[str]]:
    snapshot_files: list[dict[str, str]] = []
    changed_paths: list[str] = []
    for changed in files:
        content = reconstruct_file_content(changed)
        if not content.strip():
            continue
        snapshot_files.append({"path": changed.path, "content": content})
        changed_paths.append(changed.path)
    return snapshot_files, changed_paths
