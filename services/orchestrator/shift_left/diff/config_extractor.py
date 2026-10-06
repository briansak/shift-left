"""Config-oriented diff extraction with surrounding context."""

from __future__ import annotations

from shift_left.diff.extractor import ChangedFile, ChangedHunk, parse_unified_diff


def parse_config_diff(
    diff_text: str,
    *,
    max_hunk_lines: int = 500,
    context_lines_before: int = 5,
    context_lines_after: int = 5,
) -> list[ChangedFile]:
    """
    Parse unified diff for config/IaC review.

    Includes added, removed, and context lines (full hunk) so the model sees
    surrounding configuration context. Does not silently truncate — caller
    chunks at the model layer when context window is exceeded.
    """
    files = parse_unified_diff(
        diff_text,
        max_hunk_lines=max_hunk_lines,
        include_removed=True,
        context_padding_lines=max(context_lines_before, context_lines_after),
    )
    return files


def hunk_to_payload(hunk: ChangedHunk) -> dict:
    return {
        "new_start": hunk.new_start,
        "new_end": hunk.new_end,
        "content": hunk.content,
        "handler_hint": None,
    }


def files_to_analyze_payload(
    files: list[ChangedFile],
    *,
    context_lines_before: int,
    context_lines_after: int,
) -> list[dict]:
    return [
        {
            "path": changed.path,
            "hunks": [
                {
                    "new_start": h.new_start,
                    "new_end": h.new_end,
                    "content": h.content,
                    "context_lines_before": context_lines_before,
                    "context_lines_after": context_lines_after,
                }
                for h in changed.hunks
            ],
        }
        for changed in files
        if changed.hunks
    ]
