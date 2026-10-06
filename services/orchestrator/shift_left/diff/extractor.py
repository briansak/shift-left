"""Extract changed hunks from unified diffs."""

from __future__ import annotations

from dataclasses import dataclass

from unidiff import PatchSet


@dataclass(frozen=True)
class ChangedHunk:
    file_path: str
    old_start: int
    new_start: int
    new_end: int
    content: str
    is_new_file: bool
    is_deleted: bool


@dataclass(frozen=True)
class ChangedFile:
    path: str
    hunks: list[ChangedHunk]
    is_new_file: bool
    is_deleted: bool


def parse_unified_diff(
    diff_text: str,
    *,
    max_hunk_lines: int = 200,
    include_removed: bool = False,
    context_padding_lines: int = 0,
) -> list[ChangedFile]:
    if not diff_text.strip():
        return []

    patch = PatchSet(diff_text.splitlines(keepends=True))
    changed_files: list[ChangedFile] = []

    for patched_file in patch:
        path = patched_file.path
        if patched_file.is_removed_file:
            changed_files.append(
                ChangedFile(path=path, hunks=[], is_new_file=False, is_deleted=True)
            )
            continue

        hunks: list[ChangedHunk] = []
        for hunk in patched_file:
            raw_lines: list[tuple[str, str]] = []
            for line in hunk:
                prefix = " "
                if line.is_added:
                    prefix = "+"
                elif line.is_removed:
                    prefix = "-"
                raw_lines.append((prefix, line.value.rstrip("\n")))

            if context_padding_lines > 0 and raw_lines:
                # Expand visible context within the hunk (diff already carries some context)
                pass

            lines: list[str] = []
            for prefix, text in raw_lines:
                if line_is_relevant(prefix, include_removed=include_removed):
                    lines.append(f"{prefix}{text}")
                if len(lines) >= max_hunk_lines:
                    lines.append("... [hunk continues — chunked at model layer]")
                    break

            if not lines and not hunk:
                continue

            new_end = hunk.target_start + max(hunk.target_length - 1, 0)
            hunks.append(
                ChangedHunk(
                    file_path=path,
                    old_start=hunk.source_start,
                    new_start=hunk.target_start,
                    new_end=new_end,
                    content="\n".join(lines),
                    is_new_file=patched_file.is_added_file,
                    is_deleted=False,
                )
            )

        if hunks or patched_file.is_added_file:
            changed_files.append(
                ChangedFile(
                    path=path,
                    hunks=hunks,
                    is_new_file=patched_file.is_added_file,
                    is_deleted=False,
                )
            )

    return changed_files


def line_is_relevant(prefix: str, *, include_removed: bool) -> bool:
    if prefix == "+":
        return True
    if prefix == " ":
        return True
    if prefix == "-" and include_removed:
        return True
    return False
