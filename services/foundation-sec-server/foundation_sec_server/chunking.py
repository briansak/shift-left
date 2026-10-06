"""Structural, deterministic chunking for config/IaC hunks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Protocol

from foundation_sec_server.handlers.registry import ConfigFormatHandler


class TokenCounter(Protocol):
    def count_tokens(self, text: str) -> int: ...


@dataclass(frozen=True)
class TextChunk:
    content: str
    line_start: int
    line_end: int
    chunk_index: int


def split_structural_units(content: str, handler: ConfigFormatHandler) -> list[tuple[str, int, int]]:
    """Split hunk text into whole structural units with 1-based line ranges."""
    lines = content.splitlines()
    if not lines:
        return []

    if handler.name == "terraform":
        return _split_terraform_blocks(lines)
    if handler.name == "kubernetes":
        return _split_yaml_documents(lines)
    if handler.name == "ansible":
        return _split_ansible_tasks(lines)
    if handler.name == "device":
        return _split_device_stanzas(lines)
    return [(content, 1, len(lines))]


def _line_range_for_slice(lines: list[str], start_idx: int, end_idx: int) -> tuple[str, int, int]:
    block = "\n".join(lines[start_idx:end_idx])
    return block, start_idx + 1, end_idx


def _split_terraform_blocks(lines: list[str]) -> list[tuple[str, int, int]]:
    units: list[tuple[str, int, int]] = []
    i = 0
    while i < len(lines):
        if re.match(r'^\s*resource\s+"', lines[i]) or re.match(r'^\s*module\s+"', lines[i]):
            start = i
            depth = 0
            while i < len(lines):
                depth += lines[i].count("{") - lines[i].count("}")
                i += 1
                if depth <= 0 and i > start:
                    break
            units.append(_line_range_for_slice(lines, start, i))
        else:
            i += 1
    return units or [_line_range_for_slice(lines, 0, len(lines))]


def _split_yaml_documents(lines: list[str]) -> list[tuple[str, int, int]]:
    units: list[tuple[str, int, int]] = []
    start = 0
    for idx, line in enumerate(lines):
        if idx > start and line.strip() == "---":
            units.append(_line_range_for_slice(lines, start, idx))
            start = idx + 1
    units.append(_line_range_for_slice(lines, start, len(lines)))
    return units


def _split_ansible_tasks(lines: list[str]) -> list[tuple[str, int, int]]:
    units: list[tuple[str, int, int]] = []
    start = 0
    for idx, line in enumerate(lines):
        if idx > start and re.match(r"^\s*-\s+name:", line):
            units.append(_line_range_for_slice(lines, start, idx))
            start = idx
    units.append(_line_range_for_slice(lines, start, len(lines)))
    return units


def _split_device_stanzas(lines: list[str]) -> list[tuple[str, int, int]]:
    units: list[tuple[str, int, int]] = []
    start = 0
    for idx, line in enumerate(lines):
        if idx > start and not line.strip():
            units.append(_line_range_for_slice(lines, start, idx))
            start = idx + 1
    units.append(_line_range_for_slice(lines, start, len(lines)))
    return units


def compute_usable_token_budget(
    *,
    n_ctx: int,
    prompt_scaffold_tokens: int,
    max_output_tokens: int,
    safety_margin: int,
) -> int:
    usable = n_ctx - prompt_scaffold_tokens - max_output_tokens - safety_margin
    if usable < 256:
        raise ValueError(
            f"Configured context too small: n_ctx={n_ctx} usable={usable}. "
            "Increase n_ctx or reduce scaffold/output/margin settings."
        )
    return usable


def chunk_hunk_content(
    content: str,
    *,
    handler: ConfigFormatHandler,
    line_start: int,
    max_tokens: int,
    token_counter: TokenCounter,
    overlap_lines: int = 0,
) -> list[TextChunk]:
    """
    Deterministic structural chunking bounded by real token counts.

    Identical input always yields identical chunks (stable unit order and packing).
    """
    units = split_structural_units(content, handler)
    chunks: list[TextChunk] = []
    pack_lines: list[str] = []
    pack_start = line_start
    pack_end = line_start
    index = 0

    def flush() -> None:
        nonlocal index, pack_lines, pack_start, pack_end
        if not pack_lines:
            return
        text = "\n".join(pack_lines)
        chunks.append(
            TextChunk(
                content=text,
                line_start=pack_start,
                line_end=pack_end,
                chunk_index=index,
            )
        )
        index += 1
        if overlap_lines > 0 and len(pack_lines) > overlap_lines:
            pack_lines = pack_lines[-overlap_lines:]
            pack_start = pack_end - overlap_lines + 1
        else:
            pack_lines = []
            pack_start = pack_end + 1

    for unit_text, rel_start, rel_end in units:
        abs_start = line_start + rel_start - 1
        abs_end = line_start + rel_end - 1
        candidate_lines = pack_lines + unit_text.splitlines()
        candidate = "\n".join(candidate_lines)
        if pack_lines and token_counter.count_tokens(candidate) > max_tokens:
            flush()
            pack_lines = unit_text.splitlines()
            pack_start = abs_start
            pack_end = abs_end
        else:
            if not pack_lines:
                pack_start = abs_start
            pack_lines = candidate_lines
            pack_end = abs_end

    if pack_lines:
        text = "\n".join(pack_lines)
        chunks.append(
            TextChunk(
                content=text,
                line_start=pack_start,
                line_end=pack_end,
                chunk_index=index,
            )
        )

    if not chunks:
        return [
            TextChunk(
                content=content,
                line_start=line_start,
                line_end=line_start + max(0, len(content.splitlines()) - 1),
                chunk_index=0,
            )
        ]
    return chunks


class HeuristicTokenCounter:
    """Fallback only for scripted tests when llama tokenizer unavailable."""

    def count_tokens(self, text: str) -> int:
        return max(1, len(text) // 3)


class LlamaTokenCounter:
    def __init__(self, llm: object) -> None:
        self._llm = llm

    def count_tokens(self, text: str) -> int:
        tokenize = getattr(self._llm, "tokenize", None)
        if callable(tokenize):
            return len(tokenize(text.encode("utf-8")))
        return max(1, len(text) // 3)


def merge_findings(raw_findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    merged: list[dict] = []
    for item in sorted(
        raw_findings,
        key=lambda x: (
            x.get("file_path", ""),
            x.get("line_start", 0),
            x.get("cwe") or "",
            x.get("title") or "",
        ),
    ):
        key = (
            item.get("file_path"),
            item.get("line_start"),
            item.get("cwe"),
            item.get("title"),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged
