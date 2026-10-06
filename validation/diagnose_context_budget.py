#!/usr/bin/env python3
"""Diagnose whether context budget explains Q8_0 model eval quality."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FSEC = ROOT / "services" / "foundation-sec-server"
ORCH = ROOT / "services" / "orchestrator"
for path in (FSEC, ORCH):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from eval_handlers import GENERATED_CORPUS_DIR, HOLDOUT_CORPUS_DIR, load_corpus  # noqa: E402
from eval_model import (  # noqa: E402
    MODEL_MAX_CONTEXT_TOKENS,
    collect_file_list,
    finding_matches_any_expected_label,
    is_model_originated,
    match_registry_rules,
    model_matched_rule,
    _line_count,
)
from foundation_sec_server.chunking import (  # noqa: E402
    LlamaTokenCounter,
    chunk_hunk_content,
    compute_usable_token_budget,
    merge_findings,
)
from foundation_sec_server.engine import _EVAL_PROMPT, LlamaCppEvalEngine  # noqa: E402
from foundation_sec_server.handlers.registry import DEFAULT_REGISTRY  # noqa: E402
from foundation_sec_server.preprocess import strip_inactive_lines  # noqa: E402

REPORT_PATH = ROOT / "validation" / "reports" / "model-vs-handler.json"
ATTRIBUTION_PATH = ROOT / "validation" / "reports" / "model-line-attribution.json"
Q8_MODEL_DIR = ROOT / "models" / "foundation-sec-q8_0"

PROMPT_SCAFFOLD_TOKENS = 768
MAX_OUTPUT_TOKENS = 1024
SAFETY_MARGIN = 128
CHUNK_OVERLAP = 2


@dataclass(frozen=True)
class FileChunkProfile:
    corpus: str
    rel_path: str
    virtual_path: str
    target_type: str
    chunk_count: int
    chunk_token_counts: tuple[int, ...]
    chunk_line_ranges: tuple[tuple[int, int], ...]


def load_llm_engine() -> tuple[LlamaCppEvalEngine, LlamaTokenCounter]:
    engine = LlamaCppEvalEngine(
        Q8_MODEL_DIR,
        gguf_glob="foundation-sec-1.1-8b-instruct-q8_0.gguf",
        quant_label="default",
        load_strategy="resident",
        n_ctx=MODEL_MAX_CONTEXT_TOKENS,
    )
    engine.load()
    counter = engine.token_counter()
    assert counter is not None
    return engine, counter


def scaffold_token_count(counter: LlamaTokenCounter, handler) -> int:
    prompt = _EVAL_PROMPT.format(
        format_context=handler.prompt_context,
        file_path="diagnostic/scaffold.tf",
        line_start=1,
        line_end=1,
        content="",
    )
    return counter.count_tokens(prompt)


def chunk_profile(
    *,
    corpus: str,
    rel_path: str,
    virtual_path: str,
    target_type: str,
    content: str,
    counter: LlamaTokenCounter,
    usable: int,
) -> FileChunkProfile:
    handler = DEFAULT_REGISTRY.resolve(virtual_path)
    chunks = chunk_hunk_content(
        content,
        handler=handler,
        line_start=1,
        max_tokens=usable,
        token_counter=counter,
        overlap_lines=CHUNK_OVERLAP,
    )
    token_counts: list[int] = []
    ranges: list[tuple[int, int]] = []
    for chunk in chunks:
        active, _ = strip_inactive_lines(chunk.content, handler)
        prompt = _EVAL_PROMPT.format(
            format_context=handler.prompt_context,
            file_path=virtual_path,
            line_start=chunk.line_start,
            line_end=chunk.line_end,
            content=active[:12000],
        )
        token_counts.append(counter.count_tokens(prompt))
        ranges.append((chunk.line_start, chunk.line_end))
    return FileChunkProfile(
        corpus=corpus,
        rel_path=rel_path,
        virtual_path=virtual_path,
        target_type=target_type,
        chunk_count=len(chunks),
        chunk_token_counts=tuple(token_counts),
        chunk_line_ranges=tuple(ranges),
    )


def line_in_chunk(line_no: int, ranges: tuple[tuple[int, int], ...]) -> int | None:
    for index, (start, end) in enumerate(ranges):
        if start <= line_no <= end:
            return index
    return None


def _fmc_network_refs(content: str) -> tuple[dict[str, int], list[tuple[str, int]]]:
    """Map fmc_network resource name -> def line; list (ref_name, line) in rules."""
    lines = content.splitlines()
    definitions: dict[str, int] = {}
    references: list[tuple[str, int]] = []
    for line_no, line in enumerate(lines, start=1):
        def_match = re.search(r'resource\s+"fmc_network"\s+"([^"]+)"', line)
        if def_match:
            definitions[def_match.group(1)] = line_no
        for ref_match in re.finditer(r"fmc_network\.([A-Za-z0-9_]+)", line):
            references.append((ref_match.group(1), line_no))
    return definitions, references


def _object_group_refs(content: str) -> tuple[dict[str, int], list[tuple[str, int]]]:
    lines = content.splitlines()
    definitions: dict[str, int] = {}
    references: list[tuple[str, int]] = []
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        def_match = re.match(
            r"object(?:-group)?\s+(?:network|service)\s+(\S+)",
            stripped,
            re.IGNORECASE,
        )
        if def_match and not stripped.lower().startswith("object-group"):
            definitions[def_match.group(1)] = line_no
        og_match = re.match(r"object-group\s+\S+\s+(\S+)", stripped, re.IGNORECASE)
        if og_match:
            definitions[og_match.group(1)] = line_no
        for ref_match in re.finditer(r"object-group\s+(\S+)", stripped, re.IGNORECASE):
            references.append((ref_match.group(1), line_no))
        for ref_match in re.finditer(r"\bobject\s+(\S+)", stripped, re.IGNORECASE):
            name = ref_match.group(1)
            if name not in {"object", "object-group"}:
                references.append((name, line_no))
    return definitions, references


def reference_split_files(
    profiles: dict[str, FileChunkProfile],
    corpus_dir: Path,
    corpus: str,
    rel_path: str,
    virtual_path: str,
) -> list[dict[str, Any]]:
    content = (corpus_dir / rel_path).read_text(encoding="utf-8")
    key = f"{corpus}/{rel_path}"
    profile = profiles[key]
    if profile.chunk_count <= 1:
        return []

    splits: list[dict[str, Any]] = []
    ranges = profile.chunk_line_ranges

    if virtual_path.endswith((".tf", ".tfvars", ".hcl")):
        definitions, references = _fmc_network_refs(content)
        kind = "fmc_network"
    elif virtual_path.endswith((".cfg", ".conf")) or "asa" in rel_path or "ios" in rel_path:
        definitions, references = _object_group_refs(content)
        kind = "object-group"
    else:
        return []

    for ref_name, ref_line in references:
        def_line = definitions.get(ref_name)
        if def_line is None:
            continue
        def_chunk = line_in_chunk(def_line, ranges)
        ref_chunk = line_in_chunk(ref_line, ranges)
        if def_chunk is None or ref_chunk is None:
            continue
        if def_chunk != ref_chunk:
            splits.append(
                {
                    "kind": kind,
                    "name": ref_name,
                    "definition_line": def_line,
                    "reference_line": ref_line,
                    "definition_chunk": def_chunk,
                    "reference_chunk": ref_chunk,
                }
            )
    return splits


def infer_file(
    engine: LlamaCppEvalEngine,
    *,
    virtual_path: str,
    content: str,
    usable: int,
    counter: LlamaTokenCounter,
) -> tuple[list[dict[str, Any]], list[int]]:
    handler = DEFAULT_REGISTRY.resolve(virtual_path)
    chunks = chunk_hunk_content(
        content,
        handler=handler,
        line_start=1,
        max_tokens=usable,
        token_counter=counter,
        overlap_lines=CHUNK_OVERLAP,
    )
    completion_tokens: list[int] = []
    raw_findings: list[dict[str, Any]] = []
    for chunk in chunks:
        active, _ = strip_inactive_lines(chunk.content, handler)
        prompt = _EVAL_PROMPT.format(
            format_context=handler.prompt_context,
            file_path=virtual_path,
            line_start=chunk.line_start,
            line_end=chunk.line_end,
            content=active[:12000],
        )
        output = engine._llm(  # noqa: SLF001 — diagnostic replay of production path
            prompt,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=0.1,
            stop=["```"],
        )
        usage = output.get("usage") or {}
        completion_tokens.append(int(usage.get("completion_tokens") or 0))
        text = output["choices"][0]["text"]
        from foundation_sec_server.engine import _parse_json_findings  # noqa: WPS433

        raw_findings.extend(_parse_json_findings(text, virtual_path))
    return merge_findings(raw_findings), completion_tokens


def main() -> int:
    if not REPORT_PATH.is_file():
        print(f"ERROR: missing {REPORT_PATH}", file=sys.stderr)
        return 1
    if not ATTRIBUTION_PATH.is_file():
        print(f"ERROR: missing {ATTRIBUTION_PATH}", file=sys.stderr)
        return 1

    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    attribution = json.loads(ATTRIBUTION_PATH.read_text(encoding="utf-8"))

    print("Loading Q8_0 model for token measurement…", flush=True)
    engine, counter = load_llm_engine()
    usable = compute_usable_token_budget(
        n_ctx=MODEL_MAX_CONTEXT_TOKENS,
        prompt_scaffold_tokens=PROMPT_SCAFFOLD_TOKENS,
        max_output_tokens=MAX_OUTPUT_TOKENS,
        safety_margin=SAFETY_MARGIN,
    )

    profiles: dict[str, FileChunkProfile] = {}
    scaffold_by_handler: dict[str, int] = {}
    all_completion_tokens: list[int] = []
    per_file_completion: list[tuple[str, list[int]]] = []
    model_findings_by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)

    file_list = collect_file_list()
    for corpus_name, corpus_dir, entry in file_list:
        content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
        key = f"{corpus_name}/{entry.rel_path}"
        profile = chunk_profile(
            corpus=corpus_name,
            rel_path=entry.rel_path,
            virtual_path=entry.virtual_path,
            target_type=entry.target_type,
            content=content,
            counter=counter,
            usable=usable,
        )
        profiles[key] = profile

        handler = DEFAULT_REGISTRY.resolve(entry.virtual_path)
        if handler.name not in scaffold_by_handler:
            scaffold_by_handler[handler.name] = scaffold_token_count(counter, handler)

        chunk_completions: list[int] = []
        if profile.chunk_count > 0:
            findings, chunk_completions = infer_file(
                engine,
                virtual_path=entry.virtual_path,
                content=content,
                usable=usable,
                counter=counter,
            )
            for finding in findings:
                if is_model_originated(finding):
                    model_findings_by_file[key].append(finding)
        all_completion_tokens.extend(chunk_completions)
        per_file_completion.append((key, chunk_completions))

    engine.unload()

    multi_chunk = [p for p in profiles.values() if p.chunk_count > 1]
    single_chunk = [p for p in profiles.values() if p.chunk_count == 1]
    largest_chunk_tokens = max(
        (max(p.chunk_token_counts) if p.chunk_token_counts else 0 for p in profiles.values()),
        default=0,
    )

    attribution_by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in attribution.get("per_finding") or []:
        attribution_by_file[row["file"]].append(row)

    def chunk_bucket(key: str) -> str:
        return "multi_chunk" if profiles[key].chunk_count > 1 else "single_chunk"

    tp_fp_by_bucket: dict[str, Counter] = {
        "single_chunk": Counter(),
        "multi_chunk": Counter(),
    }
    attribution_by_bucket: dict[str, Counter] = {
        "single_chunk": Counter(),
        "multi_chunk": Counter(),
    }
    tight_by_bucket: dict[str, int] = {"single_chunk": 0, "multi_chunk": 0}

    for corpus_name, corpus_dir, entry in file_list:
        key = f"{corpus_name}/{entry.rel_path}"
        bucket = chunk_bucket(key)
        content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
        handler_matches = match_registry_rules(entry.target_type, content)
        expected = set(entry.expected_rule_ids)
        file_lines = _line_count(content)
        findings = model_findings_by_file.get(key, [])

        for rule_id in expected:
            if model_matched_rule(
                rule_id=rule_id,
                model_findings=findings,
                handler_matches=handler_matches,
                file_line_count=file_lines,
            ):
                tp_fp_by_bucket[bucket]["tp"] += 1

        for finding in findings:
            if finding_matches_any_expected_label(
                finding,
                expected_rule_ids=expected,
                handler_matches=handler_matches,
                file_line_count=file_lines,
            ):
                continue
            tp_fp_by_bucket[bucket]["fp"] += 1

        for row in attribution_by_file.get(key, []):
            category = row["category"]
            attribution_by_bucket[bucket][category] += 1
            if row.get("tight_anchor"):
                tight_by_bucket[bucket] += 1

    ref_split_events: list[dict[str, Any]] = []
    affected_files: set[str] = set()
    for corpus_name, corpus_dir, entry in file_list:
        key = f"{corpus_name}/{entry.rel_path}"
        events = reference_split_files(
            profiles,
            corpus_dir,
            corpus_name,
            entry.rel_path,
            entry.virtual_path,
        )
        if events:
            affected_files.add(key)
            ref_split_events.append({"file": key, "splits": events})

    scaffold_values = list(scaffold_by_handler.values())
    scaffold_min = min(scaffold_values)
    scaffold_max = max(scaffold_values)

    print("\n=== Context budget diagnostic (Q8_0) ===\n")
    print("## 1. Chunking (148 files)")
    print(f"- Files total: {len(profiles)}")
    print(f"- Single-chunk files: {len(single_chunk)}")
    print(f"- Multi-chunk files: {len(multi_chunk)}")
    print(f"- Usable input budget per chunk: {usable} tokens (n_ctx={MODEL_MAX_CONTEXT_TOKENS})")
    print(f"- Largest single chunk (prompt tokens incl. content): {largest_chunk_tokens}")
    if multi_chunk:
        print("- Multi-chunk file breakdown:")
        for profile in sorted(multi_chunk, key=lambda p: (-p.chunk_count, p.rel_path)):
            print(
                f"  - {profile.corpus}/{profile.rel_path}: {profile.chunk_count} chunks "
                f"(prompt tokens/chunk: {list(profile.chunk_token_counts)})"
            )
    else:
        print("- No files required multiple chunks.")

    print("\n## 2. Finding quality vs chunking")
    for bucket, label in (("single_chunk", "Single-chunk files"), ("multi_chunk", "Multi-chunk files")):
        counts = tp_fp_by_bucket[bucket]
        attr = attribution_by_bucket[bucket]
        print(f"\n### {label}")
        print(f"- Model rule-level TP (labeled matches): {counts['tp']}")
        print(f"- Model finding-level FP (unlabeled findings): {counts['fp']}")
        print(
            f"- Line attribution (unlabeled findings only): "
            f"tight_anchor={tight_by_bucket[bucket]}, "
            f"contains={attr['contains']}, mismatch={attr['mismatch']}, "
            f"fabricated={attr['fabricated']}"
        )

    print("\n## 3. Definition/reference splits across chunk boundaries")
    print(f"- Files with object-group or fmc_network def/ref split across chunks: {len(affected_files)}")
    if affected_files:
        for item in ref_split_events:
            print(f"  - {item['file']}:")
            for split in item["splits"]:
                print(
                    f"      {split['kind']} `{split['name']}`: "
                    f"def L{split['definition_line']} (chunk {split['definition_chunk']}) "
                    f"→ ref L{split['reference_line']} (chunk {split['reference_chunk']})"
                )
    else:
        print("- None detected among multi-chunk files.")

    print("\n## 4. Token budget vs reserved")
    print(f"- Prompt scaffold (empty content), by handler: {scaffold_by_handler}")
    print(f"- Prompt scaffold range: {scaffold_min}–{scaffold_max} tokens (reserved: {PROMPT_SCAFFOLD_TOKENS})")
    if scaffold_max > PROMPT_SCAFFOLD_TOKENS:
        print(f"  ⚠ Actual scaffold exceeds reserved by up to {scaffold_max - PROMPT_SCAFFOLD_TOKENS} tokens")
    else:
        print(f"  ✓ Reserved scaffold headroom: {PROMPT_SCAFFOLD_TOKENS - scaffold_max} tokens at most")

    if all_completion_tokens:
        print(
            f"- Observed completion tokens per chunk: "
            f"min={min(all_completion_tokens)}, max={max(all_completion_tokens)}, "
            f"mean={sum(all_completion_tokens)/len(all_completion_tokens):.1f}, "
            f"total={sum(all_completion_tokens)} across {len(all_completion_tokens)} chunks"
        )
        over = sum(1 for value in all_completion_tokens if value >= MAX_OUTPUT_TOKENS)
        print(f"- Chunks hitting max_output cap ({MAX_OUTPUT_TOKENS}): {over}")
        pct95 = sorted(all_completion_tokens)[int(0.95 * len(all_completion_tokens)) - 1]
        print(f"- 95th percentile completion tokens: {pct95} (reserved: {MAX_OUTPUT_TOKENS})")
    else:
        print("- No completion token usage captured.")

    quant = report.get("quant_evaluated") or (report.get("model_config") or {}).get("quant_evaluated")
    print(f"\n(Source: {REPORT_PATH.name}, quant_evaluated={quant})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
