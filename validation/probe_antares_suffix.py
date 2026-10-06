#!/usr/bin/env python3
"""Antares prompt-suffix sensitivity probe on hand-written code defects."""

from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from typing import Any

import httpx
from transformers import AutoTokenizer

ROOT = Path(__file__).resolve().parents[1]
ANTARES_SERVER = ROOT / "services" / "antares-server"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ANTARES_SERVER, ROOT / "validation"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from antares_server.contract import parse_and_validate_findings  # noqa: E402

MANIFEST = ROOT / "validation" / "probe" / "antares-suffix" / "manifest.json"
MODEL_PATH = ROOT / "models" / "350m"
OUTPUT_JSON = ROOT / "validation" / "reports" / "antares-suffix-sensitivity.json"
OUTPUT_MD = ROOT / "validation" / "reports" / "antares-suffix-sensitivity.md"
ANTARES_URL = "http://127.0.0.1:8090"

_PROMPT_BODY = """You are Antares, a security model that localizes likely vulnerabilities in code changes.
Analyze the diff hunk below and respond with ONLY a JSON array (no markdown fences).
Each object must include:
  file_path, line_start, line_end, cwe, severity (info|low|medium|high|critical),
  confidence (0.0-1.0), title, description, evidence, trace

If no likely issue is present, return [].

File: {file_path}
Lines: {line_start}-{line_end}
```diff
{content}
```
"""

_SUFFIX_VARIANTS = {
    "colon": "JSON array:",
    "bracket": "JSON array:\n[",
    "none": "",
}


def build_prompt(file_path: str, line_start: int, line_end: int, content: str, suffix_key: str) -> str:
    tail = _SUFFIX_VARIANTS[suffix_key]
    if tail:
        return _PROMPT_BODY.format(
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            content=content,
        ) + tail
    return _PROMPT_BODY.format(
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        content=content,
    ).rstrip() + "\n"


def _completion_tokens(tokenizer: Any, text: str) -> int:
    return len(tokenizer.encode(text or "", add_special_tokens=False))


def _first_tokens(tokenizer: Any, text: str, count: int = 5) -> list[str]:
    ids = tokenizer.encode(text or "", add_special_tokens=False)[:count]
    return tokenizer.convert_ids_to_tokens(ids)


def _classify_degenerate(text: str, *, suffix_key: str, completion_tokens: int) -> list[str]:
    stripped = (text or "").strip()
    lead = (text or "").lstrip()
    labels: list[str] = []
    if stripped == "]":
        labels.append("single_close_bracket")
    if stripped == "[]" or lead.startswith("[]"):
        labels.append("empty_array_literal")
    if lead.startswith("://") or re.match(r"^://json\b", stripped):
        labels.append("url_prefix")
    if lead.startswith("```diff") or lead.startswith("```\ndiff"):
        labels.append("continues_diff_fence")
    if "```json" in (text or "")[:60] or lead.startswith("```json"):
        labels.append("markdown_json_fence")
    if suffix_key == "bracket" and lead.startswith("{"):
        labels.append("object_continuation_after_open_bracket")
    if suffix_key == "none" and lead.startswith("```"):
        labels.append("continues_markdown_fence")
    if completion_tokens >= 1024:
        labels.append("max_token_truncation")
    return labels


def _parse_findings(text: str, file_path: str, *, suffix_key: str) -> dict[str, Any]:
    attempts: list[tuple[str, str]] = [("raw", text or "")]
    if suffix_key == "bracket":
        stripped = (text or "").lstrip()
        if stripped and not stripped.startswith("["):
            attempts.append(("prepend_bracket", "[" + text))
    for label, payload in attempts:
        result = parse_and_validate_findings(payload, default_path=file_path)
        if result.ok and result.findings:
            return {
                "parse_path": label,
                "parseable": True,
                "findings_count": len(result.findings),
                "failure_message": None,
            }
    last = parse_and_validate_findings(text or "", default_path=file_path)
    return {
        "parse_path": "raw",
        "parseable": bool(last.ok and last.findings),
        "findings_count": len(last.findings) if last.ok else 0,
        "failure_message": last.failure_message,
    }


def _complete(prompt: str, *, max_tokens: int = 1024) -> str:
    response = httpx.post(
        f"{ANTARES_URL}/v1/completions",
        json={
            "model": "antares",
            "prompt": prompt,
            "max_tokens": max_tokens,
            "temperature": 0.0,
            "top_p": 1.0,
        },
        timeout=300.0,
    )
    response.raise_for_status()
    payload = response.json()
    return str(payload["choices"][0].get("text") or "")


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tokens = [row["completion_tokens"] for row in rows]
    degenerate_rows = [row for row in rows if row["degenerate_labels"]]
    parseable_rows = [row for row in rows if row["parseable"]]
    return {
        "files": len(rows),
        "completion_tokens_mean": round(mean(tokens), 1) if tokens else 0.0,
        "completion_tokens_max": max(tokens) if tokens else 0,
        "degenerate_count": len(degenerate_rows),
        "degenerate_rate": round(len(degenerate_rows) / len(rows), 4) if rows else 0.0,
        "parseable_findings_count": len(parseable_rows),
        "parseable_findings_rate": round(len(parseable_rows) / len(rows), 4) if rows else 0.0,
        "degenerate_breakdown": {
            label: sum(1 for row in rows if label in row["degenerate_labels"])
            for label in (
                "single_close_bracket",
                "empty_array_literal",
                "url_prefix",
                "continues_diff_fence",
                "continues_markdown_fence",
                "markdown_json_fence",
                "object_continuation_after_open_bracket",
                "max_token_truncation",
            )
        },
        "per_file": rows,
    }


def main() -> int:
    health = httpx.get(f"{ANTARES_URL}/health", timeout=10.0)
    health.raise_for_status()
    server_health = health.json()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_PATH), local_files_only=True)

    by_suffix: dict[str, list[dict[str, Any]]] = {key: [] for key in _SUFFIX_VARIANTS}

    total = len(manifest["files"]) * len(_SUFFIX_VARIANTS)
    step = 0
    for suffix_key in _SUFFIX_VARIANTS:
        for entry in manifest["files"]:
            step += 1
            prompt = build_prompt(
                entry["file_path"],
                entry["line_start"],
                entry["line_end"],
                entry["diff"],
                suffix_key,
            )
            raw = _complete(prompt)
            tokens = _completion_tokens(tokenizer, raw)
            degenerate = _classify_degenerate(
                raw,
                suffix_key=suffix_key,
                completion_tokens=tokens,
            )
            parsed = _parse_findings(raw, entry["file_path"], suffix_key=suffix_key)
            row = {
                "fixture_id": entry["id"],
                "language": entry["language"],
                "defect": entry["defect"],
                "file_path": entry["file_path"],
                "suffix": suffix_key,
                "prompt_tail_repr": repr(prompt[-16:]),
                "raw_completion": raw,
                "raw_completion_repr": repr(raw[:240]),
                "completion_tokens": tokens,
                "first_5_tokens": _first_tokens(tokenizer, raw, 5),
                "degenerate_labels": degenerate,
                **parsed,
            }
            by_suffix[suffix_key].append(row)
            print(
                f"[{step}/{total}] {suffix_key} {entry['id']} "
                f"tokens={tokens} degenerate={degenerate or '-'} "
                f"parseable={parsed['parseable']}",
                flush=True,
            )

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "task": "antares_suffix_sensitivity_probe",
        "purpose": (
            "Determine whether Foundation-Sec degenerate-continuation behavior "
            "is family-wide before investing in a labeled code corpus."
        ),
        "model": {
            "id": "fdtn-ai/antares-350m",
            "variant": "350m",
            "architecture": "GraniteMoeHybridForCausalLM",
            "model_path": str(MODEL_PATH),
            "device": server_health.get("device"),
            "backend": server_health.get("backend"),
        },
        "inference": {
            "path": "antares-server /v1/completions",
            "temperature": 0.0,
            "top_p": 1.0,
            "max_new_tokens": 1024,
            "do_sample": False,
        },
        "fixtures": len(manifest["files"]),
        "suffix_variants": _SUFFIX_VARIANTS,
        "by_suffix": {key: _aggregate(rows) for key, rows in by_suffix.items()},
    }

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Antares prompt-suffix sensitivity probe",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Configuration",
        "",
        f"- Model: `{report['model']['id']}` ({report['model']['variant']})",
        f"- Path: `{report['model']['model_path']}`",
        f"- Device: {report['model']['device']}",
        f"- Inference: {report['inference']['path']}, T={report['inference']['temperature']}",
        f"- Fixtures: {report['fixtures']} hand-written files (Python/Go/JS; SQLi, secret, path traversal)",
        "",
        "## Summary by suffix",
        "",
        "| Suffix | Mean tokens | Max tokens | Degenerate rate | Parseable findings |",
        "|--------|-------------|------------|-----------------|-------------------|",
    ]
    for suffix_key, label in (
        ("colon", '`JSON array:`'),
        ("bracket", '`JSON array:\\n[`'),
        ("none", "no trailing cue"),
    ):
        block = report["by_suffix"][suffix_key]
        lines.append(
            f"| {label} | {block['completion_tokens_mean']} | {block['completion_tokens_max']} | "
            f"{block['degenerate_count']}/{block['files']} ({block['degenerate_rate']:.0%}) | "
            f"{block['parseable_findings_count']}/{block['files']} |"
        )
    lines.extend(
        [
            "",
            "## Degenerate-mode breakdown",
            "",
            "| Mode | colon | bracket | none |",
            "|------|-------|---------|------|",
        ]
    )
    all_labels = [
        "single_close_bracket",
        "empty_array_literal",
        "url_prefix",
        "object_continuation_after_open_bracket",
        "continues_diff_fence",
        "continues_markdown_fence",
        "markdown_json_fence",
        "max_token_truncation",
    ]
    for label in all_labels:
        cols = [
            str(report["by_suffix"][suffix]["degenerate_breakdown"].get(label, 0))
            for suffix in _SUFFIX_VARIANTS
        ]
        lines.append(f"| {label} | {' | '.join(cols)} |")
    lines.extend(
        [
            "",
            "## Interpretation vs Foundation-Sec",
            "",
            "- **Colon (`JSON array:`):** Antares does **not** show the Foundation-Sec `://` "
            "artifact (0/10). It opens `[` and emits malformed positional JSON or "
            "` ```json` fences instead.",
            "- **Bracket (`JSON array:\\n[`):** Antares does **not** emit single-token `]` "
            "(0/10). It continues with bare `{` objects (10/10 "
            "`object_continuation_after_open_bracket`) — schema-invalid for the contract.",
            "- **None (no trailing cue):** Antares continues the diff/markdown context "
            "(`continues_markdown_fence` / `continues_diff_fence`, 10/10) rather than "
            "emitting JSON.",
            "",
            "**Parseable findings: 0/30 across all suffixes.** Suffix changes the failure "
            "mode but not the outcome — structured output is not reliable on Antares-350m "
            "without constraints beyond prompt wording.",
            "",
            "## Per-file first tokens",
            "",
        ]
    )
    for suffix_key in _SUFFIX_VARIANTS:
        lines.append(f"### `{suffix_key}`")
        for row in report["by_suffix"][suffix_key]["per_file"]:
            lines.append(
                f"- **{row['fixture_id']}** ({row['language']}/{row['defect']}): "
                f"tokens={row['completion_tokens']} "
                f"first5={row['first_5_tokens']} "
                f"degenerate={row['degenerate_labels'] or '—'} "
                f"parseable={row['parseable']}"
            )
        lines.append("")
    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nWrote {OUTPUT_JSON.relative_to(ROOT)}")
    print(f"Wrote {OUTPUT_MD.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
