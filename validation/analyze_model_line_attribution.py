#!/usr/bin/env python3
"""Analyze line attribution for unlabeled model findings in model-vs-handler reports."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

ROOT = Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "validation"
if str(VALIDATION) not in sys.path:
    sys.path.insert(0, str(VALIDATION))

from report_quant_stamping import merge_quant_metadata, quant_fields_from_report  # noqa: E402

DEFAULT_INPUT = ROOT / "validation" / "reports" / "model-vs-handler.json"
DEFAULT_OUTPUT = ROOT / "validation" / "reports" / "model-line-attribution.json"
GENERATED_CORPUS_DIR = ROOT / "validation" / "corpus" / "config"
HOLDOUT_CORPUS_DIR = ROOT / "validation" / "corpus" / "holdout"

Category = Literal["contains", "mismatch", "fabricated"]
WIDE_CITE_THRESHOLD = 15
TIGHT_CITE_SPAN = 3


@dataclass(frozen=True)
class EvidenceMatch:
    line_numbers: tuple[int, ...]
    quality: str


def corpus_path(corpus: str, rel_path: str) -> Path:
    base = GENERATED_CORPUS_DIR if corpus == "generated" else HOLDOUT_CORPUS_DIR
    return base / rel_path


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def score_line_match(line: str, evidence_line: str) -> float:
    line_norm = norm(line)
    evidence_norm = norm(evidence_line)
    if not evidence_norm:
        return 0.0
    if line_norm == evidence_norm:
        return 1.0
    if evidence_norm in line_norm or line_norm in evidence_norm:
        return 0.9
    line_tokens = set(re.findall(r"[A-Za-z0-9_./:=\-\$\"']+", line_norm.lower()))
    evidence_tokens = set(re.findall(r"[A-Za-z0-9_./:=\-\$\"']+", evidence_norm.lower()))
    if not evidence_tokens:
        return 0.0
    return len(line_tokens & evidence_tokens) / len(evidence_tokens)


def locate_evidence(content: str, evidence: str) -> EvidenceMatch:
    lines = content.splitlines()
    if not evidence.strip():
        return EvidenceMatch((), "empty")

    evidence_lines = [line for line in evidence.splitlines() if norm(line)]
    if not evidence_lines:
        return EvidenceMatch((), "empty")

    if len(evidence_lines) > 1:
        target = [norm(line) for line in evidence_lines]
        for index in range(len(lines)):
            window = [norm(lines[offset]) for offset in range(index, min(index + len(target), len(lines)))]
            if window == target:
                return EvidenceMatch(
                    tuple(range(index + 1, index + len(target) + 1)),
                    "exact_block",
                )
        best_line: int | None = None
        best_score = 0.0
        for line_no, line in enumerate(lines, start=1):
            score = score_line_match(line, evidence_lines[0])
            if score > best_score:
                best_score = score
                best_line = line_no
        if best_line is not None and best_score >= 0.5:
            return EvidenceMatch((best_line,), "first_line_fuzzy")
        return EvidenceMatch((), "not_found")

    evidence_line = evidence_lines[0]
    scored = [
        (line_no, score_line_match(line, evidence_line))
        for line_no, line in enumerate(lines, start=1)
    ]
    scored.sort(key=lambda item: (-item[1], item[0]))
    if not scored or scored[0][1] < 0.5:
        return EvidenceMatch((), "not_found")

    top_score = scored[0][1]
    hits = sorted(
        line_no
        for line_no, score in scored
        if score >= top_score - 0.05 and score >= 0.5
    )
    return EvidenceMatch(tuple(hits), "single_line_fuzzy")


def classify_attribution(
    *,
    cited_start: int,
    cited_end: int,
    actual_lines: tuple[int, ...],
) -> tuple[Category, int | None, bool, bool]:
    if not actual_lines:
        return "fabricated", None, False, False

    primary_line = actual_lines[0]
    cite_span = cited_end - cited_start + 1
    in_range = any(cited_start <= line_no <= cited_end for line_no in actual_lines)
    if not in_range:
        return "mismatch", primary_line - cited_start, False, False

    tight_anchor = cited_start <= primary_line <= cited_end and (
        primary_line == cited_start or cite_span <= TIGHT_CITE_SPAN
    )
    wide_cite = cite_span > WIDE_CITE_THRESHOLD
    return "contains", primary_line - cited_start, tight_anchor, wide_cite


def quant_metadata(source_report: dict[str, Any], *, source_report_path: Path) -> dict[str, Any]:
    model_config = source_report.get("model_config") or {}
    server_health = model_config.get("server_health") or {}
    try:
        rel_source = source_report_path.relative_to(ROOT)
        source_label = str(rel_source)
    except ValueError:
        source_label = str(source_report_path)
    fields = quant_fields_from_report(source_report)
    return {
        **fields,
        "gguf_file": server_health.get("gguf_file"),
        "source_report_generated_at": source_report.get("generated_at"),
        "source_report_path": source_label,
    }


def findings_for_attribution(
    source_report: dict[str, Any],
    *,
    scope: str = "auto",
) -> list[dict[str, Any]]:
    if scope == "emitted" or (
        scope == "auto" and source_report.get("emitted_model_findings")
    ):
        return list(source_report.get("emitted_model_findings") or [])
    if scope == "survivors" or (
        scope == "auto" and source_report.get("surviving_model_findings")
    ):
        return list(source_report.get("surviving_model_findings") or [])
    return list(source_report.get("unlabeled_model_findings") or [])


def analyze_report(
    source_report: dict[str, Any],
    *,
    source_report_path: Path,
    scope: str = "auto",
) -> dict[str, Any]:
    findings_in = findings_for_attribution(source_report, scope=scope)
    per_finding: list[dict[str, Any]] = []

    for index, item in enumerate(findings_in, start=1):
        corpus = str(item.get("corpus") or "")
        rel_path = str(item.get("rel_path") or "")
        finding = item.get("finding") or {}
        cited_start = int(finding.get("line_start") or 1)
        cited_end = int(finding.get("line_end") or cited_start)
        evidence = str(finding.get("evidence") or "")

        path = corpus_path(corpus, rel_path)
        if not path.is_file():
            per_finding.append(
                {
                    "index": index,
                    "corpus": corpus,
                    "rel_path": rel_path,
                    "file": f"{corpus}/{rel_path}",
                    "title": finding.get("title"),
                    "cited_start": cited_start,
                    "cited_end": cited_end,
                    "evidence": evidence,
                    "evidence_lines": [],
                    "evidence_primary_line": None,
                    "delta": None,
                    "category": "fabricated",
                    "match_quality": "missing_file",
                    "tight_anchor": False,
                    "wide_cite": cited_end - cited_start + 1 > WIDE_CITE_THRESHOLD,
                    "cite_span": cited_end - cited_start + 1,
                }
            )
            continue

        content = path.read_text(encoding="utf-8")
        match = locate_evidence(content, evidence)
        category, delta, tight_anchor, wide_cite = classify_attribution(
            cited_start=cited_start,
            cited_end=cited_end,
            actual_lines=match.line_numbers,
        )
        per_finding.append(
            {
                "index": index,
                "corpus": corpus,
                "rel_path": rel_path,
                "file": f"{corpus}/{rel_path}",
                "title": finding.get("title"),
                "cited_start": cited_start,
                "cited_end": cited_end,
                "evidence": evidence,
                "evidence_lines": list(match.line_numbers),
                "evidence_primary_line": match.line_numbers[0] if match.line_numbers else None,
                "delta": delta,
                "category": category,
                "match_quality": match.quality,
                "tight_anchor": tight_anchor,
                "wide_cite": wide_cite,
                "cite_span": cited_end - cited_start + 1,
            }
        )

    contains = [row for row in per_finding if row["category"] == "contains"]
    mismatch = [row for row in per_finding if row["category"] == "mismatch"]
    fabricated = [row for row in per_finding if row["category"] == "fabricated"]

    quant = quant_metadata(source_report, source_report_path=source_report_path)
    return merge_quant_metadata(
        {
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": (
            "emitted"
            if scope == "emitted" or source_report.get("emitted_model_findings")
            else "survivors"
            if scope == "survivors" or source_report.get("surviving_model_findings")
            else "unlabeled"
        ),
        "source": quant,
        "summary": {
            "findings_total": len(per_finding),
            "contains": len(contains),
            "mismatch": len(mismatch),
            "fabricated": len(fabricated),
            "contains_pct": round(100 * len(contains) / len(per_finding), 1) if per_finding else 0.0,
            "mismatch_pct": round(100 * len(mismatch) / len(per_finding), 1) if per_finding else 0.0,
            "fabricated_pct": round(100 * len(fabricated) / len(per_finding), 1) if per_finding else 0.0,
            "tight_anchor": sum(1 for row in per_finding if row["tight_anchor"]),
            "wide_cite_contains": sum(
                1 for row in contains if row["wide_cite"] and not row["tight_anchor"]
            ),
            "cite_span_lte_5_contains": sum(
                1 for row in contains if row["cite_span"] <= 5
            ),
        },
        "per_finding": per_finding,
        },
        source_report=source_report,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="model-vs-handler.json report to analyze",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Where to write model-line-attribution.json",
    )
    parser.add_argument(
        "--scope",
        choices=("auto", "unlabeled", "survivors", "emitted"),
        default="auto",
        help="Findings to analyze: emitted uses emitted_model_findings when present.",
    )
    args = parser.parse_args()

    if not args.input.is_file():
        print(f"ERROR: input report not found: {args.input}", flush=True)
        return 1

    source_report = json.loads(args.input.read_text(encoding="utf-8"))
    result = analyze_report(
        source_report,
        source_report_path=args.input,
        scope=args.scope,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")

    summary = result["summary"]
    quant = result["source"]
    try:
        out_label = args.output.relative_to(ROOT)
    except ValueError:
        out_label = args.output
    print(f"Wrote {out_label}")
    print(
        f"  quant_evaluated={quant.get('quant_evaluated')} "
        f"quant_intended={quant.get('quant_intended')} "
        f"accuracy_only={quant.get('accuracy_only')}"
    )
    print(
        f"  contains={summary['contains']} mismatch={summary['mismatch']} "
        f"fabricated={summary['fabricated']} tight_anchor={summary['tight_anchor']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
