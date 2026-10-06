"""Resolve advisory (model) finding locations against declared config text."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from shift_left.models.schema import Finding, FindingSource

LocationSource = Literal["parser_resolved", "unanchored"]


@dataclass(frozen=True)
class AdvisoryLocation:
    display_location: str
    location_source: LocationSource
    location_unverified: bool
    model_cited_line: int | None
    model_cited_start: int | None
    model_cited_end: int | None
    parser_resolved_line: int | None
    parser_resolved_lines: tuple[int, ...] = ()


@dataclass(frozen=True)
class AdvisoryAttributionSummary:
    parser_resolved: int
    unanchored: int


def is_advisory_finding(finding: Finding) -> bool:
    return finding.source == FindingSource.ANTARES or (
        finding.handler_asserted_cwe is None and finding.model_asserted_cwe is not None
    )


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def _score_line_match(line: str, evidence_line: str) -> float:
    line_norm = _norm(line)
    evidence_norm = _norm(evidence_line)
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


def locate_evidence_lines(content: str, evidence: str) -> tuple[int, ...]:
    """Return 1-based line numbers where evidence text appears in content."""
    if not evidence.strip():
        return ()

    lines = content.splitlines()
    evidence_lines = [line for line in evidence.splitlines() if _norm(line)]
    if not evidence_lines:
        return ()

    if len(evidence_lines) > 1:
        target = [_norm(line) for line in evidence_lines]
        for index in range(len(lines)):
            window = [_norm(lines[offset]) for offset in range(index, min(index + len(target), len(lines)))]
            if window == target:
                return tuple(range(index + 1, index + len(target) + 1))
        best_line: int | None = None
        best_score = 0.0
        for line_no, line in enumerate(lines, start=1):
            score = _score_line_match(line, evidence_lines[0])
            if score > best_score:
                best_score = score
                best_line = line_no
        return (best_line,) if best_line is not None and best_score >= 0.5 else ()

    evidence_line = evidence_lines[0]
    scored = [
        (line_no, _score_line_match(line, evidence_line))
        for line_no, line in enumerate(lines, start=1)
    ]
    scored.sort(key=lambda item: (-item[1], item[0]))
    if not scored or scored[0][1] < 0.5:
        return ()

    top_score = scored[0][1]
    return tuple(
        sorted(
            line_no
            for line_no, score in scored
            if score >= top_score - 0.05 and score >= 0.5
        )
    )


def _model_cited_line(finding: Finding) -> int | None:
    if finding.line_range is None:
        return None
    return finding.line_range.start


def _model_disagrees_with_parser(
    model_cited_line: int | None,
    parser_primary: int,
) -> bool:
    if model_cited_line is None:
        return False
    return model_cited_line != parser_primary


def resolve_advisory_location(
    finding: Finding,
    file_content: str | None,
) -> AdvisoryLocation:
    cited_start = finding.line_range.start if finding.line_range else None
    cited_end = finding.line_range.end if finding.line_range else cited_start
    model_cited_line = _model_cited_line(finding)
    evidence = (finding.evidence or "").strip()
    parser_lines = locate_evidence_lines(file_content or "", evidence)
    parser_primary = parser_lines[0] if parser_lines else None

    if parser_primary is not None:
        disagrees = _model_disagrees_with_parser(model_cited_line, parser_primary)
        display = f"{finding.file_path} L{parser_primary} (parser-resolved)"
        if disagrees and model_cited_line is not None:
            display = (
                f"{finding.file_path} L{parser_primary} "
                f"(parser-resolved; model cited L{model_cited_line})"
            )
        return AdvisoryLocation(
            display_location=display,
            location_source="parser_resolved",
            location_unverified=disagrees,
            model_cited_line=model_cited_line,
            model_cited_start=cited_start,
            model_cited_end=cited_end,
            parser_resolved_line=parser_primary,
            parser_resolved_lines=parser_lines,
        )

    return AdvisoryLocation(
        display_location=f"{finding.file_path} (location unverified)",
        location_source="unanchored",
        location_unverified=True,
        model_cited_line=model_cited_line,
        model_cited_start=cited_start,
        model_cited_end=cited_end,
        parser_resolved_line=None,
        parser_resolved_lines=(),
    )


def summarize_advisory_attribution(
    findings: list[Finding],
    file_contents: dict[str, str],
) -> AdvisoryAttributionSummary:
    parser_resolved = 0
    unanchored = 0
    for finding in findings:
        if not is_advisory_finding(finding):
            continue
        resolved = resolve_advisory_location(
            finding,
            file_contents.get(finding.file_path),
        )
        if resolved.location_source == "parser_resolved":
            parser_resolved += 1
        else:
            unanchored += 1
    return AdvisoryAttributionSummary(
        parser_resolved=parser_resolved,
        unanchored=unanchored,
    )
