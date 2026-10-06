"""Semantic matching between model findings and handler registry rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Literal

from shift_left.handlers.config.registry_matching import RegistryRuleMatch, match_registry_rules

MatcherId = Literal["legacy_cwe_overlap", "best_fit_v1"]

MATCHER_LEGACY: MatcherId = "legacy_cwe_overlap"
MATCHER_BEST_FIT: MatcherId = "best_fit_v1"

MATCHER_METADATA: dict[str, dict[str, Any]] = {
    MATCHER_LEGACY: {
        "id": MATCHER_LEGACY,
        "description": (
            "Legacy matcher: trace/pattern_id match OR CWE equality alone counts as a rule hit. "
            "A single finding may inflate FP on multiple rules sharing the same CWE."
        ),
    },
    MATCHER_BEST_FIT: {
        "id": MATCHER_BEST_FIT,
        "description": (
            "Corrected matcher: each model finding may match at most one rule. "
            "CWE agreement is necessary but not sufficient; explicit trace/pattern_id wins, "
            "otherwise the highest defect-summary semantic-fit score among CWE-aligned rules "
            "with line overlap must meet MIN_SEMANTIC_FIT."
        ),
        "min_semantic_fit": 0.12,
        "relative_fit_ratio": 0.72,
    },
}

MIN_SEMANTIC_FIT = float(MATCHER_METADATA[MATCHER_BEST_FIT]["min_semantic_fit"])
RELATIVE_FIT_RATIO = float(MATCHER_METADATA[MATCHER_BEST_FIT]["relative_fit_ratio"])


@dataclass(frozen=True)
class RuleSemantic:
    rule_id: str
    target_type: str
    cwe: str
    semantic_key: str
    defect_summary: str


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _finding_text_blob(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("evidence") or ""),
        str(finding.get("trace") or ""),
    ]
    return " ".join(parts).strip().lower()


def semantic_fit_score(finding: dict[str, Any], sem: RuleSemantic) -> float:
    blob = _finding_text_blob(finding)
    if not blob:
        return 0.0
    summary = sem.defect_summary.lower()
    summary_tokens = _tokenize(summary)
    blob_tokens = _tokenize(blob)
    if not summary_tokens:
        return 0.0
    token_overlap = len(summary_tokens & blob_tokens) / len(summary_tokens)
    sequence_ratio = SequenceMatcher(None, blob, summary).ratio()
    slug = sem.semantic_key.split("/", 1)[-1].replace("-", " ")
    slug_tokens = _tokenize(slug)
    slug_overlap = (
        len(slug_tokens & blob_tokens) / len(slug_tokens) if slug_tokens else 0.0
    )
    return max(token_overlap, 0.55 * sequence_ratio + 0.45 * slug_overlap)


def _line_count(content: str) -> int:
    if not content:
        return 1
    return max(1, content.count("\n") + (0 if content.endswith("\n") else 1))


def _ranges_overlap(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    if start_a <= 0:
        return True
    return not (end_a < start_b or start_a > end_b)


def _finding_lines(finding: dict[str, Any]) -> tuple[int, int]:
    start = int(finding.get("line_start") or 0)
    end = int(finding.get("line_end") or start)
    if start <= 0:
        return 0, 0
    return start, end


def is_model_originated(finding: dict[str, Any]) -> bool:
    if finding.get("deterministic_only"):
        return False
    if finding.get("model_asserted_cwe"):
        return True
    if finding.get("cwe") and not finding.get("handler_asserted_cwe"):
        return True
    trace = str(finding.get("trace") or "")
    if trace.startswith("handler:") and finding.get("model_asserted_cwe") is None:
        return False
    return bool(finding.get("title") or finding.get("description"))


def _anchor_ranges(
    rule_id: str,
    handler_matches: list[RegistryRuleMatch],
    file_line_count: int,
) -> list[tuple[int, int]]:
    anchors = [m for m in handler_matches if m.rule_id == rule_id]
    if anchors:
        return [(m.line_start, m.line_end) for m in anchors]
    return [(1, file_line_count)]


def _line_overlaps_rule(
    finding: dict[str, Any],
    rule_id: str,
    handler_matches: list[RegistryRuleMatch],
    file_line_count: int,
) -> bool:
    f_start, f_end = _finding_lines(finding)
    if f_start <= 0:
        return True
    for a_start, a_end in _anchor_ranges(rule_id, handler_matches, file_line_count):
        if _ranges_overlap(f_start, f_end, a_start, a_end):
            return True
    return False


def explicit_trace_match(
    finding: dict[str, Any],
    rule_id: str,
    *,
    handler_matches: list[RegistryRuleMatch],
) -> bool:
    trace = str(finding.get("trace") or "")
    if rule_id in trace:
        return True
    for match in handler_matches:
        if match.rule_id == rule_id and match.pattern_id and match.pattern_id in trace:
            return True
    return False


def legacy_semantic_match(
    finding: dict[str, Any],
    rule_id: str,
    *,
    rule_semantics: dict[str, RuleSemantic],
    handler_matches: list[RegistryRuleMatch],
) -> bool:
    sem = rule_semantics.get(rule_id)
    if sem is None:
        return False
    if explicit_trace_match(finding, rule_id, handler_matches=handler_matches):
        return True
    model_cwe = finding.get("model_asserted_cwe") or finding.get("cwe")
    return bool(model_cwe and model_cwe == sem.cwe)


def legacy_model_matched_rule(
    *,
    rule_id: str,
    model_findings: list[dict[str, Any]],
    handler_matches: list[RegistryRuleMatch],
    file_line_count: int,
    rule_semantics: dict[str, RuleSemantic],
) -> bool:
    for finding in model_findings:
        if not is_model_originated(finding):
            continue
        if not legacy_semantic_match(
            finding,
            rule_id,
            rule_semantics=rule_semantics,
            handler_matches=handler_matches,
        ):
            continue
        if _line_overlaps_rule(finding, rule_id, handler_matches, file_line_count):
            return True
    return False


def assign_finding_to_rule(
    finding: dict[str, Any],
    *,
    candidate_rule_ids: list[str],
    rule_semantics: dict[str, RuleSemantic],
    handler_matches: list[RegistryRuleMatch],
    file_line_count: int,
) -> str | None:
    if not is_model_originated(finding):
        return None

    explicit: list[str] = []
    for rule_id in candidate_rule_ids:
        if explicit_trace_match(finding, rule_id, handler_matches=handler_matches):
            if _line_overlaps_rule(finding, rule_id, handler_matches, file_line_count):
                explicit.append(rule_id)
    if len(explicit) == 1:
        return explicit[0]
    if len(explicit) > 1:
        return max(
            explicit,
            key=lambda rid: semantic_fit_score(finding, rule_semantics[rid]),
        )

    model_cwe = finding.get("model_asserted_cwe") or finding.get("cwe")
    if not model_cwe:
        return None

    all_scored: list[tuple[float, str]] = []
    for rule_id in candidate_rule_ids:
        sem = rule_semantics.get(rule_id)
        if sem is None:
            continue
        if not _line_overlaps_rule(finding, rule_id, handler_matches, file_line_count):
            continue
        score = semantic_fit_score(finding, sem)
        all_scored.append((score, rule_id))
    if not all_scored:
        return None

    best_overall_score, best_overall_rule = max(all_scored, key=lambda item: (item[0], item[1]))
    cwe_scored = [
        (score, rule_id)
        for score, rule_id in all_scored
        if rule_semantics[rule_id].cwe == model_cwe
    ]
    if not cwe_scored:
        return None

    best_cwe_score, best_cwe_rule = max(cwe_scored, key=lambda item: (item[0], item[1]))
    if best_cwe_score < MIN_SEMANTIC_FIT:
        return None

    best_overall_cwe = rule_semantics[best_overall_rule].cwe
    if best_overall_cwe != model_cwe and best_cwe_score < best_overall_score * RELATIVE_FIT_RATIO:
        return None

    return best_cwe_rule


def best_fit_model_matched_rule(
    *,
    rule_id: str,
    model_findings: list[dict[str, Any]],
    handler_matches: list[RegistryRuleMatch],
    file_line_count: int,
    rule_semantics: dict[str, RuleSemantic],
    candidate_rule_ids: list[str],
) -> bool:
    for finding in model_findings:
        assigned = assign_finding_to_rule(
            finding,
            candidate_rule_ids=candidate_rule_ids,
            rule_semantics=rule_semantics,
            handler_matches=handler_matches,
            file_line_count=file_line_count,
        )
        if assigned == rule_id:
            return True
    return False


def model_matched_rule(
    *,
    matcher: MatcherId,
    rule_id: str,
    model_findings: list[dict[str, Any]],
    handler_matches: list[RegistryRuleMatch],
    file_line_count: int,
    rule_semantics: dict[str, RuleSemantic],
    candidate_rule_ids: list[str],
) -> bool:
    if matcher == MATCHER_LEGACY:
        return legacy_model_matched_rule(
            rule_id=rule_id,
            model_findings=model_findings,
            handler_matches=handler_matches,
            file_line_count=file_line_count,
            rule_semantics=rule_semantics,
        )
    return best_fit_model_matched_rule(
        rule_id=rule_id,
        model_findings=model_findings,
        handler_matches=handler_matches,
        file_line_count=file_line_count,
        rule_semantics=rule_semantics,
        candidate_rule_ids=candidate_rule_ids,
    )


def finding_matches_any_expected_label(
    finding: dict[str, Any],
    *,
    matcher: MatcherId,
    expected_rule_ids: set[str],
    handler_matches: list[RegistryRuleMatch],
    file_line_count: int,
    rule_semantics: dict[str, RuleSemantic],
    applicable_rule_ids: list[str],
) -> bool:
    if matcher == MATCHER_BEST_FIT:
        assigned = assign_finding_to_rule(
            finding,
            candidate_rule_ids=applicable_rule_ids,
            rule_semantics=rule_semantics,
            handler_matches=handler_matches,
            file_line_count=file_line_count,
        )
        return assigned is not None and assigned in expected_rule_ids
    return any(
        legacy_model_matched_rule(
            rule_id=rule_id,
            model_findings=[finding],
            handler_matches=handler_matches,
            file_line_count=file_line_count,
            rule_semantics=rule_semantics,
        )
        for rule_id in expected_rule_ids
    )


@dataclass
class MetricCounts:
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
        }


@dataclass
class ModelMetricCounts:
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    files_measured: int = 0

    def as_dict(self) -> dict[str, Any]:
        if self.files_measured == 0:
            return "not_measured"
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "files_measured": self.files_measured,
        }


@dataclass
class FpFindingDiagnostic:
    distinct_fp_findings: int = 0
    max_rules_per_finding: int = 0
    rule_level_fp_count: int = 0
    multi_rule_fp_findings: int = 0
    finding_rule_hits: list[dict[str, Any]] = field(default_factory=list)


def _finding_key(
    corpus_name: str,
    rel_path: str,
    finding: dict[str, Any],
) -> tuple[str, str, int, int, str, str]:
    model_cwe = str(finding.get("model_asserted_cwe") or finding.get("cwe") or "")
    title = str(finding.get("title") or "")
    start, end = _finding_lines(finding)
    return (corpus_name, rel_path, start, end, title, model_cwe)


def collect_legacy_fp_rule_hits(
    *,
    corpus_name: str,
    rel_path: str,
    entry: Any,
    content: str,
    model_findings: list[dict[str, Any]],
    handler_matches: list[RegistryRuleMatch],
    rule_semantics: dict[str, RuleSemantic],
) -> dict[tuple[str, str, int, int, str, str], set[str]]:
    expected = set(entry.expected_rule_ids)
    file_lines = _line_count(content)
    applicable_rules = [
        rule_id
        for rule_id in rule_semantics
        if rule_semantics[rule_id].target_type == entry.target_type or rule_id in expected
    ]
    hits: dict[tuple[str, str, int, int, str, str], set[str]] = {}
    for finding in model_findings:
        if not is_model_originated(finding):
            continue
        key = _finding_key(corpus_name, rel_path, finding)
        for rule_id in applicable_rules:
            if rule_id in expected:
                continue
            if legacy_model_matched_rule(
                rule_id=rule_id,
                model_findings=[finding],
                handler_matches=handler_matches,
                file_line_count=file_lines,
                rule_semantics=rule_semantics,
            ):
                hits.setdefault(key, set()).add(rule_id)
    return hits


def summarize_fp_diagnostics(
    per_finding_hits: dict[tuple[str, str, int, int, str, str], set[str]],
) -> FpFindingDiagnostic:
    rule_level_fp = sum(len(rules) for rules in per_finding_hits.values())
    max_rules = max((len(rules) for rules in per_finding_hits.values()), default=0)
    multi = sum(1 for rules in per_finding_hits.values() if len(rules) > 1)
    samples = []
    for key, rules in sorted(per_finding_hits.items(), key=lambda item: (-len(item[1]), item[0][1])):
        if not rules:
            continue
        samples.append(
            {
                "corpus": key[0],
                "rel_path": key[1],
                "line_start": key[2],
                "line_end": key[3],
                "title": key[4],
                "model_cwe": key[5],
                "fp_rules": sorted(rules),
                "fp_rule_count": len(rules),
            }
        )
    return FpFindingDiagnostic(
        distinct_fp_findings=len(per_finding_hits),
        max_rules_per_finding=max_rules,
        rule_level_fp_count=rule_level_fp,
        multi_rule_fp_findings=multi,
        finding_rule_hits=samples,
    )


def handler_matched_rule(rule_id: str, handler_matches: list[RegistryRuleMatch]) -> bool:
    return any(match.rule_id == rule_id for match in handler_matches)


def score_file(
    *,
    matcher: MatcherId,
    entry: Any,
    corpus_name: str,
    content: str,
    model_findings: list[dict[str, Any]] | None,
    handler_stats: dict[str, dict[str, MetricCounts]],
    model_stats: dict[str, dict[str, ModelMetricCounts]],
    unlabeled_model_findings: list[dict[str, Any]],
    rule_semantics: dict[str, RuleSemantic],
    legacy_fp_hits: dict[tuple[str, str, int, int, str, str], set[str]] | None = None,
) -> None:
    handler_matches = match_registry_rules(entry.target_type, content)
    expected = set(entry.expected_rule_ids)
    file_lines = _line_count(content)
    applicable_rules = [
        rule_id
        for rule_id in rule_semantics
        if rule_semantics[rule_id].target_type == entry.target_type or rule_id in expected
    ]

    if legacy_fp_hits is not None and model_findings is not None:
        legacy_fp_hits.update(
            collect_legacy_fp_rule_hits(
                corpus_name=corpus_name,
                rel_path=entry.rel_path,
                entry=entry,
                content=content,
                model_findings=model_findings,
                handler_matches=handler_matches,
                rule_semantics=rule_semantics,
            )
        )

    for rule_id in applicable_rules:
        h_bucket = handler_stats.setdefault(entry.target_type, {}).setdefault(
            rule_id, MetricCounts()
        )
        h_hit = rule_id in expected and handler_matched_rule(rule_id, handler_matches)
        if rule_id in expected and h_hit:
            h_bucket.true_positives += 1
        elif rule_id not in expected and h_hit:
            h_bucket.false_positives += 1
        elif rule_id in expected and not h_hit:
            h_bucket.false_negatives += 1

        if model_findings is None:
            continue

        m_bucket = model_stats.setdefault(entry.target_type, {}).setdefault(
            rule_id, ModelMetricCounts()
        )
        m_bucket.files_measured += 1
        m_hit = model_matched_rule(
            matcher=matcher,
            rule_id=rule_id,
            model_findings=model_findings,
            handler_matches=handler_matches,
            file_line_count=file_lines,
            rule_semantics=rule_semantics,
            candidate_rule_ids=applicable_rules,
        )
        if rule_id in expected and m_hit:
            m_bucket.true_positives += 1
        elif rule_id not in expected and m_hit:
            m_bucket.false_positives += 1
        elif rule_id in expected and not m_hit:
            m_bucket.false_negatives += 1

    if model_findings is None:
        return

    for finding in model_findings:
        if not finding_matches_any_expected_label(
            finding,
            matcher=matcher,
            expected_rule_ids=expected,
            handler_matches=handler_matches,
            file_line_count=file_lines,
            rule_semantics=rule_semantics,
            applicable_rule_ids=applicable_rules,
        ):
            unlabeled_model_findings.append(
                {
                    "corpus": corpus_name,
                    "rel_path": entry.rel_path,
                    "target_type": entry.target_type,
                    "virtual_path": entry.virtual_path,
                    "expected_rule_ids": sorted(expected),
                    "finding": finding,
                }
            )


def aggregate_model_metrics(
    model_stats: dict[str, dict[str, ModelMetricCounts]],
) -> tuple[int, int, int]:
    tp = fp = fn = 0
    for rules in model_stats.values():
        for bucket in rules.values():
            if bucket.files_measured == 0:
                continue
            tp += bucket.true_positives
            fp += bucket.false_positives
            fn += bucket.false_negatives
    return tp, fp, fn


def build_per_rule_report(
    handler_stats: dict[str, dict[str, MetricCounts]],
    model_stats: dict[str, dict[str, ModelMetricCounts]],
    rule_semantics: dict[str, RuleSemantic],
) -> dict[str, dict[str, dict[str, Any]]]:
    per_rule: dict[str, dict[str, dict[str, Any]]] = {}
    sem_map = {
        rule_id: {
            "target_type": sem.target_type,
            "cwe": sem.cwe,
            "semantic_key": sem.semantic_key,
            "defect_summary": sem.defect_summary,
        }
        for rule_id, sem in sorted(rule_semantics.items())
    }
    for target_type in sorted(set(handler_stats) | set(model_stats)):
        per_rule[target_type] = {}
        rule_ids = sorted(
            set(handler_stats.get(target_type, {})) | set(model_stats.get(target_type, {}))
        )
        for rule_id in rule_ids:
            per_rule[target_type][rule_id] = {
                "handler": handler_stats.get(target_type, {})
                .get(rule_id, MetricCounts())
                .as_dict(),
                "model": model_stats.get(target_type, {})
                .get(rule_id, ModelMetricCounts())
                .as_dict(),
                "semantic": sem_map.get(rule_id, {}),
            }
    return per_rule
