"""Tests for semantic model-to-rule matching."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
ORCH = ROOT / "services" / "orchestrator"
for path in (ORCH, VALIDATION, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from eval_model import RULE_SEMANTICS  # noqa: E402
from model_eval_matching import (  # noqa: E402
    MATCHER_BEST_FIT,
    MATCHER_LEGACY,
    assign_finding_to_rule,
    legacy_model_matched_rule,
    model_matched_rule,
)


def _logging_cwe693_finding() -> dict:
    return {
        "line_start": 4,
        "line_end": 4,
        "title": "Action Not Logged",
        "description": (
            "The rule action is set to ALLOW, but logging is only enabled for connection begin. "
            "It is recommended to log both connection begin and end."
        ),
        "evidence": "action = \"ALLOW\", log_connection_begin = true",
        "trace": "Consider enabling log_connection_end to capture both the start and end.",
        "model_asserted_cwe": "CWE-693",
    }


def _shadow_cwe693_finding() -> dict:
    return {
        "line_start": 20,
        "line_end": 25,
        "title": "Shadowed allow rule",
        "description": (
            "FMC ALLOW rule is shadowed by a catch-all BLOCK in the same "
            "fmc_access_rules ordered set."
        ),
        "evidence": "dead allow before block-all",
        "trace": "ordered fmc_access_rules shadow",
        "model_asserted_cwe": "CWE-693",
    }


def test_legacy_cwe693_logging_finding_matches_multiple_ftd_rules() -> None:
    finding = _logging_cwe693_finding()
    handler_matches = []
    file_lines = 40
    cisco_ftd_rules = [
        rule_id
        for rule_id, sem in RULE_SEMANTICS.items()
        if sem.target_type == "cisco_ftd" and sem.cwe == "CWE-693"
    ]
    matched = [
        rule_id
        for rule_id in cisco_ftd_rules
        if legacy_model_matched_rule(
            rule_id=rule_id,
            model_findings=[finding],
            handler_matches=handler_matches,
            file_line_count=file_lines,
            rule_semantics=RULE_SEMANTICS,
        )
    ]
    assert "FTD-006" in matched


def test_best_fit_logging_finding_does_not_match_ftd006() -> None:
    finding = _logging_cwe693_finding()
    handler_matches = []
    file_lines = 40
    cisco_ftd_rules = [
        rule_id
        for rule_id, sem in RULE_SEMANTICS.items()
        if sem.target_type == "cisco_ftd"
    ]
    assigned = assign_finding_to_rule(
        finding,
        candidate_rule_ids=cisco_ftd_rules,
        rule_semantics=RULE_SEMANTICS,
        handler_matches=handler_matches,
        file_line_count=file_lines,
    )
    assert assigned is None
    assert not model_matched_rule(
        matcher=MATCHER_BEST_FIT,
        rule_id="FTD-006",
        model_findings=[finding],
        handler_matches=handler_matches,
        file_line_count=file_lines,
        rule_semantics=RULE_SEMANTICS,
        candidate_rule_ids=cisco_ftd_rules,
    )


def test_best_fit_shadow_finding_matches_ftd006() -> None:
    finding = _shadow_cwe693_finding()
    handler_matches = []
    file_lines = 40
    cisco_ftd_rules = [
        rule_id
        for rule_id, sem in RULE_SEMANTICS.items()
        if sem.target_type == "cisco_ftd"
    ]
    assigned = assign_finding_to_rule(
        finding,
        candidate_rule_ids=cisco_ftd_rules,
        rule_semantics=RULE_SEMANTICS,
        handler_matches=handler_matches,
        file_line_count=file_lines,
    )
    assert assigned == "FTD-006"


def test_each_finding_matches_at_most_one_rule_under_best_fit() -> None:
    findings = [_logging_cwe693_finding(), _shadow_cwe693_finding()]
    handler_matches = []
    file_lines = 40
    cisco_ftd_rules = [
        rule_id
        for rule_id, sem in RULE_SEMANTICS.items()
        if sem.target_type == "cisco_ftd"
    ]
    for finding in findings:
        assigned = assign_finding_to_rule(
            finding,
            candidate_rule_ids=cisco_ftd_rules,
            rule_semantics=RULE_SEMANTICS,
            handler_matches=handler_matches,
            file_line_count=file_lines,
        )
        hit_rules = [
            rule_id
            for rule_id in cisco_ftd_rules
            if model_matched_rule(
                matcher=MATCHER_BEST_FIT,
                rule_id=rule_id,
                model_findings=[finding],
                handler_matches=handler_matches,
                file_line_count=file_lines,
                rule_semantics=RULE_SEMANTICS,
                candidate_rule_ids=cisco_ftd_rules,
            )
        ]
        assert len(hit_rules) <= 1
        if assigned is None:
            assert hit_rules == []
        else:
            assert hit_rules == [assigned]
