"""Tests for Experiment D RCM CWE input construction."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
for path in (ROOT / "services" / "orchestrator", ROOT / "services" / "shift-left-shared", VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from rcm_cwe_inputs import build_rcm_instances, neutral_match_description  # noqa: E402
from rcm_cwe_scoring import parse_predicted_cwe, score_predictions  # noqa: E402
from shift_left.handlers.config.rules.registry import ALL_RULES  # noqa: E402


def test_build_rcm_instances_count_and_no_label_leakage():
    instances = build_rcm_instances()
    assert len(instances) == 150

    rule_cwes = {rule.id: rule.cwe for rule in ALL_RULES}
    for instance in instances:
        assert instance.expected_cwe == rule_cwes[instance.rule_id]
        assert instance.config_block.strip()
        assert instance.match_description
        assert "CWE-" not in instance.match_description
        assert instance.expected_cwe not in instance.prompt
        assert instance.match_description in instance.prompt


def test_neutral_match_description_strips_cwe_tokens():
    from shift_left.handlers.config.registry_matching import RegistryRuleMatch

    rule = next(item for item in ALL_RULES if item.id == "FTD-001")
    match = RegistryRuleMatch(
        rule_id="FTD-001",
        line_start=1,
        line_end=3,
        cwe="CWE-284",
        pattern_id="FTD-001",
        description="Internet-wide ALLOW mapped to CWE-284 exposure.",
    )
    text = neutral_match_description(rule, match)
    assert "CWE-" not in text
    assert "Internet-wide ALLOW" in text


def test_parse_predicted_cwe_prefers_final_line():
    response = (
        "This looks like missing logging on a permit rule.\n"
        "CWE-778"
    )
    assert parse_predicted_cwe(response) == "CWE-778"


def test_parse_predicted_cwe_after_the_cwe_is_bare_number_with_period():
    assert parse_predicted_cwe("778.", after_the_cwe_is=True) == "CWE-778"
    assert parse_predicted_cwe("284", after_the_cwe_is=True) == "CWE-284"


def test_parse_predicted_cwe_cwe_with_trailing_prose():
    assert parse_predicted_cwe("CWE-284: improper access control") == "CWE-284"


def test_score_predictions_overall_and_per_target_type():
    rows = [
        {"expected_cwe": "CWE-284", "predicted_cwe": "CWE-284", "target_type": "cisco_ftd"},
        {"expected_cwe": "CWE-284", "predicted_cwe": "CWE-20", "target_type": "cisco_ftd"},
        {"expected_cwe": "CWE-778", "predicted_cwe": None, "target_type": "cisco_ios_xe"},
    ]
    summary = score_predictions(rows)
    assert summary["total"] == 3
    assert summary["correct"] == 1
    assert summary["invalid_predictions"] == 1
    assert summary["per_target_type"]["cisco_ftd"]["correct"] == 1
    assert summary["per_target_type"]["cisco_ftd"]["total"] == 2
