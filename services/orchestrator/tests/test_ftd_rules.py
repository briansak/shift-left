"""FTD FMC parser-backed rule fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from shift_left.handlers.config.gate_findings import findings_for_corpus_file
from shift_left.handlers.config.parsers.ftd_fmc import match_ftd_fmc_rules
from shift_left.handlers.config.rules.registry import ALL_RULES, rules_for_target_type

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "ftd"

RULE_CASES = {
    "FTD-001": [
        ("ftd-001-violation-1.tf", True),
        ("ftd-001-violation-2.tf", True),
        ("ftd-001-violation-3.tf", True),
        ("ftd-001-clean-1.tf", False),
        ("ftd-001-clean-2.tf", False),
    ],
    "FTD-002": [
        ("ftd-002-violation-1.tf", True),
        ("ftd-002-violation-2.tf", True),
        ("ftd-002-clean-1.tf", False),
        ("ftd-002-clean-2.tf", False),
    ],
    "FTD-003": [
        ("ftd-003-violation-1.tf", True),
        ("ftd-003-violation-2.tf", True),
        ("ftd-003-clean-1.tf", False),
        ("ftd-003-clean-2.tf", False),
    ],
    "FTD-004": [
        ("ftd-004-violation-1.tf", True),
        ("ftd-004-violation-2.tf", True),
        ("ftd-004-clean-1.tf", False),
        ("ftd-004-clean-2.tf", False),
    ],
    "FTD-005": [
        ("ftd-005-violation-1.tf", True),
        ("ftd-005-violation-2.tf", True),
        ("ftd-005-violation-3.tf", True),
        ("ftd-005-clean-1.tf", False),
        ("ftd-005-clean-2.tf", False),
        ("ftd-005-clean-3.tf", False),
    ],
    "FTD-006": [
        ("ftd-006-violation-1.tf", True),
        ("ftd-006-violation-2.tf", True),
        ("ftd-006-violation-3.tf", True),
        ("ftd-006-violation-4.tf", True),
        ("ftd-006-clean-1.tf", False),
        ("ftd-006-clean-2.tf", False),
        ("ftd-006-clean-3.tf", False),
    ],
    "FTD-008": [
        ("ftd-008-violation-1.tf", True),
        ("ftd-008-violation-2.tf", True),
        ("ftd-008-violation-3.tf", True),
        ("ftd-008-violation-4.tf", True),
        ("ftd-008-clean-1.tf", False),
        ("ftd-008-clean-2.tf", False),
    ],
}


def _rule(rule_id: str):
    for item in ALL_RULES:
        if item.id == rule_id:
            return item
    raise KeyError(rule_id)


@pytest.mark.parametrize(
    ("rule_id", "fixture_name", "should_match"),
    [
        (rule_id, fixture_name, should_match)
        for rule_id, cases in RULE_CASES.items()
        for fixture_name, should_match in cases
    ],
)
def test_ftd_fixture(rule_id: str, fixture_name: str, should_match: bool) -> None:
    content = (FIXTURES / fixture_name).read_text()
    matches = match_ftd_fmc_rules(
        chunk_content=content,
        line_offset=0,
        rule_id=rule_id,
    )
    assert (len(matches) > 0) == should_match


def test_ftd_rules_enabled_for_cisco_ftd_target() -> None:
    enabled_ids = {item.id for item in rules_for_target_type("cisco_ftd")}
    assert enabled_ids == {
        "FTD-001",
        "FTD-002",
        "FTD-003",
        "FTD-004",
        "FTD-005",
        "FTD-006",
        "FTD-008",
        "FTD-009",
    }


def test_ftd_007_disabled_with_reason() -> None:
    rule = _rule("FTD-007")
    assert rule.registry_status == "disabled"
    assert rule.enabled is False


def test_ftd_rules_all_enabled() -> None:
    for rule_id in RULE_CASES:
        rule = _rule(rule_id)
        assert rule.enabled is True


def test_undefined_object_on_mgmt_port_is_ftd008_not_ftd005() -> None:
    content = (FIXTURES / "ftd-008-violation-3.tf").read_text()
    ftd008 = match_ftd_fmc_rules(chunk_content=content, line_offset=0, rule_id="FTD-008")
    ftd005 = match_ftd_fmc_rules(chunk_content=content, line_offset=0, rule_id="FTD-005")
    assert len(ftd008) > 0
    assert len(ftd005) == 0


def test_shadowed_bulk_cooccurs_ftd005_and_ftd006() -> None:
    content = (FIXTURES / "ftd-006-violation-1.tf").read_text()
    ftd005 = match_ftd_fmc_rules(chunk_content=content, line_offset=0, rule_id="FTD-005")
    ftd006 = match_ftd_fmc_rules(chunk_content=content, line_offset=0, rule_id="FTD-006")
    assert len(ftd005) > 0
    assert len(ftd006) > 0


def test_permissive_shadowed_cooccurs_ftd001_and_ftd006() -> None:
    content = (FIXTURES / "ftd-006-violation-4.tf").read_text()
    ftd001 = match_ftd_fmc_rules(chunk_content=content, line_offset=0, rule_id="FTD-001")
    ftd006 = match_ftd_fmc_rules(chunk_content=content, line_offset=0, rule_id="FTD-006")
    assert len(ftd001) > 0
    assert len(ftd006) > 0


def test_cooccur_corpus_ftd001_ftd003_ftd006() -> None:
    corpus = (
        Path(__file__).resolve().parents[3]
        / "validation"
        / "corpus"
        / "config"
        / "cisco_ftd"
        / "cooccur-ftd-001-006-object-shadow.tf"
    )
    content = corpus.read_text()
    ftd001 = match_ftd_fmc_rules(chunk_content=content, line_offset=0, rule_id="FTD-001")
    ftd003 = match_ftd_fmc_rules(chunk_content=content, line_offset=0, rule_id="FTD-003")
    ftd006 = match_ftd_fmc_rules(chunk_content=content, line_offset=0, rule_id="FTD-006")
    assert len(ftd001) > 0
    assert len(ftd003) > 0
    assert len(ftd006) > 0


def test_demo_dryrun_insecure_tf_still_asserts_ftd_001() -> None:
    fixture = (
        Path(__file__).resolve().parents[3]
        / "scripts"
        / "demo-dryrun"
        / "fixtures"
        / "insecure.tf"
    )
    content = fixture.read_text()
    matches = match_ftd_fmc_rules(chunk_content=content, line_offset=0, rule_id="FTD-001")
    assert matches, "FTD-001 must still match the demo-dryrun insecure.tf fixture"
    findings = findings_for_corpus_file(
        path="terraform/policies/insecure.tf",
        target_type="cisco_ftd",
        content=content,
    )
    traces = {finding.trace for finding in findings}
    assert "handler:FTD-001" in traces
