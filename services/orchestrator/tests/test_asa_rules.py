"""ASA / FTD parser-backed rule fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from shift_left.handlers.config.parsers.asa.parser import parse_asa_config
from shift_left.handlers.config.parsers.asa.resolver import count_asa_007_targets
from shift_left.handlers.config.parsers.asa_config import match_asa_config_rules
from shift_left.handlers.config.rules.registry import ALL_RULES
from shift_left.models.schema import PolicyAction, PolicySeverity

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "asa"

RULE_CASES = {
    "ASA-001": [
        ("asa-001-violation-1.conf", True),
        ("asa-001-violation-2.conf", True),
        ("asa-001-clean-1.conf", False),
        ("asa-001-clean-2.conf", False),
    ],
    "ASA-002": [
        ("asa-002-violation-1.conf", True),
        ("asa-002-violation-2.conf", True),
        ("asa-002-clean-1.conf", False),
        ("asa-002-clean-2.conf", False),
    ],
    "ASA-003": [
        ("asa-003-violation-1.conf", True),
        ("asa-003-violation-2.conf", True),
        ("asa-003-clean-1.conf", False),
        ("asa-003-clean-2.conf", False),
    ],
    "ASA-004": [
        ("asa-004-violation-1.conf", True),
        ("asa-004-violation-2.conf", True),
        ("asa-004-clean-1.conf", False),
        ("asa-004-clean-2.conf", False),
    ],
    "ASA-005": [
        ("asa-005-violation-1.conf", True),
        ("asa-005-violation-2.conf", True),
        ("asa-005-clean-1.conf", False),
        ("asa-005-clean-2.conf", False),
    ],
    "ASA-006": [
        ("asa-006-violation-1.conf", True),
        ("asa-006-violation-2.conf", True),
        ("asa-006-clean-1.conf", False),
        ("asa-006-clean-2.conf", False),
    ],
    "ASA-007": [
        ("asa-007-violation-1.conf", True),
        ("asa-007-clean-1.conf", False),
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
def test_asa_fixture(rule_id: str, fixture_name: str, should_match: bool) -> None:
    content = (FIXTURES / fixture_name).read_text()
    matches = match_asa_config_rules(
        chunk_content=content,
        line_offset=0,
        rule_id=rule_id,
    )
    assert (len(matches) > 0) == should_match


def test_asa_003_disabled_in_registry() -> None:
    rule = _rule("ASA-003")
    assert rule.registry_status == "disabled"
    assert rule.enabled is False


def test_enabled_asa_rules_do_not_include_asa_003() -> None:
    from shift_left.handlers.config.rules.registry import rules_for_target_type

    enabled_ids = {item.id for item in rules_for_target_type("cisco_secure_firewall")}
    assert "ASA-003" not in enabled_ids
    assert {"ASA-001", "ASA-002", "ASA-004", "ASA-005", "ASA-006", "ASA-007"}.issubset(enabled_ids)


def _asa_corpus_rules_paths() -> list[Path]:
    root = Path(__file__).resolve().parents[3] / "validation" / "corpus"
    paths: list[Path] = []
    for subdir in ("config", "holdout"):
        paths.extend(
            path
            for path in (root / subdir).rglob("*.rules")
            if "cisco_secure_firewall" in str(path)
        )
    return paths


def test_asa_007_unparsed_line_reconciliation() -> None:
    unparsed_line_count = 0
    unresolvable_ace_count = 0
    asa_007_finding_count = 0

    for path in _asa_corpus_rules_paths():
        content = path.read_text()
        config = parse_asa_config(content)
        unparsed, unresolvable = count_asa_007_targets(config)
        unparsed_line_count += unparsed
        unresolvable_ace_count += unresolvable

        findings = match_asa_config_rules(chunk_content=content, rule_id="ASA-007")
        asa_007_finding_count += len(findings)

        for line in config.unparsed_access_list_lines:
            line_findings = [
                item
                for item in findings
                if item.line_start == line.line_no and item.line_end == line.line_no
            ]
            assert len(line_findings) == 1

    assert asa_007_finding_count == unparsed_line_count + unresolvable_ace_count


def test_parse_coverage_gap_matches_unparsed_line_count() -> None:
    from shift_left.handlers.config.parsers.asa.parser import acl_parse_coverage

    for path in _asa_corpus_rules_paths():
        content = path.read_text()
        config = parse_asa_config(content)
        parsed, total = acl_parse_coverage(content)
        unparsed, _unresolvable = count_asa_007_targets(config)
        assert total - parsed == unparsed


def test_undefined_service_group_is_asa007_not_asa002() -> None:
    content = """\
hostname test-undefined-svc-group
!
access-list TEST_IN extended permit object-group MISSING-SVC-GROUP 10.0.0.0 255.0.0.0 any
access-list TEST_IN extended deny ip any any log
"""
    asa007 = match_asa_config_rules(chunk_content=content, line_offset=0, rule_id="ASA-007")
    asa002 = match_asa_config_rules(chunk_content=content, line_offset=0, rule_id="ASA-002")
    assert len(asa007) == 1
    assert len(asa002) == 0


def test_resolved_service_group_still_matches_asa002() -> None:
    content = """\
hostname test-resolved-svc-group
!
object service SVC-WIDE
 service tcp
!
object-group service WIDE-GROUP
 service-object object SVC-WIDE
!
access-list TEST_IN extended permit object-group WIDE-GROUP any any
access-list TEST_IN extended deny ip any any log
"""
    asa002 = match_asa_config_rules(chunk_content=content, line_offset=0, rule_id="ASA-002")
    asa007 = match_asa_config_rules(chunk_content=content, line_offset=0, rule_id="ASA-007")
    assert len(asa002) >= 1
    assert len(asa007) == 0


def test_asa_007_blocks_gate_at_high_severity() -> None:
    from shift_left.models.schema import Finding, FindingSource, LineRange, TargetKind
    from shift_left.policy.engine import PolicyEngine
    from shift_left.policy.severity import apply_policy_severities

    content = (FIXTURES / "asa-007-violation-1.conf").read_text()
    matches = match_asa_config_rules(chunk_content=content, rule_id="ASA-007")
    assert len(matches) == 1
    match = matches[0]
    finding = apply_policy_severities(
        [
            Finding(
                source=FindingSource.HANDLER,
                target_kind=TargetKind.CONFIG,
                repo="org/repo",
                pr_ref="PR-1",
                commit_sha="deadbeef",
                file_path="firewall/edge.rules",
                line_range=LineRange(start=match.line_start or 1, end=match.line_end or 1),
                handler_asserted_cwe=match.cwe,
                title=match.title or "ASA-007",
                description=match.description or "unparsed ACL",
                trace=f"handler:{match.pattern_id}",
            )
        ],
        _minimal_config().policy,
    )[0]
    assert finding.handler_asserted_cwe == "CWE-754"
    assert finding.policy_severity == PolicySeverity.HIGH

    engine = PolicyEngine(_minimal_config().policy)
    result = engine.evaluate(
        repo="org/repo",
        pr_ref="PR-1",
        commit_sha="deadbeef",
        findings=[finding],
    )
    assert result.pr_action == PolicyAction.BLOCK


def _minimal_config():
    from shift_left.config import AppConfig

    return AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": "/tmp/shift-left-test.db"},
            "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
        }
    )
