"""IOS-XE structural parser and IOS-001 rule tests."""

from __future__ import annotations

from pathlib import Path

from shift_left.handlers.config.parsers.ios_xe.parser import (
    cli_parse_coverage,
    parse_ios_xe_config,
)
from shift_left.handlers.config.parsers.ios_xe.resolver import resolve_ios_xe_config
from shift_left.handlers.config.parsers.ios_xe_config import match_ios_xe_config_rules
from shift_left.handlers.config.registry_matching import match_registry_rules
from shift_left.handlers.config.rules.registry import rules_for_target_type

FIXTURES = Path(__file__).resolve().parents[3] / "validation" / "corpus" / "config" / "cisco_ios_xe"
HOLDOUT = Path(__file__).resolve().parents[3] / "validation" / "corpus" / "holdout" / "cisco_ios_xe"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_nested_group_resolution() -> None:
    content = _fixture("nested-group-resolution.cfg")
    parsed = parse_ios_xe_config(content)
    resolved = resolve_ios_xe_config(parsed)
    entry = parsed.access_list_entries[0]
    ace = resolved.ace_resolutions[entry.line_no]
    assert "host:10.1.1.10" in ace.destination_values
    assert "net:10.0.0.0/0.0.255.255" in ace.destination_values
    assert not parsed.unresolved_references
    matches = match_ios_xe_config_rules(chunk_content=content, rule_id="IOS-001")
    assert matches == []


def test_circular_object_group_emits_ios_001() -> None:
    content = _fixture("circular-object-group.cfg")
    matches = match_ios_xe_config_rules(chunk_content=content, rule_id="IOS-001")
    assert len(matches) >= 1
    assert all(match.pattern_id == "IOS-001" for match in matches)


def test_unparsed_acl_line_emits_ios_001() -> None:
    content = _fixture("unparsed-acl-line.cfg")
    parsed = parse_ios_xe_config(content)
    assert parsed.unparsed_lines
    matches = match_ios_xe_config_rules(chunk_content=content, rule_id="IOS-001")
    assert len(matches) == 1
    assert matches[0].pattern_id == "IOS-001"


def test_clean_scoped_config_has_no_ios_001() -> None:
    content = _fixture("clean-scoped.cfg")
    parsed = parse_ios_xe_config(content)
    assert parsed.interface_blocks
    assert parsed.aaa_config is not None
    assert parsed.snmp_config is not None
    assert parsed.management_services
    assert len(parsed.access_list_entries) == 2
    matches = match_ios_xe_config_rules(chunk_content=content, rule_id="IOS-001")
    assert matches == []


def test_cli_parse_coverage_counts_parsed_aces() -> None:
    content = _fixture("clean-scoped.cfg")
    parsed, total = cli_parse_coverage(content)
    assert parsed == 2
    assert total == 2


def test_enabled_ios_rules_registered() -> None:
    enabled_ids = {rule.id for rule in rules_for_target_type("cisco_ios_xe")}
    assert enabled_ids == {
        "IOS-001",
        "IOS-010",
        "IOS-002",
        "IOS-003",
        "IOS-004",
        "IOS-005",
        "IOS-006",
        "IOS-007",
        "IOS-008",
    }


def test_platform_mismatch_finding_names_declared_and_detected() -> None:
    cases = (
        ("holdout-iosxe-sniff-asa.cfg", "cisco_secure_firewall"),
        ("holdout-iosxe-sniff-nxos.cfg", "cisco_nx_os"),
    )
    for filename, detected in cases:
        content = (HOLDOUT / filename).read_text()
        mismatch_matches = [
            match
            for match in match_registry_rules("cisco_ios_xe", content)
            if match.rule_id == "IOS-010"
        ]
        assert len(mismatch_matches) == 1
        description = mismatch_matches[0].description or ""
        assert "cisco_ios_xe" in description
        assert detected in description


def test_platform_mismatch_does_not_suppress_ios_001_on_sniff_asa() -> None:
    content = (HOLDOUT / "holdout-iosxe-sniff-asa.cfg").read_text()
    rule_ids = {match.rule_id for match in match_registry_rules("cisco_ios_xe", content)}
    assert rule_ids == {"IOS-001", "IOS-010"}


def _ios_xe_corpus_paths() -> list[Path]:
    root = Path(__file__).resolve().parents[3] / "validation" / "corpus"
    paths: list[Path] = []
    for subdir in ("config", "holdout"):
        paths.extend(
            path
            for path in (root / subdir).rglob("*.cfg")
            if "cisco_ios_xe" in str(path)
        )
    return paths


def test_ios_001_unparsed_line_reconciliation() -> None:
    from shift_left.handlers.config.parsers.ios_xe.resolver import count_ios_001_targets

    unparsed_line_count = 0
    unresolvable_ref_count = 0
    ios_001_finding_count = 0

    for path in _ios_xe_corpus_paths():
        content = path.read_text()
        parsed = parse_ios_xe_config(content)
        unparsed, unresolvable = count_ios_001_targets(parsed)
        unparsed_line_count += unparsed
        unresolvable_ref_count += unresolvable

        findings = match_ios_xe_config_rules(chunk_content=content, rule_id="IOS-001")
        ios_001_finding_count += len(findings)

        for line in parsed.unparsed_lines:
            if line.category != "acl":
                continue
            line_findings = [
                item
                for item in findings
                if item.line_start == line.line_no and item.line_end == line.line_no
            ]
            assert len(line_findings) == 1

    assert ios_001_finding_count == unparsed_line_count + unresolvable_ref_count
