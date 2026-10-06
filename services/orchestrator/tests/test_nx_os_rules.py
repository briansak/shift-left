"""NX-OS structural parser and NXOS-001/NXOS-002 rule tests."""

from __future__ import annotations

from pathlib import Path

from shift_left.handlers.config.parsers.nx_os.parser import (
    cli_parse_coverage,
    parse_nx_os_config,
)
from shift_left.handlers.config.parsers.nx_os.resolver import resolve_nx_os_config
from shift_left.handlers.config.parsers.nx_os_config import match_nx_os_config_rules
from shift_left.handlers.config.registry_matching import match_registry_rules
from shift_left.handlers.config.rules.registry import rules_for_target_type

FIXTURES = Path(__file__).resolve().parents[3] / "validation" / "corpus" / "config" / "cisco_nx_os"
HOLDOUT = Path(__file__).resolve().parents[3] / "validation" / "corpus" / "holdout" / "cisco_nx_os"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_nested_group_resolution() -> None:
    content = _fixture("nested-group-resolution.cfg")
    parsed = parse_nx_os_config(content)
    resolved = resolve_nx_os_config(parsed)
    entry = parsed.access_list_entries[0]
    ace = resolved.ace_resolutions[entry.line_no]
    assert "host:10.1.1.10" in ace.destination_values
    assert "net:10.0.0.0/24" in ace.destination_values
    assert not parsed.unresolved_references
    matches = match_nx_os_config_rules(chunk_content=content, rule_id="NXOS-001")
    assert matches == []


def test_circular_object_group_emits_nxos_001() -> None:
    content = _fixture("circular-object-group.cfg")
    matches = match_nx_os_config_rules(chunk_content=content, rule_id="NXOS-001")
    assert len(matches) >= 1
    assert all(match.pattern_id == "NXOS-001" for match in matches)


def test_unparsed_acl_line_emits_nxos_001() -> None:
    content = _fixture("unparsed-acl-line.cfg")
    parsed = parse_nx_os_config(content)
    assert parsed.unparsed_lines
    matches = match_nx_os_config_rules(chunk_content=content, rule_id="NXOS-001")
    assert len(matches) == 1
    assert matches[0].pattern_id == "NXOS-001"


def test_clean_scoped_config_has_no_nxos_001() -> None:
    content = _fixture("clean-scoped.cfg")
    parsed = parse_nx_os_config(content)
    assert parsed.interface_blocks
    assert parsed.aaa_config is not None
    assert parsed.snmp_config is not None
    assert parsed.vrf_contexts
    assert parsed.role_definitions
    assert any(item.feature == "ssh" and item.enabled for item in parsed.feature_declarations)
    assert any(item.feature == "telnet" and not item.enabled for item in parsed.feature_declarations)
    assert len(parsed.access_list_entries) == 1
    matches = match_nx_os_config_rules(chunk_content=content, rule_id="NXOS-001")
    assert matches == []


def test_cli_parse_coverage_counts_parsed_aces() -> None:
    content = _fixture("clean-scoped.cfg")
    parsed, total = cli_parse_coverage(content)
    assert parsed == 1
    assert total == 1


def test_enabled_nxos_rules_registered() -> None:
    enabled_ids = {rule.id for rule in rules_for_target_type("cisco_nx_os")}
    assert enabled_ids == {
        "NXOS-001",
        "NXOS-002",
        "NXOS-003",
        "NXOS-004",
        "NXOS-005",
        "NXOS-006",
        "NXOS-007",
        "NXOS-008",
        "NXOS-009",
        "NXOS-010",
    }


def test_platform_mismatch_finding_names_declared_and_detected() -> None:
    cases = (
        ("nxos-sniff-asa.cfg", "cisco_secure_firewall"),
        ("nxos-sniff-iosxe.cfg", "cisco_ios_xe"),
    )
    for filename, detected in cases:
        content = (FIXTURES / filename).read_text()
        mismatch_matches = [
            match
            for match in match_registry_rules("cisco_nx_os", content)
            if match.rule_id == "NXOS-002"
        ]
        assert len(mismatch_matches) == 1
        description = mismatch_matches[0].description or ""
        assert "cisco_nx_os" in description
        assert detected in description


def _nx_os_corpus_paths() -> list[Path]:
    root = Path(__file__).resolve().parents[3] / "validation" / "corpus"
    paths: list[Path] = []
    for subdir in ("config", "holdout"):
        paths.extend(
            path
            for path in (root / subdir).rglob("*.cfg")
            if "cisco_nx_os" in str(path)
        )
    return paths


def test_nxos_001_unparsed_line_reconciliation() -> None:
    from shift_left.handlers.config.parsers.nx_os.resolver import count_nxos_001_targets

    unparsed_line_count = 0
    unresolvable_ref_count = 0
    nxos_001_finding_count = 0

    for path in _nx_os_corpus_paths():
        content = path.read_text()
        parsed = parse_nx_os_config(content)
        unparsed, unresolvable = count_nxos_001_targets(parsed)
        unparsed_line_count += unparsed
        unresolvable_ref_count += unresolvable

        findings = match_nx_os_config_rules(chunk_content=content, rule_id="NXOS-001")
        nxos_001_finding_count += len(findings)

        for line in parsed.unparsed_lines:
            if line.category != "acl":
                continue
            line_findings = [
                item
                for item in findings
                if item.line_start == line.line_no and item.line_end == line.line_no
            ]
            assert len(line_findings) == 1

    assert nxos_001_finding_count == unparsed_line_count + unresolvable_ref_count
