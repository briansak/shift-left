"""Tests for advisory finding line attribution."""

from __future__ import annotations

from shift_left.models.schema import Finding, FindingSource, LineRange, PolicySeverity, TargetKind
from shift_left.ui.advisory_line_attribution import (
    is_advisory_finding,
    locate_evidence_lines,
    resolve_advisory_location,
    summarize_advisory_attribution,
)

_JUMP_HOST = """\
hostname jump
no ip http server
aaa authentication login default local
snmp-server community nms-ro-9c2f RO
"""


def test_locate_evidence_lines_finds_config_line() -> None:
    lines = locate_evidence_lines(_JUMP_HOST, "no ip http server")
    assert lines == (2,)


def test_resolve_advisory_location_prefers_parser_over_wrong_model_cite() -> None:
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="switches/jump.cfg",
        line_range=LineRange(start=31, end=31),
        title="HTTP disabled",
        description="HTTP disabled",
        evidence="no ip http server",
        policy_severity=PolicySeverity.UNCLASSIFIED,
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        model_asserted_cwe="CWE-264",
    )
    resolved = resolve_advisory_location(finding, _JUMP_HOST)
    assert resolved.parser_resolved_line == 2
    assert resolved.model_cited_line == 31
    assert resolved.location_source == "parser_resolved"
    assert resolved.location_unverified is True
    assert "parser-resolved" in resolved.display_location
    assert "model cited L31" in resolved.display_location
    assert "L31" not in resolved.display_location.split("model cited")[0]


def test_resolve_advisory_location_unanchored_when_evidence_missing() -> None:
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="switches/jump.cfg",
        line_range=LineRange(start=9, end=9),
        title="NVE risk",
        description="NVE risk",
        evidence="The nve interface lacks IPsec protection entirely.",
        policy_severity=PolicySeverity.UNCLASSIFIED,
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        model_asserted_cwe="CWE-295",
    )
    resolved = resolve_advisory_location(finding, _JUMP_HOST)
    assert resolved.location_source == "unanchored"
    assert resolved.model_cited_line == 9
    assert resolved.parser_resolved_line is None
    assert resolved.display_location == "switches/jump.cfg (location unverified)"
    assert "L9" not in resolved.display_location


def test_summarize_advisory_attribution_counts() -> None:
    resolved_finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="switches/jump.cfg",
        line_range=LineRange(start=9, end=9),
        title="HTTP disabled",
        description="HTTP disabled",
        evidence="no ip http server",
        policy_severity=PolicySeverity.UNCLASSIFIED,
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        model_asserted_cwe="CWE-264",
    )
    unanchored_finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="switches/jump.cfg",
        line_range=LineRange(start=4, end=4),
        title="NVE risk",
        description="NVE risk",
        evidence="fabricated prose only",
        policy_severity=PolicySeverity.UNCLASSIFIED,
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        model_asserted_cwe="CWE-295",
    )
    summary = summarize_advisory_attribution(
        [resolved_finding, unanchored_finding],
        {"switches/jump.cfg": _JUMP_HOST},
    )
    assert summary.parser_resolved == 1
    assert summary.unanchored == 1


def test_is_advisory_finding_detects_model_only() -> None:
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="x.tf",
        title="t",
        description="t",
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        model_asserted_cwe="CWE-20",
    )
    assert is_advisory_finding(finding) is True
