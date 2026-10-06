"""Tests for constrained-output finding validation."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
for path in (VALIDATION, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from constrained_finding_validation import (  # noqa: E402
    partition_constrained_findings,
    validate_constrained_finding,
)


def test_valid_finding_with_verbatim_evidence_and_in_range_lines() -> None:
    content = "action = \"ALLOW\"\nsource_network_literals = [{ value = \"0.0.0.0/0\" }]\n"
    finding = {
        "line_start": 2,
        "line_end": 2,
        "evidence": "source_network_literals = [{ value = \"0.0.0.0/0\" }]",
    }
    ok, reason = validate_constrained_finding(
        finding, content=content, line_min=1, line_max=2
    )
    assert ok is True
    assert reason is None


def test_rejects_evidence_not_in_content() -> None:
    content = "action = \"ALLOW\"\n"
    finding = {"line_start": 1, "line_end": 1, "evidence": "action = \"DENY\""}
    ok, reason = validate_constrained_finding(
        finding, content=content, line_min=1, line_max=1
    )
    assert ok is False
    assert reason == "evidence_not_substring"


def test_rejects_line_out_of_range() -> None:
    content = "action = \"ALLOW\"\n"
    finding = {"line_start": 5, "line_end": 5, "evidence": "action = \"ALLOW\""}
    ok, reason = validate_constrained_finding(
        finding, content=content, line_min=1, line_max=1
    )
    assert ok is False
    assert reason == "line_out_of_range"


def test_partition_splits_valid_and_invalid() -> None:
    content = "line one\nline two\n"
    findings = [
        {"line_start": 1, "line_end": 1, "evidence": "line one"},
        {"line_start": 9, "line_end": 9, "evidence": "line two"},
    ]
    valid, invalid = partition_constrained_findings(
        findings, content=content, line_min=1, line_max=2
    )
    assert len(valid) == 1
    assert len(invalid) == 1
    assert invalid[0]["rejection_reason"] == "line_out_of_range"
