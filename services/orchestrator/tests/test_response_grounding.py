"""Tests for Experiment H grounding checks."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
if str(VALIDATION) not in sys.path:
    sys.path.insert(0, str(VALIDATION))

from response_grounding import aggregate_grounding, score_grounding  # noqa: E402


def test_score_grounding_flags_invented_cidr() -> None:
    config = 'resource "aws_security_group" "app" {\n  cidr_blocks = ["10.0.0.0/16"]\n}\n'
    response = "Restrict ingress to 192.168.1.0/24 instead of 0.0.0.0/0."
    result = score_grounding(response, config)
    assert result["has_ungrounded_references"] is True
    assert any("192.168" in item for item in result["ungrounded_references"])


def test_score_grounding_accepts_literals_from_config() -> None:
    config = 'access-list OUTSIDE_IN extended permit tcp 10.0.0.0 255.0.0.0 any\n'
    response = "Narrow source 10.0.0.0 on OUTSIDE_IN."
    result = score_grounding(response, config)
    assert result["ungrounded_reference_count"] == 0


def test_aggregate_grounding_summarizes_file_rows() -> None:
    summary = aggregate_grounding(
        [
            {"total_reference_count": 4, "ungrounded_reference_count": 2, "has_ungrounded_references": True},
            {"total_reference_count": 2, "ungrounded_reference_count": 0, "has_ungrounded_references": False},
        ]
    )
    assert summary["file_count"] == 2
    assert summary["files_with_ungrounded_references"] == 1
    assert summary["ungrounded_reference_count"] == 2
    assert summary["total_reference_count"] == 6
    assert summary["ungrounded_reference_rate"] == round(2 / 6, 4)
