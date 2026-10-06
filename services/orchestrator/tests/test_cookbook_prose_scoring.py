"""Tests for Experiment F cookbook prose detection scoring."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
for path in (ROOT / "services" / "orchestrator", ROOT / "services" / "shift-left-shared", VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from cookbook_prose_inputs import build_cookbook_inputs  # noqa: E402
from cookbook_prose_prompt import COOKBOOK_PROMPT_SHAPE, build_cookbook_prompt  # noqa: E402
from cookbook_prose_scoring import defect_detected, score_detection_recall  # noqa: E402
from eval_model import RULE_SEMANTICS  # noqa: E402


def test_prompt_shape_has_no_structured_fields():
    prompt = build_cookbook_prompt(file_path="policies/example.tf", content="resource \"x\" {}")
    assert COOKBOOK_PROMPT_SHAPE in prompt
    assert "security auditor" in prompt.lower()
    assert "misconfigurations" in prompt.lower()
    assert "recommended fix" in prompt.lower()
    assert "Do not include CWE identifiers" in prompt
    assert "line numbers" in prompt.lower()
    assert "evidence excerpts" in prompt.lower()
    assert "line_start" not in prompt
    assert "JSON" not in prompt


def test_build_cookbook_inputs_counts():
    file_runs, instances = build_cookbook_inputs()
    assert len(instances) == 150
    assert len(file_runs) == 119
    assert all(item.expected_rule_ids for item in file_runs)


def test_defect_detected_matches_summary():
    sem = RULE_SEMANTICS["FTD-001"]
    prose = (
        "Detected misconfiguration: FMC ALLOW rule uses internet-wide resolved source "
        "or destination networks including via object references. "
        "Severity: high. Recommended fix: restrict source and destination to required networks."
    )
    detected, score = defect_detected(
        prose,
        defect_summary=sem.defect_summary,
        rule_id=sem.rule_id,
        target_type=sem.target_type,
    )
    assert detected is True
    assert score > 0.12


def test_score_detection_recall_per_target_type():
    rows = [
        {
            "target_type": "cisco_ftd",
            "detected": True,
        },
        {
            "target_type": "cisco_ftd",
            "detected": False,
        },
        {
            "target_type": "cisco_ios_xe",
            "detected": True,
        },
    ]
    summary = score_detection_recall(rows)
    assert summary["labeled_defects"] == 3
    assert summary["detected"] == 2
    assert summary["per_target_type"]["cisco_ftd"]["detected"] == 1
    assert summary["per_target_type"]["cisco_ftd"]["total"] == 2
