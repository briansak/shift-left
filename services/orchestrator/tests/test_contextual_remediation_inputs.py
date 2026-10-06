"""Tests for Experiment G contextual remediation inputs."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
for path in (ROOT / "services" / "orchestrator", ROOT / "services" / "shift-left-shared", VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from contextual_remediation_inputs import build_remediation_instances  # noqa: E402


def test_build_remediation_instances_count_and_prompt_shape():
    instances = build_remediation_instances()
    assert len(instances) == 150
    for instance in instances:
        assert instance.cwe.startswith("CWE-")
        assert instance.defect_summary
        assert instance.registry_remediation
        assert instance.config_block.strip()
        assert instance.surrounding_context
        assert instance.known_identifiers
        assert "Do NOT detect new issues" in instance.prompt
        assert "Do not quote evidence" in instance.prompt
        assert instance.rule_id in instance.prompt
        assert instance.cwe in instance.prompt
