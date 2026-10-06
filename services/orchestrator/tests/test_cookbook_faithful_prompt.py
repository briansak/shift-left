"""Tests for Experiment H cookbook-faithful prompt shape."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
if str(VALIDATION) not in sys.path:
    sys.path.insert(0, str(VALIDATION))

from cookbook_faithful_inputs import build_faithful_inputs  # noqa: E402
from cookbook_faithful_prompt import build_cookbook_faithful_prompt  # noqa: E402


def test_build_cookbook_faithful_prompt_matches_configuration_assessment_shape() -> None:
    prompt = build_cookbook_faithful_prompt(config_text="resource \"x\" {}")
    assert "line-by-line" in prompt
    assert "## CONFIGURATION" in prompt
    assert "Detected misconfiguration" in prompt
    assert "Severity (Low/Medium/High)" in prompt
    assert "Recommended fix" in prompt
    assert 'resource "x" {}' in prompt


def test_build_faithful_inputs_count() -> None:
    file_runs, instances = build_faithful_inputs()
    assert len(instances) == 150
    assert file_runs
    for run in file_runs:
        assert run.config_content.strip()
        assert run.prompt.strip()
