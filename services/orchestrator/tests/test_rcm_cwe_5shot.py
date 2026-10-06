"""Tests for Experiment D2 5-shot RCM prompt construction."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
for path in (ROOT / "services" / "orchestrator", ROOT / "services" / "shift-left-shared", VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from rcm_cwe_5shot import (  # noqa: E402
    SHOT_COUNT,
    build_5shot_prompts,
    build_5shot_rcm_prompt,
    defect_context,
    select_shot_examples,
)
from rcm_cwe_inputs import build_rcm_instances  # noqa: E402


def test_defect_context_excludes_expected_cwe_label():
    instances = build_rcm_instances()
    instance = instances[0]
    context = defect_context(instance)
    assert instance.expected_cwe not in context
    assert instance.config_block.strip() in context
    assert instance.match_description in context


def test_select_shot_examples_excludes_target_and_returns_five():
    instances = build_rcm_instances()
    examples = select_shot_examples(instances, 0)
    assert len(examples) == SHOT_COUNT
    assert instances[0] not in examples


def test_build_5shot_prompt_ends_with_the_cwe_is_for_completion():
    instances = build_rcm_instances()
    target = instances[10]
    examples = select_shot_examples(instances, 10)
    prompt = build_5shot_rcm_prompt(target, examples)
    assert prompt.endswith(f"{defect_context(target)}. The CWE is")
    assert prompt.count("The CWE is") == SHOT_COUNT + 1
    for example in examples:
        assert f"The CWE is {example.expected_cwe}." in prompt
    assert target.instance_id not in {example.instance_id for example in examples}


def test_build_5shot_prompts_rotates_examples_per_instance():
    instances = build_rcm_instances()
    rows = build_5shot_prompts(instances)
    assert len(rows) == 150
    first_shots = rows[0][2]
    second_shots = rows[1][2]
    assert first_shots != second_shots
    assert instances[0].instance_id not in first_shots
    assert instances[1].instance_id not in second_shots
