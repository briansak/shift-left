"""Terraform deterministic matching is owned by the orchestrator gate, not the model server."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from foundation_sec_server.analyzer import ConfigAnalyzer
from foundation_sec_server.config_registry import registry_rule_line_set_for_path
from foundation_sec_server.engine import ScriptedEvalEngine
from foundation_sec_server.handlers.cwe_rules import match_handler_cwe, match_handler_cwes
from foundation_sec_server.handlers.registry import TERRAFORM
from foundation_sec_server.workflow_guards import is_ci_workflow_path
from shift_left.handlers.config.registry_matching import registry_rule_line_set_for_path as orch_lines

ROOT = Path(__file__).resolve().parents[3]
HOLDOUT = ROOT / "validation" / "holdout-terraform"
INSECURE = ROOT / "sample-firewall" / "terraform" / "insecure.tf"
WORKFLOW = ROOT / "templates" / "forgejo" / "workflows" / "shift-left-review.yml"
CORPUS = ROOT / "validation" / "corpus" / "config" / "generic_terraform" / "aws-open-sg.tf"


def test_model_server_does_not_match_terraform_handler_rules() -> None:
    content = INSECURE.read_text()
    assert match_handler_cwes(chunk_content=content, handler=TERRAFORM) == []
    assert match_handler_cwe(chunk_content=content, handler=TERRAFORM) is None


def test_config_registry_matches_orchestrator_registry_lines() -> None:
    content = CORPUS.read_text()
    path = "terraform/aws-open-sg.tf"
    target_type = "generic_terraform"
    assert registry_rule_line_set_for_path(target_type, path, content) == orch_lines(
        target_type, path, content
    )
    assert ("TF-001", 11) in registry_rule_line_set_for_path(target_type, path, content)


def test_analyzer_never_emits_handler_asserted_cwe_for_terraform() -> None:
    content = (HOLDOUT / "aws-open-sg-rule.tf").read_text()
    analyzer = ConfigAnalyzer(ScriptedEvalEngine())
    result = analyzer.analyze_files(
        [{"path": "terraform/aws-open-sg-rule.tf", "hunks": [{"new_start": 1, "content": content}]}]
    )
    findings = result["findings"]
    assert findings
    assert all(item.get("handler_asserted_cwe") is None for item in findings)


def test_analyzer_deterministic_across_three_runs() -> None:
    content = INSECURE.read_text()
    analyzer = ConfigAnalyzer(ScriptedEvalEngine())
    payload = [{"path": "terraform/insecure.tf", "hunks": [{"new_start": 1, "content": content}]}]
    outputs = []
    for _ in range(3):
        result = analyzer.analyze_files(payload)
        outputs.append(json.dumps(result["findings"], sort_keys=True))
    assert outputs[0] == outputs[1] == outputs[2]


def test_ci_workflow_skipped_by_analyzer() -> None:
    content = WORKFLOW.read_text()
    assert is_ci_workflow_path(".forgejo/workflows/shift-left-review.yml")
    analyzer = ConfigAnalyzer(ScriptedEvalEngine())
    result = analyzer.analyze_files(
        [
            {
                "path": ".forgejo/workflows/shift-left-review.yml",
                "hunks": [{"new_start": 1, "content": content}],
            }
        ]
    )
    assert result["findings"] == []


@pytest.mark.parametrize(
    "filename",
    [
        "azure-nsg-any-any.tf",
        "aws-open-sg-rule.tf",
        "gcp-open-firewall.tf",
        "fmc-allow-inbound.tf",
    ],
)
def test_holdout_terraform_files_match_tf001_via_gate_registry(filename: str) -> None:
    content = (HOLDOUT / filename).read_text()
    lines = registry_rule_line_set_for_path("generic_terraform", f"terraform/{filename}", content)
    assert any(rule_id == "TF-001" for rule_id, _line in lines), f"expected TF-001 in {lines}"
