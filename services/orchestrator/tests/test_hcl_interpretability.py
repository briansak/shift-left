"""HCL parser availability and CWE-754 interpretability gate coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from shift_left.config import AppConfig
from shift_left.handlers.config.gate_findings import findings_for_corpus_file
from shift_left.handlers.config.hcl_parse import (
    HclParseStatus,
    count_hcl_resource_blocks,
    parse_hcl_content,
)
from shift_left.handlers.config.registry_matching import match_registry_rules
from shift_left.models.schema import PolicyAction
from shift_left.policy.engine import PolicyEngine
from shift_left.policy.severity import apply_policy_severities

_ROOT = Path(__file__).resolve().parents[3]
_TF_FIXTURE = _ROOT / "validation/corpus/config/generic_terraform/aws-open-sg.tf"


def _minimal_config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": "/tmp/shift-left-hcl-test.db"},
            "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
        }
    )


def _unavailable_hcl_status(content: str) -> HclParseStatus:
    return HclParseStatus(
        available=False,
        parsed=None,
        error="No module named 'hcl2'",
        resource_block_count=count_hcl_resource_blocks(content),
    )


def test_gate_blocks_when_hcl_parser_unavailable_on_tf_violation_file() -> None:
    """Without python-hcl2 the gate must BLOCK (CWE-754), not silently PASS."""
    content = _TF_FIXTURE.read_text()
    config = _minimal_config()

    with patch(
        "shift_left.handlers.config.hcl_parse.parse_hcl_content",
        side_effect=_unavailable_hcl_status,
    ):
        findings = apply_policy_severities(
            findings_for_corpus_file(
                path="terraform/aws-open-sg.tf",
                target_type="generic_terraform",
                content=content,
                config=config,
            ),
            config,
        )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.handler_asserted_cwe == "CWE-754"
    assert finding.trace == "handler:HCL-001"
    assert "python-hcl2 is not available" in (finding.description or "")

    engine = PolicyEngine(config.policy)
    result = engine.evaluate(
        repo="org/repo",
        pr_ref="PR-42",
        commit_sha="deadbeef",
        findings=findings,
    )
    assert result.pr_action == PolicyAction.BLOCK


def test_match_registry_rules_cwe_754_when_parser_unavailable() -> None:
    content = 'resource "aws_security_group_rule" "wide" { cidr_blocks = ["0.0.0.0/0"] }\n'
    with patch(
        "shift_left.handlers.config.hcl_parse.parse_hcl_content",
        side_effect=_unavailable_hcl_status,
    ):
        matches = match_registry_rules("generic_terraform", content)
    assert len(matches) == 1
    assert matches[0].cwe == "CWE-754"
    assert matches[0].rule_id == "HCL-001"


@pytest.mark.parametrize("target_type", ["generic_terraform", "cisco_ftd"])
def test_hcl_target_types_block_on_parser_unavailable(target_type: str) -> None:
    content = 'resource "example" "demo" { value = 1 }\n'
    with patch(
        "shift_left.handlers.config.hcl_parse.parse_hcl_content",
        side_effect=_unavailable_hcl_status,
    ):
        matches = match_registry_rules(target_type, content)
    assert matches and matches[0].cwe == "CWE-754"
