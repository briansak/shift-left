"""Silent-pass guard for uncovered Terraform provider prefixes."""

from __future__ import annotations

from pathlib import Path

import pytest

from shift_left.config import AppConfig
from shift_left.handlers.config.gate_findings import findings_for_corpus_file
from shift_left.handlers.config.hcl_provider_coverage import (
    FTD_UNCOVERED_PROVIDER_RULE_ID,
    HCL_UNCOVERED_PROVIDER_RULE_ID,
    is_resource_type_covered,
    uncovered_provider_matches,
    uncovered_provider_prefixes,
)
from shift_left.handlers.config.registry_matching import match_registry_rules
from shift_left.models.schema import PolicyAction
from shift_left.policy.engine import PolicyEngine
from shift_left.policy.severity import apply_policy_severities

_ROOT = Path(__file__).resolve().parents[3]
_IOSXE_FIXTURE = _ROOT / "validation/corpus/holdout/cisco_ftd/holdout-ftd-iosxe-uncovered.tf"


def _minimal_config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": "/tmp/shift-left-hcl-provider-test.db"},
            "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
        }
    )


def test_covered_prefix_enumeration() -> None:
    assert is_resource_type_covered("aws_security_group", "generic_terraform")
    assert is_resource_type_covered("azurerm_network_security_rule", "generic_terraform")
    assert is_resource_type_covered("google_compute_firewall", "generic_terraform")
    assert is_resource_type_covered("fmc_access_rule", "generic_terraform")
    assert not is_resource_type_covered("iosxe_acl", "generic_terraform")
    assert is_resource_type_covered("fmc_host", "cisco_ftd")
    assert not is_resource_type_covered("iosxe_acl", "cisco_ftd")


def test_iosxe_resources_are_uncovered_for_ftd_target() -> None:
    content = _IOSXE_FIXTURE.read_text()
    assert uncovered_provider_prefixes("cisco_ftd", content) == ["iosxe_"]


def test_iosxe_tf_does_not_pass_silently_on_ftd_target() -> None:
    content = _IOSXE_FIXTURE.read_text()
    matches = match_registry_rules("cisco_ftd", content)
    rule_ids = {match.rule_id for match in matches}
    assert FTD_UNCOVERED_PROVIDER_RULE_ID in rule_ids
    assert "FTD-001" not in rule_ids


def test_gate_flags_uncovered_iosxe_provider() -> None:
    content = _IOSXE_FIXTURE.read_text()
    config = _minimal_config()
    findings = apply_policy_severities(
        findings_for_corpus_file(
            path="terraform/holdout-ftd-iosxe-uncovered.tf",
            target_type="cisco_ftd",
            content=content,
            config=config,
        ),
        config,
    )
    traces = {finding.trace for finding in findings}
    assert f"handler:{FTD_UNCOVERED_PROVIDER_RULE_ID}" in traces
    engine = PolicyEngine(config.policy)
    result = engine.evaluate(
        repo="eval/corpus",
        pr_ref="eval",
        commit_sha="eval",
        findings=findings,
    )
    assert result.pr_action == PolicyAction.FLAG
    assert result.pr_action != PolicyAction.PASS


def test_uncovered_provider_match_is_flag_not_block_rule() -> None:
    content = _IOSXE_FIXTURE.read_text()
    matches = uncovered_provider_matches(content, "cisco_ftd")
    assert len(matches) == 1
    assert matches[0].pattern_id == FTD_UNCOVERED_PROVIDER_RULE_ID


def test_generic_terraform_iosxe_gets_hcl_002() -> None:
    content = _IOSXE_FIXTURE.read_text()
    matches = match_registry_rules("generic_terraform", content)
    assert any(match.rule_id == HCL_UNCOVERED_PROVIDER_RULE_ID for match in matches)
