"""Schema v5 handler_asserted_cwe policy derivation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shift_left.config import AppConfig
from shift_left.models.schema import (
    Finding,
    FindingSource,
    PolicyRule,
    PolicySeverity,
    Severity,
    TargetKind,
)
from shift_left.policy.loader import PolicyValidationError, validate_raw_policies
from shift_left.policy.severity import apply_policy_severities


def test_policy_severity_from_handler_cwe_only() -> None:
    config = AppConfig.model_validate({"findings_store": {"sqlite_path": "/tmp/x.db"}})
    finding = apply_policy_severities(
        [
            Finding(
                source=FindingSource.FOUNDATION_SEC,
                target_kind=TargetKind.CONFIG,
                repo="o/r",
                pr_ref="PR-1",
                commit_sha="abc",
                file_path="infra/main.tf",
                model_asserted_cwe="CWE-20",
                handler_asserted_cwe="CWE-284",
                model_asserted_severity=Severity.HIGH,
                title="T",
                description="D",
            )
        ],
        config,
    )[0]
    assert finding.policy_severity == PolicySeverity.HIGH


def test_model_cwe_without_handler_is_unclassified() -> None:
    config = AppConfig.model_validate({"findings_store": {"sqlite_path": "/tmp/x.db"}})
    finding = apply_policy_severities(
        [
            Finding(
                source=FindingSource.ANTARES,
                target_kind=TargetKind.CODE,
                repo="o/r",
                pr_ref="PR-1",
                commit_sha="abc",
                file_path="app/db.py",
                model_asserted_cwe="CWE-89",
                model_asserted_severity=Severity.HIGH,
                title="T",
                description="D",
            )
        ],
        config,
    )[0]
    assert finding.policy_severity == PolicySeverity.UNCLASSIFIED


def test_policy_rule_rejects_model_asserted_cwe_field() -> None:
    with pytest.raises(ValidationError):
        PolicyRule.model_validate({"model_asserted_cwe": "CWE-89"})


def test_validate_raw_policies_rejects_model_asserted_cwe() -> None:
    with pytest.raises(PolicyValidationError, match="forbidden field"):
        validate_raw_policies(
            [
                {
                    "id": "bad",
                    "name": "Bad",
                    "rules": [{"model_asserted_cwe": "CWE-89"}],
                }
            ]
        )


def test_legacy_cwe_field_maps_to_model_asserted() -> None:
    finding = Finding.model_validate(
        {
            "source": "antares",
            "target_kind": "code",
            "repo": "o/r",
            "pr_ref": "PR-1",
            "commit_sha": "abc",
            "file_path": "app.py",
            "cwe": "CWE-78",
            "title": "T",
            "description": "D",
        }
    )
    assert finding.model_asserted_cwe == "CWE-78"
    assert finding.cwe == "CWE-78"
