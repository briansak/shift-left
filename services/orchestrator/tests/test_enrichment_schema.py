"""Schema v4 enrichment fields, ReviewSummary, and policy separation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from shift_left.config import CURRENT_SCHEMA_VERSION, AppConfig, load_config
from shift_left.enrichment.scripted import ScriptedEnrichmentEngine
from shift_left.models.schema import (
    Finding,
    FindingSource,
    PolicyRule,
    ReviewResult,
    ReviewSummary,
    TargetKind,
)
from shift_left.policy.loader import PolicyValidationError, validate_raw_policies


def test_finding_schema_includes_enrichment_prose_fields() -> None:
    finding = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="infra/main.tf",
        title="Test",
        description="Desc",
        model_context="[FIXTURE] context",
        recommended_actions=["[FIXTURE] action one"],
        enrichment_source="scripted-fixture",
        enrichment_generated_at=datetime.now(timezone.utc),
    )
    assert finding.model_context.startswith("[FIXTURE]")
    assert finding.recommended_actions


def test_review_summary_is_structurally_advisory() -> None:
    summary = ReviewSummary(
        summary_text="Advisory text",
        suggested_course_of_action="Review hunks",
        findings_covered=["id-1"],
        generator="scripted-fixture",
    )
    assert summary.is_advisory is True


def test_review_result_carries_enrichment_and_analysis_metadata() -> None:
    from shift_left.analysis.result import completed_no_findings
    from shift_left.models.schema import PolicyAction, PullRequestPolicyDecision

    decision = PullRequestPolicyDecision(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        default_action=PolicyAction.FLAG,
        pr_decision=PolicyAction.FLAG,
        explanation="Flagged.",
    )
    result = ReviewResult(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        findings=[],
        policy_decision=decision,
        advisory_action=PolicyAction.FLAG,
        message="done",
        enrichment_unavailable=True,
        analysis_results=[completed_no_findings(TargetKind.CODE)],
        stage_timings_ms={"antares_total": 12},
    )
    assert result.enrichment_unavailable is True
    assert result.analysis_results[0].target_kind == TargetKind.CODE


def test_policy_rule_extra_forbid_rejects_model_asserted_severity() -> None:
    with pytest.raises(ValidationError):
        PolicyRule.model_validate({"model_asserted_severity": "high"})


def test_validate_raw_policies_rejects_enrichment_fields(tmp_path: Path) -> None:
    with pytest.raises(PolicyValidationError, match="forbidden field"):
        validate_raw_policies(
            [
                {
                    "id": "bad",
                    "name": "Bad",
                    "rules": [{"model_context": "must not appear in policy"}],
                }
            ]
        )


def test_scripted_enrichment_engine_marks_fixture_prose() -> None:
    engine = ScriptedEnrichmentEngine()
    finding = Finding(
        source=FindingSource.ANTARES,
        target_kind=TargetKind.CODE,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="app.py",
        title="Likely issue",
        description="From diff",
    )
    payload = engine.enrich_finding(finding)
    assert payload["enrichment_source"] == "scripted-fixture"
    assert payload["model_context"].startswith("[FIXTURE]")
    summary = engine.generate_review_summary([finding])
    assert summary.is_advisory is True
    assert "[FIXTURE]" in summary.summary_text


def test_load_config_requires_schema_version_seven(tmp_path) -> None:
    path = tmp_path / "shift-left.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 4,
                "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
            }
        )
    )
    with pytest.raises(ValueError, match="unsupported schema_version 4"):
        load_config(path)


def test_load_config_accepts_schema_version_seven(tmp_path) -> None:
    path = tmp_path / "shift-left.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": CURRENT_SCHEMA_VERSION,
                "enrichment": {"enabled": False, "engine": "scripted"},
                "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
            }
        )
    )
    config = load_config(path)
    assert config.schema_version == CURRENT_SCHEMA_VERSION
    assert config.enrichment.engine == "scripted"


def test_app_config_default_enrichment_disabled() -> None:
    config = AppConfig()
    assert config.enrichment.enabled is False
