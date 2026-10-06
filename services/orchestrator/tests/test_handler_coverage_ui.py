"""Handler coverage report and UI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shift_left.auth.context import TokenCapability  # noqa: E402
from shift_left.auth.deps import TOKEN_COOKIE_NAME  # noqa: E402
from shift_left.auth.tokens import mint_api_token  # noqa: E402
from shift_left.config import AppConfig  # noqa: E402
from shift_left.handlers.config.coverage_report import (  # noqa: E402
    coverage_view_rows,
    format_parse_coverage_summary,
    model_cwe_advisory_summary,
    parse_coverage_table_rows,
)
from shift_left.main import app  # noqa: E402
from shift_left.models.schema import Finding, FindingSource, PolicySeverity, TargetKind  # noqa: E402
from shift_left.review.service import ReviewService  # noqa: E402
from validation.eval_handlers import build_rule_gaps  # noqa: E402


def test_build_rule_gaps_include_disabled_rules_with_cwe() -> None:
    gaps = {item["rule_id"]: item for item in build_rule_gaps()}
    assert set(gaps) == {"ASA-003", "FTD-007", "IOS-009"}
    assert "HCL-001" not in gaps
    assert gaps["ASA-003"]["cwe"] == "CWE-778"
    assert gaps["ASA-003"]["status"] == "disabled"
    assert gaps["FTD-007"]["cwe"] == "CWE-693"
    assert gaps["FTD-007"]["reason"]
    assert gaps["IOS-009"]["cwe"] == "CWE-693"


def test_parse_coverage_small_denominator_uses_count_phrase() -> None:
    primary, meta = format_parse_coverage_summary(19, 21, 19 / 21, "evaluable CLI lines")
    assert primary == "19 of 21 evaluable CLI lines"
    assert meta is None


def test_parse_coverage_large_denominator_uses_percent_headline() -> None:
    primary, meta = format_parse_coverage_summary(91, 92, 91 / 92, "evaluable ACL lines")
    assert primary == "98.9%"
    assert meta == "91 of 92 evaluable ACL lines"


def test_parse_coverage_table_rows_cover_cli_and_acl_shapes() -> None:
    report = {
        "parse_coverage": {
            "cisco_nx_os": {
                "parsed_cli_lines": 19,
                "total_evaluable_cli_lines": 21,
                "parse_coverage_ratio": 0.9048,
            },
            "cisco_secure_firewall": {
                "parsed_acl_lines": 91,
                "total_acl_bearing_lines": 92,
                "remark_acl_lines": 2,
                "parse_coverage_ratio": 0.9891,
            },
        }
    }
    rows = {row["target_type"]: row for row in parse_coverage_table_rows(report)}
    assert rows["cisco_nx_os"]["coverage"] == "19 of 21 evaluable CLI lines"
    assert rows["cisco_secure_firewall"]["coverage"] == "98.9%"


def test_coverage_view_rows_surface_disabled_rules() -> None:
    report = {
        "rule_gaps": build_rule_gaps(),
        "generated_corpus": {"per_rule": {"ASA-001": {"true_positives": 1}}},
        "holdout_corpus": {"per_rule": {}},
    }
    rows = {row["rule_id"]: row for row in coverage_view_rows(report)}
    assert rows["ASA-003"]["status"] == "disabled"
    assert rows["ASA-003"]["cwe"] == "CWE-778"
    assert rows["FTD-007"]["status"] == "disabled"
    assert rows["ASA-001"]["status"] == "enabled"
    assert rows["CLI-001"]["status"] == "enforced_prematch"
    assert rows["CLI-001"]["cwe"] == "CWE-754"
    assert rows["CLI-001"]["severity"] == "block"
    assert rows["HCL-001"]["status"] == "enforced_prematch"


@pytest.fixture
def coverage_ui_client(tmp_path, monkeypatch):
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "ui": {"enabled": True, "require_loopback_client": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
        }
    )
    service = ReviewService(config)
    app.state.config = config
    app.state.review_service = service
    app.state.token_store = service.token_store
    client = TestClient(app)
    _, token = mint_api_token(
        service.token_store,
        label="coverage-ui",
        actor="reviewer",
        capabilities=[TokenCapability.REVIEW],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, token)
    return client


def test_handler_coverage_report_is_non_degenerate() -> None:
    """A stub (empty parse_coverage, no baseline, zero labels) must fail CI."""
    report_path = ROOT / "validation" / "reports" / "handler-coverage.json"
    report = json.loads(report_path.read_text())
    corpus_version = report.get("corpus_version")
    assert isinstance(corpus_version, str) and corpus_version.strip()
    baseline = report.get("handler_baseline")
    assert isinstance(baseline, dict)
    labeled = int(baseline.get("labeled_defect_instances") or 0)
    assert labeled > 0
    per_rule = baseline.get("per_rule") or {}
    assert per_rule
    tp_sum = sum(int(metrics.get("true_positives") or 0) for metrics in per_rule.values())
    assert tp_sum == int(baseline["true_positives"])
    parse_coverage = report.get("parse_coverage") or {}
    assert parse_coverage, "parse_coverage must list per-target-type counts"


def test_ui_coverage_page_lists_disabled_rule_gaps(coverage_ui_client, tmp_path, monkeypatch) -> None:
    sample = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "fmc_provider_version": "2.0.1",
        "rule_gaps": build_rule_gaps(),
        "parse_coverage": {},
        "generated_corpus": {
            "gate_outcomes": {"BLOCK": 0, "FLAG": 0, "PASS": 0},
            "per_rule": {},
        },
        "holdout_corpus": {
            "gate_outcomes": {"BLOCK": 0, "FLAG": 0, "PASS": 0},
            "per_rule": {},
        },
        "gate_outcomes": {
            "generated_summary": {"pass": 0, "flag": 0, "block": 0},
            "holdout_summary": {"pass": 0, "flag": 0, "block": 0},
        },
    }
    report_path = tmp_path / "handler-coverage.json"
    report_path.write_text(json.dumps(sample))
    monkeypatch.setattr(
        "shift_left.ui.router.load_handler_coverage_report",
        lambda: json.loads(report_path.read_text()),
    )
    response = coverage_ui_client.get("/ui/coverage")
    assert response.status_code == 200
    body = response.text
    assert "ASA-003" in body
    assert "CWE-778" in body
    assert "FTD-007" in body
    assert "disabled" in body


def test_ui_coverage_page_shows_unrecognized_model_cwe_tally(coverage_ui_client) -> None:
    client = coverage_ui_client
    service = app.state.review_service
    service._store.save_findings(
        [
            Finding(
                source=FindingSource.FOUNDATION_SEC,
                target_kind=TargetKind.CONFIG,
                repo="o/r",
                pr_ref="PR-9",
                commit_sha="abc",
                file_path="terraform/x.tf",
                model_asserted_cwe="CWE-99999",
                model_cwe_recognized=False,
                policy_severity=PolicySeverity.UNCLASSIFIED,
                title="advisory",
                description="advisory",
            )
        ]
    )
    response = client.get("/ui/coverage")
    assert response.status_code == 200
    body = response.text
    assert "Model-asserted CWE advisory" in body
    assert "CWE-99999" in body
    assert model_cwe_advisory_summary(service._store.list_filtered(limit=100))["total"] == 1


def test_ui_coverage_page_renders_real_report_shape(coverage_ui_client) -> None:
    """Regression: template must match handler-coverage.json gate_outcomes layout."""
    report_path = ROOT / "validation" / "reports" / "handler-coverage.json"
    if not report_path.is_file():
        pytest.skip("handler-coverage.json not generated")
    response = coverage_ui_client.get("/ui/coverage")
    assert response.status_code == 200
    assert "Gate outcomes" in response.text
    assert "BLOCK=" in response.text
    assert "CLI-001" in response.text
    assert "enforced_prematch" in response.text
    assert "CLI-001" in response.text
    assert "enforced_prematch" in response.text
