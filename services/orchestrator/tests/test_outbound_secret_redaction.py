"""Outbound and API secret redaction guards."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from shift_left.config import AppConfig
from shift_left.main import app
from shift_left.models.schema import (
    Finding,
    FindingSource,
    LineRange,
    PolicyAction,
    PolicySeverity,
    PullRequestPolicyDecision,
    Severity,
    TargetKind,
)
from shift_left.review.service import ReviewService
from shift_left.ui.api_presentation import (
    API_CONFIG_TEXT_REQUEST_SURFACES,
    API_CONFIG_TEXT_SURFACES,
    API_ROUTES_WITHOUT_CONFIG_TEXT,
    NON_API_CONFIG_TEXT_SURFACES,
    redact_review_result_for_api,
    serialize_findings_for_api,
)
from shift_left.ui.api_route_inspection import (
    verify_clean_routes,
    verify_request_config_text_surfaces,
)


def _iter_json_api_routes() -> list[tuple[str, str]]:
    routes: list[tuple[str, str]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path.startswith("/ui"):
            continue
        for method in sorted(route.methods - {"HEAD"}):
            routes.append((method, route.path))
    return sorted(routes)


def test_every_json_api_route_classified_for_config_text() -> None:
    """New JSON API routes must declare whether they return config-derived text."""
    surfaces = {(item.method, item.path) for item in API_CONFIG_TEXT_SURFACES}
    request_surfaces = {(item.method, item.path) for item in API_CONFIG_TEXT_REQUEST_SURFACES}
    exempt = API_ROUTES_WITHOUT_CONFIG_TEXT
    unclassified: list[tuple[str, str]] = []
    for method, path in _iter_json_api_routes():
        key = (method, path)
        if key in surfaces or key in request_surfaces or key in exempt:
            continue
        unclassified.append(key)
    assert not unclassified, (
        "Unclassified API routes (add to API_CONFIG_TEXT_SURFACES with field_paths "
        f"or API_ROUTES_WITHOUT_CONFIG_TEXT): {unclassified}"
    )


def test_clean_api_routes_do_not_expose_config_text_fields() -> None:
    """Routes in API_ROUTES_WITHOUT_CONFIG_TEXT are verified via response-model inspection."""
    api_routes = [route for route in app.routes if isinstance(route, APIRoute)]
    violations = verify_clean_routes(api_routes, API_ROUTES_WITHOUT_CONFIG_TEXT)
    assert not violations, "Clean routes expose config-text fields:\n" + "\n".join(violations)


def test_request_config_text_surfaces_registered() -> None:
    """Routes that accept config-derived request text must be registered for redaction."""
    api_routes = [route for route in app.routes if isinstance(route, APIRoute)]
    request_surfaces = {(item.method, item.path) for item in API_CONFIG_TEXT_REQUEST_SURFACES}
    violations = verify_request_config_text_surfaces(api_routes, request_surfaces)
    assert not violations, "Request config-text routes not registered:\n" + "\n".join(violations)


def test_non_api_config_surfaces_enumerated() -> None:
    kinds = {item.kind for item in NON_API_CONFIG_TEXT_SURFACES}
    assert "html" in kinds
    assert "download" in kinds
    assert "outbound" in kinds
    paths = {item.path for item in NON_API_CONFIG_TEXT_SURFACES}
    assert "/api/v1/audit/export" in paths
    assert "/ui/coverage" in paths
    assert "/ui/investigations/{investigation_id}" in paths
    assert "/ui/investigations/{investigation_id}/trace" in paths
    assert "forgejo_pr_comment" in paths
    assert "forgejo_commit_status" in paths


def test_config_text_surfaces_declare_field_paths() -> None:
    for surface in API_CONFIG_TEXT_SURFACES:
        assert surface.field_paths, f"{surface.method} {surface.path} missing field_paths"
        assert surface.redaction_fn, f"{surface.method} {surface.path} missing redaction_fn"


def test_request_config_text_surfaces_declare_field_paths() -> None:
    for surface in API_CONFIG_TEXT_REQUEST_SURFACES:
        assert surface.field_paths, f"{surface.method} {surface.path} missing field_paths"
        assert surface.redaction_fn, f"{surface.method} {surface.path} missing redaction_fn"


def test_findings_api_reports_provenance_when_config_unresolvable(tmp_path) -> None:
    """Stored finding at an unresolvable SHA must not leak secrets in model prose."""
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    service = ReviewService(config)

    class _FailingGit:
        async def get_file_content(self, *_args, **_kwargs) -> str:
            raise OSError("config no longer available at recorded SHA")

    service._git = _FailingGit()
    app.state.config = config
    app.state.review_service = service
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="deadbeef",
        file_path="config/edge.cfg",
        title="SNMP community risk",
        description='Model: the community string "public" grants RW access.',
        evidence="snmp-server community public RW",
        policy_severity=PolicySeverity.MEDIUM,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        handler_asserted_cwe="CWE-287",
        trace="handler:IOS-003",
    )
    service._store.save_findings([finding])
    client = TestClient(app)
    response = client.get("/api/v1/findings/o/r/1")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("value_redaction_provenance")
    assert payload["value_redaction_provenance"][0]["source"] in {
        "finding_fields",
        "unavailable",
    }
    description = payload["findings"][0]["description"]
    assert '"public"' not in description
    assert "[REDACTED]" in description
    assert "public internet" not in description  # sanity — unrelated phrase not injected


def test_waiver_reason_redacted_in_display_text() -> None:
    from shift_left.ui.config_redaction import redact_display_text

    reason = "Accepted risk — snmp-server community Sup3rS3cr3tC0mm is lab-only."
    redacted = redact_display_text(reason)
    assert "Sup3rS3cr3tC0mm" not in redacted
    assert "[REDACTED]" in redacted


def test_findings_api_redacts_evidence_not_matched_snippet_field(tmp_path) -> None:
    """Findings API returns ``evidence`` (not UI ``matched_snippet``) and must redact it."""
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    service = ReviewService(config)
    app.state.config = config
    app.state.review_service = service
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="config/edge.cfg",
        line_range=LineRange(start=3, end=3),
        title="SNMP community risk",
        description="SNMP community grants read-write access.",
        evidence="snmp-server community Sup3rS3cr3tC0mm RW",
        policy_severity=PolicySeverity.MEDIUM,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        handler_asserted_cwe="CWE-287",
        trace="handler:IOS-003",
    )
    service._store.save_findings([finding])
    client = TestClient(app)
    response = client.get("/api/v1/findings/o/r/1")
    assert response.status_code == 200
    payload = response.json()
    assert "matched_snippet" not in payload["findings"][0]
    assert payload["findings"][0]["evidence"] is not None
    assert "Sup3rS3cr3tC0mm" not in payload["findings"][0]["evidence"]
    assert "[REDACTED]" in payload["findings"][0]["evidence"]
    stored = service._store.list_for_pr("o/r", "PR-1")[0]
    assert stored.evidence == "snmp-server community Sup3rS3cr3tC0mm RW"


def test_list_findings_api_always_emits_finding_fields_provenance(tmp_path) -> None:
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": True},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    service = ReviewService(config)
    app.state.config = config
    app.state.review_service = service
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="config/edge.cfg",
        title="SNMP community risk",
        description="SNMP community grants read-write access.",
        evidence="snmp-server community Sup3rS3cr3tC0mm RW",
        policy_severity=PolicySeverity.MEDIUM,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        handler_asserted_cwe="CWE-287",
        trace="handler:IOS-003",
    )
    service._store.save_findings([finding])
    client = TestClient(app)
    response = client.get("/api/v1/findings")
    assert response.status_code == 200
    payload = response.json()
    assert "value_redaction_provenance" in payload
    assert len(payload["value_redaction_provenance"]) == 1
    assert payload["value_redaction_provenance"][0]["source"] == "finding_fields"
    assert payload["value_redaction_provenance"][0]["finding_id"] == finding.id


def test_serialize_findings_for_api_redacts_description_prose() -> None:
    finding = Finding(
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
        file_path="config/edge.cfg",
        title="Deterministic rule: IOS-003",
        description="SNMP community 'public' is a well-known default credential.",
        policy_severity=PolicySeverity.MEDIUM,
        model_asserted_severity=Severity.MEDIUM,
        handler_asserted_cwe="CWE-284",
        trace="handler:IOS-003",
    )
    redacted = serialize_findings_for_api([finding])["findings"][0]
    assert "'public'" not in redacted.description
    assert "[REDACTED]" in redacted.description


def _policy_decision() -> PullRequestPolicyDecision:
    return PullRequestPolicyDecision(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        default_action=PolicyAction.FLAG,
        pr_decision=PolicyAction.FLAG,
        explanation="Flagged for human review.",
    )


def test_pr_comment_ios003_redacts_secret_preserves_rule_id(tmp_path) -> None:
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1", "comment_prefix": "[shift-left]"},
            "ui": {"enabled": False},
            "findings_store": {"sqlite_path": str(tmp_path / "shift-left.db")},
            "audit": {"sqlite_path": str(tmp_path / "shift-left.db")},
            "auth": {"sqlite_path": str(tmp_path / "shift-left.db")},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    service = ReviewService(config)
    finding = Finding(
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="config/edge.cfg",
        line_range=LineRange(start=1, end=1),
        title="Deterministic rule: IOS-003",
        description="SNMP community 'public' is a well-known default credential.",
        evidence="snmp-server community public RW",
        policy_severity=PolicySeverity.MEDIUM,
        model_asserted_severity=Severity.MEDIUM,
        handler_asserted_cwe="CWE-284",
        trace="handler:IOS-003",
    )
    body = service._format_comment([finding], _policy_decision())
    assert "handler:IOS-003" in body
    assert "IOS-003" in body
    assert "snmp-server community public" not in body
    assert "'public'" not in body
    assert "[REDACTED]" in body


def test_pr_comment_ios003_sample_rendered_markdown() -> None:
    """Documented sample: IOS-003 on snmp-server community public RW."""
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": False},
            "findings_store": {"sqlite_path": "/tmp/unused.db"},
            "audit": {"sqlite_path": "/tmp/unused.db"},
            "auth": {"sqlite_path": "/tmp/unused.db"},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    service = ReviewService(config)
    finding = Finding(
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="config/edge.cfg",
        line_range=LineRange(start=1, end=1),
        title="Deterministic rule: IOS-003",
        description="SNMP community grants read-write access.",
        evidence="snmp-server community public RW",
        policy_severity=PolicySeverity.MEDIUM,
        model_asserted_severity=Severity.MEDIUM,
        handler_asserted_cwe="CWE-284",
        trace="handler:IOS-003",
    )
    sample = service._format_comment([finding], _policy_decision())
    assert "snmp-server community public" not in sample
    assert "handler:IOS-003" in sample
    assert "snmp-server community [REDACTED]" in sample


def test_review_service_logs_do_not_emit_raw_config_secrets(
    tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="shift_left.review.service")
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": False},
            "findings_store": {"sqlite_path": str(tmp_path / "shift-left.db")},
            "audit": {"sqlite_path": str(tmp_path / "shift-left.db")},
            "auth": {"sqlite_path": str(tmp_path / "shift-left.db")},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    service = ReviewService(config)
    secret_line = "snmp-server community Sup3rS3cr3tC0mm RW"
    finding = Finding(
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="config/edge.cfg",
        title="Deterministic rule: IOS-003",
        description=f"SNMP community 'Sup3rS3cr3tC0mm' is weak.",
        evidence=secret_line,
        policy_severity=PolicySeverity.MEDIUM,
        model_asserted_severity=Severity.MEDIUM,
        handler_asserted_cwe="CWE-284",
        trace="handler:IOS-003",
    )
    service._format_comment([finding], _policy_decision())
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert secret_line not in log_text
    assert "Sup3rS3cr3tC0mm" not in log_text


def test_review_api_result_redacts_findings() -> None:
    decision = _policy_decision()
    finding = Finding(
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="config/edge.cfg",
        title="IOS-003",
        description="SNMP community grants read-write access.",
        evidence="snmp-server community LeakedSecret RW",
        policy_severity=PolicySeverity.MEDIUM,
        model_asserted_severity=Severity.MEDIUM,
        handler_asserted_cwe="CWE-284",
        trace="handler:IOS-003",
    )
    from shift_left.models.schema import ReviewResult

    result = ReviewResult(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        findings=[finding],
        policy_decision=decision,
        advisory_action=PolicyAction.FLAG,
        message="done",
    )
    redacted = redact_review_result_for_api(result)
    assert "LeakedSecret" not in (redacted.findings[0].evidence or "")


def test_review_api_omits_advisory_findings_and_summary() -> None:
    from shift_left.models.schema import ReviewResult, ReviewSummary

    handler = Finding(
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="firewall/edge.rules",
        title="Deterministic rule: ASA-001",
        description="ASA ACL permit ACE allows any source to any destination.",
        handler_asserted_cwe="CWE-284",
        trace="handler:ASA-001",
        construct_key="ace:outside:permit ip any any",
    )
    advisory = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="firewall/edge.rules",
        title="Fabricated any/any finding",
        description="Model claimed a weakness with invented evidence.",
        evidence="permit ip any any fabricated",
        model_asserted_cwe="CWE-284",
    )
    result = ReviewResult(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        findings=[handler, advisory],
        policy_decision=_policy_decision(),
        advisory_action=PolicyAction.FLAG,
        message="Review complete.",
        review_summary=ReviewSummary(
            summary_text="Reviewer summary covering Fabricated any/any finding.",
            suggested_course_of_action="Treat the fabricated ACE as blocking.",
            findings_covered=[advisory.id],
            generator="scripted-fixture",
        ),
    )
    presented = redact_review_result_for_api(result)
    assert [item.id for item in presented.findings] == [handler.id]
    assert presented.review_summary is None
    assert "omitted from this response" in presented.message
    assert all(item.source != FindingSource.FOUNDATION_SEC for item in presented.findings)
