"""Advisory findings stay in the UI; they must not appear on the PR comment."""

from __future__ import annotations

from shift_left.config import AppConfig
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


def _policy_decision() -> PullRequestPolicyDecision:
    return PullRequestPolicyDecision(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        default_action=PolicyAction.FLAG,
        pr_decision=PolicyAction.FLAG,
        explanation="Flagged for human review.",
    )


def test_pr_comment_omits_advisory_findings_keeps_handler(tmp_path) -> None:
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
    handler = Finding(
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="firewall/edge.rules",
        line_range=LineRange(start=1, end=1),
        title="Deterministic rule: ASA-001",
        description="ASA ACL permit ACE allows any source to any destination.",
        policy_severity=PolicySeverity.HIGH,
        model_asserted_severity=Severity.HIGH,
        handler_asserted_cwe="CWE-284",
        trace="handler:ASA-001",
        construct_key="ace:outside_in:access-list outside_in extended permit ip any any",
    )
    advisory = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="firewall/edge.rules",
        line_range=LineRange(start=4, end=4),
        title="Fabricated any/any finding",
        description="Model claimed a weakness with invented evidence.",
        evidence="permit ip any any fabricated",
        policy_severity=PolicySeverity.UNCLASSIFIED,
        model_asserted_severity=Severity.HIGH,
        model_asserted_cwe="CWE-284",
        confidence=0.5,
    )
    body = service._format_comment([handler, advisory], _policy_decision())
    assert "Deterministic rule: ASA-001" in body
    assert "handler:ASA-001" in body
    assert "Fabricated any/any finding" not in body
    assert "permit ip any any fabricated" not in body
    assert "1 advisory finding(s) omitted" in body
    assert "Shift-Left UI" in body
    assert "not posted on the PR" in body


def test_pr_comment_omits_review_summary_that_covers_advisory(tmp_path) -> None:
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
    advisory = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc123",
        file_path="firewall/edge.rules",
        title="Fabricated any/any finding",
        description="Model claimed a weakness with invented evidence.",
        model_asserted_cwe="CWE-284",
    )
    from shift_left.models.schema import ReviewSummary

    summary = ReviewSummary(
        summary_text="Reviewer summary covering Fabricated any/any finding.",
        suggested_course_of_action="Treat the fabricated ACE as blocking.",
        findings_covered=[advisory.id],
        generator="scripted-fixture",
    )
    body = service._format_comment([advisory], _policy_decision(), review_summary=summary)
    assert "Fabricated any/any finding" not in body
    assert "Treat the fabricated ACE as blocking." not in body
    assert "not posted on the PR" in body


def test_review_api_omits_advisory_findings_and_summary() -> None:
    from shift_left.models.schema import ReviewResult, ReviewSummary
    from shift_left.ui.api_presentation import redact_review_result_for_api

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


def test_pr_comment_cli001_shows_blocking_cwe_and_managed_target(tmp_path) -> None:
    from shift_left.handlers.config.gate_findings import findings_for_corpus_file

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
    content = "hostname edge-1\n!\nline vty 0 4\n"
    findings = findings_for_corpus_file(
        path="configs/marker-free-vty.cfg",
        target_type="undeclared",
        content=content,
        config=config,
    )
    assert [finding.trace for finding in findings] == ["handler:CLI-001"]
    assert findings[0].handler_asserted_cwe == "CWE-754"
    assert findings[0].policy_severity == PolicySeverity.HIGH
    body = ReviewService(config)._format_comment(findings, _policy_decision())
    assert "handler:CLI-001" in body
    assert "CWE-754" in body
    assert "`high`" in body
    assert "managed_targets:" in body
    assert "target_type: cisco_ios_xe" in body
    assert "configs/**/*.cfg" in body
