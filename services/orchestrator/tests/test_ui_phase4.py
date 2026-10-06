"""Phase 4 web UI — sovereignty, auth, rendering contracts."""

from __future__ import annotations

import re
import socket
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import AppConfig
from shift_left.main import app
from shift_left.models.schema import (
    EnrichmentStatus,
    Finding,
    FindingEnrichment,
    FindingSource,
    LineRange,
    PolicyAction,
    PolicySeverity,
    PullRequestPolicyDecision,
    Severity,
    TargetKind,
)
from shift_left.review.service import ReviewService
from shift_left.triage.service import AntaresTriageService
from shift_left.sovereignty.network import EgressGuard
from shift_left.triage.service import AntaresTriageService
from shift_left.ui.labels import PROHIBITED_TRIAGE_WORDS, PROHIBITED_VERDICT_WORDS
from shift_left.ui.sovereignty import scan_external_asset_references
from tests.test_phase3_hardening import FakeGit


UI_ROUTES = [
    "/ui/login",
    "/ui/changes",
    "/ui/findings",
    "/ui/policy",
    "/ui/audit",
    "/ui/system",
    "/ui/investigations",
    "/ui/pr/o/r/1",
]


@pytest.fixture
def ui_client(tmp_path):
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": True, "require_loopback_client": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
            "policy": {"allow_block_override": True},
            "antares_triage": {"enabled": True},
        }
    )
    service = ReviewService(config)
    fake_git = FakeGit(author="commit-author")
    service._git = fake_git
    service._approval_service._git = fake_git
    service._gate_service._git = fake_git
    triage = AntaresTriageService(config)
    app.state.config = config
    app.state.review_service = service
    app.state.triage_service = triage
    app.state.token_store = service.token_store
    client = TestClient(app)
    _, token = mint_api_token(
        service.token_store,
        label="ui-all",
        actor="reviewer",
        capabilities=[
            TokenCapability.ADMIN,
        ],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, token)
    return client, service, fake_git, config, token


def _mint(service: ReviewService, *, actor: str, capabilities: list[TokenCapability]) -> str:
    _, plaintext = mint_api_token(
        service.token_store,
        label="cap",
        actor=actor,
        capabilities=capabilities,
    )
    return plaintext


def test_build_time_external_asset_scan_is_clean() -> None:
    violations = scan_external_asset_references()
    assert violations == [], violations


def test_ui_routes_load_without_external_egress(ui_client) -> None:
    client, _, _, _, _ = ui_client
    attempts: list[tuple[str, int]] = []

    def tracking_connect(address, timeout=None, source_address=None):
        host = address[0] if isinstance(address, tuple) else str(address)
        if host not in {"127.0.0.1", "localhost", "::1"}:
            attempts.append(address if isinstance(address, tuple) else (str(address), 0))
        raise OSError("blocked in test")

    with patch("socket.create_connection", side_effect=tracking_connect):
        with patch("shift_left.api.ui_support.run_egress_probe", return_value=type("R", (), {"ok": True, "message": "blocked"})()):
            with EgressGuard(allowed_hosts=frozenset({"127.0.0.1", "localhost", "::1"})):
                for path in UI_ROUTES:
                    response = client.get(path)
                    assert response.status_code in {200, 303, 401, 403, 404}, path
    assert attempts == []


def test_triage_capability_hidden_and_api_rejects(ui_client, tmp_path) -> None:
    client, service, _, _, _ = ui_client
    from shift_left.investigations.store import InvestigationStore

    inv_db = tmp_path / "investigations.db"
    app.state.investigation_store = InvestigationStore(str(inv_db), audit=service.audit)
    triage_token = _mint(service, actor="no-triage", capabilities=[TokenCapability.REVIEW])
    client.cookies.set(TOKEN_COOKIE_NAME, triage_token)
    redirect = client.get("/ui/triage", follow_redirects=False)
    assert redirect.status_code == 301
    assert redirect.headers["location"] == "/ui/investigations"
    response = client.get("/ui/investigations")
    assert response.status_code == 403
    system = client.get("/ui/system")
    assert system.status_code == 200
    assert 'href="/ui/investigations"' not in system.text
    assert "Antares triage" not in system.text
    api = client.post(
        "/api/v1/triage/antares",
        json={"repo": "o/r", "ref": "main", "task_cwe": "CWE-89"},
        headers={"Authorization": f"Bearer {triage_token}"},
    )
    assert api.status_code == 403


def test_prohibited_triage_wording_absent_from_investigations_page(ui_client, tmp_path) -> None:
    client, service, _, _, _ = ui_client
    from shift_left.investigations.schema import InvestigationState
    from shift_left.investigations.store import InvestigationStore

    inv_db = tmp_path / "investigations.db"
    store = InvestigationStore(str(inv_db), audit=service.audit)
    app.state.investigation_store = store
    inv_id = store.create_investigation(
        repo="o/r",
        requested_ref="main",
        resolved_commit_sha="abc123",
        task_cwe="CWE-89",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    store.set_candidates(inv_id, [(1, "app/db.py")])
    store.transition_state(inv_id, InvestigationState.COMPLETED, actor="operator")

    triage_token = _mint(
        service,
        actor="triage-ui",
        capabilities=[TokenCapability.TRIAGE, TokenCapability.REVIEW],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, triage_token)
    response = client.get("/ui/investigations")
    assert response.status_code == 200
    assert not PROHIBITED_TRIAGE_WORDS.search(response.text)
    assert "Advisory Antares localization" in response.text


def test_prohibited_verdict_wording_stripped_in_zone_c(ui_client) -> None:
    client, service, _, _, _ = ui_client
    finding = Finding(
        source=FindingSource.CODE_HANDLER,
        target_kind=TargetKind.CODE,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="app/db.py",
        line_range=LineRange(start=1, end=1),
        handler_asserted_cwe="CWE-89",
        policy_severity=PolicySeverity.HIGH,
        title="SQLi",
        description="desc",
        model_context="This change is compliant and safe to merge.",
    )
    service._store.save_findings([finding])
    service._policy_decisions.save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            default_action=PolicyAction.FLAG,
            pr_decision=PolicyAction.FLAG,
            explanation="Flagged.",
        )
    )
    response = client.get("/ui/pr/o/r/1")
    assert response.status_code == 200
    assert not PROHIBITED_VERDICT_WORDS.search(response.text)
    assert "[redacted]" in response.text


def test_failed_analysis_renders_incomplete_not_passing(ui_client) -> None:
    client, service, _, _, _ = ui_client
    service._policy_decisions.save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            default_action=PolicyAction.FLAG,
            pr_decision=PolicyAction.FLAG,
            explanation="Flagged.",
        )
    )

    def fake_gate(*args, **kwargs):
        from shift_left.models.schema import DeploymentGateResult, GateBlockReason

        return DeploymentGateResult(
            allowed=False,
            reason="Required model analysis incomplete for: config.",
            commit_sha="commit-a",
            policy_decision=PolicyAction.FLAG,
            approval_present=False,
            approval_valid_for_commit=False,
            block_override_present=False,
            block_reason=GateBlockReason.ANALYSIS_INCOMPLETE,
            analysis_incomplete=True,
        )

    with patch.object(service.approvals, "check_deployment_gate", fake_gate):
        response = client.get("/ui/pr/o/r/1")
    assert response.status_code == 200
    assert "Validation incomplete" in response.text
    assert "passed review" not in response.text.lower()


def test_invalidated_approval_shown(ui_client) -> None:
    client, service, _, _, _ = ui_client
    service._policy_decisions.save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            default_action=PolicyAction.PASS,
            pr_decision=PolicyAction.PASS,
            explanation="Pass.",
        )
    )
    from shift_left.models.schema import ApprovalRecord

    service.approvals._approvals.grant(
        ApprovalRecord(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="old-sha",
            approver="alice",
            findings_snapshot=[],
            policy_decision=PolicyAction.PASS,
            policy_decision_snapshot={},
        )
    )
    service.approvals._approvals.invalidate_for_new_commit(
        "o/r",
        "PR-1",
        new_commit_sha="commit-a",
        reason="New commit landed",
    )
    response = client.get("/ui/pr/o/r/1")
    assert "Invalidated" in response.text
    assert "re-approval required" in response.text


def test_self_approval_control_unavailable_for_author(ui_client) -> None:
    client, service, fake_git, _, _ = ui_client
    fake_git.author = "reviewer"
    service._policy_decisions.save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            default_action=PolicyAction.PASS,
            pr_decision=PolicyAction.PASS,
            explanation="Pass.",
        )
    )
    triage_only = _mint(service, actor="reviewer", capabilities=[TokenCapability.APPROVE])
    client.cookies.set(TOKEN_COOKIE_NAME, triage_only)
    response = client.get("/ui/pr/o/r/1")
    assert "Separation of duties" in response.text
    assert "Approve unavailable" in response.text


def test_status_update_requires_rationale(ui_client) -> None:
    client, service, _, _, _ = ui_client
    finding = Finding(
        source=FindingSource.CODE_HANDLER,
        target_kind=TargetKind.CODE,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="app/db.py",
        title="x",
        description="d",
    )
    service._store.save_findings([finding])
    response = client.post(
        f"/ui/pr/o/r/1/finding/{finding.id}/status",
        data={"status": "false_positive", "rationale": ""},
    )
    assert response.status_code == 400


def test_audit_page_has_no_delete_controls(ui_client) -> None:
    client, _, _, _, _ = ui_client
    response = client.get("/ui/audit")
    assert response.status_code == 200
    lowered = response.text.lower()
    assert "delete" not in lowered or "no update or delete" in lowered
    assert 'method="delete"' not in lowered


def test_audit_export_with_egress_blocked(ui_client) -> None:
    client, service, _, _, _ = ui_client
    service.audit.log(actor="reviewer", action="review.completed", subject="o/r/PR-1")
    with EgressGuard(allowed_hosts=frozenset({"127.0.0.1", "localhost", "::1"})):
        response = client.get("/api/v1/audit/export")
    assert response.status_code == 200
    assert response.json()["events"]


def test_stale_cache_surfaced_on_finding(ui_client) -> None:
    client, service, _, _, _ = ui_client
    finding = Finding(
        source=FindingSource.CODE_HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="firewall/asa.rules",
        title="Wide rule",
        description="d",
        enrichment=FindingEnrichment(status=EnrichmentStatus.CACHE_STALE, stale=True),
    )
    service._store.save_findings([finding])
    response = client.get("/ui/findings")
    assert "cache_stale" in response.text or "cache stale" in response.text


def test_findings_dashboard_renders_policy_decision(ui_client) -> None:
    client, service, _, _, _ = ui_client
    from shift_left.models.schema import FindingPolicyDecision

    finding = Finding(
        source=FindingSource.CODE_HANDLER,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="commit-a",
        file_path="infra/main.tf",
        handler_asserted_cwe="CWE-284",
        policy_severity=PolicySeverity.HIGH,
        title="Open ingress",
        description="d",
    )
    service._store.save_findings([finding])
    service._policy_decisions.save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="commit-a",
            default_action=PolicyAction.BLOCK,
            pr_decision=PolicyAction.BLOCK,
            explanation="Blocked.",
            finding_decisions=[
                FindingPolicyDecision(
                    finding_id=finding.id,
                    decision=PolicyAction.BLOCK,
                    matched_policy_name="block-unrestricted-ingress",
                    matched_rule_index=0,
                    explanation="Unrestricted ingress.",
                )
            ],
        )
    )
    response = client.get("/ui/findings")
    assert response.status_code == 200
    assert "BLOCK" in response.text
    assert "block-unrestricted-ingress" in response.text
