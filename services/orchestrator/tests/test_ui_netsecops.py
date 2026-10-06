"""NetSecOps UI redesign — workflow state, plan-only deployment, RBAC."""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import AppConfig
from shift_left.deployment.terraform_plan import PlanRunResult
from shift_left.main import app
from shift_left.models.schema import (
    ChangeState,
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
from shift_left.triage.service import AntaresTriageService
from shift_left.sovereignty.network import EgressGuard
from tests.test_phase3_hardening import FakeGit


UI_ROUTES = [
    "/ui/login",
    "/ui/targets",
    "/ui/changes",
    "/ui/findings",
    "/ui/policy",
    "/ui/audit",
    "/ui/system",
    "/ui/triage",
    "/ui/pr/o/r/1",
]


async def _fake_plan(**kwargs):
    return PlanRunResult(
        output_text="Plan: 1 to add, 0 to change, 0 to destroy\nNo changes. Password=SECRET123",
        summary_add=1,
        summary_change=0,
        summary_destroy=0,
        duration_ms=12,
        exit_code=2,
    )


@pytest.fixture
def netsecops_client(tmp_path, monkeypatch):
    db = tmp_path / "shift-left.db"
    monkeypatch.setenv("TF_VAR_fmc_username", "admin")
    monkeypatch.setenv("TF_VAR_fmc_password", "SECRET123")
    monkeypatch.setenv("TF_VAR_fmc_host", "198.18.134.100")
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
            "rbac": {"allow_self_approval": False},
            "deployment": {
                "mode": "plan_only",
                "fmc": {
                    "enabled": True,
                    "terraform_workdir": str(tmp_path / "tf"),
                    "target_label": "fmc-lab",
                },
            },
        }
    )
    (tmp_path / "tf").mkdir()
    service = ReviewService(config)
    service._deployment._plan_runner = _fake_plan
    fake_git = FakeGit(author="commit-author")
    fake_git._pr_payload = {
        "head": {"sha": "commit-a", "ref": "feature/net"},
        "base": {"ref": "main"},
        "title": "Add access rule",
        "user": {"login": "commit-author"},
    }
    service._git = fake_git
    service._approval_service._git = fake_git
    service._gate_service._git = fake_git
    service._changes._git = fake_git
    service._forgejo_embed._git = fake_git
    service._changes._forgejo = service._forgejo_embed
    triage = AntaresTriageService(config)
    app.state.config = config
    app.state.review_service = service
    app.state.triage_service = triage
    app.state.token_store = service.token_store
    client = TestClient(app)
    _, admin_token = mint_api_token(
        service.token_store,
        label="admin",
        actor="admin",
        capabilities=[TokenCapability.ADMIN],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, admin_token)
    return client, service, fake_git, config, admin_token


def _seed_policy(service: ReviewService, *, sha: str = "commit-a") -> None:
    service._policy_decisions.save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha=sha,
            default_action=PolicyAction.PASS,
            pr_decision=PolicyAction.PASS,
            explanation="pass",
            finding_decisions=[],
        )
    )


def _mint(service: ReviewService, *, actor: str, capabilities: list[TokenCapability]) -> str:
    _, plaintext = mint_api_token(
        service.token_store,
        label="cap",
        actor=actor,
        capabilities=capabilities,
    )
    return plaintext


def test_change_state_is_server_computed(netsecops_client) -> None:
    client, service, _, _, _ = netsecops_client
    _seed_policy(service)
    response = client.get("/api/v1/changes/o/r/1/state")
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == ChangeState.AWAITING_APPROVAL.value
    assert "next_action" in body
    assert "reason" in body


def test_new_commit_invalidates_approval_and_plan(netsecops_client) -> None:
    client, service, fake_git, _, _ = netsecops_client
    _seed_policy(service, sha="commit-a")
    approver_token = _mint(
        service,
        actor="reviewer",
        capabilities=[TokenCapability.APPROVE, TokenCapability.DEPLOY],
    )
    client.post(
        "/api/v1/approvals/o/r/1",
        headers={"Authorization": f"Bearer {approver_token}"},
        json={"commit_sha": "commit-a"},
    )
    plan_resp = client.post(
        "/api/v1/changes/o/r/1/plan",
        headers={"Authorization": f"Bearer {approver_token}"},
        json={"commit_sha": "commit-a"},
    )
    assert plan_resp.status_code == 200
    service.approvals.invalidate_on_new_commit("o/r", "PR-1", new_commit_sha="commit-b")
    service.deployment.invalidate_plans("o/r", "PR-1", new_commit_sha="commit-b")
    fake_git._pr_payload["head"]["sha"] = "commit-b"
    _seed_policy(service, sha="commit-b")
    state = service.changes.compute_state(repo="o/r", pr_ref="PR-1", commit_sha="commit-b", pr_number=1)
    assert state.state == ChangeState.AWAITING_APPROVAL
    latest = service.deployment.latest_plan("o/r", "PR-1")
    assert latest is not None and latest.stale is True


def test_plan_endpoint_refuses_without_gate(netsecops_client) -> None:
    client, service, _, _, _ = netsecops_client
    _seed_policy(service)
    deploy_token = _mint(service, actor="deployer", capabilities=[TokenCapability.DEPLOY])
    response = client.post(
        "/api/v1/changes/o/r/1/plan",
        headers={"Authorization": f"Bearer {deploy_token}"},
        json={"commit_sha": "commit-a"},
    )
    assert response.status_code == 403


def test_plan_requires_deploy_not_approve(netsecops_client) -> None:
    client, service, _, _, _ = netsecops_client
    _seed_policy(service)
    approver_token = _mint(service, actor="reviewer", capabilities=[TokenCapability.APPROVE])
    client.post(
        "/api/v1/approvals/o/r/1",
        headers={"Authorization": f"Bearer {approver_token}"},
        json={"commit_sha": "commit-a"},
    )
    response = client.post(
        "/api/v1/changes/o/r/1/plan",
        headers={"Authorization": f"Bearer {approver_token}"},
        json={"commit_sha": "commit-a"},
    )
    assert response.status_code == 403


def test_self_approval_refused_when_rbac_false(netsecops_client) -> None:
    client, service, _, _, _ = netsecops_client
    _seed_policy(service)
    author_token = _mint(
        service,
        actor="commit-author",
        capabilities=[TokenCapability.APPROVE],
    )
    response = client.post(
        "/api/v1/approvals/o/r/1",
        headers={"Authorization": f"Bearer {author_token}"},
        json={"commit_sha": "commit-a"},
    )
    assert response.status_code == 400
    assert "Separation of duties" in response.json()["detail"]


def test_self_approval_banner_and_audit_when_rbac_true(tmp_path, monkeypatch) -> None:
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "ui": {"enabled": True, "require_loopback_client": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
            "rbac": {"allow_self_approval": True},
        }
    )
    service = ReviewService(config)
    fake_git = FakeGit(author="commit-author")
    service._git = fake_git
    service._approval_service._git = fake_git
    service._gate_service._git = fake_git
    service._changes._git = fake_git
    app.state.config = config
    app.state.review_service = service
    app.state.triage_service = AntaresTriageService(config)
    app.state.token_store = service.token_store
    _seed_policy(service)
    client = TestClient(app)
    _, token = mint_api_token(
        service.token_store,
        label="self-approve",
        actor="commit-author",
        capabilities=[TokenCapability.APPROVE, TokenCapability.ADMIN],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, token)
    page = client.get("/ui/changes")
    assert "separation of duties is disabled" in page.text
    response = client.post(
        "/api/v1/approvals/o/r/1",
        headers={"Authorization": f"Bearer {token}"},
        json={"commit_sha": "commit-a"},
    )
    assert response.status_code == 200
    events = service.audit.list_events(action="approval.granted", limit=50)
    assert events[0].details.get("self_approval_permitted") is True


def test_credentials_absent_from_plan_api(netsecops_client, monkeypatch) -> None:
    client, service, _, _, _ = netsecops_client
    _seed_policy(service)
    deploy_token = _mint(
        service,
        actor="deployer",
        capabilities=[TokenCapability.DEPLOY, TokenCapability.APPROVE],
    )
    client.post(
        "/api/v1/approvals/o/r/1",
        headers={"Authorization": f"Bearer {deploy_token}"},
        json={"commit_sha": "commit-a"},
    )
    response = client.post(
        "/api/v1/changes/o/r/1/plan",
        headers={"Authorization": f"Bearer {deploy_token}"},
        json={"commit_sha": "commit-a"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "SECRET123" not in payload["output_text"]
    logs = service.audit.list_events(action="deployment.plan_generated", limit=50)
    assert logs
    assert "SECRET123" not in str(logs[0].details)


def test_no_terraform_apply_code_path() -> None:
    root = Path(__file__).resolve().parents[1] / "shift_left" / "deployment"
    combined = "\n".join(path.read_text() for path in root.glob("*.py"))
    assert " apply" not in combined.lower().replace("no apply", "")
    assert "terraform apply" not in combined.lower()


def test_unclassified_severity_distinct_in_template() -> None:
    html = Path(__file__).resolve().parents[1] / "shift_left" / "ui" / "templates" / "pr_review.html"
    css = Path(__file__).resolve().parents[1] / "shift_left" / "ui" / "static" / "styles.css"
    assert "severity-unclassified" in css.read_text()
    assert "Unclassified" in html.read_text() or "policy_severity_label" in html.read_text()


def test_handler_match_failure_shown_on_pr_page(netsecops_client) -> None:
    client, service, _, _, _ = netsecops_client
    service.audit.log(
        actor="system",
        action="analysis.failed",
        subject="o/r/PR-1",
        details={
            "commit_sha": "commit-a",
            "failure_class": "handler_error",
            "failure_stage": "handler_match",
            "failure_message": "match_nx_os_config_rules() missing rule_id",
        },
    )
    _seed_policy(service)
    page = client.get("/ui/pr/o/r/1")
    assert page.status_code == 200
    assert "Validation incomplete" in page.text
    assert "handler_error" in page.text
    assert "handler_match" in page.text
    assert "inference_error" not in page.text


def test_validation_incomplete_not_passing(netsecops_client) -> None:
    client, service, _, _, _ = netsecops_client
    service.audit.log(
        actor="system",
        action="analysis.failed",
        subject="o/r/PR-1",
        details={"commit_sha": "commit-a", "failure_class": "timeout"},
    )
    _seed_policy(service)
    state = service.changes.compute_state(repo="o/r", pr_ref="PR-1", commit_sha="commit-a", pr_number=1)
    assert state.state == ChangeState.VALIDATION_INCOMPLETE
    page = client.get("/ui/pr/o/r/1")
    assert "Validation incomplete" in page.text
    assert "status-incomplete" in page.text


def test_declared_state_notice_present(netsecops_client) -> None:
    client, _, _, _, _ = netsecops_client
    page = client.get("/ui/pr/o/r/1")
    assert "Declared configuration only" in page.text
    assert "out-of-band" in page.text.lower()


def test_ui_routes_load_with_egress_blocked(netsecops_client) -> None:
    client, _, _, _, _ = netsecops_client
    attempts: list[tuple] = []

    def tracking_connect(address, timeout=None, source_address=None):
        host = address[0] if isinstance(address, tuple) else str(address)
        if host not in {"127.0.0.1", "localhost", "::1"}:
            attempts.append(address)
        raise OSError("blocked in test")

    with patch("socket.create_connection", side_effect=tracking_connect):
        with patch(
            "shift_left.api.ui_support.run_egress_probe",
            return_value=type("R", (), {"ok": True, "message": "blocked"})(),
        ):
            with EgressGuard(allowed_hosts=frozenset({"127.0.0.1", "localhost", "::1"})):
                for path in UI_ROUTES:
                    response = client.get(path)
                    assert response.status_code in {200, 303, 401, 404}, path
    assert attempts == []


def test_landing_redirects_to_targets(netsecops_client) -> None:
    client, _, _, _, _ = netsecops_client
    response = client.get("/ui/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/targets"
