"""Forgejo read-heavy UI embedding tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import AppConfig
from shift_left.main import app
from shift_left.models.schema import ChangeState, PolicyAction, PullRequestPolicyDecision
from shift_left.review.service import ReviewService
from shift_left.triage.service import AntaresTriageService
from tests.test_phase3_hardening import FakeGit


@pytest.fixture
def embed_client(tmp_path, monkeypatch):
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": True, "require_loopback_client": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "gate": {"check_repo": "o/r"},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
            "policy": {"allow_block_override": True},
            "antares_triage": {"enabled": False},
            "rbac": {"allow_self_approval": False},
        }
    )
    service = ReviewService(config)
    fake_git = FakeGit(author="commit-author", branch_protection=False)
    fake_git._pr_payload = {
        "number": 1,
        "head": {"sha": "commit-a", "ref": "feature/net"},
        "base": {"ref": "main"},
        "title": "Add access rule",
        "user": {"login": "commit-author"},
        "state": "open",
        "body": "Test PR body",
    }
    fake_git._gate_success = False
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
        capabilities=[TokenCapability.ADMIN, TokenCapability.APPROVE],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, admin_token)
    return client, service, fake_git, admin_token


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


def test_unreviewed_pr_appears_in_queue(embed_client) -> None:
    client, _, _, _ = embed_client
    response = client.get("/ui/changes")
    assert response.status_code == 200
    assert "PR-1" in response.text
    assert "draft/open" in response.text or "awaiting" in response.text.lower() or "validation" in response.text.lower()


def test_non_config_pr_is_distinguishable(embed_client) -> None:
    client, service, fake_git, _ = embed_client
    fake_git._pr_payload["number"] = 2
    async def classify(*_args, **_kwargs):
        return "non_config"
    service._forgejo_embed.classify_pr_scope = classify  # type: ignore[method-assign]
    response = client.get("/ui/changes")
    assert response.status_code == 200
    assert "non-config" in response.text


@pytest.mark.asyncio
async def test_approval_refused_when_head_sha_moved(embed_client) -> None:
    client, service, fake_git, admin_token = embed_client
    _seed_policy(service)
    fake_git._pr_payload["head"]["sha"] = "commit-b"
    response = client.post(
        "/api/v1/approvals/o/r/1",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"commit_sha": "commit-a"},
    )
    assert response.status_code == 400
    assert "moved" in response.json()["detail"].lower()


def test_gate_status_discrepancy_surfaces(embed_client) -> None:
    client, service, fake_git, _ = embed_client
    _seed_policy(service)
    fake_git._gate_success = True
    response = client.get("/ui/pr/o/r/1")
    assert response.status_code == 200
    assert "discrepancy" in response.text.lower() or "Forgejo reports" in response.text


def test_branch_protection_bypass_warning(embed_client) -> None:
    client, _, fake_git, _ = embed_client
    fake_git.branch_protection = False
    response = client.get("/ui/pr/o/r/1")
    assert response.status_code == 200
    assert "bypass" in response.text.lower()


def test_forgejo_unreachable_still_renders_findings(embed_client) -> None:
    client, service, fake_git, _ = embed_client
    from shift_left.models.schema import Finding, FindingSource, TargetKind

    async def boom(*_args, **_kwargs):
        raise ConnectionError("forgejo down")

    fake_git.get_pull_request = boom  # type: ignore[method-assign]
    service._store.save_findings(
        [
            Finding(
                source=FindingSource.FOUNDATION_SEC,
                target_kind=TargetKind.CONFIG,
                repo="o/r",
                pr_ref="PR-1",
                commit_sha="commit-a",
                file_path="infra/main.tf",
                handler_asserted_cwe="CWE-284",
                title="Test",
                description="Stored finding",
            )
        ]
    )
    response = client.get("/ui/pr/o/r/1")
    assert response.status_code == 200
    assert "Stored finding" in response.text
    assert "unavailable" in response.text.lower()


def test_forgejo_token_absent_from_rendered_pages(embed_client, monkeypatch) -> None:
    monkeypatch.setenv("FORGEJO_TOKEN", "super-secret-token-value-12345")
    client, _, _, admin_token = embed_client
    for path in ("/ui/changes", "/ui/pr/o/r/1"):
        response = client.get(path)
        assert response.status_code == 200
        assert "FORGEJO_TOKEN" not in response.text
        assert "super-secret-token" not in response.text
    api = client.get("/api/v1/gate/o/r/1", params={"commit_sha": "commit-a"})
    assert api.status_code == 200
    assert "FORGEJO_TOKEN" not in api.text
    assert "super-secret-token" not in api.text


def test_no_ui_write_routes_for_forgejo_comments(embed_client) -> None:
    client, _, _, _ = embed_client
    response = client.post("/ui/pr/o/r/1/comment", data={"body": "test"})
    assert response.status_code in {404, 405}


def test_runner_offline_surfaces_in_queue(embed_client) -> None:
    client, _, fake_git, _ = embed_client
    fake_git._action_runners = []  # no runners registered
    response = client.get("/ui/changes")
    assert response.status_code == 200
    assert "runner" in response.text.lower()
    assert "offline" in response.text.lower() or "no forgejo actions runners" in response.text.lower()


def test_commit_invalidation_markers(embed_client) -> None:
    client, service, fake_git, _ = embed_client
    _seed_policy(service, sha="commit-a")
    from shift_left.auth.tokens import mint_api_token as mint

    _, token = mint(
        service.token_store,
        label="rev",
        actor="reviewer",
        capabilities=[TokenCapability.APPROVE],
    )
    client.post(
        "/api/v1/approvals/o/r/1",
        headers={"Authorization": f"Bearer {token}"},
        json={"commit_sha": "commit-a"},
    )
    service.approvals.invalidate_on_new_commit("o/r", "PR-1", new_commit_sha="commit-b")

    async def two_commits(owner, repo, pr_number):
        return [
            {
                "sha": "commit-a",
                "commit": {"message": "first", "author": {"name": "a"}, "date": "2026-01-01"},
            },
            {
                "sha": "commit-b",
                "commit": {"message": "second", "author": {"name": "a"}, "date": "2026-01-02"},
            },
        ]

    fake_git.list_pull_request_commits = two_commits  # type: ignore[method-assign]
    fake_git._pr_payload["head"]["sha"] = "commit-b"
    response = client.get("/ui/pr/o/r/1")
    assert response.status_code == 200
    assert "invalidat" in response.text.lower() or "after approval" in response.text.lower()
