"""Phase 3 hardening — identity, SoD, severity, gate, audit integrity."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.tokens import mint_api_token
from shift_left.config import AppConfig, PolicyConfig
from shift_left.git.protocol import GitBackendKind
from shift_left.main import app
from shift_left.models.schema import PolicyAction, PullRequestPolicyDecision
from shift_left.review.service import ReviewService
from shift_left.triage.service import AntaresTriageService
from shift_left.sovereignty.checks import check_gate_branch_protection


class FakeGit:
    kind = GitBackendKind.BUNDLED_FORGEJO
    provider_label = "forgejo"
    is_sovereign = True

    def __init__(self, *, author: str = "commit-author", branch_protection: bool | None = False) -> None:
        self.author = author
        self.branch_protection = branch_protection
        self.statuses: list[dict[str, Any]] = []
        self._pr_payload: dict[str, Any] = {"head": {"sha": "commit-a"}}

    async def get_pull_request(self, owner: str, repo: str, pr_number: int) -> dict[str, Any]:
        return self._pr_payload

    async def get_pull_diff(self, owner: str, repo: str, pr_number: int) -> str:
        return ""

    async def post_pull_request_comment(self, owner: str, repo: str, pr_number: int, body: str) -> dict:
        return {}

    async def get_commit_author(self, owner: str, repo: str, commit_sha: str) -> str:
        return self.author

    async def publish_commit_status(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
        *,
        context: str,
        state: str,
        description: str,
        target_url: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "owner": owner,
            "repo": repo,
            "sha": commit_sha,
            "context": context,
            "state": state,
            "description": description,
        }
        self.statuses.append(payload)
        return payload

    async def branch_protection_requires_status_check(
        self,
        owner: str,
        repo: str,
        branch: str,
        context: str,
    ) -> bool | None:
        return self.branch_protection

    async def health(self) -> bool:
        return True

    async def list_open_pull_requests(
        self,
        owner: str,
        repo: str,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        number = self._pr_payload.get("number") or 1
        payload = {**self._pr_payload, "number": number, "state": "open"}
        return [payload]

    async def list_pull_request_commits(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> list[dict[str, Any]]:
        sha = self._pr_payload.get("head", {}).get("sha", "commit-a")
        return [
            {
                "sha": sha,
                "commit": {
                    "message": "test commit",
                    "author": {"name": self.author},
                    "date": "2026-01-01T00:00:00Z",
                },
            }
        ]

    async def list_pull_request_comments(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> list[dict[str, Any]]:
        return [{"body": "Shift-Left findings comment", "user": {"login": "shift-left"}, "created_at": "2026-01-01"}]

    async def list_commit_statuses(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
    ) -> list[dict[str, Any]]:
        return [
            {
                "context": "shift-left/gate",
                "status": "failure" if not getattr(self, "_gate_success", False) else "success",
                "description": "orchestrator gate",
            }
        ]

    async def list_action_runners(self) -> tuple[bool, str, list[dict[str, Any]]]:
        runners = getattr(self, "_action_runners", None)
        if runners is None:
            return True, "ok", [{"status": "online", "labels": ["self-hosted:host"]}]
        if isinstance(runners, tuple) and len(runners) == 3:
            return runners  # type: ignore[return-value]
        return True, "ok", runners  # type: ignore[arg-type]


@pytest.fixture
def orchestrator(tmp_path):
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
            "gate": {
                "enabled": True,
                "status_context": "shift-left/gate",
                "publish_commit_status": True,
            },
        }
    )
    service = ReviewService(config)
    fake_git = FakeGit()
    service._git = fake_git
    service._approval_service._git = fake_git
    service._gate_service._git = fake_git
    app.state.config = config
    app.state.review_service = service
    app.state.token_store = service.token_store
    app.state.triage_service = AntaresTriageService(config)
    client = TestClient(app)
    return client, service, fake_git, config


def _mint(service: ReviewService, *, actor: str, capabilities: list[TokenCapability]) -> str:
    _, plaintext = mint_api_token(
        service.token_store,
        label="test",
        actor=actor,
        capabilities=capabilities,
    )
    return plaintext


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _save_flag_decision(service: ReviewService, commit_sha: str) -> None:
    service._policy_decisions.save(
        PullRequestPolicyDecision(
            repo="o/r",
            pr_ref="PR-1",
            commit_sha=commit_sha,
            default_action=PolicyAction.FLAG,
            pr_decision=PolicyAction.FLAG,
            explanation="Flagged.",
        )
    )


class TestIdentityAndAuthorization:
    STATE_CHANGING = [
        ("POST", "/api/v1/review", {"owner": "o", "repo": "r", "pr_number": 1}),
        ("PATCH", "/api/v1/findings/fid/status", {"status": "open"}),
        ("POST", "/api/v1/approvals/o/r/1", {"commit_sha": "commit-a"}),
        ("DELETE", "/api/v1/approvals/o/r/1", None),
        ("POST", "/api/v1/overrides/o/r/1", {"commit_sha": "c", "justification": "j"}),
    ]

    def test_no_token_rejected(self, orchestrator) -> None:
        client, _, _, _ = orchestrator
        for method, path, body in self.STATE_CHANGING:
            if method == "POST":
                response = client.post(path, json=body)
            elif method == "PATCH":
                response = client.patch(path, json=body)
            else:
                response = client.delete(path)
            assert response.status_code == 401, f"{method} {path} should require token"

    def test_client_supplied_approver_rejected(self, orchestrator) -> None:
        client, service, _, _ = orchestrator
        token = _mint(service, actor="alice", capabilities=[TokenCapability.APPROVE])
        response = client.post(
            "/api/v1/approvals/o/r/1",
            json={"commit_sha": "commit-a", "approver": "evil"},
            headers=_auth(token),
        )
        assert response.status_code == 422

    def test_token_without_approve_cannot_approve(self, orchestrator) -> None:
        client, service, _, _ = orchestrator
        _save_flag_decision(service, "commit-a")
        token = _mint(service, actor="bob", capabilities=[TokenCapability.TRIAGE])
        response = client.post(
            "/api/v1/approvals/o/r/1",
            json={"commit_sha": "commit-a"},
            headers=_auth(token),
        )
        assert response.status_code == 403

    def test_token_without_override_cannot_override(self, orchestrator) -> None:
        client, service, _, config = orchestrator
        config.policy.allow_block_override = True
        service._approval_service._policy_config = config.policy
        token = _mint(service, actor="lead", capabilities=[TokenCapability.APPROVE])
        response = client.post(
            "/api/v1/overrides/o/r/1",
            json={"commit_sha": "commit-a", "justification": "because"},
            headers=_auth(token),
        )
        assert response.status_code == 403

    def test_revoked_token_rejected_immediately(self, orchestrator) -> None:
        client, service, _, _ = orchestrator
        record, plaintext = mint_api_token(
            service.token_store,
            label="revoke-me",
            actor="alice",
            capabilities=[TokenCapability.APPROVE],
        )
        assert service.token_store.revoke(record.id)
        response = client.post(
            "/api/v1/approvals/o/r/1",
            json={"commit_sha": "commit-a"},
            headers=_auth(plaintext),
        )
        assert response.status_code == 401

    def test_audit_events_have_token_derived_actor(self, orchestrator) -> None:
        client, service, _, _ = orchestrator
        _save_flag_decision(service, "commit-a")
        token = _mint(service, actor="carol", capabilities=[TokenCapability.APPROVE])
        client.post(
            "/api/v1/approvals/o/r/1",
            json={"commit_sha": "commit-a"},
            headers=_auth(token),
        )
        events = service.audit.list_events(action="approval.granted")
        assert events
        assert events[0].actor == "carol"
        assert events[0].actor is not None


class TestSeparationOfDuties:
    @pytest.mark.asyncio
    async def test_approver_equal_author_denied_by_default(self, orchestrator) -> None:
        _, service, fake_git, _ = orchestrator
        fake_git.author = "alice"
        _save_flag_decision(service, "commit-a")
        with pytest.raises(ValueError, match="Separation of duties"):
            await service.approvals.grant_approval(
                repo="o/r",
                pr_ref="PR-1",
                commit_sha="commit-a",
                approver="alice",
            )

    @pytest.mark.asyncio
    async def test_sod_fields_in_approval_and_audit(self, orchestrator) -> None:
        client, service, fake_git, _ = orchestrator
        fake_git.author = "author-user"
        _save_flag_decision(service, "commit-a")
        token = _mint(service, actor="approver-user", capabilities=[TokenCapability.APPROVE])
        response = client.post(
            "/api/v1/approvals/o/r/1",
            json={"commit_sha": "commit-a"},
            headers=_auth(token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["commit_author"] == "author-user"
        assert body["approver_matches_author"] is False
        assert body["separation_of_duties_result"] == "passed_approver_differs_from_author"
        audit = service.audit.list_events(action="approval.granted")[0]
        assert audit.details["approver_matches_author"] is False
        assert audit.details["separation_of_duties_result"] == "passed_approver_differs_from_author"

    def test_disabled_sod_reflected_in_gate_response(self, tmp_path) -> None:
        db = tmp_path / "db.sqlite"
        config = AppConfig.model_validate(
            {
                "findings_store": {"sqlite_path": str(db)},
                "policy": {"approval": {"separation_of_duties_enforced": False}},
                "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
                "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            }
        )
        service = ReviewService(config)
        service.audit.log(
            actor="system:shift-left",
            action="config.separation_of_duties_disabled",
            subject="policy.approval",
            details={},
        )
        _save_flag_decision(service, "commit-a")
        gate = service.approvals.check_deployment_gate(
            repo="o/r", pr_ref="PR-1", commit_sha="commit-a"
        )
        assert gate.separation_of_duties_disabled is True
        assert gate.separation_of_duties_enforced is False
        assert any(
            event.action == "config.separation_of_duties_disabled"
            for event in service.audit.list_events()
        )


class TestDeterministicSeverity:
    def test_same_finding_same_policy_severity(self, tmp_path) -> None:
        from shift_left.models.schema import Finding, FindingSource, Severity, TargetKind
        from shift_left.policy.severity import apply_policy_severities

        config = AppConfig.model_validate({"findings_store": {"sqlite_path": str(tmp_path / "x.db")}})
        raw = Finding(
            source=FindingSource.ANTARES,
            target_kind=TargetKind.CODE,
            repo="o/r",
            pr_ref="PR-1",
            commit_sha="aaa",
            file_path="app/x.py",
            model_asserted_cwe="CWE-89",
            handler_asserted_cwe="CWE-89",
            model_asserted_severity=Severity.LOW,
            confidence=0.5,
            title="T",
            description="D",
        )
        first = apply_policy_severities([raw], config)[0]
        second = apply_policy_severities([raw.model_copy()], config)[0]
        assert first.policy_severity == second.policy_severity


class TestGateEnforcement:
    @pytest.mark.asyncio
    async def test_gate_publishes_commit_status(self, orchestrator) -> None:
        client, service, fake_git, _ = orchestrator
        _save_flag_decision(service, "commit-a")
        token = _mint(service, actor="approver", capabilities=[TokenCapability.APPROVE])
        fake_git.author = "approver"
        config = service._config
        config.policy.approval.separation_of_duties_enforced = False
        service._approval_service._policy_config = config.policy
        client.post(
            "/api/v1/approvals/o/r/1",
            json={"commit_sha": "commit-a"},
            headers=_auth(token),
        )
        response = client.get("/api/v1/gate/o/r/1", params={"commit_sha": "commit-a"})
        assert response.status_code == 200
        assert response.json()["allowed"] is True
        assert fake_git.statuses
        assert fake_git.statuses[-1]["context"] == "shift-left/gate"
        assert fake_git.statuses[-1]["sha"] == "commit-a"

    def test_branch_protection_self_check_warns(self, tmp_path) -> None:
        config = AppConfig.model_validate(
            {
                "findings_store": {"sqlite_path": str(tmp_path / "x.db")},
                "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
                "gate": {
                    "check_repo": "o/r",
                    "protected_branch": "main",
                    "status_context": "shift-left/gate",
                    "warn_if_branch_protection_missing": True,
                },
            }
        )
        result = check_gate_branch_protection(config)
        assert result.ok is False
        assert "does NOT require" in result.message or "Could not" in result.message


class TestAuditIntegrity:
    def test_no_update_delete_api(self, orchestrator) -> None:
        client, _, _, _ = orchestrator
        assert client.put("/api/v1/audit/events/x", json={}).status_code == 404
        assert client.delete("/api/v1/audit/events/x").status_code == 404

    def test_prune_requires_export_first(self, tmp_path) -> None:
        from shift_left.models.database import AuditStore
        from shift_left.models.schema import utc_now
        from datetime import timedelta

        store = AuditStore(str(tmp_path / "audit.db"))
        store.log(actor="alice", action="old", subject="s", details={})
        export = tmp_path / "export.json"
        result = store.prune_before(
            before=utc_now() + timedelta(days=1),
            export_path=export,
            actor="operator:cli",
        )
        assert export.exists()
        assert result["exported_count"] >= 1
        protected = [event for event in store.export_all() if event["action"] == "audit.pruned"]
        assert protected
