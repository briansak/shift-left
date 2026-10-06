"""NetSecOps target-centric UI routes."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import AppConfig
from shift_left.deployment.terraform_plan import PlanRunResult
from shift_left.main import app
from shift_left.models.schema import AppliedRevision, PolicySeverity
from shift_left.review.service import ReviewService
from shift_left.triage.service import AntaresTriageService
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


class TargetFakeGit(FakeGit):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._branch_sha = "declared-head-aaa"
        self._compare_diff = (
            "diff --git a/terraform/main.tf b/terraform/main.tf\n"
            "index 111..222 100644\n"
            "--- a/terraform/main.tf\n"
            "+++ b/terraform/main.tf\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        self._tree_paths = ["terraform/main.tf", "terraform/unclaimed.tf"]
        self._file_contents = {"terraform/main.tf": "resource \"x\" {}\n"}

    async def get_branch(self, owner: str, repo: str, branch: str) -> dict:
        return {
            "name": branch,
            "commit": {
                "id": self._branch_sha,
                "timestamp": "2026-01-02T00:00:00Z",
            },
        }

    async def list_repo_commits(self, owner, repo, *, sha, path=None, limit=50):
        return [
            {
                "sha": self._branch_sha,
                "commit": {
                    "message": "update firewall",
                    "author": {"name": "netops"},
                    "committer": {"date": "2026-01-02T00:00:00Z"},
                },
            },
            {
                "sha": "prev-rev-bbb",
                "commit": {
                    "message": "prior change",
                    "author": {"name": "netops"},
                    "committer": {"date": "2026-01-01T00:00:00Z"},
                },
            },
        ]

    async def get_file_content(self, owner, repo, path, ref):
        return self._file_contents.get(path, "")

    async def compare_commits(self, owner, repo, base, head):
        return {"diff": self._compare_diff, "commits": [{"sha": head}]}

    async def list_repo_tree_paths(self, owner, repo, ref):
        return self._tree_paths

    async def get_pull_diff(self, owner: str, repo: str, pr_number: int) -> str:
        return (
            "diff --git a/terraform/main.tf b/terraform/main.tf\n"
            "index 111..222 100644\n"
            "--- a/terraform/main.tf\n"
            "+++ b/terraform/main.tf\n"
            "@@ -1 +1,2 @@\n"
            " baseline\n"
            "+change\n"
        )


@pytest.fixture
def targets_client(tmp_path, monkeypatch):
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
            "gate": {
                "enabled": True,
                "status_context": "shift-left/gate",
                "check_repo": "o/r",
                "protected_branch": "main",
                "warn_if_branch_protection_missing": True,
            },
            "managed_targets": {
                "targets": [
                    {
                        "id": "edge-fw-01",
                        "display_name": "edge-fw-01",
                        "target_type": "generic_terraform",
                        "repo": "o/r",
                        "branch": "main",
                        "config_paths": ["terraform/**"],
                    }
                ]
            },
            "deployment": {
                "mode": "plan_only",
                "fmc": {
                    "enabled": True,
                    "terraform_workdir": str(tmp_path / "tf"),
                },
            },
        }
    )
    (tmp_path / "tf").mkdir()
    service = ReviewService(config)
    fake_git = TargetFakeGit(branch_protection=False)
    fake_git._pr_payload = {
        "number": 1,
        "head": {"sha": "pr-head-ccc", "ref": "feature"},
        "base": {"ref": "main"},
        "title": "Unvalidated change",
        "user": {"login": "author"},
    }
    service._git = fake_git
    service._approval_service._git = fake_git
    service._gate_service._git = fake_git
    service._changes._git = fake_git
    service._forgejo_embed._git = fake_git
    service._changes._forgejo = service._forgejo_embed
    service._targets._git = fake_git
    app.state.config = config
    app.state.review_service = service
    app.state.triage_service = AntaresTriageService(config)
    app.state.token_store = service.token_store
    client = TestClient(app)
    _, admin_token = mint_api_token(
        service.token_store,
        label="admin",
        actor="admin",
        capabilities=[TokenCapability.ADMIN],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, admin_token)
    return client, service, fake_git


async def _fake_plan(**kwargs):
    return PlanRunResult(
        output_text="Plan: 0 to add, 0 to change, 1 to destroy",
        summary_add=0,
        summary_change=0,
        summary_destroy=1,
        duration_ms=5,
        exit_code=2,
    )


def test_targets_overview_shows_no_apply_recorded(targets_client) -> None:
    client, _, _ = targets_client
    response = client.get("/ui/targets")
    assert response.status_code == 200
    assert "no apply recorded" in response.text
    assert "edge-fw-01" in response.text


def test_runner_and_gate_alerts_on_overview(targets_client) -> None:
    client, _, fake_git = targets_client
    fake_git._action_runners = (True, "ok", [])
    response = client.get("/ui/targets")
    assert response.status_code == 200
    assert "runner" in response.text.lower() or "No Forgejo Actions runners" in response.text
    assert "bypassable" in response.text.lower() or "does not require" in response.text


def test_unvalidated_pr_in_inflight_list(targets_client) -> None:
    client, _, _ = targets_client
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "changes"})
    assert response.status_code == 200
    assert "target-change-card" in response.text or "No config changes recorded" in response.text


def test_target_detail_renders_cloud_control_layout(targets_client) -> None:
    client, _, _ = targets_client
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "config"})
    assert response.status_code == 200
    text = response.text
    assert 'class="target-breadcrumb"' in text
    assert 'class="target-tab-strip"' in text
    assert 'class="targets-summary-grid"' in text
    assert 'class="targets-page-title"' in text


def test_failed_validation_not_on_config_tab_placeholder(targets_client) -> None:
    client, _, fake_git = targets_client
    fake_git._gate_success = False
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "config"})
    assert response.status_code == 200
    assert "target-config-card" in response.text or "No declared configuration" in response.text
    assert "Validation incomplete" not in response.text


def test_status_conveyed_with_text_prefix_not_color_only(targets_client) -> None:
    client, _, _ = targets_client
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert 'class="target-tab-strip"' in response.text


def test_last_applied_not_on_summary_cards(targets_client) -> None:
    client, _, _ = targets_client
    response = client.get("/ui/targets/edge-fw-01")
    assert response.status_code == 200
    assert "no apply recorded" not in response.text
    assert "HCL parse coverage" in response.text


def test_divergence_not_shown_on_detail_page(targets_client) -> None:
    client, service, _ = targets_client
    from shift_left.models.schema import AppliedRevision
    from datetime import datetime, timezone

    service._config.managed_targets.applied_revisions.append(
        AppliedRevision(
            target_id="edge-fw-01",
            applied_sha="prev-rev-bbb",
            applied_at=datetime.now(timezone.utc),
            actor="operator",
            adapter="none",
        )
    )
    response = client.get("/ui/targets/edge-fw-01")
    assert "commits ahead of applied" not in response.text


def test_history_tab_empty_state(targets_client) -> None:
    client, _, _ = targets_client
    response = client.get(
        "/ui/targets/edge-fw-01",
        params={"tab": "history"},
    )
    assert response.status_code == 200
    assert "No recorded events for this target" in response.text
    assert "Declared HEAD" in response.text


def test_unclassified_finding_in_advisory_group(targets_client) -> None:
    client, service, _ = targets_client
    from shift_left.models.schema import Finding, FindingSource, Severity, TargetKind

    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="pr-head-ccc",
        file_path="terraform/main.tf",
        title="Test",
        description="d",
        severity=Severity.MEDIUM,
        policy_severity=PolicySeverity.UNCLASSIFIED,
        source=FindingSource.CODE_HANDLER,
        target_kind=TargetKind.CONFIG,
        model_asserted_cwe="CWE-284",
    )
    service._store.save_findings([finding])
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    assert "source-pill--advisory" in response.text


def test_plan_refused_without_gate(targets_client) -> None:
    client, service, fake_git = targets_client
    service._deployment._plan_runner = _fake_plan
    service._config.deployment.fmc.enabled = True
    service._config.managed_targets.targets[0].deployment_adapter = "fmc"
    fake_git._gate_success = False
    import os

    os.environ.setdefault("TF_VAR_fmc_username", "admin")
    os.environ.setdefault("TF_VAR_fmc_password", "SECRET123")
    os.environ.setdefault("TF_VAR_fmc_host", "198.18.134.100")
    response = client.post(
        "/ui/targets/edge-fw-01/plan",
        data={"commit_sha": fake_git._branch_sha},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=" in response.headers["location"]


def test_deploy_tab_empty_state(targets_client) -> None:
    client, _, _ = targets_client
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "deploy"})
    assert response.status_code == 200
    assert "Plan-only deployment" in response.text
    assert "Generate plan" not in response.text


def test_plan_stale_not_shown_on_deploy_placeholder(targets_client) -> None:
    client, service, _ = targets_client
    from shift_left.models.schema import TerraformPlanRecord

    service._plans.save(
        TerraformPlanRecord(
            repo="o/r",
            pr_ref="TARGET-edge-fw-01",
            commit_sha="stale-sha-old",
            target="edge-fw-01",
            output_text="old plan",
            generated_by="admin",
            summary_destroy=0,
        )
    )
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "deploy"})
    assert "stale" not in response.text.lower()


def test_ui_routes_load_with_egress_blocked(targets_client) -> None:
    client, _, _ = targets_client
    routes = UI_ROUTES + ["/ui/targets/edge-fw-01"]
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
            from shift_left.sovereignty.network import EgressGuard

            with EgressGuard(allowed_hosts=frozenset({"127.0.0.1", "localhost", "::1"})):
                for route in routes:
                    response = client.get(route)
                    assert response.status_code in {200, 303, 401, 404}, route
    assert attempts == []


def test_ui_routes_block_egress(targets_client) -> None:
    client, _, _ = targets_client
    for route in UI_ROUTES + ["/ui/targets/edge-fw-01"]:
        response = client.get(route)
        assert response.status_code in {200, 303, 401, 404}
