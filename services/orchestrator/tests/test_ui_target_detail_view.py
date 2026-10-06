"""Target detail page — Cloud Control shell, summary cards, findings tab."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import AppConfig
from shift_left.main import app
from shift_left.models.schema import (
    Finding,
    FindingSource,
    FindingWaiverRecord,
    LineRange,
    PolicySeverity,
    Severity,
    TargetKind,
)
from shift_left.policy.finding_waiver import finding_waiver_identity
from shift_left.review.service import ReviewService
from shift_left.triage.service import AntaresTriageService
from shift_left.ui.target_detail_view import (
    _disabled_rules_for_target_type,
    build_summary_metrics,
    build_target_detail_view,
)
from tests.test_phase3_hardening import FakeGit


class TargetDetailFakeGit(FakeGit):
    def __init__(
        self,
        *,
        tree_paths: list[str],
        file_contents: dict[str, str],
        branch_sha: str = "declared-head-aaa",
    ) -> None:
        super().__init__()
        self._branch_sha = branch_sha
        self._tree_paths = tree_paths
        self._file_contents = file_contents

    async def get_branch(self, owner: str, repo: str, branch: str) -> dict:
        return {
            "name": branch,
            "commit": {"id": self._branch_sha, "timestamp": "2026-01-02T00:00:00Z"},
        }

    async def list_repo_commits(self, owner, repo, *, sha, path=None, limit=50):
        return [
            {
                "sha": self._branch_sha,
                "commit": {
                    "message": "update",
                    "author": {"name": "netops"},
                    "committer": {"date": "2026-01-02T00:00:00Z"},
                },
            }
        ]

    async def get_file_content(self, owner, repo, path, ref):
        return self._file_contents.get(path, "")

    async def list_repo_tree_paths(self, owner, repo, ref):
        return self._tree_paths


def _build_client(
    tmp_path,
    *,
    target_id: str,
    target_type: str,
    config_paths: list[str],
    tree_paths: list[str],
    file_contents: dict[str, str],
) -> tuple[TestClient, ReviewService]:
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
            "gate": {
                "enabled": True,
                "status_context": "shift-left/gate",
                "check_repo": "o/r",
                "protected_branch": "main",
                "warn_if_branch_protection_missing": False,
            },
            "managed_targets": {
                "targets": [
                    {
                        "id": target_id,
                        "display_name": target_id,
                        "target_type": target_type,
                        "repo": "o/r",
                        "branch": "main",
                        "config_paths": config_paths,
                    }
                ]
            },
        }
    )
    service = ReviewService(config)
    fake_git = TargetDetailFakeGit(tree_paths=tree_paths, file_contents=file_contents)
    service._git = fake_git
    service._approval_service._git = fake_git
    service._gate_service._git = fake_git
    service._changes._git = fake_git
    service._forgejo_embed._git = fake_git
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
    return client, service


@pytest.fixture
def detail_client(tmp_path):
    return _build_client(
        tmp_path,
        target_id="edge-fw-01",
        target_type="generic_terraform",
        config_paths=["terraform/**"],
        tree_paths=["terraform/main.tf", "terraform/device.cfg"],
        file_contents={
            "terraform/main.tf": 'resource "aws_security_group" "web" {}\n',
            "terraform/device.cfg": "# device cfg\n",
        },
    )


def _findings_group_section(html: str, label: str) -> str:
    start = html.find(f">{label}</span>")
    if start == -1:
        return ""
    for other in ("Blocking", "Flagged", "Advisory"):
        if other == label:
            continue
        end = html.find(f">{other}</span>", start + 1)
        if end != -1:
            return html[start:end]
    return html[start:]


def _save_waiver(service: ReviewService, finding: Finding, *, actor: str, reason: str) -> None:
    identity = finding_waiver_identity(finding)
    assert identity is not None
    service.waivers._waivers.grant(
        FindingWaiverRecord(
            repo=identity.repo,
            pr_ref=identity.pr_ref,
            commit_sha=finding.commit_sha,
            target_kind=identity.target_kind,
            rule_id=identity.rule_id,
            file_path=identity.file_path,
            line_start=identity.line_start,
            construct_key=identity.construct_key,
            weakness_class=identity.weakness_class,
            finding_id=finding.id,
            actor=actor,
            reason=reason,
            granted_with_capability="approve",
        )
    )


def test_target_detail_shell_and_breadcrumb(detail_client) -> None:
    client, _ = detail_client
    response = client.get("/ui/targets/edge-fw-01")
    assert response.status_code == 200
    text = response.text
    assert 'class="target-breadcrumb"' in text
    assert "Change Review" in text
    assert "Targets" in text
    assert "edge-fw-01" in text
    assert 'class="targets-page target-detail-page"' in text
    assert 'class="target-tab-strip"' in text
    assert 'class="targets-summary-grid"' in text


def test_target_detail_summary_cards(detail_client) -> None:
    client, _ = detail_client
    response = client.get("/ui/targets/edge-fw-01")
    assert response.status_code == 200
    text = response.text
    assert "Rules active" in text
    assert "Findings" in text
    assert "HCL parse coverage" in text


def test_target_detail_config_tab_empty_state(detail_client) -> None:
    client, _ = detail_client
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "config"})
    assert response.status_code == 200
    assert "Declared configuration files" in response.text
    assert "terraform/main.tf" in response.text


def test_target_detail_findings_empty_state(detail_client) -> None:
    client, _ = detail_client
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    assert "No findings —" in response.text
    assert "rules evaluated" in response.text


def test_target_detail_findings_advisory_no_severity_pill(detail_client) -> None:
    client, service = detail_client
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="declared-head-aaa",
        file_path="terraform/main.tf",
        title="Model advisory",
        description="advisory detail",
        severity=Severity.MEDIUM,
        policy_severity=PolicySeverity.UNCLASSIFIED,
        source=FindingSource.ANTARES,
        target_kind=TargetKind.CONFIG,
        model_asserted_cwe="CWE-284",
    )
    service._store.save_findings([finding])
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    text = response.text
    assert "Advisory" in text
    assert "source-pill--advisory" in text
    assert "status-pill--danger" not in text.split("Advisory")[1][:500]


def test_target_detail_unrecognized_model_cwe_renders_trigger(detail_client) -> None:
    client, service = detail_client
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="declared-head-aaa",
        file_path="terraform/main.tf",
        title="Model advisory",
        description="unknown cwe",
        policy_severity=PolicySeverity.UNCLASSIFIED,
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        model_asserted_cwe="CWE-99999",
        model_cwe_recognized=False,
    )
    service._store.save_findings([finding])
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    text = response.text
    assert 'data-cwe-id="CWE-99999"' in text
    assert 'data-cwe-unrecognized="true"' in text
    assert "cwe-ref-trigger" in text


def test_target_detail_unclaimed_banner(detail_client) -> None:
    client, _ = detail_client
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    text = response.text
    assert "target-unclaimed-banner" in text
    assert "terraform/device.cfg" in text
    assert "routing.config_globs" in text
    assert "routing.routing_parser_claim_globs" in text
    assert "routing.pr_gate_exclusion_globs" in text


def test_target_detail_blocking_finding_group(detail_client) -> None:
    client, service = detail_client
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="declared-head-aaa",
        file_path="terraform/main.tf",
        line_range=LineRange(start=1, end=1),
        title="Unrestricted ingress",
        description="0.0.0.0/0",
        policy_severity=PolicySeverity.HIGH,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        handler_asserted_cwe="CWE-284",
        trace="handler:TF-001",
    )
    service._store.save_findings([finding])
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    text = response.text
    assert "Blocking" in text
    assert "TF-001" in text
    assert "status-pill--danger" in text
    assert "source-pill--deterministic" in text


def test_waived_block_finding_stays_in_blocking_group_with_inline_waiver(detail_client) -> None:
    client, service = detail_client
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="declared-head-aaa",
        file_path="terraform/main.tf",
        line_range=LineRange(start=1, end=1),
        title="Unrestricted ingress",
        description="0.0.0.0/0",
        policy_severity=PolicySeverity.HIGH,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        handler_asserted_cwe="CWE-284",
        trace="handler:TF-001",
        construct_key="resource:aws_security_group.open",
    )
    service._store.save_findings([finding])
    _save_waiver(
        service,
        finding,
        actor="netops-lead",
        reason="Emergency change INC-42 with compensating monitor.",
    )
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    text = response.text
    assert "Waived findings" not in text
    blocking = _findings_group_section(text, "Blocking")
    assert "TF-001" in blocking
    assert "status-pill--waived" in blocking
    assert "Emergency change INC-42" in blocking
    assert "netops-lead" in blocking
    assert "declare" in blocking
    waiver_pos = blocking.find("status-pill--waived")
    details_pos = blocking.find("<details")
    if details_pos != -1:
        assert waiver_pos != -1 and waiver_pos < details_pos


def test_cli001_renders_in_blocking_group_with_managed_target_remediation(detail_client) -> None:
    client, service = detail_client
    from shift_left.handlers.config.rules.registry import rule_by_id

    rule = rule_by_id("CLI-001")
    assert rule is not None
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="declared-head-aaa",
        file_path="terraform/device.cfg",
        line_range=LineRange(start=1, end=2),
        title="Platform could not be determined",
        description=rule.description,
        policy_severity=PolicySeverity.HIGH,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        handler_asserted_cwe="CWE-754",
        trace="handler:CLI-001",
        construct_key="file",
    )
    service._store.save_findings([finding])
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    blocking = _findings_group_section(response.text, "Blocking")
    assert "CLI-001" in blocking
    assert "CWE-754" in blocking
    assert "status-pill--danger" in blocking
    assert "managed_targets" in blocking
    assert "target_type: cisco_ios_xe" in blocking
    assert "configs/**/*.cfg" in blocking


def test_waived_hcl001_finding_stays_visible_with_waived_pill(detail_client) -> None:
    client, service = detail_client
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="declared-head-aaa",
        file_path="terraform/broken.tf",
        line_range=LineRange(start=1, end=5),
        title="HCL content could not be interpreted",
        description="python-hcl2 is not available",
        policy_severity=PolicySeverity.HIGH,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        handler_asserted_cwe="CWE-754",
        trace="handler:HCL-001",
        construct_key="file",
    )
    service._store.save_findings([finding])
    _save_waiver(
        service,
        finding,
        actor="netops-lead",
        reason="Parser gap accepted for lab rollout.",
    )
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    blocking = _findings_group_section(response.text, "Blocking")
    assert "HCL-001" in blocking
    assert "status-pill--waived" in blocking
    assert "Parser gap accepted for lab rollout." in blocking


def test_advisory_finding_has_no_severity_pill_and_not_in_blocking(detail_client) -> None:
    client, service = detail_client
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="declared-head-aaa",
        file_path="terraform/main.tf",
        title="Model advisory",
        description="advisory detail",
        severity=Severity.CRITICAL,
        policy_severity=PolicySeverity.CRITICAL,
        source=FindingSource.ANTARES,
        target_kind=TargetKind.CONFIG,
        model_asserted_cwe="CWE-284",
    )
    service._store.save_findings([finding])
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    text = response.text
    blocking = _findings_group_section(text, "Blocking")
    assert "Model advisory" not in blocking
    advisory = _findings_group_section(text, "Advisory")
    assert "Model advisory" in advisory
    assert "status-pill--danger" not in advisory
    assert "status-pill--warn" not in advisory
    assert "source-pill--advisory" in advisory


def test_handler_finding_renders_deterministic_source_pill(detail_client) -> None:
    client, service = detail_client
    finding = Finding(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="declared-head-aaa",
        file_path="terraform/main.tf",
        line_range=LineRange(start=1, end=1),
        title="Handler finding",
        description="detail",
        policy_severity=PolicySeverity.MEDIUM,
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        handler_asserted_cwe="CWE-284",
        trace="handler:TF-001",
    )
    service._store.save_findings([finding])
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    text = response.text
    assert "source-pill--deterministic" in text
    assert "DETERMINISTIC" in text
    assert "source-pill--advisory" not in text.split("Handler finding")[0]


def test_parse_coverage_asa_target_from_declared_rules(tmp_path) -> None:
    client, service = _build_client(
        tmp_path,
        target_id="asa-edge",
        target_type="cisco_secure_firewall",
        config_paths=["firewall/**"],
        tree_paths=["firewall/edge.rules"],
        file_contents={
            "firewall/edge.rules": (
                "object network INSIDE\n"
                " host 10.0.0.1\n"
                "access-list OUTSIDE extended permit tcp any host 10.0.0.1 eq 443\n"
                "access-list OUTSIDE extended permit ip any any\n"
            ),
        },
    )
    response = client.get("/ui/targets/asa-edge")
    assert response.status_code == 200
    assert "Parse coverage" in response.text
    assert "evaluable ACL lines" in response.text
    assert "corpus" not in response.text.lower()


@pytest.mark.asyncio
async def test_parse_coverage_asa_metric_from_declared_config(tmp_path) -> None:
    _, service = _build_client(
        tmp_path,
        target_id="asa-edge",
        target_type="cisco_secure_firewall",
        config_paths=["firewall/**"],
        tree_paths=["firewall/edge.rules"],
        file_contents={
            "firewall/edge.rules": (
                "access-list OUTSIDE extended permit tcp any host 10.0.0.1 eq 443\n"
                "access-list OUTSIDE extended permit ip any any\n"
            ),
        },
    )
    detail = await service.targets.detail("asa-edge")
    assert detail is not None
    _, panel = build_target_detail_view(detail, service._config, service.waivers)
    summary = build_summary_metrics(detail, table_findings=panel)
    assert summary.parse_coverage_label == "Parse coverage"
    assert summary.parse_coverage_percent == "2 of 2 evaluable ACL lines"
    assert summary.parse_coverage_meta is None


def test_parse_coverage_ftd_target_from_declared_hcl(tmp_path) -> None:
    client, _ = _build_client(
        tmp_path,
        target_id="ftd-edge",
        target_type="cisco_ftd",
        config_paths=["terraform/**"],
        tree_paths=["terraform/ftd.tf"],
        file_contents={
            "terraform/ftd.tf": (
                'resource "fmc_host" "inside" {\n'
                '  ip = "10.0.0.1"\n'
                "}\n"
                'resource "fmc_host" "dmz" {\n'
                '  ip = "10.0.0.2"\n'
                "}\n"
            ),
        },
    )
    response = client.get("/ui/targets/ftd-edge")
    assert response.status_code == 200
    text = response.text
    assert "HCL parse coverage" in text
    assert "2 of 2 HCL resources" in text


@pytest.mark.asyncio
async def test_parse_coverage_ftd_metric_from_declared_config(tmp_path) -> None:
    _, service = _build_client(
        tmp_path,
        target_id="ftd-edge",
        target_type="cisco_ftd",
        config_paths=["terraform/**"],
        tree_paths=["terraform/ftd.tf"],
        file_contents={
            "terraform/ftd.tf": 'resource "fmc_host" "inside" { ip = "10.0.0.1" }\n',
        },
    )
    detail = await service.targets.detail("ftd-edge")
    assert detail is not None
    summary, _ = build_target_detail_view(detail, service._config, service.waivers)
    assert summary.parse_coverage_label == "HCL parse coverage"
    assert summary.parse_coverage_percent == "1 of 1 HCL resources"
    assert summary.parse_coverage_meta is None


def test_parse_coverage_hcl_parse_failure_surfaces_not_100_percent(tmp_path) -> None:
    client, _ = _build_client(
        tmp_path,
        target_id="tf-broken",
        target_type="generic_terraform",
        config_paths=["terraform/**"],
        tree_paths=["terraform/broken.tf"],
        file_contents={
            "terraform/broken.tf": (
                'resource "aws_security_group" "app" {\n'
                "  name = \"app\"\n"
                "  broken syntax here\n"
            ),
        },
    )
    response = client.get("/ui/targets/tf-broken")
    assert response.status_code == 200
    text = response.text
    assert "Parse failure" in text
    assert "100.0%" not in text
    assert "could not be interpreted" in text


@pytest.mark.asyncio
async def test_parse_coverage_hcl_parse_failure_metric_flag(tmp_path) -> None:
    _, service = _build_client(
        tmp_path,
        target_id="tf-broken",
        target_type="generic_terraform",
        config_paths=["terraform/**"],
        tree_paths=["terraform/broken.tf"],
        file_contents={
            "terraform/broken.tf": 'resource "aws_security_group" "app" { name = "x"\n',
        },
    )
    detail = await service.targets.detail("tf-broken")
    assert detail is not None
    summary, _ = build_target_detail_view(detail, service._config, service.waivers)
    assert summary.parse_coverage_failed is True
    assert summary.parse_coverage_percent is None
    assert summary.parse_coverage_meta is not None
    assert "Parse failure" in summary.parse_coverage_meta


def test_parse_coverage_variables_tf_zero_resources_not_failure(tmp_path) -> None:
    client, _ = _build_client(
        tmp_path,
        target_id="tf-vars",
        target_type="generic_terraform",
        config_paths=["terraform/**"],
        tree_paths=["terraform/variables.tf"],
        file_contents={
            "terraform/variables.tf": (
                'variable "region" {\n'
                '  type    = string\n'
                '  default = "us-east-1"\n'
                "}\n"
            ),
        },
    )
    response = client.get("/ui/targets/tf-vars")
    assert response.status_code == 200
    text = response.text
    assert "No HCL resources at declared HEAD" in text
    assert "Parse failure" not in text
    assert "100.0%" not in text


@pytest.mark.asyncio
async def test_parse_coverage_variables_tf_zero_resources_metric(tmp_path) -> None:
    _, service = _build_client(
        tmp_path,
        target_id="tf-vars",
        target_type="generic_terraform",
        config_paths=["terraform/**"],
        tree_paths=["terraform/variables.tf"],
        file_contents={
            "terraform/variables.tf": 'variable "region" { type = string }\n',
        },
    )
    detail = await service.targets.detail("tf-vars")
    assert detail is not None
    summary, _ = build_target_detail_view(detail, service._config, service.waivers)
    assert summary.parse_coverage_failed is False
    assert summary.parse_coverage_percent is None
    assert summary.parse_coverage_meta == "No HCL resources at declared HEAD"


def test_cwe_ref_triggers_render_on_findings_and_gaps(detail_client) -> None:
    client, _ = detail_client
    response = client.get("/ui/targets/edge-fw-01", params={"tab": "findings"})
    assert response.status_code == 200
    text = response.text
    assert 'class="cwe-ref-trigger' in text
    assert 'data-cwe-id="CWE-657"' in text
    assert 'id="cwe-dictionary-data"' in text
    assert "Violation of Secure Design Principles" in text


def test_cwe_ref_missing_dictionary_still_renders_trigger(tmp_path) -> None:
    client, _ = _build_client(
        tmp_path,
        target_id="asa-edge",
        target_type="cisco_secure_firewall",
        config_paths=["firewall/**"],
        tree_paths=["firewall/edge.rules"],
        file_contents={"firewall/edge.rules": "access-list OUTSIDE extended permit ip any any\n"},
    )
    response = client.get("/ui/targets/asa-edge", params={"tab": "findings"})
    assert response.status_code == 200
    assert 'class="cwe-ref-trigger' in response.text


def test_target_detail_requires_authenticated_session(detail_client) -> None:
    client, _ = detail_client
    client.cookies.clear()
    response = client.get("/ui/targets/edge-fw-01", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/ui/login")


def test_target_detail_matches_findings_dashboard_auth_requirement(detail_client) -> None:
    client, _ = detail_client
    client.cookies.clear()
    findings_response = client.get("/ui/findings", follow_redirects=False)
    target_response = client.get("/ui/targets/edge-fw-01", follow_redirects=False)
    assert findings_response.status_code == target_response.status_code == 303
    assert findings_response.headers["location"].startswith("/ui/login")
    assert target_response.headers["location"].startswith("/ui/login")


def test_disabled_rule_gaps_exclude_hcl001_pre_match_enforcement() -> None:
    asa_gaps = {row.rule_id for row in _disabled_rules_for_target_type("cisco_secure_firewall")}
    terraform_gaps = {row.rule_id for row in _disabled_rules_for_target_type("generic_terraform")}
    ftd_gaps = {row.rule_id for row in _disabled_rules_for_target_type("cisco_ftd")}
    assert "ASA-003" in asa_gaps
    assert "FTD-007" in ftd_gaps
    assert "HCL-001" not in asa_gaps
    assert "HCL-001" not in terraform_gaps
    assert "HCL-001" not in ftd_gaps
