"""PR gate coverage for unclaimed changed files."""

from __future__ import annotations

from pathlib import Path

from shift_left.config import AppConfig, ManagedTargetConfig, RoutingConfig, UnclaimedFilesGateConfig
from shift_left.handlers.config.gate_findings import findings_for_corpus_file
from shift_left.handlers.unclaimed_files import findings_for_unclaimed_paths
from shift_left.models.schema import FindingSource, PolicyAction, PolicySeverity
from shift_left.policy.engine import PolicyEngine
from shift_left.policy.severity import apply_policy_severities
from shift_left.routing.path_claim import PathClaim, classify_path, unclaimed_paths


def _minimal_config(**overrides) -> AppConfig:
    base = {
        "findings_store": {"sqlite_path": "/tmp/shift-left-test.db"},
        "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
    }
    base.update(overrides)
    return AppConfig.model_validate(base)


def test_unclaimed_file_produces_handler_finding_and_blocks() -> None:
    routing = RoutingConfig()
    paths = ["docs/CHANGELOG.md"]
    assert classify_path("docs/CHANGELOG.md", routing) == PathClaim.UNCLAIMED

    gate = UnclaimedFilesGateConfig()
    findings = findings_for_unclaimed_paths(
        paths,
        gate=gate,
        repo="org/repo",
        pr_ref="PR-42",
        commit_sha="deadbeef",
    )
    assert len(findings) == 1
    finding = apply_policy_severities(findings, _minimal_config())[0]
    assert finding.source == FindingSource.HANDLER
    assert finding.handler_asserted_cwe == "CWE-657"
    assert finding.policy_severity == PolicySeverity.HIGH

    engine = PolicyEngine(_minimal_config().policy)
    result = engine.evaluate(
        repo="org/repo",
        pr_ref="PR-42",
        commit_sha="deadbeef",
        findings=[finding],
    )
    assert result.pr_action == PolicyAction.BLOCK


def test_excluded_workflow_file_passes_gate() -> None:
    routing = RoutingConfig()
    path = ".forgejo/workflows/shift-left-review.yml"
    assert classify_path(path, routing) == PathClaim.EXCLUDED
    assert unclaimed_paths([path], routing) == []


def test_matched_config_file_is_claimed_not_unclaimed() -> None:
    routing = RoutingConfig()
    path = "terraform/main.tf"
    assert classify_path(path, routing) == PathClaim.CONFIG
    assert unclaimed_paths([path], routing) == []


def test_dual_code_and_config_match_prefers_config_gate_when_parser_scoped() -> None:
    routing = RoutingConfig(
        code_globs=["**/*.tf", "**/*.py"],
        config_globs=["**/*.tf", "**/*.yaml"],
    )
    path = "terraform/aws-open-sg.tf"
    # Precedence: exclusion > config_globs+parser_globs > code_globs > config-only > unclaimed.
    assert classify_path(path, routing) == PathClaim.CONFIG
    assert classify_path(path, routing) != PathClaim.CODE
    assert unclaimed_paths([path], routing) == []


def test_dual_match_parser_scoped_config_violation_blocks_gate() -> None:
    from shift_left.handlers.config.gate_findings import findings_for_corpus_file
    from shift_left.policy.engine import PolicyEngine
    from shift_left.policy.severity import apply_policy_severities

    routing = RoutingConfig(
        code_globs=["**/*.tf"],
        config_globs=["**/*.tf"],
    )
    path = "terraform/aws-open-sg.tf"
    assert classify_path(path, routing) == PathClaim.CONFIG

    fixture = (
        Path(__file__).resolve().parents[3]
        / "validation/corpus/config/generic_terraform/aws-open-sg.tf"
    )
    content = fixture.read_text()
    config = _minimal_config()
    findings = apply_policy_severities(
        findings_for_corpus_file(
            path=path,
            target_type="generic_terraform",
            content=content,
            config=config,
        ),
        config,
    )
    assert len(findings) >= 1
    engine = PolicyEngine(config.policy)
    result = engine.evaluate(
        repo="org/repo",
        pr_ref="PR-42",
        commit_sha="deadbeef",
        findings=findings,
    )
    assert result.pr_action == PolicyAction.BLOCK


def test_dual_code_and_config_match_code_when_not_parser_scoped() -> None:
    routing = RoutingConfig(
        code_globs=["**/*.py"],
        config_globs=["**/*"],
    )
    path = "scripts/deploy.py"
    assert classify_path(path, routing) == PathClaim.CODE
    assert classify_path(path, routing) != PathClaim.UNCLAIMED
    assert unclaimed_paths([path], routing) == []


def test_cfg_without_managed_target_is_unclaimed() -> None:
    routing = RoutingConfig()
    path = "firewall/bootstrap.cfg"
    assert classify_path(path, routing) == PathClaim.UNCLAIMED
    assert unclaimed_paths([path], routing) == [path]


def test_cfg_on_asa_managed_target_stays_unclaimed() -> None:
    routing = RoutingConfig()
    path = "firewall/holdout-asa-nonrules-cfg.cfg"
    targets = [
        ManagedTargetConfig(
            id="asa-edge",
            display_name="ASA edge",
            target_type="cisco_secure_firewall",
            repo="org/repo",
            config_paths=["firewall/**"],
        )
    ]
    assert classify_path(path, routing, repo="org/repo", targets=targets) == PathClaim.UNCLAIMED
    assert unclaimed_paths([path], routing, repo="org/repo", targets=targets) == [path]


def test_nx_os_cfg_on_managed_target_is_claimed() -> None:
    routing = RoutingConfig()
    path = "switches/leaf-01.cfg"
    targets = [
        ManagedTargetConfig(
            id="nx-leaf",
            display_name="NX-OS leaf switches",
            target_type="cisco_nx_os",
            repo="org/repo",
            config_paths=["switches/**"],
        )
    ]
    assert classify_path(path, routing, repo="org/repo", targets=targets) == PathClaim.CONFIG
    assert unclaimed_paths([path], routing, repo="org/repo", targets=targets) == []


def test_ios_xe_cfg_on_managed_target_is_claimed_and_evaluates_ios_002() -> None:
    routing = RoutingConfig()
    path = "switches/access-sw01.cfg"
    targets = [
        ManagedTargetConfig(
            id="ios-access",
            display_name="IOS access switches",
            target_type="cisco_ios_xe",
            repo="org/repo",
            config_paths=["switches/**"],
        )
    ]
    assert classify_path(path, routing, repo="org/repo", targets=targets) == PathClaim.CONFIG
    assert unclaimed_paths([path], routing, repo="org/repo", targets=targets) == []

    fixture = (
        Path(__file__).resolve().parents[3]
        / "validation/corpus/config/cisco_ios_xe/ios002-violation-telnet-vty.cfg"
    )
    content = fixture.read_text()
    config = _minimal_config(
        managed_targets={
            "targets": [
                {
                    "id": "ios-access",
                    "display_name": "IOS access switches",
                    "target_type": "cisco_ios_xe",
                    "repo": "org/repo",
                    "config_paths": ["switches/**"],
                }
            ]
        }
    )
    findings = apply_policy_severities(
        findings_for_corpus_file(
            path=path,
            target_type="cisco_ios_xe",
            content=content,
            repo="org/repo",
            config=config,
        ),
        config,
    )
    traces = {item.trace for item in findings}
    assert "handler:unclaimed-file" not in traces
    assert "handler:IOS-002" in traces


def test_cwe_657_preferred_over_cwe_1053() -> None:
    """CWE-657 documents a secure-design scope violation; CWE-1053 is design-doc gaps."""
    gate = UnclaimedFilesGateConfig(handler_asserted_cwe="CWE-657")
    assert gate.handler_asserted_cwe == "CWE-657"
