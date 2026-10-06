"""Managed target configuration validation and registry."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from shift_left.config import AppConfig, CURRENT_SCHEMA_VERSION, ManagedTargetConfig, RoutingConfig, load_config
from shift_left.models.schema import AppliedRevision
from shift_left.targets.registry import ManagedTargetRegistry
from shift_left.targets.validation import (
    ManagedTargetConfigError,
    resolve_path_to_target,
    unclaimed_config_paths,
    validate_managed_targets,
)


def _target(**overrides) -> ManagedTargetConfig:
    base = {
        "id": "edge-fw-01",
        "display_name": "edge-fw-01",
        "target_type": "cisco_secure_firewall",
        "repo": "shiftleft-admin/sample-firewall",
        "branch": "main",
        "config_paths": ["terraform/**"],
    }
    base.update(overrides)
    return ManagedTargetConfig.model_validate(base)


def test_ambiguous_config_paths_rejected_at_load() -> None:
    routing = RoutingConfig()
    targets = [
        _target(id="a", config_paths=["terraform/**"]),
        _target(id="b", config_paths=["terraform/**"]),
    ]
    with pytest.raises(ManagedTargetConfigError, match="ambiguous"):
        validate_managed_targets(targets, routing=routing)


def test_path_matching_zero_targets_raises() -> None:
    targets = [_target(config_paths=["terraform/**"])]
    with pytest.raises(ManagedTargetConfigError, match="matches no managed target"):
        resolve_path_to_target("README.md", targets, repo="shiftleft-admin/sample-firewall")


def test_path_matching_multiple_targets_raises() -> None:
    targets = [
        _target(id="a", config_paths=["**/*.tf"]),
        _target(id="b", config_paths=["terraform/**"]),
    ]
    with pytest.raises(ManagedTargetConfigError, match="multiple targets"):
        resolve_path_to_target("terraform/main.tf", targets, repo="shiftleft-admin/sample-firewall")


def test_unclaimed_config_paths_reported() -> None:
    routing = RoutingConfig()
    targets = [_target(config_paths=["terraform/modules/**"])]
    repo_paths = ["terraform/modules/a/main.tf", "terraform/unclaimed.tf", "README.md"]
    unclaimed = unclaimed_config_paths(
        repo_paths,
        targets,
        routing,
        repo="shiftleft-admin/sample-firewall",
    )
    assert "terraform/unclaimed.tf" in unclaimed
    assert "terraform/modules/a/main.tf" not in unclaimed


def test_last_applied_not_inferred_from_merge_history() -> None:
    config = AppConfig.model_validate(
        {
            "managed_targets": {
                "targets": [_target().model_dump()],
                "applied_revisions": [],
            }
        }
    )
    registry = ManagedTargetRegistry(config)
    assert registry.applied_for_target("edge-fw-01") is None


def test_divergence_absent_without_applied_revision() -> None:
    from shift_left.targets.service import TargetService
    from tests.test_phase3_hardening import FakeGit

    config = AppConfig.model_validate({"managed_targets": {"targets": [_target().model_dump()]}})
    registry = ManagedTargetRegistry(config)
    service = TargetService(
        config=config,
        registry=registry,
        forgejo=None,
        git=FakeGit(),
        changes=None,  # type: ignore[arg-type]
        findings_store=None,  # type: ignore[arg-type]
        policy_decisions=None,  # type: ignore[arg-type]
        approvals=None,  # type: ignore[arg-type]
        plans=None,  # type: ignore[arg-type]
    )

    async def _run() -> None:
        divergence = await service._divergence_commits(_target(), "abc123", None)
        assert divergence is None

    import asyncio

    asyncio.run(_run())


def test_divergence_correct_with_applied_revision() -> None:
    from shift_left.targets.service import TargetService
    from tests.test_phase3_hardening import FakeGit

    applied = AppliedRevision(
        target_id="edge-fw-01",
        applied_sha="base111",
        applied_at=datetime.now(timezone.utc),
        actor="operator",
        adapter="none",
        outcome="success",
    )
    config = AppConfig.model_validate(
        {
            "managed_targets": {
                "targets": [_target().model_dump()],
                "applied_revisions": [applied.model_dump(mode="json")],
            }
        }
    )
    fake_git = FakeGit()
    fake_git._compare_payload = {"commits": [{"sha": "c1"}, {"sha": "c2"}]}

    async def compare_commits(owner, repo, base, head):
        return fake_git._compare_payload

    fake_git.compare_commits = compare_commits  # type: ignore[method-assign]

    registry = ManagedTargetRegistry(config)
    service = TargetService(
        config=config,
        registry=registry,
        forgejo=None,
        git=fake_git,
        changes=None,  # type: ignore[arg-type]
        findings_store=None,  # type: ignore[arg-type]
        policy_decisions=None,  # type: ignore[arg-type]
        approvals=None,  # type: ignore[arg-type]
        plans=None,  # type: ignore[arg-type]
    )

    async def _run() -> None:
        divergence = await service._divergence_commits(_target(), "head999", applied)
        assert divergence == 2

    import asyncio

    asyncio.run(_run())


def test_load_config_requires_schema_version_eight(tmp_path) -> None:
    config_file = tmp_path / "shift-left.yaml"
    config_file.write_text("schema_version: 7\n")
    with pytest.raises(ValueError, match="unsupported schema_version"):
        load_config(config_file)


def test_load_config_accepts_managed_targets(tmp_path) -> None:
    config_file = tmp_path / "shift-left.yaml"
    config_file.write_text(
        f"""schema_version: {CURRENT_SCHEMA_VERSION}
managed_targets:
  targets:
    - id: edge-fw-01
      display_name: edge-fw-01
      target_type: generic_terraform
      repo: o/r
      branch: main
      config_paths: ["infra/**"]
"""
    )
    config = load_config(config_file)
    assert config.schema_version == CURRENT_SCHEMA_VERSION
    assert len(config.managed_targets.targets) == 1
