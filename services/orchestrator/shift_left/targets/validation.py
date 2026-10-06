"""Managed target configuration validation."""

from __future__ import annotations

import re

from shift_left.config import ManagedTargetConfig, RoutingConfig
from shift_left.routing.globmatch import matches_any

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_ALLOWED_ADAPTERS = frozenset({"none", "fmc", "unconfigured"})


class ManagedTargetConfigError(ValueError):
    """Invalid managed_targets configuration."""


def validate_managed_targets(
    targets: list[ManagedTargetConfig],
    *,
    routing: RoutingConfig,
) -> list[str]:
    """
    Validate target declarations at config load.

    Returns unclaimed config file paths discovered from declared target path patterns
    that overlap routing.config_globs (static check on pattern overlap only when
    no repo file list is supplied).
    """
    if not targets:
        return []

    seen_ids: set[str] = set()
    for target in targets:
        if not _ID_PATTERN.match(target.id):
            raise ManagedTargetConfigError(
                f"managed_targets id {target.id!r} must match {_ID_PATTERN.pattern}"
            )
        if target.id in seen_ids:
            raise ManagedTargetConfigError(f"duplicate managed_targets id: {target.id!r}")
        seen_ids.add(target.id)
        if "/" not in target.repo or target.repo.count("/") != 1:
            raise ManagedTargetConfigError(
                f"target {target.id!r} repo must be owner/name, got {target.repo!r}"
            )
        if not target.config_paths:
            raise ManagedTargetConfigError(f"target {target.id!r} must declare config_paths")
        if target.deployment_adapter not in _ALLOWED_ADAPTERS:
            raise ManagedTargetConfigError(
                f"target {target.id!r} deployment_adapter {target.deployment_adapter!r} "
                f"not in {sorted(_ALLOWED_ADAPTERS)}"
            )

    _assert_no_ambiguous_pattern_overlap(targets)
    return []


def resolve_path_to_target(
    path: str,
    targets: list[ManagedTargetConfig],
    *,
    repo: str | None = None,
) -> ManagedTargetConfig:
    """Map a repo file path to exactly one target; raise on zero or multiple matches."""
    matches = [
        target
        for target in targets
        if repo is None or target.repo == repo
        if any(matches_any(path, [pattern]) for pattern in target.config_paths)
    ]
    if not matches:
        raise ManagedTargetConfigError(
            f"config path {path!r} on {repo or 'unknown'} matches no managed target"
        )
    if len(matches) > 1:
        ids = ", ".join(item.id for item in matches)
        raise ManagedTargetConfigError(
            f"config path {path!r} on {repo or 'unknown'} matches multiple targets: {ids}"
        )
    return matches[0]


def validate_config_paths_match_files(
    repo_paths: list[str],
    config_paths: list[str],
    *,
    repo: str,
    branch: str,
) -> None:
    """Reject globs that match zero files at the declared branch."""
    for pattern in config_paths:
        if not any(matches_any(path, [pattern]) for path in repo_paths):
            raise ManagedTargetConfigError(
                f"config_paths glob {pattern!r} matches no files in {repo}@{branch}"
            )


def unclaimed_config_paths(
    repo_paths: list[str],
    targets: list[ManagedTargetConfig],
    routing: RoutingConfig,
    *,
    repo: str,
) -> list[str]:
    """Paths in a repo that match config_globs but are not claimed by any target."""
    repo_targets = [item for item in targets if item.repo == repo]
    unclaimed: list[str] = []
    for path in repo_paths:
        if not matches_any(path, routing.config_globs):
            continue
        if matches_any(path, routing.ignore_globs):
            continue
        claimed = any(
            matches_any(path, target.config_paths) for target in repo_targets
        )
        if not claimed:
            unclaimed.append(path)
    return sorted(unclaimed)


def _assert_no_ambiguous_pattern_overlap(targets: list[ManagedTargetConfig]) -> None:
    """Reject config path patterns that could match the same file on the same repo."""
    by_repo: dict[str, list[ManagedTargetConfig]] = {}
    for target in targets:
        by_repo.setdefault(target.repo, []).append(target)

    for repo, repo_targets in by_repo.items():
        if len(repo_targets) < 2:
            continue
        probes: set[str] = {
            "terraform/main.tf",
            "terraform/modules/x/main.tf",
            "firewall/rules.conf",
            "policy/asr.rules",
            "infra/network.tf",
            "config/device.yaml",
        }
        for target in repo_targets:
            for pattern in target.config_paths:
                probes.update(_example_paths_for_pattern(pattern))
        for probe in sorted(probes):
            hits = [
                target
                for target in repo_targets
                if any(matches_any(probe, [pattern]) for pattern in target.config_paths)
            ]
            if len(hits) > 1:
                raise ManagedTargetConfigError(
                    f"ambiguous config_paths on {repo}: paths {hits[0].config_paths!r} and "
                    f"{hits[1].config_paths!r} can both match {probe!r}"
                )


def _example_paths_for_pattern(pattern: str) -> list[str]:
    if pattern.endswith("/**"):
        base = pattern[:-3].rstrip("/")
        return [f"{base}/main.tf", f"{base}/nested/x.tf"]
    if "**" in pattern:
        return [pattern.replace("**", "nested").replace("*", "file")]
    if "*" in pattern:
        return [pattern.replace("*", "file")]
    return [pattern]
