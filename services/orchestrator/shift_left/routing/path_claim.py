"""Classify changed PR paths against routing globs for gate coverage."""

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum

from shift_left.config import ManagedTargetConfig, RoutingConfig
from shift_left.handlers.config.parser_scope import (
    path_in_routing_parser_claim_scope,
    path_in_target_parser_scope,
)
from shift_left.routing.globmatch import matches_any


class PathClaim(str, Enum):
    """How a changed file is claimed during PR gate classification."""

    CODE = "code"
    CONFIG = "config"
    EXCLUDED = "excluded"
    UNCLAIMED = "unclaimed"


def _matching_targets(
    path: str,
    repo: str,
    targets: Sequence[ManagedTargetConfig],
) -> list[ManagedTargetConfig]:
    return [
        target
        for target in targets
        if target.repo == repo
        if any(matches_any(path, [pattern]) for pattern in target.config_paths)
    ]


def classify_path(
    path: str,
    routing: RoutingConfig,
    *,
    repo: str | None = None,
    targets: Sequence[ManagedTargetConfig] | None = None,
) -> PathClaim:
    """
    Classify one changed path.

    Precedence when multiple globs match:
    1. ``pr_gate_exclusion_globs`` — explicitly excluded (passes gate without analysis)
    2. Managed target ``config_paths`` with per-target parser scope — config-claimed
    3. ``config_globs`` **and** ``routing_parser_claim_globs`` — config-claimed
    4. ``code_globs`` — claimed as code (advisory Antares path when not parser-scoped)
    5. ``config_globs`` without parser scope — unclaimed (CWE-657)
    6. otherwise — unclaimed (CWE-657)
    """
    if matches_any(path, routing.pr_gate_exclusion_globs):
        return PathClaim.EXCLUDED
    is_code = matches_any(path, routing.code_globs)
    is_config = matches_any(path, routing.config_globs)

    if is_config and targets is not None and repo is not None:
        matched_targets = _matching_targets(path, repo, targets)
        if len(matched_targets) == 1:
            target = matched_targets[0]
            if path_in_target_parser_scope(target.target_type, path):
                return PathClaim.CONFIG
            return PathClaim.UNCLAIMED
        if len(matched_targets) > 1:
            return PathClaim.UNCLAIMED

    if is_config and path_in_routing_parser_claim_scope(path, routing):
        return PathClaim.CONFIG
    if is_code:
        return PathClaim.CODE
    if is_config:
        return PathClaim.UNCLAIMED
    return PathClaim.UNCLAIMED


def classify_paths(
    paths: list[str],
    routing: RoutingConfig,
    *,
    repo: str | None = None,
    targets: Sequence[ManagedTargetConfig] | None = None,
) -> dict[str, PathClaim]:
    """Return a claim classification for each path (deduplicated, stable order)."""
    seen: set[str] = set()
    ordered: list[str] = []
    for path in paths:
        if not path or path in seen:
            continue
        seen.add(path)
        ordered.append(path)
    return {
        path: classify_path(path, routing, repo=repo, targets=targets)
        for path in sorted(ordered)
    }


def unclaimed_paths(
    paths: list[str],
    routing: RoutingConfig,
    *,
    repo: str | None = None,
    targets: Sequence[ManagedTargetConfig] | None = None,
) -> list[str]:
    return sorted(
        path
        for path, claim in classify_paths(
            paths,
            routing,
            repo=repo,
            targets=targets,
        ).items()
        if claim == PathClaim.UNCLAIMED
    )
