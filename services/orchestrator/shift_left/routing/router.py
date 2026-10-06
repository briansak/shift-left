"""Route changed files to code vs config review paths."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from shift_left.config import ManagedTargetConfig, RoutingConfig
from shift_left.diff.extractor import ChangedFile
from shift_left.handlers.config.parser_scope import (
    path_in_routing_parser_claim_scope,
    path_in_target_parser_scope,
)
from shift_left.routing.globmatch import matches_any


@dataclass(frozen=True)
class RoutedChanges:
    code_files: list[ChangedFile]
    config_files: list[ChangedFile]
    skipped_files: list[str]


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


def _is_config_claimed(
    path: str,
    routing: RoutingConfig,
    *,
    repo: str | None,
    targets: Sequence[ManagedTargetConfig] | None,
) -> bool:
    if not matches_any(path, routing.config_globs):
        return False
    if targets is not None and repo is not None:
        matched_targets = _matching_targets(path, repo, targets)
        if len(matched_targets) == 1:
            return path_in_target_parser_scope(matched_targets[0].target_type, path)
        if len(matched_targets) > 1:
            return False
    return path_in_routing_parser_claim_scope(path, routing)


def route_changes(
    files: list[ChangedFile],
    routing: RoutingConfig,
    *,
    repo: str | None = None,
    targets: Sequence[ManagedTargetConfig] | None = None,
) -> RoutedChanges:
    code_files: list[ChangedFile] = []
    config_files: list[ChangedFile] = []
    skipped: list[str] = []

    for changed in files:
        path = changed.path
        if matches_any(path, routing.ignore_globs):
            skipped.append(path)
            continue

        is_code = matches_any(path, routing.code_globs)
        if _is_config_claimed(path, routing, repo=repo, targets=targets):
            config_files.append(changed)
        elif is_code:
            code_files.append(changed)
        else:
            skipped.append(path)

    return RoutedChanges(
        code_files=code_files,
        config_files=config_files,
        skipped_files=skipped,
    )
