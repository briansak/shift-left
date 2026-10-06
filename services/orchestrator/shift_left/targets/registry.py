"""In-memory registry of managed targets and apply history."""

from __future__ import annotations

from shift_left.config import AppConfig, ManagedTargetConfig
from shift_left.models.schema import AppliedRevision
from shift_left.targets.validation import (
    resolve_path_to_target,
    unclaimed_config_paths,
)


class ManagedTargetRegistry:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    @property
    def targets(self) -> list[ManagedTargetConfig]:
        return list(self._config.managed_targets.targets)

    def get(self, target_id: str) -> ManagedTargetConfig | None:
        for target in self.targets:
            if target.id == target_id:
                return target
        return None

    def applied_for_target(self, target_id: str) -> AppliedRevision | None:
        records = [
            item
            for item in self._config.managed_targets.applied_revisions
            if item.target_id == target_id
        ]
        if not records:
            return None
        return max(records, key=lambda item: item.applied_at)

    def resolve_path(self, repo: str, path: str) -> ManagedTargetConfig:
        return resolve_path_to_target(path, self.targets, repo=repo)

    def unclaimed_in_repo(self, repo_paths: list[str], repo: str) -> list[str]:
        return unclaimed_config_paths(
            repo_paths,
            self.targets,
            self._config.routing,
            repo=repo,
        )
