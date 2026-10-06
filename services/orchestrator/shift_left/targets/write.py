"""Persist managed targets to operator config."""

from __future__ import annotations

import re
from typing import Any

from shift_left.config import AppConfig, ManagedTargetConfig
from shift_left.models.database import AuditStore
from shift_left.system.config_store import ConfigStore
from shift_left.targets.validation import (
    ManagedTargetConfigError,
    validate_config_paths_match_files,
    validate_managed_targets,
)

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_ALLOWED_ADAPTERS = frozenset({"none", "fmc", "unconfigured"})


def slugify_target_id(value: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", value.strip().lower())
    slug = slug.strip("-")
    return slug or "target"


def unique_target_id(display_name: str, existing_ids: set[str]) -> str:
    base = slugify_target_id(display_name)
    if not _ID_PATTERN.match(base):
        base = "target"
    candidate = base
    suffix = 2
    while candidate in existing_ids:
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def parse_config_paths(raw: str) -> list[str]:
    paths = [item.strip() for item in raw.replace("\n", ",").split(",") if item.strip()]
    if not paths:
        raise ValueError("At least one config path glob is required.")
    return paths


class ManagedTargetWriteService:
    def __init__(self, *, config: AppConfig, audit: AuditStore) -> None:
        self._config = config
        self._audit = audit
        self._store = ConfigStore(config)

    @property
    def config_path(self) -> str:
        return str(self._store.path)

    def add_target(
        self,
        *,
        actor: str,
        display_name: str,
        target_type: str,
        repo: str,
        branch: str = "main",
        config_paths: list[str],
        target_id: str | None = None,
        description: str = "",
        environment: str = "",
        criticality: str = "",
        owner: str = "",
        deployment_adapter: str = "unconfigured",
        repo_paths: list[str] | None = None,
    ) -> ManagedTargetConfig:
        display_name = display_name.strip()
        if not display_name:
            raise ValueError("Display name is required.")
        target_type = target_type.strip()
        if not target_type:
            raise ValueError("Target type is required.")
        if "/" not in repo or repo.count("/") != 1:
            raise ValueError("Repository must be owner/name.")
        if deployment_adapter not in _ALLOWED_ADAPTERS:
            raise ValueError(
                f"deployment_adapter must be one of: {', '.join(sorted(_ALLOWED_ADAPTERS))}"
            )

        raw = self._store.read_raw()
        managed = raw.setdefault("managed_targets", {})
        targets_raw = managed.setdefault("targets", [])
        if not isinstance(targets_raw, list):
            targets_raw = []
            managed["targets"] = targets_raw

        existing_ids = {
            str(item.get("id"))
            for item in targets_raw
            if isinstance(item, dict) and item.get("id")
        }
        resolved_id = (target_id or "").strip() or unique_target_id(display_name, existing_ids)
        if resolved_id in existing_ids:
            raise ValueError(f"Target id {resolved_id!r} already exists.")

        target = ManagedTargetConfig(
            id=resolved_id,
            display_name=display_name,
            target_type=target_type,
            description=description.strip(),
            repo=repo.strip(),
            branch=(branch or "main").strip() or "main",
            config_paths=config_paths,
            deployment_adapter=deployment_adapter,
            deployment_adapter_settings={},
            environment=environment.strip(),
            criticality=criticality.strip(),
            owner=owner.strip(),
        )

        proposed = [
            ManagedTargetConfig.model_validate(item)
            for item in targets_raw
            if isinstance(item, dict)
        ] + [target]
        try:
            validate_managed_targets(proposed, routing=self._config.routing)
            if repo_paths is not None:
                validate_config_paths_match_files(
                    repo_paths,
                    config_paths,
                    repo=target.repo,
                    branch=target.branch,
                )
        except ManagedTargetConfigError as exc:
            raise ValueError(str(exc)) from exc

        entry: dict[str, Any] = target.model_dump(mode="json")
        targets_raw.append(entry)
        self._store.persist_raw(raw)

        self._audit.log(
            actor=actor,
            action="managed_target.created",
            subject=f"target/{target.id}",
            details={
                "old": None,
                "new": entry,
                "repo": target.repo,
                "branch": target.branch,
                "config_paths": target.config_paths,
            },
        )
        return target
