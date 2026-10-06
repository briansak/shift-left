"""Comment-preserving YAML config persistence."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import yaml

from shift_left.config import (
    CURRENT_SCHEMA_VERSION,
    AppConfig,
    load_config,
    resolve_config_path,
)

try:
    from ruamel.yaml import YAML

    _HAS_RUAMEL = True
except ImportError:  # pragma: no cover - tested via fallback path
    _HAS_RUAMEL = False


IMMUTABLE_CONFIG_PATHS = frozenset(
    {
        "sovereignty.deny_egress",
        "sovereignty.runtime_allowed_endpoints",
    }
)


def _dot_set(root: dict, path: str, value: Any) -> Any:
    parts = path.split(".")
    cursor = root
    for key in parts[:-1]:
        if key not in cursor or not isinstance(cursor[key], dict):
            cursor[key] = {}
        cursor = cursor[key]
    old = cursor.get(parts[-1])
    cursor[parts[-1]] = value
    return old


class ConfigStore:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._path = resolve_config_path()
        self._loaded_mtime = self._path.stat().st_mtime if self._path.exists() else None
        self._loaded_digest = self._file_digest(self._path)

    @property
    def path(self) -> Path:
        return self._path

    def drift_status(self) -> dict[str, Any]:
        if not self._path.exists():
            return {"on_disk": False, "drift_detected": False}
        current_mtime = self._path.stat().st_mtime
        current_digest = self._file_digest(self._path)
        drift = (
            self._loaded_mtime is not None
            and (
                current_mtime != self._loaded_mtime
                or current_digest != self._loaded_digest
            )
        )
        return {
            "on_disk": True,
            "path": str(self._path),
            "drift_detected": drift,
            "note": (
                "On-disk config changed since orchestrator start — restart to apply file edits "
                "made outside the System view."
                if drift
                else None
            ),
        }

    def read_raw(self) -> dict[str, Any]:
        if _HAS_RUAMEL:
            yaml_loader = YAML()
            yaml_loader.preserve_quotes = True
            with self._path.open() as handle:
                data = yaml_loader.load(handle)
            return data if isinstance(data, dict) else {}
        with self._path.open() as handle:
            return yaml.safe_load(handle) or {}

    def apply_updates(self, updates: dict[str, Any]) -> list[tuple[str, Any, Any]]:
        for path in updates:
            if path in IMMUTABLE_CONFIG_PATHS:
                raise ValueError(
                    f"Setting {path!r} is immutable — edit config/shift-left.yaml and restart."
                )
        raw = self.read_raw()
        if raw.get("schema_version") != CURRENT_SCHEMA_VERSION:
            raw["schema_version"] = CURRENT_SCHEMA_VERSION
        changes: list[tuple[str, Any, Any]] = []
        for path, value in updates.items():
            old = _dot_set(raw, path, value)
            changes.append((path, old, value))
        self._validate_raw(raw)
        self._write_raw(raw)
        self._loaded_mtime = self._path.stat().st_mtime
        self._loaded_digest = self._file_digest(self._path)
        return changes

    def reload_app_config(self) -> AppConfig:
        return load_config(self._path)

    @staticmethod
    def _validate_raw(raw: dict[str, Any]) -> None:
        from shift_left.config import _migrate_legacy_config, _resolve_config_paths, _validate_config_schema
        from shift_left.policy.loader import validate_raw_policies

        migrated = _migrate_legacy_config(copy.deepcopy(raw))
        _validate_config_schema(migrated, Path("shift-left.yaml"))
        raw_policy = migrated.get("policy") or {}
        if isinstance(raw_policy, dict):
            validate_raw_policies(list(raw_policy.get("rules") or []))
        resolved, _rewrites = _resolve_config_paths(migrated, resolve_config_path())
        config = AppConfig.model_validate(resolved)
        from shift_left.targets.validation import ManagedTargetConfigError, validate_managed_targets

        try:
            validate_managed_targets(config.managed_targets.targets, routing=config.routing)
        except ManagedTargetConfigError as exc:
            raise ValueError(str(exc)) from exc

    def persist_raw(self, raw: dict[str, Any]) -> None:
        if raw.get("schema_version") != CURRENT_SCHEMA_VERSION:
            raw["schema_version"] = CURRENT_SCHEMA_VERSION
        self._validate_raw(raw)
        self._write_raw(raw)
        self._loaded_mtime = self._path.stat().st_mtime
        self._loaded_digest = self._file_digest(self._path)

    def _write_raw(self, raw: dict[str, Any]) -> None:
        if _HAS_RUAMEL:
            yaml_writer = YAML()
            yaml_writer.default_flow_style = False
            yaml_writer.indent(mapping=2, sequence=4, offset=2)
            yaml_writer.preserve_quotes = True
            with self._path.open("w") as handle:
                yaml_writer.dump(raw, handle)
            return
        with self._path.open("w") as handle:
            yaml.safe_dump(raw, handle, sort_keys=False)

    @staticmethod
    def _file_digest(path: Path) -> str:
        if not path.exists():
            return ""
        return hashlib.sha256(path.read_bytes()).hexdigest()
