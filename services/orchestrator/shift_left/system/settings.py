"""Tiered mutable settings — validated writes with audit."""

from __future__ import annotations

from typing import Any

from shift_left.config import AppConfig
from shift_left.models.database import AuditStore
from shift_left.system.config_store import ConfigStore, IMMUTABLE_CONFIG_PATHS
from shift_left.system.settings_validation import (
    validate_service_url,
    validate_use_low_memory,
    validate_weights_path,
)

RBAC_ENABLE_PHRASE = "ENABLE SELF APPROVAL"
RBAC_DISABLE_PHRASE = "DISABLE SELF APPROVAL"

TIER3_SETTINGS: dict[str, dict[str, Any]] = {
    "models.foundation_sec.use_low_memory": {"type": "bool"},
    "models.foundation_sec.max_context_tokens": {"type": "int", "min": 1024, "max": 32768},
    "models.foundation_sec.load_strategy": {
        "type": "enum",
        "values": {"on_demand", "resident_for_run"},
    },
    "models.foundation_sec.service_url": {"type": "url", "label": "Foundation-Sec service URL"},
    "models.foundation_sec.local_path": {"type": "path", "profile": "foundation_sec_q8"},
    "models.foundation_sec.local_path_low_memory": {"type": "path", "profile": "foundation_sec_q4"},
    "models.antares.load_strategy": {
        "type": "enum",
        "values": {"on_demand", "resident_for_run"},
    },
    "models.antares.service_url": {"type": "url", "label": "Antares service URL"},
    "models.antares.local_path": {"type": "path", "profile": "antares"},
    "models.antares.agent.recycle_after_runs": {"type": "int", "min": 1, "max": 1000},
    "reference_data.cache_dir": {"type": "path", "profile": None},
    "findings_store.sqlite_path": {"type": "path", "profile": None},
    "enrichment.enabled": {"type": "bool"},
    "enrichment.enrich_findings": {"type": "bool"},
    "enrichment.generate_review_summary": {"type": "bool"},
}

REQUIRES_MODEL_RESTART = frozenset(
    {
        "models.foundation_sec.use_low_memory",
        "models.foundation_sec.max_context_tokens",
        "models.foundation_sec.service_url",
        "models.foundation_sec.local_path",
        "models.foundation_sec.local_path_low_memory",
        "models.antares.service_url",
        "models.antares.local_path",
    }
)

REQUIRES_ORCHESTRATOR_RESTART = frozenset(
    {
        "reference_data.cache_dir",
        "findings_store.sqlite_path",
    }
)


class SettingsService:
    def __init__(self, *, config: AppConfig, audit: AuditStore) -> None:
        self._config = config
        self._audit = audit
        self._store = ConfigStore(config)

    def tier1_snapshot(self) -> dict[str, Any]:
        return {
            "sovereignty.deny_egress": self._config.sovereignty.deny_egress,
            "sovereignty.runtime_allowed_endpoints": list(
                self._config.sovereignty.runtime_allowed_endpoints
            ),
            "immutable_note": (
                "Sovereignty egress controls are config-file only and require orchestrator restart. "
                "They are intentionally not mutable from the UI or API."
            ),
        }

    def tier3_form(self) -> dict[str, Any]:
        fs = self._config.models.foundation_sec
        ant = self._config.models.antares
        enr = self._config.enrichment
        inventory = foundation_sec_inventory(self._config)
        return {
            "foundation_sec": {
                "use_low_memory": fs.use_low_memory,
                "max_context_tokens": fs.max_context_tokens,
                "load_strategy": fs.load_strategy,
                "service_url": fs.service_url,
                "local_path": fs.local_path,
                "local_path_low_memory": fs.local_path_low_memory,
                "requires_restart_for": sorted(REQUIRES_MODEL_RESTART),
                "q4_k_m_staged": inventory.get("q4_k_m_staged", False),
                "q4_staging_command": (
                    "hf download fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF "
                    f"--local-dir {fs.local_path_low_memory}"
                ),
            },
            "antares": {
                "load_strategy": ant.load_strategy,
                "recycle_after_runs": ant.agent.recycle_after_runs,
                "service_url": ant.service_url,
                "local_path": ant.local_path,
            },
            "paths": {
                "reference_cache_dir": self._config.reference_data.cache_dir,
                "findings_sqlite_path": self._config.findings_store.sqlite_path,
            },
            "enrichment": {
                "enabled": enr.enabled,
                "enrich_findings": enr.enrich_findings,
                "generate_review_summary": enr.generate_review_summary,
            },
        }

    def apply_tier3(self, *, updates: dict[str, Any], actor: str) -> dict[str, Any]:
        normalized = self._validate_tier3(updates)
        changes = self._store.apply_updates(normalized)
        for path, old, new in changes:
            self._audit.log(
                actor=actor,
                action="settings.changed",
                subject=path,
                details={"old": old, "new": new, "tier": 3},
            )
        new_config = self._store.reload_app_config()
        restart_services = sorted(
            {
                "foundation-sec-server"
                for path in normalized
                if path.startswith("models.foundation_sec")
            }
            | {
                "antares-server"
                for path in normalized
                if path.startswith("models.antares")
            }
        )
        return {
            "applied": {path: new for path, _, new in changes},
            "requires_service_restart": restart_services,
            "requires_orchestrator_restart": sorted(
                path for path in normalized if path in REQUIRES_ORCHESTRATOR_RESTART
            ),
            "config_path": str(self._store.path),
            "config": new_config.model_dump(mode="json"),
        }

    def set_allow_self_approval(
        self,
        *,
        enabled: bool,
        confirmation_phrase: str,
        actor: str,
    ) -> dict[str, Any]:
        expected = RBAC_ENABLE_PHRASE if enabled else RBAC_DISABLE_PHRASE
        if confirmation_phrase.strip() != expected:
            raise ValueError(f"Confirmation phrase must exactly match: {expected}")
        old = self._config.rbac.allow_self_approval
        changes = self._store.apply_updates({"rbac.allow_self_approval": enabled})
        self._audit.log(
            actor=actor,
            action="settings.rbac_allow_self_approval",
            subject="rbac.allow_self_approval",
            details={"old": old, "new": enabled, "tier": 2, "confirmation": expected},
        )
        return {
            "rbac_allow_self_approval": enabled,
            "applied": {path: new for path, _, new in changes},
        }

    def reject_immutable_write(self, updates: dict[str, Any]) -> None:
        blocked = [path for path in updates if path in IMMUTABLE_CONFIG_PATHS]
        if blocked:
            raise PermissionError(
                f"Cannot modify immutable sovereignty settings via API: {', '.join(blocked)}"
            )

    def _validate_tier3(self, updates: dict[str, Any]) -> dict[str, Any]:
        if not updates:
            raise ValueError("No settings provided.")
        self.reject_immutable_write(updates)
        normalized: dict[str, Any] = {}
        for path, value in updates.items():
            if path not in TIER3_SETTINGS:
                raise ValueError(f"Setting {path!r} is not mutable from the System view.")
            normalized[path] = self._coerce_value(path, value)
        if normalized.get("models.foundation_sec.use_low_memory") is True:
            q4_path = normalized.get(
                "models.foundation_sec.local_path_low_memory",
                self._config.models.foundation_sec.local_path_low_memory,
            )
            validate_weights_path(str(q4_path), profile="foundation_sec_q4", config=self._config)
        return normalized

    def _coerce_value(self, path: str, value: Any) -> Any:
        spec = TIER3_SETTINGS[path]
        kind = spec["type"]
        if kind == "bool":
            if isinstance(value, bool):
                coerced = value
            elif str(value).lower() in {"true", "1", "yes", "on"}:
                coerced = True
            elif str(value).lower() in {"false", "0", "no", "off"}:
                coerced = False
            else:
                raise ValueError(f"{path} requires a boolean.")
            if path == "models.foundation_sec.use_low_memory" and coerced:
                validate_use_low_memory(True, config=self._config)
            return coerced
        if kind == "int":
            parsed = int(value)
            if parsed < spec["min"] or parsed > spec["max"]:
                raise ValueError(f"{path} must be between {spec['min']} and {spec['max']}.")
            return parsed
        if kind == "enum":
            text = str(value)
            if text not in spec["values"]:
                raise ValueError(f"{path} must be one of: {', '.join(sorted(spec['values']))}.")
            return text
        if kind == "url":
            return validate_service_url(str(value), config=self._config, label=spec.get("label", path))
        if kind == "path":
            profile = spec.get("profile")
            if profile:
                return validate_weights_path(str(value), profile=profile, config=self._config)
            from shift_left.system.settings_validation import _readable_path

            resolved = _readable_path(str(value), label=path)
            return str(resolved)
        raise ValueError(f"Unknown setting type for {path}.")


def foundation_sec_inventory(config: AppConfig) -> dict[str, Any]:
    from shift_left.system.models_inventory import foundation_sec_inventory as _inventory

    return _inventory(config)
