"""Server-computed overall system state and service health."""

from __future__ import annotations

import os
from typing import Any

from shift_left.config import AppConfig, resolve_foundation_sec_service_url
from shift_left.git.protocol import GitBackend
from shift_left.models.database import AuditStore
from shift_left.reference.cache import ReferenceDataCache
from shift_left.system.models_inventory import foundation_sec_inventory
from shift_left.system.prerequisites import OverallSystemState, PrerequisiteChecker


class SystemStatusService:
    def __init__(
        self,
        *,
        config: AppConfig,
        git: GitBackend,
        reference: ReferenceDataCache,
        audit: AuditStore,
        foundation_client=None,
    ) -> None:
        self._config = config
        self._git = git
        self._reference = reference
        self._audit = audit
        self._foundation_client = foundation_client
        self._prerequisites = PrerequisiteChecker(
            config=config,
            git=git,
            reference=reference,
            foundation_client=foundation_client,
        )

    async def build_status(self, *, force_refresh: bool = False) -> dict[str, Any]:
        prereq = await self._prerequisites.build_report(force_refresh=force_refresh)
        overall = OverallSystemState(prereq["overall_state"])
        models = foundation_sec_inventory(
            self._config,
            prereq_checks=prereq["checks"],
        )
        config_drift = self._config_drift_hint()

        failing = [
            item
            for item in prereq["checks"]
            if not item.get("ok") and item.get("status") not in {"skipped", "advisory_failed"}
            and item.get("criticality") in {"critical", "degraded_config", "degraded_code"}
        ]
        conditions = [
            {
                "code": item["id"],
                "severity": (
                    OverallSystemState.FAILED.value
                    if item["criticality"] == "critical"
                    else OverallSystemState.DEGRADED.value
                ),
                "message": item.get("error") or item.get("skipped_reason") or item["name"],
                "affected_capability": item.get("affected_capability"),
                "remediation": item.get("remediation"),
                "diagnosis": item.get("details", {}).get("diagnosis"),
            }
            for item in failing
        ]

        return {
            "overall_state": overall.value,
            "conditions": conditions,
            "summary": prereq["summary"],
            "affected_capabilities": prereq["affected_capabilities"],
            "prerequisites": prereq,
            "git": {
                "backend": self._git.kind.value,
                "sovereign": self._git.is_sovereign,
            },
            "foundation_sec": self._foundation_summary(prereq),
            "antares": self._antares_summary(prereq),
            "reference_cache": self._reference.cache_status(),
            "models_inventory": models,
            "policy_rules_loaded": None,
            "telemetry": "absent",
            "ready": prereq["ready"],
            "config_drift": config_drift,
            "topology": prereq["topology"],
        }

    def _foundation_summary(self, prereq: dict[str, Any]) -> dict[str, Any]:
        fs_cfg = self._config.models.foundation_sec
        by_id = {item["id"]: item for item in prereq["checks"]}
        server = by_id.get("foundation_sec_server", {})
        return {
            "enabled": fs_cfg.enabled,
            "service_url": resolve_foundation_sec_service_url(self._config),
            "configured_quant_label": (
                fs_cfg.quant_label_low_memory if fs_cfg.use_low_memory else fs_cfg.quant_label
            ),
            "configured_n_ctx": fs_cfg.max_context_tokens,
            "load_strategy": fs_cfg.load_strategy,
            "reachability": "ok" if server.get("ok") else "unreachable",
            "summary": server.get("error") or "Foundation-Sec operational.",
            "diagnosis": (server.get("details") or {}).get("diagnosis"),
            "runtime": (server.get("details") or {}).get("runtime"),
        }

    def _antares_summary(self, prereq: dict[str, Any]) -> dict[str, Any]:
        cfg = self._config.models.antares
        by_id = {item["id"]: item for item in prereq["checks"]}
        server = by_id.get("antares_server", {})
        return {
            "enabled": cfg.enabled,
            "status": "advisory_triage_only",
            "note": "Antares is not part of the PR merge gate — use /ui/triage/antares",
            "service_url": os.environ.get("ANTARES_SERVICE_URL", cfg.service_url),
            "load_strategy": cfg.load_strategy,
            "advisory_ok": server.get("ok", False),
            "error": server.get("error"),
        }

    def _config_drift_hint(self) -> dict[str, Any]:
        from shift_left.system.config_store import ConfigStore

        store = ConfigStore(self._config)
        return store.drift_status()
