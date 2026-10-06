"""Runtime prerequisite checks — functional verification with criticality classes."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine

import httpx

from shift_left.config import (
    CURRENT_SCHEMA_VERSION,
    AppConfig,
    resolve_foundation_sec_service_url,
    resolve_repo_relative_path,
    resolve_repo_root,
)
from shift_left.git.forgejo import BundledForgejoBackend
from shift_left.git.protocol import GitBackend
from shift_left.reference.cache import ReferenceDataCache
from shift_left.sovereignty.checks import check_policy_config
from shift_left.system.diagnostics import diagnose_service_url_error
from shift_left.system.models_inventory import foundation_sec_inventory
from shift_left.system.services import compose_exec_argv
from shift_left.system.topology import cached_topology_report, topology_label

CHECK_CACHE_TTL_SECONDS = 30
DEFAULT_CHECK_TIMEOUT_SECONDS = 3.0
WORKFLOW_RUNNER_LABEL = "self-hosted"


class OverallSystemState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"


class PrerequisiteCriticality(str, Enum):
    CRITICAL = "critical"
    DEGRADED_CONFIG = "degraded_config"
    DEGRADED_CODE = "degraded_code"
    ADVISORY = "advisory"
    DEPLOYMENT = "deployment"


@dataclass(frozen=True)
class PrerequisiteCheck:
    id: str
    name: str
    criticality: PrerequisiteCriticality
    ok: bool
    status: str
    error: str | None = None
    affected_capability: str | None = None
    remediation: str | None = None
    remediation_service: str | None = None
    remediation_action: str | None = None
    topology: str = "n/a"
    last_checked: str = ""
    duration_ms: int = 0
    skipped_reason: str | None = None
    depends_on: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "criticality": self.criticality.value,
            "ok": self.ok,
            "status": self.status,
            "error": self.error,
            "affected_capability": self.affected_capability,
            "remediation": self.remediation,
            "remediation_service": self.remediation_service,
            "remediation_action": self.remediation_action,
            "topology": self.topology,
            "last_checked": self.last_checked,
            "duration_ms": self.duration_ms,
            "skipped_reason": self.skipped_reason,
            "depends_on": self.depends_on,
            "details": self.details,
        }


def compute_overall_state(checks: list[PrerequisiteCheck]) -> OverallSystemState:
    """Compute overall state from criticality — advisory failures do not degrade."""
    for check in checks:
        if check.criticality != PrerequisiteCriticality.CRITICAL:
            continue
        if check.status in {"failed", "timed_out"} and not check.skipped_reason:
            return OverallSystemState.FAILED
    for check in checks:
        if check.criticality in {
            PrerequisiteCriticality.DEGRADED_CONFIG,
            PrerequisiteCriticality.DEGRADED_CODE,
        }:
            if check.status in {"failed", "timed_out"} and not check.skipped_reason:
                return OverallSystemState.DEGRADED
    return OverallSystemState.HEALTHY


def summarize_state(state: OverallSystemState, checks: list[PrerequisiteCheck]) -> str:
    if state == OverallSystemState.HEALTHY:
        return "All critical pipeline prerequisites are satisfied."
    failing = [
        check
        for check in checks
        if check.status in {"failed", "timed_out"}
        and not check.skipped_reason
        and check.criticality
        in {
            PrerequisiteCriticality.CRITICAL,
            PrerequisiteCriticality.DEGRADED_CONFIG,
            PrerequisiteCriticality.DEGRADED_CODE,
        }
    ]
    codes = ", ".join(check.id for check in failing)
    return f"System {state.value}: {codes}"


def affected_capabilities(checks: list[PrerequisiteCheck]) -> list[str]:
    caps: list[str] = []
    for check in checks:
        if check.ok or check.skipped_reason or not check.affected_capability:
            continue
        if check.affected_capability not in caps:
            caps.append(check.affected_capability)
    return caps


class PrerequisiteChecker:
    """Bounded, cacheable functional prerequisite verification."""

    def __init__(
        self,
        *,
        config: AppConfig,
        git: GitBackend,
        reference: ReferenceDataCache,
        foundation_client=None,
    ) -> None:
        self._config = config
        self._git = git
        self._reference = reference
        self._foundation_client = foundation_client
        self._cache: dict[str, Any] | None = None
        self._cache_at: float | None = None

    async def build_report(self, *, force_refresh: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        if (
            not force_refresh
            and self._cache is not None
            and self._cache_at is not None
            and now - self._cache_at < CHECK_CACHE_TTL_SECONDS
        ):
            cached = dict(self._cache)
            cached["cache"] = {
                "hit": True,
                "ttl_seconds": CHECK_CACHE_TTL_SECONDS,
                "cached_at": cached.get("report_generated_at"),
            }
            return cached

        topology = self._runtime_topology()
        topo_report = self._topology_report()
        checks = await self._run_all_checks(topology)
        overall = compute_overall_state(checks)
        generated_at = datetime.now(timezone.utc).isoformat()
        report = {
            "overall_state": overall.value,
            "summary": summarize_state(overall, checks),
            "affected_capabilities": affected_capabilities(checks),
            "topology": topology,
            "topology_report": topo_report.to_dict(),
            "checks": [check.to_dict() for check in checks],
            "groups": self._group_checks(checks),
            "groups_failing": self._group_checks_failing(checks),
            "derived_prerequisites": self._derived_catalog(),
            "consolidated_with": [
                "shift_left.sovereignty.checks.check_policy_config",
                "shift_left_shared.weights.verify_gguf_weight / verify_antares_weights",
                "shift_left.handlers.code.registry.validate_code_rules",
                "shift_left.system.models_inventory.foundation_sec_inventory",
            ],
            "ready": overall != OverallSystemState.FAILED,
            "report_generated_at": generated_at,
            "cache": {"hit": False, "ttl_seconds": CHECK_CACHE_TTL_SECONDS, "cached_at": generated_at},
        }
        self._cache = report
        self._cache_at = now
        return report

    def invalidate_cache(self) -> None:
        self._cache = None
        self._cache_at = None

    async def verify_check(self, check_id: str, *, topology: str | None = None) -> PrerequisiteCheck:
        """Run a single prerequisite check (bypasses report cache)."""
        topo = topology or self._runtime_topology()
        dispatch: dict[str, Callable[[str], Coroutine[Any, Any, PrerequisiteCheck]]] = {
            "postgres": self._check_postgres,
            "forgejo": self._check_forgejo_api,
            "forgejo_token": self._check_forgejo_token,
            "forgejo_runner": self._check_forgejo_runner,
            "git_backend": self._check_external_git,
            "orchestrator_store": self._check_orchestrator_store,
            "policy_config": self._check_policy_config,
            "foundation_sec_server": self._check_foundation_sec_server,
            "foundation_sec_weights": self._check_foundation_sec_weights,
            "code_handlers": self._check_code_handlers,
            "antares_server": self._check_antares_server,
        }
        if check_id not in dispatch:
            raise ValueError(f"Unknown prerequisite check: {check_id}")
        return await self._timed(check_id, lambda: dispatch[check_id](topo))

    async def _run_all_checks(self, topology: str) -> list[PrerequisiteCheck]:
        results: dict[str, PrerequisiteCheck] = {}

        async def record(check: PrerequisiteCheck) -> None:
            results[check.id] = check

        sovereign = self._config.git.is_sovereign()
        if sovereign:
            await record(await self._timed("postgres", lambda: self._check_postgres(topology)))
            postgres = results.get("postgres")
            if postgres and postgres.ok:
                await record(await self._timed("forgejo", lambda: self._check_forgejo_api(topology)))
            else:
                await record(self._skipped_dependent("forgejo", depends_on="postgres", topology=topology))
            forgejo = results.get("forgejo")
            if forgejo and forgejo.ok:
                await record(await self._timed("forgejo_token", lambda: self._check_forgejo_token(topology)))
            else:
                await record(
                    self._skipped_dependent(
                        "forgejo_token",
                        depends_on="forgejo" if forgejo and not forgejo.ok else "postgres",
                        topology=topology,
                    )
                )
            token = results.get("forgejo_token")
            if token and token.ok:
                await record(await self._timed("forgejo_runner", lambda: self._check_forgejo_runner(topology)))
            else:
                await record(
                    self._skipped_dependent(
                        "forgejo_runner",
                        depends_on="forgejo_token",
                        topology=topology,
                    )
                )
        else:
            await record(await self._timed("git_backend", lambda: self._check_external_git(topology)))

        await record(await self._timed("orchestrator_store", lambda: self._check_orchestrator_store(topology)))
        await record(await self._timed("policy_config", lambda: self._check_policy_config(topology)))

        if self._config.models.foundation_sec.enabled:
            await record(
                await self._timed("foundation_sec_server", lambda: self._check_foundation_sec_server(topology))
            )
            await record(
                await self._timed(
                    "foundation_sec_weights",
                    lambda: self._check_foundation_sec_weights(topology),
                )
            )
        await record(await self._timed("code_handlers", lambda: self._check_code_handlers(topology)))

        await record(await self._timed("antares_server", lambda: self._check_antares_server(topology)))
        await record(await self._timed("antares_weights", lambda: self._check_antares_weights(topology)))
        await record(await self._timed("reference_cache", lambda: self._check_reference_cache(topology)))

        if self._config.deployment.fmc.enabled:
            await record(await self._timed("terraform_binary", lambda: self._check_terraform_binary(topology)))
            await record(await self._timed("fmc_provider", lambda: self._check_fmc_provider(topology)))
            await record(await self._timed("fmc_credentials", lambda: self._check_fmc_credentials(topology)))

        return [results[key] for key in self._ordered_ids(results)]

    @staticmethod
    def _ordered_ids(results: dict[str, PrerequisiteCheck]) -> list[str]:
        order = [
            "postgres",
            "forgejo",
            "forgejo_token",
            "forgejo_runner",
            "git_backend",
            "orchestrator_store",
            "policy_config",
            "foundation_sec_server",
            "foundation_sec_weights",
            "code_handlers",
            "antares_server",
            "antares_weights",
            "reference_cache",
            "terraform_binary",
            "fmc_provider",
            "fmc_credentials",
        ]
        return [item for item in order if item in results]

    async def _timed(
        self,
        check_id: str,
        factory: Callable[[], Coroutine[Any, Any, PrerequisiteCheck]],
        *,
        timeout: float = DEFAULT_CHECK_TIMEOUT_SECONDS,
    ) -> PrerequisiteCheck:
        started = time.perf_counter()
        stamp = datetime.now(timezone.utc).isoformat()
        try:
            check = await asyncio.wait_for(factory(), timeout=timeout)
        except asyncio.TimeoutError:
            meta = self._meta_for(check_id)
            return PrerequisiteCheck(
                id=check_id,
                name=meta["name"],
                criticality=meta["criticality"],
                ok=False,
                status="timed_out",
                error=f"Check timed out after {timeout:.0f}s",
                affected_capability=meta.get("capability"),
                remediation=meta.get("remediation"),
                remediation_service=meta.get("service"),
                remediation_action=meta.get("action"),
                topology=meta.get("topology", "n/a"),
                last_checked=stamp,
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        return PrerequisiteCheck(
            id=check.id,
            name=check.name,
            criticality=check.criticality,
            ok=check.ok,
            status=check.status,
            error=check.error,
            affected_capability=check.affected_capability,
            remediation=check.remediation,
            remediation_service=check.remediation_service,
            remediation_action=check.remediation_action,
            topology=check.topology,
            last_checked=stamp,
            duration_ms=int((time.perf_counter() - started) * 1000),
            skipped_reason=check.skipped_reason,
            depends_on=check.depends_on,
            details=check.details,
        )

    def _skipped_dependent(
        self,
        check_id: str,
        *,
        depends_on: str,
        topology: str,
    ) -> PrerequisiteCheck:
        meta = self._meta_for(check_id)
        parent = self._meta_for(depends_on)
        return PrerequisiteCheck(
            id=check_id,
            name=meta["name"],
            criticality=meta["criticality"],
            ok=False,
            status="skipped",
            error=f"Skipped — {parent['name']} unavailable.",
            affected_capability=meta.get("capability"),
            remediation=f"Restore {parent['name']} first, then re-check.",
            remediation_service=parent.get("service"),
            remediation_action=parent.get("action"),
            topology=topology,
            last_checked=datetime.now(timezone.utc).isoformat(),
            skipped_reason=f"{depends_on}_unavailable",
            depends_on=depends_on,
        )

    async def _check_postgres(self, topology: str) -> PrerequisiteCheck:
        meta = self._meta_for("postgres")
        report = self._topology_report()
        host = os.environ.get("POSTGRES_HOST", "postgres")
        port = int(os.environ.get("POSTGRES_PORT", "5432"))
        user = os.environ.get("POSTGRES_USER", "forgejo")
        database = os.environ.get("POSTGRES_DB", "forgejo")

        query_ok = False
        query_detail = ""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.0)
            writer.close()
            await writer.wait_closed()
        except Exception as exc:  # noqa: BLE001
            if report.compose_dns_resolves:
                remediation = "Start Postgres (Tier 4: start postgres or start-all prerequisites)."
            elif report.orchestrator_in_container:
                remediation = (
                    "Postgres is unreachable on the Compose network — verify postgres service is "
                    "running and orchestrator is attached to sovereign_internal."
                )
            else:
                remediation = (
                    "Compose DNS name 'postgres' does not resolve from a host-native orchestrator. "
                    "Run the orchestrator in Compose, or set POSTGRES_HOST to a reachable address."
                )
            return self._failed(
                "postgres",
                error=str(exc),
                remediation=remediation,
                topology=topology,
            )

        if report.docker_socket_available and not report.orchestrator_in_container:
            try:
                cmd = compose_exec_argv(
                    self._config,
                    "postgres",
                    "psql",
                    "-U",
                    user,
                    "-d",
                    database,
                    "-c",
                    "SELECT 1",
                )
                result = subprocess.run(
                    cmd,
                    cwd=str(resolve_repo_root()),
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                query_ok = result.returncode == 0
                query_detail = (result.stderr or result.stdout or "").strip()
            except RuntimeError as exc:
                query_ok = False
                query_detail = str(exc)
        else:
            query_ok = True
            if report.orchestrator_in_container:
                query_detail = (
                    "TCP connect succeeded on Compose network; SELECT 1 not run via "
                    "compose exec (orchestrator in container — host project paths unavailable)."
                )
            else:
                query_detail = "TCP connect succeeded; SELECT 1 not verified (docker socket unavailable)."

        if not query_ok:
            return self._failed(
                "postgres",
                error=query_detail or "Postgres did not respond to SELECT 1.",
                remediation="Start Postgres and wait for pg_isready before starting Forgejo.",
                topology=topology,
            )
        return self._ok(
            "postgres",
            details={"host": host, "port": port, "query": query_detail, "topology_report": report.to_dict()},
            topology=topology,
        )

    async def _check_forgejo_api(self, topology: str) -> PrerequisiteCheck:
        if not isinstance(self._git, BundledForgejoBackend):
            return self._ok("forgejo", details={"note": "non-forgejo backend"}, topology=topology)
        ok, message, details = await self._git.verify_api_reachable()
        if not ok:
            diagnosis = diagnose_service_url_error(
                "Forgejo",
                self._config.git.bundled.url,
                RuntimeError(message),
            )
            return self._failed(
                "forgejo",
                error=message,
                remediation="Start Forgejo (Tier 4: start forgejo) after Postgres is healthy.",
                topology=topology,
                details={"diagnosis": diagnosis},
            )
        return self._ok("forgejo", details=details, topology=topology)

    async def _check_forgejo_token(self, topology: str) -> PrerequisiteCheck:
        if not isinstance(self._git, BundledForgejoBackend):
            return self._ok("forgejo_token", topology=topology)
        if not self._config.git.token():
            return self._failed(
                "forgejo_token",
                error=f"Missing {self._config.git.token_env_name()}.",
                remediation="Create a Forgejo PAT with repo + issue scopes and set FORGEJO_TOKEN.",
                topology=topology,
            )
        ok, message, details = await self._git.verify_token()
        if not ok:
            return self._failed(
                "forgejo_token",
                error=message,
                remediation=(
                    "Create a new Forgejo PAT with read/write repository and issue scopes. "
                    "Set FORGEJO_TOKEN and restart orchestrator."
                ),
                topology=topology,
                details=details,
            )
        return self._ok("forgejo_token", details=details, topology=topology)

    async def _check_forgejo_runner(self, topology: str) -> PrerequisiteCheck:
        meta = self._meta_for("forgejo_runner")
        report = self._topology_report()
        runner_file = resolve_repo_root() / "data/forgejo-runner/.runner"
        marker = Path("/var/lib/shift-left/forgejo-runner.registered")
        registration_present = (
            marker.is_file()
            if report.orchestrator_in_container
            else runner_file.is_file()
        )
        if not registration_present:
            return self._failed(
                "forgejo_runner",
                error="Runner not registered — data/forgejo-runner/.runner missing.",
                remediation=(
                    "Register runner: FORGEJO_RUNNER_TOKEN=… ./scripts/register-forgejo-runner.sh "
                    "then start forgejo-runner (Tier 4)."
                ),
                remediation_service="forgejo-runner",
                remediation_action="start",
                topology=topology,
            )

        if not isinstance(self._git, BundledForgejoBackend):
            return self._ok("forgejo_runner", details={"registered_file": str(runner_file)}, topology=topology)

        ok, message, runners = await self._git.list_action_runners()
        if not ok and "404" in message and registration_present:
            return self._ok(
                "forgejo_runner",
                details={
                    "registered_file": str(marker if report.orchestrator_in_container else runner_file),
                    "note": (
                        "Runner API unavailable (HTTP 404); registration file present. "
                        "Ensure forgejo-runner container is running and Forgejo is healthy."
                    ),
                },
                topology=topology,
            )
        if not ok and not runners:
            return self._failed(
                "forgejo_runner",
                error=message,
                remediation=(
                    "Ensure forgejo-runner is running and registered. "
                    "Admin PAT required to list runners via API."
                ),
                remediation_service="forgejo-runner",
                remediation_action="start",
                topology=topology,
                details={"registered_file": str(runner_file)},
            )

        if not runners:
            return self._failed(
                "forgejo_runner",
                error="No runners registered in Forgejo Actions.",
                remediation="Run scripts/register-forgejo-runner.sh and start forgejo-runner.",
                remediation_service="forgejo-runner",
                remediation_action="start",
                topology=topology,
            )

        online = [item for item in runners if str(item.get("status", "")).lower() in {"online", "active", "idle"}]
        if not online:
            offline = runners[0]
            return self._failed(
                "forgejo_runner",
                error=(
                    f"Runner {offline.get('name')!r} is offline "
                    f"(last online: {offline.get('last_online') or 'unknown'})."
                ),
                remediation="Start forgejo-runner (Tier 4) and verify daemon connects to Forgejo.",
                remediation_service="forgejo-runner",
                remediation_action="start",
                topology=topology,
                details={"runners": runners},
            )

        runner = online[0]
        labels = _runner_labels(runner)
        if WORKFLOW_RUNNER_LABEL not in labels:
            return self._failed(
                "forgejo_runner",
                error=(
                    f"Runner labels {sorted(labels)} do not include workflow target "
                    f"{WORKFLOW_RUNNER_LABEL!r} — jobs will queue forever."
                ),
                remediation=(
                    f"Re-register runner with --labels {WORKFLOW_RUNNER_LABEL}:host "
                    "(see scripts/register-forgejo-runner.sh)."
                ),
                remediation_service="forgejo-runner",
                remediation_action="restart",
                topology=topology,
                details={"runners": runners, "labels": sorted(labels)},
            )

        return self._ok(
            "forgejo_runner",
            details={
                "name": runner.get("name"),
                "status": runner.get("status"),
                "labels": sorted(labels),
                "last_online": runner.get("last_online"),
            },
            topology=topology,
        )

    async def _check_external_git(self, topology: str) -> PrerequisiteCheck:
        ok = await self._git.health()
        if not ok:
            return self._failed(
                "git_backend",
                error=f"Git backend ({self._git.kind.value}) unreachable.",
                remediation="Verify git backend URL and API token for the configured provider.",
                topology=topology,
            )
        if not self._config.git.token():
            return self._failed(
                "git_backend",
                error=f"Missing {self._config.git.token_env_name()}.",
                remediation="Set the configured git API token environment variable.",
                topology=topology,
            )
        return self._ok("git_backend", topology=topology)

    async def _check_orchestrator_store(self, topology: str) -> PrerequisiteCheck:
        path = Path(self._config.findings_store.sqlite_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            probe = path.parent / ".write_probe"
            probe.write_text("ok")
            probe.unlink(missing_ok=True)
            conn = sqlite3.connect(path)
            conn.execute("SELECT 1")
            conn.close()
        except Exception as exc:  # noqa: BLE001
            return self._failed(
                "orchestrator_store",
                error=str(exc),
                remediation=f"Ensure findings store path is writable: {path}",
                topology=topology,
            )

        if self._config.schema_version != CURRENT_SCHEMA_VERSION:
            return self._failed(
                "orchestrator_store",
                error=(
                    f"Config schema_version {self._config.schema_version} "
                    f"≠ expected {CURRENT_SCHEMA_VERSION}."
                ),
                remediation="Update config/shift-left.yaml schema_version and migrate config.",
                topology=topology,
            )
        return self._ok(
            "orchestrator_store",
            details={"sqlite_path": str(path), "schema_version": self._config.schema_version},
            topology=topology,
        )

    async def _check_policy_config(self, topology: str) -> PrerequisiteCheck:
        result = check_policy_config(self._config)
        if not result.ok:
            return self._failed(
                "policy_config",
                error=result.message,
                remediation="Fix policy rules in config/shift-left.yaml and reload.",
                topology=topology,
            )
        return self._ok("policy_config", details={"message": result.message}, topology=topology)

    async def _check_foundation_sec_server(self, topology: str) -> PrerequisiteCheck:
        fs_cfg = self._config.models.foundation_sec
        service_url = resolve_foundation_sec_service_url(self._config)
        if fs_cfg.model_variant == "reasoning":
            expected_quant = fs_cfg.quant_label_reasoning
            expected_variant = "reasoning"
        else:
            expected_quant = (
                fs_cfg.quant_label_low_memory if fs_cfg.use_low_memory else fs_cfg.quant_label
            )
            expected_variant = "instruct"
        if self._foundation_client is None:
            return self._failed(
                "foundation_sec_server",
                error="Foundation-Sec client not initialized.",
                remediation="Enable models.foundation_sec and restart orchestrator.",
                topology=topology,
            )
        try:
            payload = await self._foundation_client.health()
        except Exception as exc:  # noqa: BLE001
            diagnosis = diagnose_service_url_error("Foundation-Sec", service_url, exc)
            return self._failed(
                "foundation_sec_server",
                error=diagnosis["root_cause"],
                remediation="; ".join(diagnosis.get("remediation") or []) or "Start foundation-sec-server.",
                remediation_service="foundation-sec-server",
                remediation_action="start",
                topology=topology,
                details={"diagnosis": diagnosis},
            )

        if payload.get("status") != "ok":
            return self._failed(
                "foundation_sec_server",
                error=f"Health status not ok: {payload}",
                remediation="Check foundation-sec-server logs.",
                remediation_service="foundation-sec-server",
                remediation_action="restart",
                topology=topology,
                details={"runtime": payload},
            )

        runtime_quant = payload.get("quant")
        if runtime_quant and runtime_quant != expected_quant:
            return self._failed(
                "foundation_sec_server",
                error=(
                    f"Model server quant mismatch: running {runtime_quant!r}, "
                    f"configured {expected_quant!r}."
                ),
                remediation=(
                    "Restart foundation-sec-server with matching FOUNDATION_SEC_QUANT_LABEL / "
                    "use_low_memory settings."
                ),
                remediation_service="foundation-sec-server",
                remediation_action="restart",
                topology=topology,
                details={"runtime": payload, "expected_quant": expected_quant},
            )

        runtime_variant = payload.get("model_variant")
        if runtime_variant and runtime_variant != expected_variant:
            return self._failed(
                "foundation_sec_server",
                error=(
                    f"Model server variant mismatch: running {runtime_variant!r}, "
                    f"configured {expected_variant!r}."
                ),
                remediation=(
                    "Restart foundation-sec-server with matching models.foundation_sec.model_variant "
                    "and staged GGUF weights."
                ),
                remediation_service="foundation-sec-server",
                remediation_action="restart",
                topology=topology,
                details={"runtime": payload, "expected_variant": expected_variant},
            )
        return self._ok(
            "foundation_sec_server",
            details={"runtime": payload, "service_url": service_url},
            topology=topology,
        )

    async def _check_foundation_sec_weights(self, topology: str) -> PrerequisiteCheck:
        from shift_left_shared.weights import (
            VERIFIED_FOUNDATION_SEC_Q4_K_M,
            VERIFIED_FOUNDATION_SEC_Q8_0,
            WeightVerificationError,
            load_prewarm_manifest,
            verify_gguf_weight,
        )

        report = self._topology_report()
        if report.orchestrator_in_container and report.model_hosting in {
            "host-native-macos",
            "host-native",
        }:
            return self._ok(
                "foundation_sec_weights",
                details={
                    "note": (
                        "GGUF weights live on the host for host-native model servers; "
                        "verified via foundation_sec_server health when running."
                    ),
                    "model_hosting": report.model_hosting,
                    "verified_via": "runtime_health",
                },
                topology=topology,
            )

        from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M

        fs = self._config.models.foundation_sec
        repo_root = resolve_repo_root()
        manifest = load_prewarm_manifest(repo_root)
        if fs.model_variant == "reasoning":
            verified = VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M
            model_dir = resolve_repo_relative_path(fs.local_path_reasoning)
        elif fs.use_low_memory:
            verified = VERIFIED_FOUNDATION_SEC_Q4_K_M
            model_dir = resolve_repo_relative_path(fs.local_path_low_memory)
        else:
            verified = VERIFIED_FOUNDATION_SEC_Q8_0
            model_dir = resolve_repo_relative_path(fs.local_path)
        try:
            path = verify_gguf_weight(
                model_dir,
                manifest,
                manifest_key=verified["manifest_key"],
                verified_meta=verified,
            )
        except WeightVerificationError as exc:
            inv = foundation_sec_inventory(self._config)
            return self._failed(
                "foundation_sec_weights",
                error=str(exc),
                remediation=(
                    "Stage GGUF weights under models/ and update models/.prewarm-manifest.json "
                    "(see scripts/self-check.sh)."
                ),
                topology=topology,
                details={"inventory": inv},
            )
        return self._ok(
            "foundation_sec_weights",
            details={"path": str(path)},
            topology=topology,
        )

    async def _check_code_handlers(self, topology: str) -> PrerequisiteCheck:
        from shift_left.handlers.code.registry import validate_code_rules

        try:
            validate_code_rules()
        except Exception as exc:  # noqa: BLE001
            return self._failed(
                "code_handlers",
                error=str(exc),
                remediation="Sync reference CWE catalog or fix handler rule definitions.",
                topology=topology,
            )
        return self._ok("code_handlers", topology=topology)

    def _antares_weights_dir(self) -> tuple[Path, str]:
        from shift_left.system.model_paths import resolve_antares_weights_dir
        from shift_left_shared.weights import (
            VERIFIED_ANTARES_1B,
            WeightVerificationError,
            load_prewarm_manifest,
            verify_antares_weights,
        )

        repo_root = resolve_repo_root()
        model_dir = resolve_antares_weights_dir(repo_root, self._config.models.antares)
        try:
            verify_antares_weights(model_dir, load_prewarm_manifest(repo_root))
        except WeightVerificationError as exc:
            rel = model_dir.relative_to(repo_root) if model_dir.is_relative_to(repo_root) else model_dir
            remediation = (
                f"Stage Antares weights under {rel} "
                f"(verified layout: {VERIFIED_ANTARES_1B['local_path_default']}) "
                "and update models/.prewarm-manifest.json."
            )
            return model_dir, str(exc), remediation
        rel = model_dir.relative_to(repo_root) if model_dir.is_relative_to(repo_root) else model_dir
        return model_dir, "", f"Antares weights staged at {rel}"

    async def _check_antares_server(self, topology: str) -> PrerequisiteCheck:
        if not self._config.models.antares.installed and not self._config.antares_triage.installed:
            return PrerequisiteCheck(
                id="antares_server",
                name="Antares server (advisory)",
                criticality=PrerequisiteCriticality.ADVISORY,
                ok=True,
                status="not_installed",
                affected_capability="Antares triage (/ui/triage)",
                remediation="Optional — run: ./shift-left install-antares (accept HF terms + HF_TOKEN required)",
                topology=topology,
                skipped_reason="antares_not_installed",
            )
        cfg = self._config.models.antares
        url = os.environ.get("ANTARES_SERVICE_URL", cfg.service_url).rstrip("/") + "/health"
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.get(url)
            payload = response.json() if response.status_code == 200 else {}
        except Exception as exc:  # noqa: BLE001
            return PrerequisiteCheck(
                id="antares_server",
                name="Antares server (advisory)",
                criticality=PrerequisiteCriticality.ADVISORY,
                ok=False,
                status="advisory_failed",
                error=str(exc),
                affected_capability="Antares triage (/ui/triage)",
                remediation="Start antares-server for advisory triage (Tier 4). Not required for PR gate.",
                remediation_service="antares-server",
                remediation_action="start",
                topology=topology,
            )
        _, weights_error, weights_remediation = self._antares_weights_dir()
        if weights_error:
            return PrerequisiteCheck(
                id="antares_server",
                name="Antares server (advisory)",
                criticality=PrerequisiteCriticality.ADVISORY,
                ok=False,
                status="advisory_failed",
                error=weights_error,
                affected_capability="Antares triage (/ui/triage)",
                remediation=weights_remediation,
                details={"runtime": payload, "service_url": url, "weights_verified": False},
                topology=topology,
            )
        return PrerequisiteCheck(
            id="antares_server",
            name="Antares server (advisory)",
            criticality=PrerequisiteCriticality.ADVISORY,
            ok=True,
            status="ok",
            affected_capability="Antares triage (/ui/triage)",
            details={"runtime": payload, "service_url": url, "weights_verified": True},
            topology=topology,
        )

    async def _check_antares_weights(self, topology: str) -> PrerequisiteCheck:
        if not self._config.models.antares.installed and not self._config.antares_triage.installed:
            return PrerequisiteCheck(
                id="antares_weights",
                name="Antares weights staged (advisory)",
                criticality=PrerequisiteCriticality.ADVISORY,
                ok=True,
                status="not_installed",
                affected_capability="Antares triage",
                remediation="Optional — ./shift-left install-antares",
                topology=topology,
                skipped_reason="antares_not_installed",
            )
        model_dir, weights_error, weights_remediation = self._antares_weights_dir()
        if weights_error:
            return PrerequisiteCheck(
                id="antares_weights",
                name="Antares weights staged (advisory)",
                criticality=PrerequisiteCriticality.ADVISORY,
                ok=False,
                status="advisory_failed",
                error=weights_error,
                affected_capability="Antares triage",
                remediation=weights_remediation,
                topology=topology,
            )
        return PrerequisiteCheck(
            id="antares_weights",
            name="Antares weights staged (advisory)",
            criticality=PrerequisiteCriticality.ADVISORY,
            ok=True,
            status="ok",
            details={"path": str(model_dir)},
            topology=topology,
        )

    async def _check_reference_cache(self, topology: str) -> PrerequisiteCheck:
        status = self._reference.cache_status()
        stale = status.get("stale")
        return PrerequisiteCheck(
            id="reference_cache",
            name="Reference data cache (advisory)",
            criticality=PrerequisiteCriticality.ADVISORY,
            ok=not stale,
            status="ok" if not stale else "advisory_failed",
            error="Reference cache absent or stale." if stale else None,
            affected_capability="Finding enrichment (graceful degradation)",
            remediation="Sync reference data from System view (seed or operator-initiated NVD egress).",
            details=status,
            topology=topology,
        )

    async def _check_terraform_binary(self, topology: str) -> PrerequisiteCheck:
        cfg = self._config.deployment.fmc
        try:
            result = subprocess.run(
                [cfg.terraform_bin, "version", "-json"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except FileNotFoundError:
            return self._failed(
                "terraform_binary",
                error=f"Terraform binary not found: {cfg.terraform_bin}",
                remediation="Install Terraform and set deployment.fmc.terraform_bin.",
                topology=topology,
            )
        if result.returncode != 0:
            return self._failed(
                "terraform_binary",
                error=(result.stderr or result.stdout or "terraform version failed").strip(),
                remediation="Install a compatible Terraform version.",
                topology=topology,
            )
        import json

        payload = json.loads(result.stdout or "{}")
        return self._ok(
            "terraform_binary",
            details={"version": payload.get("terraform_version")},
            topology=topology,
        )

    async def _check_fmc_provider(self, topology: str) -> PrerequisiteCheck:
        cfg = self._config.deployment.fmc
        workdir = self._resolve_fmc_workdir()
        providers = workdir / ".terraform" / "providers"
        if not providers.is_dir():
            return self._failed(
                "fmc_provider",
                error=f"Terraform providers not initialized in {workdir}.",
                remediation=f"Run terraform init in {workdir} (operator-initiated, may egress).",
                topology=topology,
            )
        return self._ok("fmc_provider", details={"providers_dir": str(providers)}, topology=topology)

    async def _check_fmc_credentials(self, topology: str) -> PrerequisiteCheck:
        cfg = self._config.deployment.fmc
        missing = [
            name
            for name in (cfg.username_env, cfg.password_env, cfg.host_env)
            if name and not os.environ.get(name)
        ]
        if missing:
            return self._failed(
                "fmc_credentials",
                error=f"Missing FMC credential env var(s): {', '.join(missing)}",
                remediation="Set TF_VAR_fmc_* environment variables (presence only — not validated here).",
                topology=topology,
            )
        return self._ok(
            "fmc_credentials",
            details={
                "username_env_set": bool(os.environ.get(cfg.username_env)),
                "password_env_set": bool(os.environ.get(cfg.password_env)),
                "host_env_set": bool(os.environ.get(cfg.host_env)),
            },
            topology=topology,
        )

    def _resolve_fmc_workdir(self) -> Path:
        raw = self._config.deployment.fmc.terraform_workdir
        path = Path(raw)
        if not path.is_absolute():
            path = resolve_repo_root() / raw
        return path

    def _group_checks(self, checks: list[PrerequisiteCheck]) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {
            item.value: [] for item in PrerequisiteCriticality
        }
        for check in checks:
            grouped[check.criticality.value].append(check.to_dict())
        return grouped

    def _group_checks_failing(self, checks: list[PrerequisiteCheck]) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {
            item.value: [] for item in PrerequisiteCriticality
        }
        for check in checks:
            if check.ok or check.skipped_reason:
                continue
            grouped[check.criticality.value].append(check.to_dict())
        return grouped

    def _derived_catalog(self) -> list[dict[str, str]]:
        return [
            {
                "id": check_id,
                "name": item["name"],
                "criticality": item["criticality"].value,
            }
            for check_id, item in self._CHECK_META.items()
        ]

    _CHECK_META: dict[str, dict[str, Any]] = {
        "postgres": {
            "name": "Postgres (Forgejo database)",
            "criticality": PrerequisiteCriticality.CRITICAL,
            "capability": "PR pipeline (Forgejo persistence)",
            "remediation": "Start postgres service.",
            "service": "postgres",
            "action": "start",
        },
        "forgejo": {
            "name": "Forgejo git hosting",
            "criticality": PrerequisiteCriticality.CRITICAL,
            "capability": "PR pipeline (git, PRs, branch protection)",
            "service": "forgejo",
            "action": "start",
        },
        "forgejo_token": {
            "name": "FORGEJO_TOKEN scopes",
            "criticality": PrerequisiteCriticality.CRITICAL,
            "capability": "PR pipeline (authenticated API)",
        },
        "forgejo_runner": {
            "name": "Forgejo Actions runner",
            "criticality": PrerequisiteCriticality.CRITICAL,
            "capability": "PR pipeline (workflow triggers review)",
            "service": "forgejo-runner",
            "action": "start",
        },
        "git_backend": {
            "name": "Git backend",
            "criticality": PrerequisiteCriticality.CRITICAL,
            "capability": "PR pipeline",
        },
        "orchestrator_store": {
            "name": "Orchestrator findings store",
            "criticality": PrerequisiteCriticality.CRITICAL,
            "capability": "Findings persistence and gate",
        },
        "policy_config": {
            "name": "Policy rules loaded",
            "criticality": PrerequisiteCriticality.CRITICAL,
            "capability": "Policy evaluation",
        },
        "foundation_sec_server": {
            "name": "Foundation-Sec server",
            "criticality": PrerequisiteCriticality.DEGRADED_CONFIG,
            "capability": "Config path review",
            "service": "foundation-sec-server",
            "action": "start",
        },
        "foundation_sec_weights": {
            "name": "Foundation-Sec GGUF SHA256",
            "criticality": PrerequisiteCriticality.DEGRADED_CONFIG,
            "capability": "Config path review",
        },
        "code_handlers": {
            "name": "Code handler rules",
            "criticality": PrerequisiteCriticality.DEGRADED_CODE,
            "capability": "Code path deterministic findings",
        },
        "antares_server": {
            "name": "Antares server",
            "criticality": PrerequisiteCriticality.ADVISORY,
            "capability": "Antares triage",
            "service": "antares-server",
            "action": "start",
        },
        "antares_weights": {
            "name": "Antares weights",
            "criticality": PrerequisiteCriticality.ADVISORY,
            "capability": "Antares triage",
        },
        "reference_cache": {
            "name": "Reference data cache",
            "criticality": PrerequisiteCriticality.ADVISORY,
            "capability": "Finding enrichment",
        },
        "terraform_binary": {
            "name": "Terraform binary",
            "criticality": PrerequisiteCriticality.DEPLOYMENT,
            "capability": "FMC plan-only deployment",
        },
        "fmc_provider": {
            "name": "FMC Terraform provider",
            "criticality": PrerequisiteCriticality.DEPLOYMENT,
            "capability": "FMC plan-only deployment",
        },
        "fmc_credentials": {
            "name": "FMC credentials configured",
            "criticality": PrerequisiteCriticality.DEPLOYMENT,
            "capability": "FMC plan-only deployment",
        },
    }

    def _meta_for(self, check_id: str) -> dict[str, Any]:
        return self._CHECK_META[check_id]

    def _ok(
        self,
        check_id: str,
        *,
        details: dict[str, Any] | None = None,
        topology: str,
    ) -> PrerequisiteCheck:
        meta = self._meta_for(check_id)
        return PrerequisiteCheck(
            id=check_id,
            name=meta["name"],
            criticality=meta["criticality"],
            ok=True,
            status="ok",
            affected_capability=meta.get("capability"),
            details=details or {},
            topology=topology,
        )

    def _failed(
        self,
        check_id: str,
        *,
        error: str,
        remediation: str,
        topology: str,
        details: dict[str, Any] | None = None,
        remediation_service: str | None = None,
        remediation_action: str | None = None,
    ) -> PrerequisiteCheck:
        meta = self._meta_for(check_id)
        return PrerequisiteCheck(
            id=check_id,
            name=meta["name"],
            criticality=meta["criticality"],
            ok=False,
            status="failed",
            error=error,
            affected_capability=meta.get("capability"),
            remediation=remediation,
            remediation_service=remediation_service or meta.get("service"),
            remediation_action=remediation_action or meta.get("action"),
            details=details or {},
            topology=topology,
        )

    @staticmethod
    def _runtime_topology() -> str:
        from shift_left.config import load_config

        try:
            config = load_config()
            return topology_label(config.orchestrator.compose_command)
        except Exception:  # noqa: BLE001
            return topology_label(None)

    @staticmethod
    def _topology_report():
        from shift_left.config import load_config

        try:
            config = load_config()
            return cached_topology_report(config.orchestrator.compose_command)
        except Exception:  # noqa: BLE001
            return cached_topology_report(None)


def _runner_labels(runner: dict[str, Any]) -> set[str]:
    labels = runner.get("labels") or runner.get("label") or []
    parsed: set[str] = set()
    if isinstance(labels, dict):
        parsed.update(labels.keys())
        parsed.update(str(value) for value in labels.values())
    elif isinstance(labels, list):
        for item in labels:
            if isinstance(item, str):
                if ":" in item:
                    key, _, value = item.partition(":")
                    parsed.add(key)
                    parsed.add(value)
                else:
                    parsed.add(item)
    return parsed


def shutil_which(name: str) -> str | None:
    from shutil import which

    return which(name)
