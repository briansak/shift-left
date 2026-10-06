"""Hardcoded service lifecycle — no client-supplied shell fragments."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

import httpx

from shift_left.config import AppConfig, resolve_foundation_sec_service_url, resolve_repo_root
from shift_left.models.database import AuditStore
from shift_left.system.compose_cli import cached_compose_cli, compose_argv_prefix
from shift_left.system.service_dependencies import (
    CRITICAL_PIPELINE_CHAIN,
    DEGRADED_RECOVERY_CHAIN,
    READINESS_POLL_BACKOFF_FACTOR,
    READINESS_POLL_INITIAL_SECONDS,
    READINESS_POLL_MAX_SECONDS,
    SERVICE_DEPENDENCIES,
    SERVICE_PREREQUISITE_CHECKS,
    readiness_timeout,
    transitive_dependencies,
)
from shift_left.system.topology import TopologyReport, cached_topology_report, topology_label

ServiceName = Literal[
    "foundation-sec-server",
    "antares-server",
    "forgejo-runner",
    "orchestrator",
    "forgejo",
    "postgres",
]
ServiceAction = Literal["start", "stop", "restart"]

ALL_SERVICE_NAMES: frozenset[ServiceName] = frozenset(
    (
        "foundation-sec-server",
        "antares-server",
        "forgejo-runner",
        "orchestrator",
        "forgejo",
        "postgres",
    )
)

VerificationOutcome = Literal[
    "not_applicable",
    "command_failed",
    "verification_timeout",
    "verified_healthy",
]


@dataclass(frozen=True)
class ManagedService:
    name: ServiceName
    display_name: str
    health_url: str | None
    host_native_argv: dict[ServiceAction, tuple[str, ...]] | None
    docker_argv: dict[ServiceAction, tuple[str, ...]] | None
    process_match: str | None = None


def _repo_root() -> str:
    return str(resolve_repo_root())


def _managed_services(compose_prefix: tuple[str, ...]) -> dict[ServiceName, ManagedService]:
    root = _repo_root()
    py = sys.executable

    def compose(*parts: str) -> tuple[str, ...]:
        return (*compose_prefix, *parts)

    return {
        "foundation-sec-server": ManagedService(
            name="foundation-sec-server",
            display_name="Foundation-Sec inference",
            health_url="http://127.0.0.1:8091/health",
            host_native_argv={
                "start": (py, "-m", "foundation_sec_server.main"),
                "stop": ("pkill", "-f", "foundation_sec_server.main"),
                "restart": (py, "-m", "foundation_sec_server.main"),
            },
            docker_argv={
                "start": compose("--profile", "linux-cpu", "up", "-d", "foundation-sec-server"),
                "stop": compose("stop", "foundation-sec-server"),
                "restart": compose("--profile", "linux-cpu", "restart", "foundation-sec-server"),
            },
            process_match="foundation_sec_server.main",
        ),
        "antares-server": ManagedService(
            name="antares-server",
            display_name="Antares triage inference",
            health_url="http://127.0.0.1:8090/health",
            host_native_argv={
                "start": (py, "-m", "antares_server.main"),
                "stop": ("pkill", "-f", "antares_server.main"),
                "restart": (py, "-m", "antares_server.main"),
            },
            docker_argv={
                "start": compose("--profile", "linux-cpu", "up", "-d", "antares-server"),
                "stop": compose("stop", "antares-server"),
                "restart": compose("--profile", "linux-cpu", "restart", "antares-server"),
            },
            process_match="antares_server.main",
        ),
        "orchestrator": ManagedService(
            name="orchestrator",
            display_name="Shift-Left orchestrator",
            health_url="http://127.0.0.1:8080/health",
            host_native_argv=None,
            docker_argv={
                "start": compose("up", "-d", "orchestrator"),
                "stop": compose("stop", "orchestrator"),
                "restart": compose("restart", "orchestrator"),
            },
        ),
        "forgejo": ManagedService(
            name="forgejo",
            display_name="Forgejo git hosting",
            health_url=None,
            host_native_argv=None,
            docker_argv={
                "start": compose("up", "-d", "forgejo"),
                "stop": compose("stop", "forgejo"),
                "restart": compose("restart", "forgejo"),
            },
        ),
        "postgres": ManagedService(
            name="postgres",
            display_name="Forgejo Postgres",
            health_url=None,
            host_native_argv=None,
            docker_argv={
                "start": compose("up", "-d", "postgres"),
                "stop": compose("stop", "postgres"),
                "restart": compose("restart", "postgres"),
            },
        ),
        "forgejo-runner": ManagedService(
            name="forgejo-runner",
            display_name="Forgejo Actions runner",
            health_url=None,
            host_native_argv=None,
            docker_argv={
                "start": compose("up", "-d", "forgejo-runner"),
                "stop": compose("stop", "forgejo-runner"),
                "restart": compose("restart", "forgejo-runner"),
            },
            process_match="forgejo-runner",
        ),
    }


class ServiceLifecycleManager:
    ALLOWED_ACTIONS: frozenset[ServiceAction] = frozenset({"start", "stop", "restart"})
    ALLOWED_SERVICES: frozenset[ServiceName] = ALL_SERVICE_NAMES
    COMPOSE_SERVICES = frozenset({"postgres", "forgejo", "forgejo-runner"})
    MODEL_SERVICES = frozenset({"foundation-sec-server", "antares-server"})

    def __init__(self, *, config: AppConfig, audit: AuditStore) -> None:
        self._config = config
        self._audit = audit
        self._prerequisites = None
        self._refresh_service_catalog()

    def _refresh_service_catalog(self) -> None:
        compose_report = cached_compose_cli(self._config.orchestrator.compose_command)
        prefix = compose_report.argv_prefix if compose_report.available else ()
        self._services = _managed_services(prefix)
        self.ALLOWED_SERVICES = frozenset(self._services.keys())

    def attach_prerequisite_checker(self, checker) -> None:
        self._prerequisites = checker

    def topology_report(self) -> TopologyReport:
        return cached_topology_report(self._config.orchestrator.compose_command)

    def topology(self) -> str:
        return topology_label(self._config.orchestrator.compose_command)

    def compose_cli_report(self) -> dict[str, Any]:
        return cached_compose_cli(self._config.orchestrator.compose_command).to_dict()

    def docker_control_available(self) -> bool:
        report = self.topology_report()
        cli = cached_compose_cli(self._config.orchestrator.compose_command)
        return report.docker_socket_available and cli.available

    def dependency_graph(self) -> dict[str, Any]:
        return {
            "edges": {service: list(deps) for service, deps in SERVICE_DEPENDENCIES.items()},
            "critical_pipeline_chain": list(CRITICAL_PIPELINE_CHAIN),
            "degraded_recovery_chain": list(DEGRADED_RECOVERY_CHAIN),
            "prerequisite_checks": dict(SERVICE_PREREQUISITE_CHECKS),
            "readiness_timeouts_seconds": {
                service: readiness_timeout(service) for service in self.ALLOWED_SERVICES
            },
        }

    def start_feasibility(self, service: ServiceName) -> dict[str, Any]:
        report = self.topology_report()
        spec = self._services[service]
        cli = cached_compose_cli(self._config.orchestrator.compose_command)

        if service == "orchestrator":
            return {
                "feasibility": "detect_only",
                "control_mode": report.service_control_mode,
                "note": (
                    "Orchestrator cannot restart itself from this UI — use "
                    f"{cli.form if cli.available else 'docker compose'} or your process manager."
                ),
            }

        if service in self.COMPOSE_SERVICES:
            if self.docker_control_available():
                return {
                    "feasibility": "start",
                    "control_mode": "compose-via-docker-socket",
                    "note": (
                        "Compose service controlled via mounted Docker socket (/var/run/docker.sock). "
                        "This grants effective host control — actions are limited to the fixed named set."
                    ),
                }
            return {
                "feasibility": "detect_only",
                "control_mode": report.service_control_mode,
                "note": (
                    "Docker socket or Compose CLI unavailable — mount /var/run/docker.sock and install "
                    f"{' or '.join(repr(f) for f in ('docker compose', 'docker-compose'))}."
                    + (f" ({cli.error})" if cli.error else "")
                ),
            }

        if service in self.MODEL_SERVICES:
            root = resolve_repo_root()
            report = self.topology_report()
            if report.model_hosting == "host-native-macos":
                if not report.orchestrator_in_container:
                    return {
                        "feasibility": "start",
                        "control_mode": "supervised-host-native",
                        "note": (
                            f"{spec.display_name} supervised by ./shift-left (PID file under .shift-left/). "
                            "Logs in .shift-left/logs/."
                        ),
                    }
                return {
                    "feasibility": "detect_only",
                    "control_mode": "host-native-external",
                    "note": (
                        f"{spec.display_name} runs on the host (Apple Silicon). "
                        "Orchestrator is containerized — control from the host: "
                        f"./shift-left model restart {service.replace('_', '-')}"
                    ),
                }
            if report.model_hosting == "compose-linux" and self.docker_control_available():
                return {
                    "feasibility": "start",
                    "control_mode": "compose-via-docker-socket",
                    "note": (
                        "Linux container profile (linux-cpu / linux-gpu) — started via Compose. "
                        "Readiness via GET /health only."
                    ),
                }

        return {
            "feasibility": "detect_only",
            "control_mode": report.service_control_mode,
            "note": "No lifecycle control available in this topology.",
        }

    async def assess_start(self, service: ServiceName) -> dict[str, Any]:
        feasibility = self.start_feasibility(service)
        deps = transitive_dependencies(service)
        blocking: list[dict[str, Any]] = []
        if self._prerequisites and deps:
            for dep in deps:
                check_id = SERVICE_PREREQUISITE_CHECKS.get(dep)
                if not check_id:
                    continue
                check = await self._prerequisites.verify_check(check_id)
                if not check.ok:
                    blocking.append(
                        {
                            "service": dep,
                            "check_id": check_id,
                            "error": check.error,
                            "affected_capability": check.affected_capability,
                        }
                    )
        return {
            "service": service,
            "feasibility": feasibility,
            "dependencies": deps,
            "blocking_dependencies": blocking,
            "can_start": feasibility["feasibility"] == "start" and not blocking,
            "suggest_start_chain": bool(blocking),
        }

    def _compose_running_services(self) -> set[str] | None:
        if not self.docker_control_available():
            return None
        prefix = compose_argv_prefix(config_override=self._config.orchestrator.compose_command)
        result = subprocess.run(
            [*prefix, "ps", "--services", "--filter", "status=running"],
            cwd=_repo_root(),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}

    async def status_all(self) -> list[dict[str, Any]]:
        compose_running = self._compose_running_services()
        rows: list[dict[str, Any]] = []
        for name in sorted(self.ALLOWED_SERVICES):
            rows.append(await self.status(name, compose_running=compose_running))
        return rows

    async def status(
        self,
        service: ServiceName,
        *,
        compose_running: set[str] | None = None,
    ) -> dict[str, Any]:
        spec = self._services[service]
        topology = self.topology()
        health_url = self._effective_health_url(spec)
        running = False
        runtime: dict[str, Any] = {}
        error: str | None = None

        if health_url:
            try:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    response = await client.get(health_url)
                    running = response.status_code == 200
                    if running:
                        runtime = response.json()
            except Exception as exc:  # noqa: BLE001
                error = str(exc)
                running = False
        elif service in self.COMPOSE_SERVICES:
            running_services = (
                compose_running
                if compose_running is not None
                else self._compose_running_services()
            )
            if running_services is not None:
                running = service in running_services

        report = self.topology_report()
        if spec.process_match and not report.orchestrator_in_container:
            pid = self._find_pid(spec.process_match)
        else:
            pid = None
        memory_kb = self._process_memory_kb(pid) if pid else None
        feasibility = self.start_feasibility(service)

        return {
            "service": service,
            "display_name": spec.display_name,
            "topology": topology,
            "control_mode": feasibility["control_mode"],
            "start_feasibility": feasibility["feasibility"],
            "feasibility_note": feasibility["note"],
            "dependencies": list(SERVICE_DEPENDENCIES.get(service, ())),
            "running": running,
            "health_url": health_url,
            "pid": pid,
            "memory_rss_kb": memory_kb,
            "runtime": runtime,
            "error": error,
            "actions_available": list(self.ALLOWED_ACTIONS),
            "readiness_timeout_seconds": readiness_timeout(service),
        }

    async def run_action(
        self,
        *,
        service: ServiceName,
        action: ServiceAction,
        actor: str,
        skip_dependency_check: bool = False,
        skip_verification: bool = False,
    ) -> dict[str, Any]:
        if service not in self.ALLOWED_SERVICES:
            raise ValueError(f"Unknown service: {service}")
        if action not in self.ALLOWED_ACTIONS:
            raise ValueError(f"Unknown action: {action}")

        if action in {"start", "restart"} and not skip_dependency_check:
            assessment = await self.assess_start(service)
            if not assessment["can_start"]:
                blocking = assessment["blocking_dependencies"]
                feasibility = assessment["feasibility"]["feasibility"]
                if feasibility != "start":
                    raise ValueError(
                        f"Cannot {action} {service} from this orchestrator: "
                        f"{assessment['feasibility']['note']}"
                    )
                if blocking:
                    dep = blocking[0]
                    raise ValueError(
                        f"Cannot {action} {service}: dependency {dep['service']} is unhealthy "
                        f"({dep['error']}). Start the dependency chain first."
                    )

        spec = self._services[service]
        topology = self.topology()
        argv = self._argv_for(spec, action, topology)
        if argv is None:
            raise ValueError(
                f"{action} for {service} is not available in {topology} topology from this orchestrator."
            )

        command_started = time.perf_counter()
        command_outcome, command_detail = await self._dispatch_command(
            service, action, argv, topology
        )
        command_ms = int((time.perf_counter() - command_started) * 1000)

        self._audit.log(
            actor=actor,
            action="service.lifecycle.command",
            subject=f"{service}/{action}",
            details={
                "service": service,
                "action": action,
                "topology": topology,
                "outcome": command_outcome,
                "duration_ms": command_ms,
                "detail": command_detail,
                "argv": list(argv),
            },
        )

        verification: dict[str, Any] = {
            "outcome": "not_applicable",
            "progress": [],
            "elapsed_ms": 0,
        }
        verified_outcome: VerificationOutcome = "not_applicable"

        if (
            action in {"start", "restart"}
            and not skip_verification
            and command_outcome == "ok"
            and service in SERVICE_PREREQUISITE_CHECKS
            and self._prerequisites is not None
        ):
            verification = await self._poll_readiness(service)
            verified_outcome = verification["outcome"]
            self._prerequisites.invalidate_cache()
        elif action in {"start", "restart"} and command_outcome != "ok":
            verified_outcome = "command_failed"
        elif action in {"start", "restart"} and command_outcome == "ok":
            verified_outcome = "verified_healthy" if skip_verification else "not_applicable"

        if action in {"start", "restart"}:
            self._audit.log(
                actor=actor,
                action="service.lifecycle.verified",
                subject=f"{service}/{action}",
                details={
                    "service": service,
                    "action": action,
                    "command_outcome": command_outcome,
                    "verification_outcome": verified_outcome,
                    "verification": verification,
                },
            )

        current = await self.status(service)
        final_outcome = (
            verified_outcome
            if verified_outcome not in {"not_applicable"}
            else ("command_failed" if command_outcome != "ok" else "verified_healthy")
        )
        return {
            "outcome": final_outcome,
            "command_outcome": command_outcome,
            "verification_outcome": verified_outcome,
            "detail": command_detail,
            "command_duration_ms": command_ms,
            "verification": verification,
            "status": current,
        }

    async def start_all_prerequisites(
        self,
        *,
        actor: str,
        include_degraded: bool = True,
    ) -> dict[str, Any]:
        chain: list[ServiceName] = list(CRITICAL_PIPELINE_CHAIN)
        if include_degraded and self._config.models.foundation_sec.enabled:
            for item in DEGRADED_RECOVERY_CHAIN:
                if item not in chain:
                    chain.append(item)

        steps: list[dict[str, Any]] = []
        for service in chain:
            feasibility = self.start_feasibility(service)
            if feasibility["feasibility"] != "start":
                steps.append(
                    {
                        "service": service,
                        "phase": "skipped",
                        "outcome": "detect_only",
                        "error": feasibility["note"],
                    }
                )
                continue

            steps.append({"service": service, "phase": "starting"})
            try:
                result = await self.run_action(
                    service=service,
                    action="start",
                    actor=actor,
                    skip_dependency_check=True,
                )
            except ValueError as exc:
                steps[-1].update(
                    {
                        "phase": "failed",
                        "outcome": "command_failed",
                        "error": str(exc),
                    }
                )
                if self._prerequisites is not None:
                    self._prerequisites.invalidate_cache()
                return {
                    "outcome": "chain_stopped",
                    "failed_service": service,
                    "failed_phase": "start",
                    "steps": steps,
                    "dependency_graph": self.dependency_graph(),
                }

            steps[-1].update(
                {
                    "phase": "complete",
                    "command_outcome": result["command_outcome"],
                    "verification_outcome": result["verification_outcome"],
                    "verification": result.get("verification"),
                    "outcome": result["outcome"],
                }
            )
            if result["outcome"] != "verified_healthy":
                if self._prerequisites is not None:
                    self._prerequisites.invalidate_cache()
                return {
                    "outcome": "chain_stopped",
                    "failed_service": service,
                    "failed_phase": "verification",
                    "steps": steps,
                    "dependency_graph": self.dependency_graph(),
                    "error": result.get("detail") or (result.get("verification") or {}).get("error"),
                }

        if self._prerequisites is not None:
            self._prerequisites.invalidate_cache()

        started = [step["service"] for step in steps if step.get("phase") == "complete"]
        skipped = [step["service"] for step in steps if step.get("phase") == "skipped"]
        return {
            "outcome": "chain_complete",
            "steps": steps,
            "started_services": started,
            "skipped_services": skipped,
            "dependency_graph": self.dependency_graph(),
        }

    async def _poll_readiness(self, service: ServiceName) -> dict[str, Any]:
        check_id = SERVICE_PREREQUISITE_CHECKS[service]
        timeout_s = readiness_timeout(service)
        deadline = time.monotonic() + timeout_s
        delay = READINESS_POLL_INITIAL_SECONDS
        progress: list[dict[str, Any]] = []
        started = time.monotonic()

        progress.append(
            {
                "phase": "starting",
                "elapsed_ms": 0,
                "message": f"Command dispatched for {service}.",
            }
        )

        last_error: str | None = None
        while time.monotonic() < deadline:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            progress.append(
                {
                    "phase": "waiting_for_readiness",
                    "elapsed_ms": elapsed_ms,
                    "message": f"Polling prerequisite {check_id} ({elapsed_ms}ms elapsed).",
                }
            )
            assert self._prerequisites is not None
            check = await self._prerequisites.verify_check(check_id)
            if check.ok:
                progress.append(
                    {
                        "phase": "verified_healthy",
                        "elapsed_ms": elapsed_ms,
                        "message": f"{service} confirmed healthy via {check_id}.",
                    }
                )
                return {
                    "outcome": "verified_healthy",
                    "check_id": check_id,
                    "elapsed_ms": elapsed_ms,
                    "progress": progress,
                    "check": check.to_dict(),
                }
            last_error = check.error
            await asyncio.sleep(delay)
            delay = min(delay * READINESS_POLL_BACKOFF_FACTOR, READINESS_POLL_MAX_SECONDS)

        elapsed_ms = int((time.monotonic() - started) * 1000)
        progress.append(
            {
                "phase": "verification_timeout",
                "elapsed_ms": elapsed_ms,
                "message": f"{service} did not become healthy within {timeout_s:.0f}s.",
            }
        )
        return {
            "outcome": "verification_timeout",
            "check_id": check_id,
            "elapsed_ms": elapsed_ms,
            "error": last_error,
            "progress": progress,
        }

    async def _dispatch_command(
        self,
        service: ServiceName,
        action: ServiceAction,
        argv: tuple[str, ...],
        topology: str,
    ) -> tuple[str, str]:
        try:
            if action == "stop" and argv[0] == "pkill":
                result = subprocess.run(
                    list(argv),
                    cwd=_repo_root(),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                detail = (result.stderr or result.stdout or "").strip()
                return ("ok" if result.returncode in {0, 1} else "failed", detail)

            env = os.environ.copy()
            if service == "foundation-sec-server" and topology == "host-native":
                env.setdefault("FOUNDATION_SEC_BIND_HOST", "127.0.0.1")
            if service in self.MODEL_SERVICES and self.topology_report().model_hosting == "host-native-macos":
                if not self.topology_report().orchestrator_in_container:
                    from shift_left.system.supervisor import restart_service, start_service, stop_service

                    root = resolve_repo_root()
                    if action == "start":
                        start_service(root, service)
                    elif action == "stop":
                        stop_service(root, service)
                    else:
                        restart_service(root, service)
                    return ("ok", f"Supervisor {action} issued for {service}.")
            if action in {"start", "restart"} and service == "forgejo":
                _cleanup_stale_forgejo_run_containers()
            if action == "start":
                if service in self.COMPOSE_SERVICES:
                    result = subprocess.run(
                        list(argv),
                        cwd=_repo_root(),
                        env=env,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=120,
                    )
                    detail = (result.stderr or result.stdout or "").strip()
                    if result.returncode != 0:
                        return ("failed", detail or f"compose start failed for {service}")
                    return ("ok", detail or f"Compose start completed for {service}.")
                subprocess.Popen(
                    list(argv),
                    cwd=self._workdir(service, topology),
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return ("ok", f"Start command issued for {service}.")
            result = subprocess.run(
                list(argv),
                cwd=_repo_root(),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode not in {0, 1}:
                detail = (result.stderr or result.stdout or f"exit {result.returncode}").strip()
                return ("failed", detail)
            detail = (result.stderr or result.stdout or "").strip()
            return ("ok", detail or f"{action} completed for {service}.")
        except Exception as exc:  # noqa: BLE001
            return ("failed", str(exc))

    def _argv_for(
        self,
        spec: ManagedService,
        action: ServiceAction,
        topology: str,
    ) -> tuple[str, ...] | None:
        feasibility = self.start_feasibility(spec.name)
        if feasibility["feasibility"] != "start" and action in {"start", "restart"}:
            return None
        report = self.topology_report()
        if spec.name in self.COMPOSE_SERVICES or (
            spec.name in self.MODEL_SERVICES and report.model_hosting == "compose-linux"
        ):
            return spec.docker_argv.get(action) if spec.docker_argv else None
        if spec.host_native_argv and spec.name in self.MODEL_SERVICES:
            return spec.host_native_argv.get(action)
        return spec.docker_argv.get(action) if spec.docker_argv else None

    @staticmethod
    def _control_mode(spec: ManagedService, topology: str) -> str:
        if topology == "host-native" and spec.host_native_argv:
            return "host-native"
        if spec.docker_argv:
            return "docker-compose"
        return "unavailable"

    @staticmethod
    def _workdir(service: ServiceName, topology: str) -> str:
        root = _repo_root()
        if topology != "host-native":
            return root
        if service == "foundation-sec-server":
            return os.path.join(root, "services/foundation-sec-server")
        if service == "antares-server":
            return os.path.join(root, "services/antares-server")
        return root

    def _effective_health_url(self, spec: ManagedService) -> str | None:
        if spec.name == "foundation-sec-server" and self._config.models.foundation_sec.enabled:
            return f"{resolve_foundation_sec_service_url(self._config).rstrip('/')}/health"
        if spec.name == "antares-server":
            return (
                f"{os.environ.get('ANTARES_SERVICE_URL', self._config.models.antares.service_url).rstrip('/')}/health"
            )
        return spec.health_url

    @staticmethod
    def _find_pid(match: str | None) -> int | None:
        if not match:
            return None
        try:
            result = subprocess.run(
                ["pgrep", "-f", match],
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return None
        if result.returncode != 0 or not result.stdout.strip():
            return None
        try:
            return int(result.stdout.strip().splitlines()[0])
        except ValueError:
            return None

    @staticmethod
    def _process_memory_kb(pid: int | None) -> int | None:
        if pid is None:
            return None
        try:
            result = subprocess.run(
                ["ps", "-o", "rss=", "-p", str(pid)],
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return None
        if result.returncode != 0:
            return None
        try:
            return int(result.stdout.strip())
        except ValueError:
            return None


def compose_exec_argv(
    config: AppConfig,
    service: str,
    *args: str,
) -> list[str]:
    """Build a hardcoded ``compose exec`` argv for prerequisite checks."""
    prefix = compose_argv_prefix(config_override=config.orchestrator.compose_command)
    return [*prefix, "exec", "-T", service, *args]


def _cleanup_stale_forgejo_run_containers() -> None:
    project = os.environ.get("COMPOSE_PROJECT_NAME", "shift-left")
    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name={project}-forgejo-run-"],
        capture_output=True,
        text=True,
        check=False,
    )
    for container_id in result.stdout.split():
        container_id = container_id.strip()
        if container_id:
            subprocess.run(["docker", "stop", container_id], capture_output=True, check=False)
