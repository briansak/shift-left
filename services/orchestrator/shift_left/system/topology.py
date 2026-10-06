"""Authoritative runtime topology detection from observable facts."""

from __future__ import annotations

import os
import platform
import socket
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

TopologyLabel = Literal["docker-compose", "host-native"]

COMPOSE_DNS_PROBE_HOST = "postgres"
COMPOSE_DNS_PROBE_PORT = 5432
DOCKER_SOCKET_PATH = "/var/run/docker.sock"


@dataclass(frozen=True)
class TopologyReport:
    """Observable runtime context — not configuration assumptions."""

    orchestrator_in_container: bool
    cgroup_container: bool
    compose_dns_resolves: bool
    docker_socket_available: bool
    platform_system: str
    platform_machine: str
    model_hosting: Literal["host-native-macos", "compose-linux", "host-native", "unknown"]
    topology_label: TopologyLabel
    service_control_mode: str
    prior_mismatch: list[str] = field(default_factory=list)
    detection_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "topology": self.topology_label,
            "orchestrator_in_container": self.orchestrator_in_container,
            "cgroup_container": self.cgroup_container,
            "compose_dns_resolves": self.compose_dns_resolves,
            "docker_socket_available": self.docker_socket_available,
            "platform": f"{self.platform_system}/{self.platform_machine}",
            "model_hosting": self.model_hosting,
            "service_control_mode": self.service_control_mode,
            "prior_mismatch": self.prior_mismatch,
            "detection_notes": self.detection_notes,
        }


def _explicit_topology_override() -> TopologyLabel | None:
    explicit = os.environ.get("SHIFT_LEFT_SERVICE_TOPOLOGY", "").strip().lower()
    if explicit in {"host-native", "docker-compose"}:
        return explicit  # type: ignore[return-value]
    return None


def _in_dockerenv() -> bool:
    return Path("/.dockerenv").exists()


def _cgroup_indicates_container() -> bool:
    candidates = (Path("/proc/1/cgroup"), Path("/proc/self/cgroup"))
    markers = ("docker", "containerd", "kubepods", "podman", "lxc")
    for path in candidates:
        if not path.exists():
            continue
        try:
            text = path.read_text()
        except OSError:
            continue
        lowered = text.lower()
        if any(marker in lowered for marker in markers):
            return True
    return False


def _compose_dns_resolves(host: str = COMPOSE_DNS_PROBE_HOST, port: int = COMPOSE_DNS_PROBE_PORT) -> bool:
    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return True
    except OSError:
        return False


def _docker_socket_available() -> bool:
    path = Path(DOCKER_SOCKET_PATH)
    if not path.exists():
        return False
    return os.access(path, os.R_OK | os.W_OK)


def _infer_model_hosting(*, in_container: bool, compose_dns: bool) -> Literal[
    "host-native-macos", "compose-linux", "host-native", "unknown"
]:
    explicit = os.environ.get("SHIFT_LEFT_MODEL_HOSTING", "").strip().lower()
    if explicit in {"host-native-macos", "compose-linux", "host-native"}:
        return explicit  # type: ignore[return-value]

    antares_url = os.environ.get("ANTARES_SERVICE_URL", "")
    foundation_url = os.environ.get("FOUNDATION_SEC_SERVICE_URL", "")
    if "host.docker.internal" in antares_url or "host.docker.internal" in foundation_url:
        return "host-native-macos"

    if in_container and compose_dns:
        return "compose-linux"

    if not in_container:
        system = platform.system().lower()
        machine = platform.machine().lower()
        if system == "darwin" and machine in {"arm64", "aarch64"}:
            return "host-native-macos"
        return "host-native"

    return "unknown"


def _derive_topology_label(
    *,
    override: TopologyLabel | None,
    in_container: bool,
    compose_dns: bool,
) -> TopologyLabel:
    if override:
        return override
    if in_container or compose_dns:
        return "docker-compose"
    return "host-native"


def _derive_service_control_mode(
    *,
    docker_socket: bool,
    in_container: bool,
    compose_dns: bool,
) -> str:
    if docker_socket:
        return "compose-via-docker-socket"
    if in_container and not docker_socket:
        return "detect-only-no-socket"
    if compose_dns:
        return "compose-network-only"
    return "host-native-unmanaged"


def _prior_mismatch_notes(
    *,
    old_label: TopologyLabel,
    report: TopologyReport,
) -> list[str]:
    notes: list[str] = []
    if old_label == "host-native" and report.compose_dns_resolves:
        notes.append(
            "Previously labeled host-native while Compose DNS names (e.g. postgres) resolve — "
            "orchestrator is on the Compose network."
        )
    if old_label == "host-native" and report.docker_socket_available:
        notes.append(
            "Previously labeled host-native while Docker socket is available — "
            "service control uses Compose, not host-native process spawn."
        )
    if old_label == "docker-compose" and not report.orchestrator_in_container and not report.compose_dns_resolves:
        notes.append(
            "Previously labeled docker-compose but neither container markers nor Compose DNS "
            "resolve — checks using postgres/forgejo hostnames will fail."
        )
    if report.orchestrator_in_container and not report.docker_socket_available:
        notes.append(
            "Orchestrator runs in a container without Docker socket access — "
            "Compose lifecycle actions are detect-only until /var/run/docker.sock is mounted."
        )
    return notes


def detect_topology(*, config_override: str | None = None) -> TopologyReport:
    """
    Detect runtime topology from observable facts.

    Order: env override → /.dockerenv & cgroup → Compose DNS probe → docker socket.
    """
    override_env = _explicit_topology_override()
    override = None
    if config_override:
        normalized = config_override.strip().lower()
        if normalized in {"host-native", "docker-compose"}:
            override = normalized  # type: ignore[assignment]
    if override is None:
        override = override_env

    in_container = _in_dockerenv() or _cgroup_indicates_container()
    cgroup_container = _cgroup_indicates_container()
    compose_dns = _compose_dns_resolves()
    docker_socket = _docker_socket_available()
    system = platform.system()
    machine = platform.machine()
    model_hosting = _infer_model_hosting(in_container=in_container, compose_dns=compose_dns)

    topology_label = _derive_topology_label(
        override=override,
        in_container=in_container,
        compose_dns=compose_dns,
    )

    # Legacy naive label for comparison
    naive_old: TopologyLabel = "docker-compose" if _in_dockerenv() else "host-native"
    report = TopologyReport(
        orchestrator_in_container=in_container,
        cgroup_container=cgroup_container,
        compose_dns_resolves=compose_dns,
        docker_socket_available=docker_socket,
        platform_system=system,
        platform_machine=machine,
        model_hosting=model_hosting,
        topology_label=topology_label,
        service_control_mode=_derive_service_control_mode(
            docker_socket=docker_socket,
            in_container=in_container,
            compose_dns=compose_dns,
        ),
        prior_mismatch=_prior_mismatch_notes(old_label=naive_old, report=TopologyReport(
            orchestrator_in_container=in_container,
            cgroup_container=cgroup_container,
            compose_dns_resolves=compose_dns,
            docker_socket_available=docker_socket,
            platform_system=system,
            platform_machine=machine,
            model_hosting=model_hosting,
            topology_label=naive_old,
            service_control_mode="",
        )),
        detection_notes=[
            f"orchestrator_in_container={in_container} (/.dockerenv={_in_dockerenv()}, cgroup={cgroup_container})",
            f"compose_dns_resolves({COMPOSE_DNS_PROBE_HOST})={compose_dns}",
            f"docker_socket_available={docker_socket}",
            f"model_hosting={model_hosting}",
        ],
    )
    return report


@lru_cache(maxsize=1)
def cached_topology_report(config_override: str | None = None) -> TopologyReport:
    return detect_topology(config_override=config_override)


def topology_label(config_override: str | None = None) -> TopologyLabel:
    return cached_topology_report(config_override).topology_label


def invalidate_topology_cache() -> None:
    cached_topology_report.cache_clear()
