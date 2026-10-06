"""Service dependency graph and readiness configuration."""

from __future__ import annotations

from typing import Literal

ServiceName = Literal[
    "foundation-sec-server",
    "antares-server",
    "forgejo-runner",
    "orchestrator",
    "forgejo",
    "postgres",
]

SERVICE_DEPENDENCIES: dict[ServiceName, tuple[ServiceName, ...]] = {
    "postgres": (),
    "forgejo": ("postgres",),
    "forgejo-runner": ("postgres", "forgejo"),
    "orchestrator": ("postgres", "forgejo"),
    "foundation-sec-server": (),
    "antares-server": (),
}

SERVICE_PREREQUISITE_CHECKS: dict[ServiceName, str] = {
    "postgres": "postgres",
    "forgejo": "forgejo",
    "forgejo-runner": "forgejo_runner",
    "foundation-sec-server": "foundation_sec_server",
    "antares-server": "antares_server",
}

CRITICAL_PIPELINE_CHAIN: tuple[ServiceName, ...] = ("postgres", "forgejo", "forgejo-runner")

DEGRADED_RECOVERY_CHAIN: tuple[ServiceName, ...] = ("foundation-sec-server",)

DEFAULT_READINESS_TIMEOUTS: dict[ServiceName, float] = {
    "postgres": 90.0,
    "forgejo": 120.0,
    "forgejo-runner": 90.0,
    "orchestrator": 60.0,
    "foundation-sec-server": 45.0,
    "antares-server": 60.0,
}

READINESS_POLL_INITIAL_SECONDS = 0.5
READINESS_POLL_MAX_SECONDS = 5.0
READINESS_POLL_BACKOFF_FACTOR = 1.5


def readiness_timeout(service: ServiceName) -> float:
    return DEFAULT_READINESS_TIMEOUTS.get(service, 60.0)


def transitive_dependencies(service: ServiceName) -> list[ServiceName]:
    ordered: list[ServiceName] = []
    seen: set[ServiceName] = set()

    def visit(name: ServiceName) -> None:
        if name in seen:
            return
        for dep in SERVICE_DEPENDENCIES.get(name, ()):
            visit(dep)
        if name not in seen:
            seen.add(name)
            ordered.append(name)

    for dep in SERVICE_DEPENDENCIES.get(service, ()):
        visit(dep)
    return ordered
