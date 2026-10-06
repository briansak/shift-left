"""Start/stop Compose stack in dependency order."""

from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path

from shift_left_cli.compose_util import detect_compose


def start_compose_stack(root: Path) -> None:
    from shift_left_cli.configure import generate_config

    config_path = root / "config" / "shift-left.yaml"
    if config_path.is_dir() or not config_path.is_file():
        generate_config(root)

    compose = detect_compose(root)
    from shift_left_cli.forgejo_config import ensure_forgejo_data_permissions

    ensure_forgejo_data_permissions(root)
    for service in ("postgres", "forgejo", "orchestrator"):
        print(f"Starting {service}…")
        subprocess.check_call(compose.cmd("up", "-d", service), cwd=root)
        _wait_after_start(root, service)

    print("Starting forgejo-runner…")
    subprocess.check_call(compose.cmd("up", "-d", "forgejo-runner"), cwd=root)


def stop_compose_stack(root: Path) -> None:
    compose = detect_compose(root)
    for service in ("forgejo-runner", "orchestrator", "forgejo", "postgres"):
        subprocess.run(compose.cmd("stop", service), cwd=root, check=False)


def service_host_port(service: str) -> tuple[str, int]:
    """Host-side reachability for published Compose ports (operator CLI runs on host)."""
    if service == "forgejo":
        return "127.0.0.1", int(os.environ.get("FORGEJO_PORT", "3000"))
    if service == "orchestrator":
        return "127.0.0.1", int(os.environ.get("ORCHESTRATOR_PORT", "8080"))
    raise ValueError(f"No host port mapping for {service!r}")


def _wait_after_start(root: Path, service: str) -> None:
    if service == "postgres":
        _wait_postgres_ready(root)
        return
    host, port = service_host_port(service)
    timeout = 120.0 if service == "forgejo" else 90.0
    _wait_tcp(host, port, service, timeout=timeout)


def _wait_postgres_ready(root: Path, timeout: float = 90.0) -> None:
    compose = detect_compose(root)
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            compose.cmd("exec", "-T", "postgres", "pg_isready", "-U", "forgejo", "-d", "forgejo"),
            cwd=root,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("Timed out waiting for postgres to accept connections")


def _wait_tcp(host: str, port: int, service: str, *, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(1)
    raise RuntimeError(f"Timed out waiting for {service} on {host}:{port}")
