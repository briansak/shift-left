"""Preflight checks before ./shift-left up."""

from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

from shift_left_cli.compose_util import detect_compose


class PreflightError(RuntimeError):
    pass


def detect_platform() -> dict[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    apple_silicon = system == "darwin" and machine in {"arm64", "aarch64"}
    return {
        "system": system,
        "machine": machine,
        "apple_silicon": str(apple_silicon).lower(),
        "model_hosting": "host-native-macos" if apple_silicon else "compose-linux",
    }


def run_preflight(root: Path) -> dict[str, str]:
    info = detect_platform()
    print(f"Platform: {info['system']}/{info['machine']} (model hosting: {info['model_hosting']})")

    if shutil.which("docker") is None:
        raise PreflightError(
            "Docker not found. Install Colima or Docker Desktop, then re-run ./shift-left up."
        )

    ensure_docker_daemon(root)

    compose = detect_compose(root)
    print(f"Compose CLI: {compose.form}")
    info["compose_form"] = compose.form

    _check_disk(root)
    _check_memory(info)
    return info


def ensure_docker_daemon(root: Path, *, resume: str = "./shift-left up") -> None:
    """Verify the Docker API is reachable before pull/compose operations."""
    result = subprocess.run(
        ["docker", "info"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        print("Docker daemon: running")
        return

    detail = (result.stderr or result.stdout or "").strip()
    hint = _docker_start_hint(detail)
    tail = detail.splitlines()[-1].strip() if detail else "docker info failed"
    raise PreflightError(
        "Docker daemon is not running — container images cannot be pulled.\n"
        f"{hint}\n"
        f"Then resume with: {resume}\n"
        f"({tail})"
    )


def _docker_start_hint(detail: str) -> str:
    lowered = detail.lower()
    if "colima" in lowered or ".colima/" in lowered:
        return "  colima start"
    if "docker desktop" in lowered or "com.docker.docker" in lowered:
        return "  Open Docker Desktop and wait until it reports running."
    if platform.system().lower() == "darwin":
        return "  colima start   — or open Docker Desktop if you use that instead."
    return "  Start Docker (system service or Docker Desktop), then retry."


def _check_disk(root: Path) -> None:
    usage = shutil.disk_usage(root)
    free_gb = usage.free / (1024**3)
    if free_gb < 15:
        raise PreflightError(
            f"Low disk space: {free_gb:.1f} GB free. Need ~15 GB for images + Q4_K_M weights."
        )
    print(f"Disk: {free_gb:.1f} GB free")


def _check_memory(info: dict[str, str]) -> None:
    if info["model_hosting"] == "host-native-macos":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True,
                text=True,
                check=True,
            )
            mem_gb = int(result.stdout.strip()) / (1024**3)
        except (OSError, ValueError, subprocess.CalledProcessError):
            mem_gb = 0
        if mem_gb and mem_gb < 16:
            raise PreflightError(
                f"Host memory {mem_gb:.1f} GB — Q4_K_M at n_ctx=4096 needs ~16 GB+ for comfortable headroom."
            )
        if mem_gb:
            print(f"Memory: {mem_gb:.1f} GB")
