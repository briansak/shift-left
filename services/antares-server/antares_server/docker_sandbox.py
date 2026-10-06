"""Per-investigation Docker isolation for Antares terminal exploration.

Docker socket access
--------------------
Containers are created via the host Docker Engine API, reached through the Unix
socket at ``/var/run/docker.sock`` (override with ``DOCKER_HOST``). The
host-native ``antares-server`` process holds this access — not the containerized
orchestrator.

What socket access grants
-------------------------
Any process with permission to talk to the Docker socket can create, start, stop,
and exec into containers on the host, bind-mount host paths, and (without
additional hardening) effectively run code as root on the host via container
breakout misconfiguration. This implementation uses that capability only to:

- Start one ephemeral investigation container per agent query
- Mount the repo snapshot read-only at ``/workspace/repo``
- ``docker exec`` allowlisted read-only commands inside that container
- Remove the container when the investigation completes or fails

Operators should treat ``antares-server`` as a privileged host service and restrict
who can modify its environment or binary.
"""

from __future__ import annotations

import logging
import os
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from antares_server.sandbox_audit import (
    SandboxAuditSink,
    completion_audit_event,
    dispatch_audit_event,
)
from antares_server.sandbox_policy import validate_command
from antares_server.tool_output_sanitization import sanitize_tool_output

logger = logging.getLogger(__name__)

REPO_MOUNT = "/workspace/repo"
DEFAULT_IMAGE = "shift-left-antares-sandbox:bookworm"
DEFAULT_CPUS = "2"
DEFAULT_MEMORY = "4g"
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_OUTPUT_CHARS = 2000


@dataclass(frozen=True)
class SandboxResult:
    output: str
    exit_code: int
    truncated: bool


class DockerInvestigationSandbox:
    """One Docker container per investigation — destroyed on close."""

    def __init__(
        self,
        root: Path,
        *,
        investigation_id: str | None = None,
        audit_sink: SandboxAuditSink | None = None,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        command_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        image: str | None = None,
        cpus: str | None = None,
        memory: str | None = None,
    ) -> None:
        self.root = root.resolve()
        self.investigation_id = investigation_id or f"antares-inv-{uuid.uuid4().hex[:12]}"
        self._audit_sink = audit_sink
        self.max_output_chars = max_output_chars
        self.command_timeout_seconds = command_timeout_seconds
        self._image = image or os.environ.get("ANTARES_SANDBOX_IMAGE", DEFAULT_IMAGE)
        self._cpus = cpus or os.environ.get("ANTARES_SANDBOX_CPUS", DEFAULT_CPUS)
        self._memory = memory or os.environ.get("ANTARES_SANDBOX_MEMORY", DEFAULT_MEMORY)
        self._container_id: str | None = None
        self.invocation_log: list[str] = []

    def start(self) -> None:
        if self._container_id:
            return
        name = self.investigation_id
        create = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "--network",
                "none",
                "--cpus",
                self._cpus,
                "--memory",
                self._memory,
                "--pids-limit",
                "256",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "-v",
                f"{self.root}:{REPO_MOUNT}:ro",
                "-w",
                REPO_MOUNT,
                self._image,
                "sleep",
                "infinity",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if create.returncode != 0:
            detail = (create.stderr or create.stdout or "").strip()
            raise RuntimeError(
                f"Could not start Antares investigation container ({name}): {detail or create.returncode}"
            )
        self._container_id = create.stdout.strip()
        logger.info(
            "Antares investigation container started id=%s investigation=%s image=%s",
            self._container_id[:12],
            self.investigation_id,
            self._image,
        )

    def execute(self, command: str) -> SandboxResult:
        command = command.strip()
        self.invocation_log.append(command)
        validation = validate_command(command)
        if not validation.ok:
            result = SandboxResult(output=validation.error, exit_code=1, truncated=False)
            self._record_audit(command, result)
            return result

        if self._container_id is None:
            raise RuntimeError("Docker investigation container is not started")

        command_id = self._record_dispatch(command)
        try:
            if validation.shell_command:
                completed = subprocess.run(
                    [
                        "docker",
                        "exec",
                        "-w",
                        REPO_MOUNT,
                        self._container_id,
                        "sh",
                        "-c",
                        validation.shell_command,
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.command_timeout_seconds,
                    check=False,
                )
            else:
                completed = subprocess.run(
                    ["docker", "exec", "-w", REPO_MOUNT, self._container_id, *validation.argv_command],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.command_timeout_seconds,
                    check=False,
                )
        except subprocess.TimeoutExpired:
            result = SandboxResult(output="error: command timed out", exit_code=124, truncated=False)
            self._record_audit(command, result, command_id=command_id)
            return result

        merged = sanitize_tool_output((completed.stdout or "") + (completed.stderr or ""))
        truncated = len(merged) > self.max_output_chars
        if truncated:
            merged = merged[: self.max_output_chars] + "\n... [output truncated]"
        result = SandboxResult(
            output=merged or "(no output)",
            exit_code=completed.returncode,
            truncated=truncated,
        )
        self._record_audit(command, result, command_id=command_id)
        return result

    def destroy(self) -> None:
        if not self._container_id:
            return
        subprocess.run(
            ["docker", "rm", "-f", self._container_id],
            capture_output=True,
            text=True,
            check=False,
        )
        logger.info(
            "Antares investigation container removed investigation=%s",
            self.investigation_id,
        )
        self._container_id = None

    def close(self) -> None:
        self.destroy()

    def __enter__(self) -> DockerInvestigationSandbox:
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.destroy()

    def _record_dispatch(self, command: str) -> str | None:
        if self._audit_sink is None:
            return None
        event = dispatch_audit_event(
            investigation_id=self.investigation_id,
            command=command,
        )
        self._audit_sink.record(event)
        return event.command_id

    def _record_audit(
        self,
        command: str,
        result: SandboxResult,
        *,
        command_id: str | None = None,
    ) -> None:
        if self._audit_sink is None:
            return
        self._audit_sink.record(
            completion_audit_event(
                investigation_id=self.investigation_id,
                command=command,
                command_id=command_id,
                exit_code=result.exit_code,
                output_truncated=result.output,
                truncated=result.truncated,
            )
        )


def investigation_container_exists(investigation_id: str) -> bool:
    """Return whether a container with ``docker ps --filter name=…`` exists."""
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"name=^{investigation_id}$",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return bool((result.stdout or "").strip())


def destroy_investigation_container(investigation_id: str) -> bool:
    """Force-remove the investigation container by name (``docker rm -f``)."""
    result = subprocess.run(
        ["docker", "rm", "-f", investigation_id],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        logger.info("Antares investigation container force-removed investigation=%s", investigation_id)
        return True
    detail = (result.stderr or result.stdout or "").strip()
    if detail and "No such container" not in detail:
        logger.warning(
            "Could not force-remove investigation container %s: %s",
            investigation_id,
            detail,
        )
    return False


def docker_available() -> bool:
    try:
        completed = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
