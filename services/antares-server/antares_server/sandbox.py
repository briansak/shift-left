"""Investigation sandbox — Docker-isolated by default, subprocess fallback for tests."""

from __future__ import annotations

import os
import shlex
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol

from antares_server.docker_sandbox import DockerInvestigationSandbox
from antares_server.sandbox_audit import (
    SandboxAuditSink,
    completion_audit_event,
    dispatch_audit_event,
)
from antares_server.sandbox_policy import validate_command
from antares_server.tool_output_sanitization import sanitize_tool_output


@dataclass(frozen=True)
class SandboxResult:
    output: str
    exit_code: int
    truncated: bool


class InvestigationSandbox(Protocol):
    root: Path
    investigation_id: str
    invocation_log: list[str]

    def execute(self, command: str) -> SandboxResult: ...

    def close(self) -> None: ...


class SubprocessInvestigationSandbox:
    """Host subprocess fallback — not the production isolation boundary."""

    def __init__(
        self,
        root: Path,
        *,
        investigation_id: str | None = None,
        audit_sink: SandboxAuditSink | None = None,
        max_output_chars: int = 2000,
        command_timeout_seconds: float = 10.0,
    ) -> None:
        self.root = root.resolve()
        self.investigation_id = investigation_id or new_investigation_id()
        self._audit_sink = audit_sink
        self.max_output_chars = max_output_chars
        self.command_timeout_seconds = command_timeout_seconds
        self.invocation_log: list[str] = []

    def execute(self, command: str) -> SandboxResult:
        command = command.strip()
        self.invocation_log.append(command)
        validation = validate_command(command)
        if not validation.ok:
            result = SandboxResult(output=validation.error, exit_code=1, truncated=False)
            self._record_audit(command, result)
            return result

        command_id = self._record_dispatch(command)
        try:
            if validation.shell_command:
                completed = subprocess.run(
                    validation.shell_command,
                    shell=True,
                    cwd=self.root,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.command_timeout_seconds,
                    check=False,
                )
            else:
                completed = subprocess.run(
                    validation.argv_command,
                    cwd=self.root,
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

    def close(self) -> None:
        return None

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


# Backward-compatible alias used in tests and scripted generator typing.
ReadOnlySandbox = SubprocessInvestigationSandbox


def sandbox_backend() -> str:
    return os.environ.get("ANTARES_SANDBOX", "docker").strip().lower()


@contextmanager
def open_investigation_sandbox(
    root: Path,
    *,
    investigation_id: str,
    audit_sink: SandboxAuditSink | None = None,
) -> Iterator[InvestigationSandbox]:
    backend = sandbox_backend()
    if backend == "subprocess":
        sandbox = SubprocessInvestigationSandbox(
            root,
            investigation_id=investigation_id,
            audit_sink=audit_sink,
        )
        try:
            yield sandbox
        finally:
            sandbox.close()
        return

    sandbox = DockerInvestigationSandbox(
        root,
        investigation_id=investigation_id,
        audit_sink=audit_sink,
    )
    sandbox.start()
    try:
        yield sandbox
    finally:
        sandbox.destroy()


def new_investigation_id(prefix: str = "antares-inv") -> str:
    import uuid

    return f"{prefix}-{uuid.uuid4().hex[:12]}"
