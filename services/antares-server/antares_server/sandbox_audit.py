"""Per-command sandbox audit events for persistence through the orchestrator chokepoint."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

AUDIT_PHASE_DISPATCHED = "dispatched"
AUDIT_PHASE_COMPLETED = "completed"
DISPATCH_OUTPUT = "(dispatched; waiting for sandbox)"


@dataclass(frozen=True)
class SandboxCommandAudit:
    investigation_id: str
    command: str
    exit_code: int
    output_truncated: str
    truncated: bool
    recorded_at: str
    charged: bool = True
    duplicate_of_turn: int | None = None
    command_id: str | None = None
    phase: str = AUDIT_PHASE_COMPLETED

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "investigation_id": self.investigation_id,
            "command": self.command,
            "exit_code": self.exit_code,
            "output_truncated": self.output_truncated,
            "truncated": self.truncated,
            "recorded_at": self.recorded_at,
            "charged": self.charged,
            "phase": self.phase,
        }
        if self.duplicate_of_turn is not None:
            payload["duplicate_of_turn"] = self.duplicate_of_turn
        if self.command_id is not None:
            payload["command_id"] = self.command_id
        return payload


def new_command_id() -> str:
    return str(uuid4())


def dispatch_audit_event(
    *,
    investigation_id: str,
    command: str,
    charged: bool = True,
) -> SandboxCommandAudit:
    return SandboxCommandAudit(
        investigation_id=investigation_id,
        command=command,
        exit_code=0,
        output_truncated=DISPATCH_OUTPUT,
        truncated=False,
        recorded_at=audit_timestamp(),
        charged=charged,
        command_id=new_command_id(),
        phase=AUDIT_PHASE_DISPATCHED,
    )


def completion_audit_event(
    *,
    investigation_id: str,
    command: str,
    command_id: str | None,
    exit_code: int,
    output_truncated: str,
    truncated: bool,
    charged: bool = True,
    duplicate_of_turn: int | None = None,
) -> SandboxCommandAudit:
    return SandboxCommandAudit(
        investigation_id=investigation_id,
        command=command,
        exit_code=exit_code,
        output_truncated=output_truncated,
        truncated=truncated,
        recorded_at=audit_timestamp(),
        charged=charged,
        duplicate_of_turn=duplicate_of_turn,
        command_id=command_id,
        phase=AUDIT_PHASE_COMPLETED,
    )


class SandboxAuditSink(Protocol):
    def record(self, event: SandboxCommandAudit) -> None: ...


@dataclass
class CollectedAuditSink:
    events: list[SandboxCommandAudit] = field(default_factory=list)

    def record(self, event: SandboxCommandAudit) -> None:
        if event.phase == AUDIT_PHASE_COMPLETED and event.command_id:
            for index, existing in enumerate(self.events):
                if existing.command_id == event.command_id:
                    self.events[index] = event
                    return
        self.events.append(event)

    def to_dicts(self) -> list[dict[str, object]]:
        return [event.to_dict() for event in self.events]


@dataclass
class ChainedAuditSink:
    """Fan-out audit events to multiple sinks."""

    sinks: tuple[SandboxAuditSink, ...]

    def __init__(self, *sinks: SandboxAuditSink) -> None:
        self.sinks = sinks

    def record(self, event: SandboxCommandAudit) -> None:
        for sink in self.sinks:
            sink.record(event)


def audit_payload_from_sink(audit: SandboxAuditSink) -> tuple[dict[str, object], ...]:
    if isinstance(audit, CollectedAuditSink):
        return tuple(audit.to_dicts())
    if isinstance(audit, ChainedAuditSink):
        for sink in audit.sinks:
            payload = audit_payload_from_sink(sink)
            if payload:
                return payload
    return ()


def audit_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
