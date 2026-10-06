"""Persist Antares sandbox command audit through the presentation redaction chokepoint."""

from __future__ import annotations

import os
from typing import Any

from shift_left.config import AppConfig
from shift_left.models.database import AuditStore
from shift_left.ui.config_redaction import redact_display_text


def sandbox_audit_callback_url(config: AppConfig) -> str:
    override = os.environ.get("ANTARES_SANDBOX_AUDIT_CALLBACK_URL", "").strip()
    if override:
        return override.rstrip("/")
    host = config.orchestrator.host.strip() or "127.0.0.1"
    port = config.orchestrator.port
    return f"http://{host}:{port}/api/v1/internal/antares/sandbox-command-audit"


def persist_sandbox_command_audit(
    audit: AuditStore,
    *,
    actor: str,
    subject: str,
    events: list[dict[str, Any]],
    token_id: str | None = None,
) -> None:
    for event in events:
        command = redact_display_text(str(event.get("command") or ""))
        output = redact_display_text(str(event.get("output_truncated") or ""))
        details: dict[str, Any] = {
            "investigation_id": event.get("investigation_id"),
            "command": command,
            "exit_code": event.get("exit_code"),
            "output_truncated": output,
            "truncated": event.get("truncated"),
            "recorded_at": event.get("recorded_at"),
            "charged": bool(event.get("charged", True)),
            "phase": str(event.get("phase") or "completed"),
        }
        command_id = event.get("command_id")
        if command_id:
            details["command_id"] = command_id
        duplicate_of_turn = event.get("duplicate_of_turn")
        if duplicate_of_turn is not None:
            details["duplicate_of_turn"] = duplicate_of_turn
        if token_id:
            details["token_id"] = token_id
        audit.log(
            actor=actor,
            action="antares.sandbox.command",
            subject=subject,
            details=details,
        )
