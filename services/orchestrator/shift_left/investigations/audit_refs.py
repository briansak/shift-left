"""Presentation helpers for investigation references in audit events."""

from __future__ import annotations

from typing import Any

from shift_left.investigations.store import InvestigationStore
from shift_left.models.schema import AuditEvent

_INVESTIGATION_AUDIT_ACTIONS = frozenset(
    {
        "investigation.launched",
        "investigation.state_transition",
        "antares.sandbox.command",
    }
)


def _investigation_id_from_details(details: dict[str, Any]) -> str | None:
    raw = details.get("investigation_id")
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def annotate_investigation_audit_reference(
    event: AuditEvent | dict[str, Any],
    investigation_store: InvestigationStore | None,
) -> AuditEvent | dict[str, Any]:
    """Label investigation_id references as active or purged for audit readers."""
    if investigation_store is None:
        return event

    if isinstance(event, AuditEvent):
        details = dict(event.details)
        action = event.action
        merged = event.model_copy(update={"details": details})
    else:
        details = dict(event.get("details") or {})
        action = str(event.get("action") or "")
        merged = dict(event)
        merged["details"] = details

    if action not in _INVESTIGATION_AUDIT_ACTIONS:
        return merged

    investigation_id = _investigation_id_from_details(details)
    if not investigation_id:
        return merged

    if investigation_store.exists(investigation_id):
        details["investigation_reference_status"] = "active"
    else:
        details["investigation_reference_status"] = "purged"

    if isinstance(merged, AuditEvent):
        return merged.model_copy(update={"details": details})
    merged["details"] = details
    return merged
