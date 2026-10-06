"""Cross-store consistency between investigation trace turns and sandbox audit."""

from __future__ import annotations

from shift_left.investigations.store import InvestigationStore
from shift_left.models.database import AuditStore

SANDBOX_AUDIT_ACTION = "antares.sandbox.command"

# Each sandbox command writes:
#   1. investigation_trace_turns row at dispatch, updated on completion
#   2. antares.sandbox.command audit events (dispatch, then completion)
# These are separate commits with no shared two-phase contract, so either side can
# diverge: trace without audit (audit callback failed after trace commit), audit
# without trace (callback succeeded before trace persist failed), or partial skew
# mid-run. Dispatch without completion is the expected crash/hang residue.


def _sandbox_audit_events_for_investigation(
    audit: AuditStore,
    investigation_id: str,
) -> list[dict[str, object]]:
    events = audit.list_events(action=SANDBOX_AUDIT_ACTION, limit=10_000)
    return [
        dict(event.details)
        for event in events
        if str(event.details.get("investigation_id") or "") == investigation_id
    ]


def _unique_command_attempts(events: list[dict[str, object]]) -> list[dict[str, object]]:
    """One row per command: prefer completion, else the lone dispatch."""
    by_id: dict[str, dict[str, object]] = {}
    legacy: list[dict[str, object]] = []
    # list_events is newest-first; walk oldest-first so completion overwrites dispatch.
    for details in reversed(events):
        command_id = details.get("command_id")
        if command_id:
            existing = by_id.get(str(command_id))
            if existing is None or str(details.get("phase") or "") == "completed":
                by_id[str(command_id)] = details
            continue
        legacy.append(details)
    return legacy + list(by_id.values())


def count_sandbox_audit_attempts(audit: AuditStore, investigation_id: str) -> int:
    return len(_unique_command_attempts(_sandbox_audit_events_for_investigation(audit, investigation_id)))


def count_sandbox_audit_charged_attempts(audit: AuditStore, investigation_id: str) -> int:
    return sum(
        1
        for details in _unique_command_attempts(
            _sandbox_audit_events_for_investigation(audit, investigation_id)
        )
        if bool(details.get("charged", True))
    )


def reconcile_trace_audit(
    store: InvestigationStore,
    audit: AuditStore,
    investigation_id: str,
) -> "AuditTraceReconciliation":
    from shift_left.investigations.schema import AuditTraceReconciliation

    trace_attempt_count = store.count_trace_turns(investigation_id)
    sandbox_audit_attempt_count = count_sandbox_audit_attempts(audit, investigation_id)
    trace_charged_count = store.count_trace_charged_turns(investigation_id)
    sandbox_audit_charged_count = count_sandbox_audit_charged_attempts(audit, investigation_id)
    counts_match = trace_attempt_count == sandbox_audit_attempt_count
    divergence_note: str | None = None
    if not counts_match:
        if trace_attempt_count > sandbox_audit_attempt_count:
            divergence_note = (
                f"{trace_attempt_count - sandbox_audit_attempt_count} trace attempt(s) lack a matching "
                f"{SANDBOX_AUDIT_ACTION} audit event (audit callback may have failed)"
            )
        else:
            divergence_note = (
                f"{sandbox_audit_attempt_count - trace_attempt_count} sandbox audit event(s) lack a matching "
                "trace attempt (trace persist may have failed or ordering skew mid-run)"
            )
    return AuditTraceReconciliation(
        trace_attempt_count=trace_attempt_count,
        sandbox_audit_attempt_count=sandbox_audit_attempt_count,
        trace_charged_count=trace_charged_count,
        sandbox_audit_charged_count=sandbox_audit_charged_count,
        counts_match=counts_match,
        divergence_note=divergence_note,
    )
