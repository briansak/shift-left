"""Cancel and re-run operations for investigations.

Cancel is **cooperative** in the agent loop: the cancellation flag is checked only
at turn boundaries (before model generation and before the next sandbox command).
The orchestrator marks the investigation ``cancelled`` immediately, and
``antares-server`` is asked to tear down the sandbox container without waiting for
the current turn to finish.

Container teardown uses ``docker rm -f`` on the investigation id (container name)
as soon as the cancel request reaches antares-server. Worst-case delay before the
loop observes cancellation is therefore bounded by an in-flight ``docker exec``
(host-side timeout default 10s) or an in-flight model generation call — not by
container lifetime after cancel. A hung ``docker exec`` cannot outlive cancel
because the container is removed while the exec is running.
"""

from __future__ import annotations

from shift_left.config import AppConfig
from shift_left.investigations.cancel_registry import InvestigationCancelRegistry
from shift_left.investigations.launch import LaunchRequest, launch_investigation
from shift_left.investigations.schema import InvestigationRecord, InvestigationState
from shift_left.investigations.store import InvestigationStore
from shift_left.investigations.trace_markers import (
    CANCELLATION_MARKER_COMMAND,
    CANCELLATION_MARKER_EXIT_STATUS,
    CANCELLATION_MARKER_OUTPUT,
)
from shift_left.triage.service import AntaresTriageService


class LifecycleRejectedError(ValueError):
    pass


async def cancel_investigation(
    *,
    store: InvestigationStore,
    triage: AntaresTriageService,
    cancel_registry: InvestigationCancelRegistry,
    investigation_id: str,
    actor: str,
) -> InvestigationRecord:
    record = store.get(investigation_id)
    if record is None:
        raise LookupError(f"Investigation not found: {investigation_id}")
    if record.state not in {InvestigationState.QUEUED, InvestigationState.RUNNING}:
        raise LifecycleRejectedError(
            f"Cannot cancel investigation in state {record.state.value}"
        )

    if record.state == InvestigationState.RUNNING:
        cancel_registry.request_cancel(investigation_id)
        try:
            await triage._client.cancel_investigation(investigation_id)
        except Exception:
            pass
        turn_index = store.count_trace_turns(investigation_id)
        store.append_trace_turn(
            investigation_id,
            turn_index=turn_index,
            command=CANCELLATION_MARKER_COMMAND,
            exit_status=CANCELLATION_MARKER_EXIT_STATUS,
            output_truncated=CANCELLATION_MARKER_OUTPUT,
        )

    return store.transition_state(
        investigation_id,
        InvestigationState.CANCELLED,
        actor=actor,
        reason="cancelled by operator",
    )


async def rerun_investigation(
    *,
    config: AppConfig,
    store: InvestigationStore,
    triage: AntaresTriageService,
    investigation_id: str,
    actor: str,
) -> InvestigationRecord:
    original = store.get(investigation_id)
    if original is None:
        raise LookupError(f"Investigation not found: {investigation_id}")

    launched = await launch_investigation(
        config=config,
        store=store,
        triage=triage,
        actor=actor,
        request=LaunchRequest(
            repo=original.repo,
            ref=original.requested_ref,
            task_cwe=original.task_cwe,
            task_cwe_description=original.task_cwe_description,
            advisory_cve=original.advisory_cve,
            exclude_test_paths=original.exclude_test_paths,
            snapshot_scope=original.snapshot_scope,
            snapshot_base_ref=original.snapshot_base_ref or "main",
        ),
        require_server_available=True,
        originating_investigation_id=original.investigation_id,
    )
    return launched.record
