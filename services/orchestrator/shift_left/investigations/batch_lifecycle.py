"""Batch investigation cancel — queued children and the running child."""

from __future__ import annotations

from shift_left.investigations.batch_schema import BatchState
from shift_left.investigations.cancel_registry import InvestigationCancelRegistry
from shift_left.investigations.lifecycle import LifecycleRejectedError, cancel_investigation
from shift_left.investigations.schema import InvestigationState
from shift_left.investigations.store import InvestigationStore
from shift_left.triage.service import AntaresTriageService


class BatchLifecycleRejectedError(ValueError):
    pass


async def cancel_investigation_batch(
    *,
    store: InvestigationStore,
    triage: AntaresTriageService,
    cancel_registry: InvestigationCancelRegistry,
    batch_id: str,
    actor: str,
) -> None:
    batch = store.get_batch(batch_id)
    if batch is None:
        raise LookupError(f"Batch not found: {batch_id}")
    if batch.state == BatchState.CANCELLED:
        raise BatchLifecycleRejectedError("Batch is already cancelled")
    if batch.state == BatchState.COMPLETED:
        raise BatchLifecycleRejectedError("Batch is already completed")

    for investigation_id in batch.investigation_ids:
        record = store.get(investigation_id)
        if record is None:
            continue
        if record.state not in {InvestigationState.QUEUED, InvestigationState.RUNNING}:
            continue
        try:
            await cancel_investigation(
                store=store,
                triage=triage,
                cancel_registry=cancel_registry,
                investigation_id=investigation_id,
                actor=actor,
            )
        except LifecycleRejectedError:
            continue

    store.mark_batch_cancelled(batch_id)
