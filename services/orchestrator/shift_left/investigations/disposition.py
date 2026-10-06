"""Candidate disposition updates — results immutable, disposition fields only."""

from __future__ import annotations

from shift_left.investigations.schema import CandidateDisposition, CandidateRecord
from shift_left.investigations.store import InvestigationStore


class DispositionUpdateError(ValueError):
    pass


def parse_disposition(value: str) -> CandidateDisposition:
    text = (value or "").strip().lower()
    try:
        return CandidateDisposition(text)
    except ValueError:
        raise DispositionUpdateError(
            f"Invalid disposition {value!r}; expected open, reviewed, or not_actionable"
        ) from None


def update_candidate_disposition(
    store: InvestigationStore,
    *,
    investigation_id: str,
    submission_rank: int,
    disposition: CandidateDisposition,
    actor: str,
    note: str | None = None,
) -> CandidateRecord:
    if not store.exists(investigation_id):
        raise LookupError(f"Investigation not found: {investigation_id}")
    return store.update_candidate_disposition(
        investigation_id,
        submission_rank,
        disposition=disposition,
        actor=actor,
        note=note.strip() if note else None,
    )
