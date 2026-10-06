"""Batch investigation grouping — each CWE remains an independent investigation."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from shift_left.models.schema import utc_now

BatchSource = Literal["profiled", "top25", "custom"]
ProfileEvidenceTier = Literal["direct", "indirect", "language-only", "none"]


class BatchState(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class InvestigationBatchRecord(BaseModel):
    batch_id: str
    source: BatchSource
    repo: str
    requested_ref: str
    resolved_commit_sha: str
    actor: str
    created_at: datetime = Field(default_factory=utc_now)
    state: BatchState = BatchState.ACTIVE
    profile_snapshot: dict[str, Any] = Field(default_factory=dict)
    top25_survivor_count: int | None = Field(
        default=None,
        description="Base/Variant Top 25 CWEs matching repo languages (top25 source only).",
    )
    investigation_ids: list[str] = Field(default_factory=list)


class BatchChildRecord(BaseModel):
    batch_id: str
    investigation_id: str
    task_cwe: str
    sort_order: int = Field(ge=0)
    profile_evidence_tier: ProfileEvidenceTier = "none"
    tractability: str = "unrated"
    candidate_count: int | None = None
