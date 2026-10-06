"""Shared handler rule match types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

EvaluationStatus = Literal["matched", "unevaluated"]


@dataclass(frozen=True)
class HandlerCweMatch:
    cwe: str
    pattern_id: str
    line_start: int | None = None
    line_end: int | None = None
    evaluation_status: EvaluationStatus | None = "matched"
    title: str | None = None
    description: str | None = None
