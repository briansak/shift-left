"""Shared types for deterministic config handler rules."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

EvaluationStatus = Literal["matched", "unevaluated"]


@dataclass(frozen=True)
class ConfigRuleMatch:
    cwe: str
    pattern_id: str
    line_start: int | None = None
    line_end: int | None = None
    evaluation_status: EvaluationStatus | None = "matched"
    title: str | None = None
    description: str | None = None
    construct_key: str = ""

    def with_line_offset(self, line_offset: int) -> ConfigRuleMatch:
        if line_offset == 0:
            return self
        return replace(
            self,
            line_start=(self.line_start or 1) + line_offset,
            line_end=(self.line_end or 1) + line_offset,
        )
