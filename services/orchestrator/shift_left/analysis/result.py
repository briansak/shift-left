"""Structured analysis outcomes — fail-closed semantics for model stages."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from shift_left.models.schema import Finding, TargetKind


class AnalysisOutcome(str, Enum):
    COMPLETED_NO_FINDINGS = "completed_no_findings"
    COMPLETED_WITH_FINDINGS = "completed_with_findings"
    FAILED = "failed"


class AnalysisFailureClass(str, Enum):
    TIMEOUT = "timeout"
    HTTP_ERROR = "http_error"
    INFERENCE_ERROR = "inference_error"
    PARSE_ERROR = "parse_error"
    CONFIG_ERROR = "config_error"
    CHUNK_ERROR = "chunk_error"
    HANDLER_ERROR = "handler_error"


class AnalysisStage(str, Enum):
    CONNECT = "connect"
    LOAD = "load"
    PROMPT = "prompt"
    GENERATION = "generation"
    UNLOAD = "unload"
    CHUNK = "chunk"
    HANDLER_MATCH = "handler_match"


class TargetAnalysisResult(BaseModel):
    """Per-target-kind analysis result — never conflate FAILED with zero findings."""

    target_kind: TargetKind
    outcome: AnalysisOutcome
    findings: list[Finding] = Field(default_factory=list)
    failure_class: AnalysisFailureClass | None = None
    failure_stage: AnalysisStage | None = None
    failure_message: str | None = None
    timings_ms: dict[str, int] = Field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.outcome != AnalysisOutcome.FAILED

    @property
    def incomplete(self) -> bool:
        return self.outcome == AnalysisOutcome.FAILED


def completed_no_findings(
    target_kind: TargetKind,
    *,
    timings_ms: dict[str, int] | None = None,
) -> TargetAnalysisResult:
    return TargetAnalysisResult(
        target_kind=target_kind,
        outcome=AnalysisOutcome.COMPLETED_NO_FINDINGS,
        timings_ms=timings_ms or {},
    )


def completed_with_findings(
    target_kind: TargetKind,
    findings: list[Finding],
    *,
    timings_ms: dict[str, int] | None = None,
) -> TargetAnalysisResult:
    return TargetAnalysisResult(
        target_kind=target_kind,
        outcome=AnalysisOutcome.COMPLETED_WITH_FINDINGS,
        findings=findings,
        timings_ms=timings_ms or {},
    )


def failed_analysis(
    target_kind: TargetKind,
    *,
    failure_class: AnalysisFailureClass,
    failure_stage: AnalysisStage,
    failure_message: str,
    timings_ms: dict[str, int] | None = None,
) -> TargetAnalysisResult:
    return TargetAnalysisResult(
        target_kind=target_kind,
        outcome=AnalysisOutcome.FAILED,
        failure_class=failure_class,
        failure_stage=failure_stage,
        failure_message=failure_message,
        timings_ms=timings_ms or {},
    )


def parse_server_analysis_response(
    data: dict[str, Any],
    *,
    target_kind: TargetKind,
    normalize_finding: Any,
    repo: str,
    pr_ref: str,
    commit_sha: str,
) -> TargetAnalysisResult:
    """Parse structured analyze response from a model server."""
    outcome_raw = str(data.get("outcome", "")).lower()
    timings = {str(k): int(v) for k, v in (data.get("timings_ms") or {}).items()}

    if outcome_raw == AnalysisOutcome.FAILED.value:
        fc_raw = data.get("failure_class")
        fs_raw = data.get("failure_stage")
        try:
            failure_class = AnalysisFailureClass(str(fc_raw))
        except ValueError:
            failure_class = AnalysisFailureClass.INFERENCE_ERROR
        try:
            failure_stage = AnalysisStage(str(fs_raw))
        except ValueError:
            failure_stage = AnalysisStage.GENERATION
        return failed_analysis(
            target_kind,
            failure_class=failure_class,
            failure_stage=failure_stage,
            failure_message=str(data.get("failure_message") or "Analysis failed"),
            timings_ms=timings,
        )

    raw_findings = data.get("findings") or []
    findings = [
        normalize_finding(item, repo, pr_ref, commit_sha)
        for item in raw_findings
        if isinstance(item, dict)
    ]

    if outcome_raw == AnalysisOutcome.COMPLETED_WITH_FINDINGS.value or findings:
        return completed_with_findings(target_kind, findings, timings_ms=timings)
    return completed_no_findings(target_kind, timings_ms=timings)
