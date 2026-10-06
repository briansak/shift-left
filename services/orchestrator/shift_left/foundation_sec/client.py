"""Foundation-Sec inference client — local service only (Phase 2: llama.cpp GGUF)."""

from __future__ import annotations

import time
from typing import Any

import httpx

from shift_left.analysis.result import (
    AnalysisFailureClass,
    AnalysisStage,
    TargetAnalysisResult,
    completed_no_findings,
    failed_analysis,
    parse_server_analysis_response,
)
from shift_left.config import ModelStageTimeouts
from shift_left.diff.extractor import ChangedFile
from shift_left.http.local_client import LocalOnlyAsyncClient, raise_local_inference_error
from shift_left.models.schema import (
    Finding,
    FindingSource,
    LineRange,
    PolicySeverity,
    Severity,
    TargetKind,
)
from shift_left.ui.cwe_dictionary import apply_model_asserted_cwe_fields


class FoundationSecClient:
    def __init__(
        self,
        service_url: str,
        *,
        timeout: float = 600.0,
        max_context_tokens: int = 8192,
        chunk_overlap_lines: int = 2,
        context_lines_before: int = 5,
        context_lines_after: int = 5,
        stage_timeouts: ModelStageTimeouts | None = None,
    ) -> None:
        self._service_url = service_url.rstrip("/")
        self._timeout = timeout
        self._max_context_tokens = max_context_tokens
        self._chunk_overlap_lines = chunk_overlap_lines
        self._context_before = context_lines_before
        self._context_after = context_lines_after
        self._stage_timeouts = stage_timeouts
        self._http = LocalOnlyAsyncClient(
            timeout=timeout,
            stage_timeouts=stage_timeouts,
        )

    async def health(self) -> dict[str, Any]:
        try:
            response = await self._http.get(f"{self._service_url}/health")
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # noqa: BLE001
            raise_local_inference_error("Foundation-Sec", exc)
            raise

    async def analyze_hunks(
        self,
        *,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        files: list[ChangedFile],
    ) -> TargetAnalysisResult:
        if not files:
            return completed_no_findings(TargetKind.CONFIG)

        payload = {
            "repo": repo,
            "pr_ref": pr_ref,
            "commit_sha": commit_sha,
            "max_context_tokens": self._max_context_tokens,
            "chunk_overlap_lines": self._chunk_overlap_lines,
            "files": [
                {
                    "path": changed.path,
                    "hunks": [
                        {
                            "new_start": hunk.new_start,
                            "new_end": hunk.new_end,
                            "content": hunk.content,
                            "context_lines_before": self._context_before,
                            "context_lines_after": self._context_after,
                        }
                        for hunk in changed.hunks
                    ],
                }
                for changed in files
                if changed.hunks
            ],
        }

        started = time.monotonic()
        try:
            response = await self._http.post(
                f"{self._service_url}/v1/analyze",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        except httpx.TimeoutException as exc:
            return failed_analysis(
                TargetKind.CONFIG,
                failure_class=AnalysisFailureClass.TIMEOUT,
                failure_stage=AnalysisStage.GENERATION,
                failure_message=str(exc),
                timings_ms={"total": int((time.monotonic() - started) * 1000)},
            )
        except httpx.HTTPStatusError as exc:
            return failed_analysis(
                TargetKind.CONFIG,
                failure_class=AnalysisFailureClass.HTTP_ERROR,
                failure_stage=AnalysisStage.GENERATION,
                failure_message=str(exc),
                timings_ms={"total": int((time.monotonic() - started) * 1000)},
            )
        except Exception as exc:  # noqa: BLE001
            return failed_analysis(
                TargetKind.CONFIG,
                failure_class=AnalysisFailureClass.INFERENCE_ERROR,
                failure_stage=AnalysisStage.CONNECT,
                failure_message=str(exc),
                timings_ms={"total": int((time.monotonic() - started) * 1000)},
            )

        result = parse_server_analysis_response(
            data,
            target_kind=TargetKind.CONFIG,
            normalize_finding=self._normalize,
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
        )
        if not result.timings_ms:
            result = result.model_copy(
                update={"timings_ms": {"total": int((time.monotonic() - started) * 1000)}}
            )
        return result

    async def unload(self) -> None:
        try:
            await self._http.post(f"{self._service_url}/v1/unload")
        except Exception:
            return

    @staticmethod
    def _normalize(
        raw: dict[str, Any],
        repo: str,
        pr_ref: str,
        commit_sha: str,
    ) -> Finding:
        line_range = None
        if raw.get("line_start") is not None:
            line_range = LineRange(
                start=int(raw["line_start"]),
                end=int(raw.get("line_end") or raw["line_start"]),
            )

        severity_raw = str(raw.get("severity", "medium")).lower()
        try:
            severity = Severity(severity_raw)
        except ValueError:
            severity = Severity.MEDIUM

        model_cwe, model_cwe_recognized = apply_model_asserted_cwe_fields(
            model_asserted_cwe=raw.get("model_asserted_cwe"),
            legacy_cwe=raw.get("cwe"),
        )

        return Finding(
            source=FindingSource.FOUNDATION_SEC,
            target_kind=TargetKind.CONFIG,
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            file_path=raw.get("file_path", "unknown"),
            line_range=line_range,
            model_asserted_cwe=model_cwe,
            model_cwe_recognized=model_cwe_recognized,
            handler_asserted_cwe=None,
            cve_refs=list(raw.get("cve_refs") or []),
            model_asserted_severity=severity,
            confidence=float(raw.get("confidence", 0.5)),
            title=raw.get("title") or "Likely config issue (review required)",
            description=raw.get("description")
            or "Model identified a potential issue in the changed configuration.",
            evidence=raw.get("evidence"),
            trace=raw.get("trace"),
            policy_severity=PolicySeverity.UNCLASSIFIED,
        )
