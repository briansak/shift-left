"""Antares inference client — advisory triage only (not PR merge gate)."""

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
from shift_left.antares.localization import triage_payload_from_response
from shift_left.config import ModelStageTimeouts
from shift_left.diff.extractor import ChangedFile
from shift_left.http.local_client import LocalOnlyAsyncClient, raise_local_inference_error
from shift_left.models.schema import (
    Finding,
    FindingSource,
    LineRange,
    Severity,
    TargetKind,
)
from shift_left.ui.cwe_dictionary import apply_model_asserted_cwe_fields

PUBLISHED_FILE_F1: dict[str, float] = {
    "fdtn-ai/antares-350m": 0.135,
    "fdtn-ai/antares-1b": 0.209,
    "fdtn-ai/antares-3b": 0.223,
}


class AntaresClient:
    def __init__(
        self,
        service_url: str,
        *,
        timeout: float = 600.0,
        stage_timeouts: ModelStageTimeouts | None = None,
    ) -> None:
        self._service_url = service_url.rstrip("/")
        self._timeout = timeout
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
            raise_local_inference_error("Antares", exc)
            raise

    async def run_triage_query(
        self,
        *,
        repo: str,
        ref: str,
        repo_root: str,
        task_cwe: str,
        task_cwe_description: str = "",
        max_terminal_calls: int | None = None,
        temperature: float | None = None,
        top_p: float | None = None,
        loop_control_enabled: bool | None = None,
        model_variant: str = "fdtn-ai/antares-1b",
        audit_callback_url: str | None = None,
        audit_callback_token: str | None = None,
        audit_actor: str | None = None,
        audit_subject: str | None = None,
        investigation_id: str | None = None,
        exclude_test_paths: bool = True,
        changed_paths: list[str] | None = None,
    ) -> tuple[TargetAnalysisResult, Any]:
        payload = {
            "repo": repo,
            "ref": ref,
            "repo_root": repo_root,
            "queries": [{"task_cwe": task_cwe, "task_cwe_description": task_cwe_description}],
            "max_terminal_calls": max_terminal_calls,
            "temperature": temperature,
            "top_p": top_p,
            "loop_control_enabled": loop_control_enabled,
            "model_variant": model_variant,
            "exclude_test_paths": exclude_test_paths,
        }
        if changed_paths:
            payload["changed_paths"] = list(changed_paths)
        if audit_callback_url:
            payload["audit_callback_url"] = audit_callback_url
            payload["audit_actor"] = audit_actor or "antares"
            payload["audit_subject"] = audit_subject or f"{repo}@{ref}"
            if audit_callback_token:
                payload["audit_callback_token"] = audit_callback_token
        if investigation_id:
            payload["investigation_id"] = investigation_id
        started = time.monotonic()
        try:
            response = await self._http.post(f"{self._service_url}/v1/triage/run", json=payload)
            response.raise_for_status()
            data = response.json()
        except httpx.TimeoutException as exc:
            return (
                failed_analysis(
                    TargetKind.CODE,
                    failure_class=AnalysisFailureClass.TIMEOUT,
                    failure_stage=AnalysisStage.GENERATION,
                    failure_message=str(exc),
                    timings_ms={"total": int((time.monotonic() - started) * 1000)},
                ),
                triage_payload_from_response({"outcome": "failed", "failure_message": str(exc)}),
            )
        except httpx.HTTPStatusError as exc:
            return (
                failed_analysis(
                    TargetKind.CODE,
                    failure_class=AnalysisFailureClass.HTTP_ERROR,
                    failure_stage=AnalysisStage.GENERATION,
                    failure_message=str(exc),
                    timings_ms={"total": int((time.monotonic() - started) * 1000)},
                ),
                triage_payload_from_response({"outcome": "failed", "failure_message": str(exc)}),
            )
        except Exception as exc:  # noqa: BLE001
            return (
                failed_analysis(
                    TargetKind.CODE,
                    failure_class=AnalysisFailureClass.INFERENCE_ERROR,
                    failure_stage=AnalysisStage.CONNECT,
                    failure_message=str(exc),
                    timings_ms={"total": int((time.monotonic() - started) * 1000)},
                ),
                triage_payload_from_response({"outcome": "failed", "failure_message": str(exc)}),
            )

        timings = {str(k): int(v) for k, v in (data.get("timings_ms") or {}).items()}
        if not timings:
            timings = {"total": int((time.monotonic() - started) * 1000)}
        triage_payload = triage_payload_from_response(data)

        if str(data.get("outcome", "")).lower() == "failed":
            return (
                failed_analysis(
                    TargetKind.CODE,
                    failure_class=AnalysisFailureClass.PARSE_ERROR,
                    failure_stage=AnalysisStage.GENERATION,
                    failure_message=str(data.get("failure_message") or "Triage run failed"),
                    timings_ms=timings,
                ),
                triage_payload,
            )

        return completed_no_findings(TargetKind.CODE, timings_ms=timings), triage_payload

    async def analyze_hunks(
        self,
        *,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        files: list[ChangedFile],
    ) -> TargetAnalysisResult:
        if not files:
            return completed_no_findings(TargetKind.CODE)

        payload = {
            "repo": repo,
            "pr_ref": pr_ref,
            "commit_sha": commit_sha,
            "files": [
                {
                    "path": changed.path,
                    "hunks": [
                        {
                            "new_start": hunk.new_start,
                            "new_end": hunk.new_end,
                            "content": hunk.content,
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
                TargetKind.CODE,
                failure_class=AnalysisFailureClass.TIMEOUT,
                failure_stage=AnalysisStage.GENERATION,
                failure_message=str(exc),
                timings_ms={"total": int((time.monotonic() - started) * 1000)},
            )
        except httpx.HTTPStatusError as exc:
            return failed_analysis(
                TargetKind.CODE,
                failure_class=AnalysisFailureClass.HTTP_ERROR,
                failure_stage=AnalysisStage.GENERATION,
                failure_message=str(exc),
                timings_ms={"total": int((time.monotonic() - started) * 1000)},
            )
        except Exception as exc:  # noqa: BLE001
            return failed_analysis(
                TargetKind.CODE,
                failure_class=AnalysisFailureClass.INFERENCE_ERROR,
                failure_stage=AnalysisStage.CONNECT,
                failure_message=str(exc),
                timings_ms={"total": int((time.monotonic() - started) * 1000)},
            )

        result = parse_server_analysis_response(
            data,
            target_kind=TargetKind.CODE,
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

    async def cancel_investigation(self, investigation_id: str) -> None:
        try:
            response = await self._http.post(
                f"{self._service_url}/v1/investigations/{investigation_id}/cancel"
            )
            response.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            raise_local_inference_error("Antares", exc)
            raise

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
            source=FindingSource.ANTARES,
            target_kind=TargetKind.CODE,
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            file_path=raw.get("file_path", "unknown"),
            line_range=line_range,
            model_asserted_cwe=model_cwe,
            model_cwe_recognized=model_cwe_recognized,
            handler_asserted_cwe=raw.get("handler_asserted_cwe"),
            cve_refs=list(raw.get("cve_refs") or []),
            model_asserted_severity=severity,
            confidence=float(raw.get("confidence", 0.5)),
            title=raw.get("title") or "Likely vulnerability (review required)",
            description=raw.get("description")
            or "Model identified a potential issue in the changed code.",
            evidence=raw.get("evidence"),
            trace=raw.get("trace"),
        )
