"""Materialize PR snapshot files and run CWE queries."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

from antares_server.adapters import ModelAdapter, default_adapter
from antares_server.agent_loop import (
    OUTCOME_COMPLETED,
    OUTCOME_FAILED,
    QUERY_FAILED,
    AgentQueryResult,
    build_generator,
    engine_mode_from_env,
    run_agent_query,
)
from antares_server.sandbox_audit import ChainedAuditSink, CollectedAuditSink, SandboxAuditSink
from antares_server.snapshot_materialize import (
    materialize_snapshot,
    materialize_tree_snapshot,
    remove_snapshot,
)

__all__ = [
    "AgentQueryEngine",
    "materialize_snapshot",
    "materialize_tree_snapshot",
]

logger = logging.getLogger(__name__)

DEFAULT_TRIAGE_SNAPSHOT_MAX_BYTES = int(
    os.environ.get("ANTARES_SNAPSHOT_MAX_BYTES", str(50_000_000))
)


def _query_audit_sink(
    stream_sink: SandboxAuditSink | None,
) -> SandboxAuditSink:
    collected = CollectedAuditSink()
    if stream_sink is None:
        return collected
    return ChainedAuditSink(stream_sink, collected)


def _localization_payload(result: AgentQueryResult) -> dict[str, Any]:
    return {
        "task_cwe": result.task_cwe,
        "outcome": result.outcome,
        "ranked_files": result.ranked_files,
        "exploration_trace": result.exploration_trace,
        "terminal_calls_used": result.terminal_calls_used,
        "total_terminal_attempts": result.total_terminal_attempts,
        "duplicate_commands_suppressed": result.duplicate_commands_suppressed,
        "degenerate_repetition_rejections": result.degenerate_repetition_rejections,
        "duplicate_loop_hard_stop_fired": result.duplicate_loop_hard_stop_fired,
        "forced_submission": result.forced_submission,
        "search_hit_files": list(result.search_hit_files),
        "budget_escalation_fired": result.budget_escalation_fired,
        "attempt_cap_reached": result.attempt_cap_reached,
        "inspected_files": list(result.inspected_files),
        "failure_class": result.failure_class,
        "failure_message": result.failure_message,
        "investigation_id": result.investigation_id,
        "sandbox_audit": list(result.sandbox_audit),
        "terminal_budget": result.terminal_budget,
        "loop_control_enabled": result.loop_control_enabled,
        "adapter_identity": dict(result.adapter_identity),
        "generation_params": dict(result.generation_params),
    }


class AgentQueryEngine:
    """Run official Antares agent queries against materialized snapshots."""

    def __init__(
        self,
        inference_engine: Any,
        *,
        adapter: ModelAdapter | None = None,
    ) -> None:
        self._engine = inference_engine
        self._engine_mode = engine_mode_from_env()
        self._adapter = adapter or default_adapter()

    def runtime_metadata(self, loop_control_enabled: bool | None = None) -> dict[str, Any]:
        return {
            "terminal_budget": self._adapter.terminal_budget,
            "loop_control_enabled": _reported_loop_control_state(
                [], loop_control_enabled
            ),
            "adapter_identity": self._adapter.identity.to_dict(),
            "generation_params": self._adapter.generation_params(),
        }

    def query(
        self,
        *,
        snapshot_files: list[dict[str, str]],
        changed_paths: list[str],
        queries: list[dict[str, str]],
        max_terminal_calls: int | None = None,
        temperature: float | None = None,
        top_p: float | None = None,
        loop_control_enabled: bool | None = None,
        max_snapshot_bytes: int = 2_000_000,
        audit_sink: SandboxAuditSink | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        snapshot_root: Path | None = None
        localizations: list[dict[str, Any]] = []
        any_failed = False

        try:
            snapshot_root = materialize_snapshot(snapshot_files, max_bytes=max_snapshot_bytes)
            if self._engine_mode == "llm":
                self._engine.load()

            for query in queries:
                task_cwe = str(query.get("task_cwe", "")).strip()
                if not task_cwe:
                    any_failed = True
                    localizations.append(
                        {
                            "task_cwe": task_cwe or "unknown",
                            "outcome": QUERY_FAILED,
                            "ranked_files": [],
                            "exploration_trace": "",
                            "terminal_calls_used": 0,
                            "terminal_budget": (
                                self._adapter.terminal_budget
                                if max_terminal_calls is None
                                else max_terminal_calls
                            ),
                            "loop_control_enabled": _reported_loop_control_state(
                                [], loop_control_enabled
                            ),
                            "adapter_identity": self._adapter.identity.to_dict(),
                            "generation_params": self._adapter.generation_params(),
                            "failure_class": "config_error",
                            "failure_message": "Missing task_cwe",
                        }
                    )
                    continue

                generator = build_generator(
                    engine=self._engine,
                    sandbox_root=snapshot_root,
                    task_cwe=task_cwe,
                    engine_mode=self._engine_mode,
                    generation_params=self._adapter.generation_params(),
                )
                result: AgentQueryResult = run_agent_query(
                    sandbox_root=snapshot_root,
                    task_cwe=task_cwe,
                    task_cwe_description=str(query.get("task_cwe_description") or ""),
                    changed_paths=changed_paths,
                    generator=generator,
                    max_terminal_calls=max_terminal_calls,
                    temperature=temperature,
                    top_p=top_p,
                    audit_sink=_query_audit_sink(audit_sink),
                    adapter=self._adapter,
                    loop_control_enabled=loop_control_enabled,
                )
                if result.outcome == QUERY_FAILED:
                    any_failed = True
                localizations.append(_localization_payload(result))
        except Exception as exc:  # noqa: BLE001
            timings = {"total": int((time.monotonic() - started) * 1000)}
            return {
                "outcome": OUTCOME_FAILED,
                "localizations": localizations,
                "failure_class": "inference_error",
                "failure_stage": "generation",
                "failure_message": str(exc),
                "timings_ms": timings,
                "terminal_budget": (
                    self._adapter.terminal_budget
                    if max_terminal_calls is None
                    else max_terminal_calls
                ),
                "loop_control_enabled": _reported_loop_control_state(
                    localizations, loop_control_enabled
                ),
                "adapter_identity": self._adapter.identity.to_dict(),
                "generation_params": self._adapter.generation_params(),
            }
        finally:
            if snapshot_root:
                remove_snapshot(snapshot_root)
            if self._engine_mode == "llm" and getattr(self._engine, "_load_strategy", "") == "on_demand":
                try:
                    self._engine.unload()
                except Exception:  # noqa: BLE001
                    pass

        timings = {"total": int((time.monotonic() - started) * 1000)}
        return {
            "outcome": OUTCOME_FAILED if any_failed else OUTCOME_COMPLETED,
            "localizations": localizations,
            "failure_class": "parse_error" if any_failed else None,
            "failure_stage": "generation" if any_failed else None,
            "failure_message": "One or more agent queries failed" if any_failed else None,
            "timings_ms": timings,
            "terminal_budget": (
                self._adapter.terminal_budget
                if max_terminal_calls is None
                else max_terminal_calls
            ),
            "loop_control_enabled": _reported_loop_control_state(
                localizations, loop_control_enabled
            ),
            "adapter_identity": self._adapter.identity.to_dict(),
            "generation_params": self._adapter.generation_params(),
        }

    def run_triage(
        self,
        *,
        repo_root: str,
        queries: list[dict[str, str]],
        max_terminal_calls: int | None = None,
        temperature: float | None = None,
        top_p: float | None = None,
        loop_control_enabled: bool | None = None,
        max_snapshot_bytes: int = DEFAULT_TRIAGE_SNAPSHOT_MAX_BYTES,
        exclude_test_paths: bool = True,
        changed_paths: list[str] | None = None,
        audit_sink: SandboxAuditSink | None = None,
        investigation_id: str | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        root = Path(repo_root).resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"Repo checkout not found: {root}")

        localizations: list[dict[str, Any]] = []
        any_failed = False
        recycle_status: dict[str, Any] = {"runs_since_recycle": 0, "recycled": False}
        snapshot_root: Path | None = None

        try:
            snapshot_root = materialize_tree_snapshot(
                root,
                max_bytes=max_snapshot_bytes,
                exclude_test_paths=exclude_test_paths,
            )
            if self._engine_mode == "llm":
                self._engine.load()

            for query in queries:
                task_cwe = str(query.get("task_cwe", "")).strip()
                generator = build_generator(
                    engine=self._engine,
                    sandbox_root=snapshot_root,
                    task_cwe=task_cwe,
                    engine_mode=self._engine_mode,
                    generation_params=self._adapter.generation_params(),
                )
                result = run_agent_query(
                    sandbox_root=snapshot_root,
                    task_cwe=task_cwe,
                    task_cwe_description=str(query.get("task_cwe_description") or ""),
                    changed_paths=list(changed_paths or []),
                    generator=generator,
                    max_terminal_calls=max_terminal_calls,
                    temperature=temperature,
                    top_p=top_p,
                    audit_sink=_query_audit_sink(audit_sink),
                    investigation_id=investigation_id,
                    adapter=self._adapter,
                    loop_control_enabled=loop_control_enabled,
                )
                if result.outcome == QUERY_FAILED:
                    any_failed = True
                localizations.append(_localization_payload(result))
        finally:
            if snapshot_root:
                remove_snapshot(snapshot_root)
            if self._engine_mode == "llm":
                recycle_status = self._engine.unload_after_run()

        timings = {"total": int((time.monotonic() - started) * 1000)}
        return {
            "outcome": OUTCOME_FAILED if any_failed else OUTCOME_COMPLETED,
            "localizations": localizations,
            "failure_class": "parse_error" if any_failed else None,
            "failure_stage": "generation" if any_failed else None,
            "failure_message": "One or more agent queries failed" if any_failed else None,
            "timings_ms": timings,
            "recycle_status": recycle_status,
            "terminal_budget": (
                self._adapter.terminal_budget
                if max_terminal_calls is None
                else max_terminal_calls
            ),
            "loop_control_enabled": (
                _reported_loop_control_state(localizations, loop_control_enabled)
            ),
            "adapter_identity": self._adapter.identity.to_dict(),
            "generation_params": self._adapter.generation_params(),
        }


def _reported_loop_control_state(
    localizations: list[dict[str, Any]],
    requested: bool | None,
) -> bool:
    if localizations:
        return bool(localizations[0]["loop_control_enabled"])
    if requested is not None:
        return requested
    return os.environ.get("ANTARES_LOOP_CONTROL", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }
