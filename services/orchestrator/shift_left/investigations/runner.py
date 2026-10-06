"""Single-worker FIFO investigation queue runner."""

from __future__ import annotations

import asyncio
import logging
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any

from shift_left.antares.localization import triage_payload_from_response
from shift_left.antares.sandbox_audit import (
    persist_sandbox_command_audit,
    sandbox_audit_callback_url,
)
from shift_left.config import AppConfig
from shift_left.investigations.cancel_registry import InvestigationCancelRegistry
from shift_left.investigations.git_checkout import (
    estimate_launch_snapshot_bytes,
    materialize_worktree_at_sha,
    remove_worktree,
)
from shift_left.investigations.repo_root_paths import (
    antares_visible_repo_root,
    investigation_worktree_path,
)
from shift_left.investigations.preflight import check_antares_server_available
from shift_left.investigations.schema import InvestigationRecord, InvestigationState
from shift_left.investigations.store import InvestigationStore
from shift_left.models.database import AuditStore
from shift_left.models.schema import utc_now
from shift_left.triage.service import AntaresTriageService

logger = logging.getLogger(__name__)

QUERY_COMPLETED_WITH_FILES = "completed_with_files"
QUERY_COMPLETED_NO_FILES = "completed_no_files"


class InvestigationQueueRunner:
    def __init__(
        self,
        *,
        config: AppConfig,
        store: InvestigationStore,
        triage: AntaresTriageService,
        audit: AuditStore,
        cancel_registry: InvestigationCancelRegistry,
        audit_callback_tokens: Any,
        runner_id: str = "investigation-runner",
        poll_interval_seconds: float = 1.0,
    ) -> None:
        self._config = config
        self._store = store
        self._triage = triage
        self._audit = audit
        self._cancel_registry = cancel_registry
        self._audit_callback_tokens = audit_callback_tokens
        self._runner_id = runner_id
        self._poll_interval_seconds = poll_interval_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._health_gate_reason: str | None = None
        self._current_investigation_id: str | None = None
        self._current_started_at: datetime | None = None

    @property
    def health_gate_reason(self) -> str | None:
        return self._health_gate_reason

    @property
    def current_investigation_id(self) -> str | None:
        return self._current_investigation_id

    @property
    def current_started_at(self) -> datetime | None:
        return self._current_started_at

    def is_alive(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run_forever(), name="investigation-queue-runner")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run_forever(self) -> None:
        while not self._stop.is_set():
            try:
                await self._poll_once()
            except Exception:  # noqa: BLE001
                logger.exception("investigation runner poll failed")
            await asyncio.sleep(self._poll_interval_seconds)

    async def _poll_once(self) -> None:
        await self._apply_queue_wait_timeouts()
        if not await check_antares_server_available(self._triage._client):
            self._health_gate_reason = "Waiting for antares-server — server health check failed"
            await self._mark_queue_waiting()
            return
        self._health_gate_reason = None
        head = self._store.list_queued_fifo()
        if head:
            self._store.clear_queue_waiting(head[0].investigation_id)
        claimed = self._store.claim_next_queued(self._runner_id)
        if claimed is None:
            return
        await asyncio.to_thread(self._execute_investigation, claimed.investigation_id)

    async def _mark_queue_waiting(self) -> None:
        queued = self._store.list_queued_fifo()
        if not queued:
            return
        reason = "Waiting for antares-server — server health check failed"
        self._store.set_queue_waiting(queued[0].investigation_id, reason=reason)

    async def _apply_queue_wait_timeouts(self) -> None:
        timeout = timedelta(minutes=self._config.investigations.queue_wait_timeout_minutes)
        now = utc_now()
        for record in self._store.list_queued_fifo():
            if not record.queue_waiting_reason or record.queued_waiting_since is None:
                continue
            if now - record.queued_waiting_since < timeout:
                continue
            self._store.transition_state(
                record.investigation_id,
                InvestigationState.FAILED,
                actor=self._runner_id,
                reason="antares-server unavailable",
            )

    def _execute_investigation(self, investigation_id: str) -> None:
        record = self._store.get(investigation_id)
        if record is None or record.state != InvestigationState.RUNNING:
            return

        self._current_investigation_id = investigation_id
        self._current_started_at = utc_now()
        self._cancel_registry.register(investigation_id)
        checkout = self._triage.checkout_path(record.repo)
        worktree = investigation_worktree_path(self._config, investigation_id)
        worktree_parent = worktree.parent
        loop = asyncio.new_event_loop()
        try:
            changed_paths: list[str] = []
            archive_paths: list[str] | None = None
            if (record.snapshot_scope or "full") == "pr_changed":
                _, archive_paths = estimate_launch_snapshot_bytes(
                    checkout,
                    record.resolved_commit_sha,
                    snapshot_scope="pr_changed",
                    base_ref=record.snapshot_base_ref or "main",
                )
                changed_paths = list(archive_paths or [])
            snapshot_bytes = materialize_worktree_at_sha(
                checkout,
                record.resolved_commit_sha,
                worktree,
                paths=archive_paths,
            )
            self._store.update_snapshot_bytes(investigation_id, snapshot_bytes)

            if self._is_cancelled(investigation_id):
                return

            analysis_result, localization = loop.run_until_complete(
                self._run_antares(
                    record=record,
                    repo_root=antares_visible_repo_root(worktree),
                    investigation_id=investigation_id,
                    changed_paths=changed_paths,
                )
            )
            if self._is_cancelled(investigation_id):
                return
            self._finalize_from_result(investigation_id, analysis_result, localization)
        except Exception as exc:  # noqa: BLE001
            logger.exception("investigation %s failed", investigation_id)
            if not self._is_cancelled(investigation_id):
                self._store.transition_state(
                    investigation_id,
                    InvestigationState.FAILED,
                    actor=self._runner_id,
                    reason=str(exc),
                )
        finally:
            loop.close()
            remove_worktree(checkout, worktree)
            if worktree_parent.exists():
                shutil.rmtree(worktree_parent, ignore_errors=True)
            self._cancel_registry.unregister(investigation_id)
            finished = self._store.get(investigation_id)
            if finished and finished.batch_id:
                self._store.refresh_batch_state(finished.batch_id)
            self._current_investigation_id = None
            self._current_started_at = None

    def _is_cancelled(self, investigation_id: str) -> bool:
        record = self._store.get(investigation_id)
        return record is not None and record.state == InvestigationState.CANCELLED

    async def _run_antares(
        self,
        *,
        record: InvestigationRecord,
        repo_root: str,
        investigation_id: str,
        changed_paths: list[str] | None = None,
    ):
        agent_cfg = self._config.models.antares.agent
        audit_callback_url = sandbox_audit_callback_url(self._config)
        audit_callback_token = self._audit_callback_tokens.issue()
        return await self._triage._client.run_triage_query(
            repo=record.repo,
            ref=record.requested_ref,
            repo_root=repo_root,
            task_cwe=record.task_cwe,
            task_cwe_description=record.task_cwe_description or "",
            max_terminal_calls=agent_cfg.max_terminal_calls,
            temperature=agent_cfg.temperature,
            top_p=agent_cfg.top_p,
            loop_control_enabled=agent_cfg.loop_control_enabled,
            model_variant=record.model_variant,
            audit_callback_url=audit_callback_url,
            audit_callback_token=audit_callback_token,
            audit_actor=record.actor,
            audit_subject=f"{record.repo}@{record.requested_ref}",
            investigation_id=investigation_id,
            exclude_test_paths=record.exclude_test_paths,
            changed_paths=changed_paths or [],
        )

    def _finalize_from_result(self, investigation_id: str, analysis_result: Any, localization: Any) -> None:
        if self._is_cancelled(investigation_id):
            return
        if hasattr(localization, "outcome"):
            payload = localization
        elif isinstance(localization, dict):
            payload = triage_payload_from_response(localization)
        else:
            payload = triage_payload_from_response({})
        terminal_calls = int(getattr(payload, "turn_count", 0) or 0)
        outcome = str(getattr(payload, "outcome", "") or "")

        audit_events = getattr(payload, "sandbox_audit", ()) or ()
        if audit_events:
            persist_sandbox_command_audit(
                self._audit,
                actor=self._runner_id,
                subject=f"investigation:{investigation_id}",
                events=[dict(entry) for entry in audit_events],
            )
            for index, entry in enumerate(audit_events):
                command_id = entry.get("command_id")
                if command_id and self._store.complete_trace_turn(
                    investigation_id,
                    command_id=str(command_id),
                    exit_status=int(entry.get("exit_code") or 0),
                    output_truncated=str(entry.get("output_truncated") or ""),
                    charged=bool(entry.get("charged", True)),
                    duplicate_of_turn=entry.get("duplicate_of_turn"),
                ):
                    continue
                if self._store.count_trace_turns(investigation_id) > index:
                    continue
                self._store.append_trace_turn(
                    investigation_id,
                    turn_index=index,
                    command=str(entry.get("command") or ""),
                    exit_status=int(entry.get("exit_code") or 0),
                    output_truncated=str(entry.get("output_truncated") or ""),
                    charged=bool(entry.get("charged", True)),
                    duplicate_of_turn=entry.get("duplicate_of_turn"),
                    command_id=str(command_id) if command_id else None,
                    phase=str(entry.get("phase") or "completed"),
                )

        if not analysis_result.succeeded and outcome not in {
            QUERY_COMPLETED_NO_FILES,
            QUERY_COMPLETED_WITH_FILES,
        }:
            self._store.transition_state(
                investigation_id,
                InvestigationState.FAILED,
                actor=self._runner_id,
                reason=getattr(payload, "failure_message", None) or "Antares triage failed",
                terminal_calls_used=terminal_calls,
            )
            return

        if outcome == QUERY_COMPLETED_NO_FILES:
            self._store.transition_state(
                investigation_id,
                InvestigationState.COMPLETED_NO_FILES,
                actor=self._runner_id,
                reason="submit_no_vulnerability_found",
                terminal_calls_used=terminal_calls,
            )
            return

        ranked = getattr(payload, "ranked_files", None) or []
        if ranked:
            self._store.persist_candidates_from_ranked_files(investigation_id, ranked)
            self._store.transition_state(
                investigation_id,
                InvestigationState.COMPLETED,
                actor=self._runner_id,
                terminal_calls_used=terminal_calls,
            )
            return

        self._store.transition_state(
            investigation_id,
            InvestigationState.COMPLETED_NO_FILES,
            actor=self._runner_id,
            reason="submit_no_vulnerability_found",
            terminal_calls_used=terminal_calls,
        )
