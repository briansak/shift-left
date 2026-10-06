"""Investigation launch validation and enqueue."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from shift_left.config import AppConfig
from shift_left.investigations.git_checkout import (
    GitCheckoutError,
    estimate_launch_snapshot_bytes,
    resolve_ref_to_sha,
)
from shift_left.investigations.preflight import (
    build_launch_preflight,
    check_antares_server_available,
    variant_below_minimum,
    minimum_variant_message,
)
from shift_left.investigations.schema import InvestigationRecord
from shift_left.investigations.store import InvestigationStore
from shift_left.investigations.suitability import (
    SNAPSHOT_WARN_BYTES,
    cwe_suitability_hint,
    normalize_task_cwe,
)
from shift_left.triage.service import AntaresTriageService


class LaunchRejectedError(ValueError):
    """Launch preconditions failed with an operator-facing message."""


def ensure_queue_capacity(
    store: InvestigationStore,
    config: AppConfig,
    *,
    additional: int = 1,
) -> None:
    if additional < 1:
        return
    queued = store.count_queued()
    cap = config.investigations.queue_depth_cap
    if queued + additional > cap:
        raise LaunchRejectedError(
            f"Investigation queue cannot accept {additional} more run(s) "
            f"({queued} queued, cap {cap}). "
            "Wait for running investigations to finish or cancel queued runs."
        )


@dataclass(frozen=True)
class LaunchRequest:
    repo: str
    ref: str
    task_cwe: str | None = None
    task_cwe_description: str | None = None
    advisory_cve: str | None = None
    exclude_test_paths: bool = True
    snapshot_scope: str = "full"
    snapshot_base_ref: str = "main"


@dataclass(frozen=True)
class LaunchResult:
    record: InvestigationRecord
    snapshot_bytes: int
    snapshot_warn: bool
    cwe_hint: str | None


async def launch_investigation(
    *,
    config: AppConfig,
    store: InvestigationStore,
    triage: AntaresTriageService,
    actor: str,
    request: LaunchRequest,
    require_server_available: bool = True,
    originating_investigation_id: str | None = None,
) -> LaunchResult:
    if not config.antares_triage.enabled:
        raise LaunchRejectedError("Antares triage is disabled in configuration")

    if variant_below_minimum(config):
        raise LaunchRejectedError(minimum_variant_message(config))

    if require_server_available and not await check_antares_server_available(triage._client):
        raise LaunchRejectedError(
            "antares-server is unavailable — install or start it from System before launching"
        )

    ensure_queue_capacity(store, config, additional=1)

    checkout = triage.checkout_path(request.repo)
    if not checkout.is_dir():
        raise LaunchRejectedError(
            f"Repo {request.repo!r} has no local checkout at {checkout}. "
            "Maintain a checkout under repos_checkout_dir before launching."
        )

    try:
        resolved_cwe, _source = triage.resolve_cwe(
            cwe=request.task_cwe,
            advisory_cve=request.advisory_cve,
        )
    except ValueError as exc:
        raise LaunchRejectedError(str(exc)) from exc

    try:
        normalized_cwe = normalize_task_cwe(resolved_cwe)
    except ValueError as exc:
        raise LaunchRejectedError(str(exc)) from exc

    try:
        commit_sha = resolve_ref_to_sha(checkout, request.ref)
    except GitCheckoutError as exc:
        raise LaunchRejectedError(str(exc)) from exc

    try:
        snapshot_bytes, _paths = estimate_launch_snapshot_bytes(
            checkout,
            commit_sha,
            snapshot_scope=request.snapshot_scope or "full",
            base_ref=request.snapshot_base_ref or "main",
        )
    except GitCheckoutError as exc:
        raise LaunchRejectedError(str(exc)) from exc

    agent_cfg = config.models.antares.agent
    record = store.create_investigation(
        repo=request.repo.strip(),
        requested_ref=request.ref.strip(),
        resolved_commit_sha=commit_sha,
        task_cwe=normalized_cwe,
        task_cwe_description=request.task_cwe_description,
        advisory_cve=request.advisory_cve,
        actor=actor,
        model_variant=config.antares_triage.model_variant,
        terminal_call_budget=agent_cfg.max_terminal_calls or 15,
        snapshot_bytes=snapshot_bytes,
        originating_investigation_id=originating_investigation_id,
        exclude_test_paths=request.exclude_test_paths,
        snapshot_scope=request.snapshot_scope or "full",
        snapshot_base_ref=request.snapshot_base_ref or "main",
    )
    return LaunchResult(
        record=record,
        snapshot_bytes=snapshot_bytes,
        snapshot_warn=snapshot_bytes > SNAPSHOT_WARN_BYTES,
        cwe_hint=cwe_suitability_hint(normalized_cwe),
    )


async def build_launch_form_state(config: AppConfig, triage: AntaresTriageService):
    from shift_left.investigations.preflight import LaunchPreflight

    preflight = await build_launch_preflight(config, triage._client)
    return preflight
