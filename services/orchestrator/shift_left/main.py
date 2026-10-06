"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any, Literal

import uvicorn
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from shift_left.auth.context import AuthContext, TokenCapability
from shift_left.auth.deps import get_auth_context, reject_client_actor_fields, require_capability
from shift_left.api.ui_support import router as ui_api_router
from shift_left.config import PolicyConfig, load_config
from shift_left.models.database import SYSTEM_ACTOR
from shift_left.api.openapi_models import (
    ApprovalRevokeResponse,
    AntaresTriageResponse,
    AuditEventListResponse,
    AuditExportResponse,
    CandidateDispositionResponse,
    ConfigChangeListResponse,
    FindingsListResponse,
    HealthResponse,
    InvestigationBatchLaunchResponse,
    InvestigationLaunchResponse,
    InvestigationStateResponse,
    PolicyDocumentResponse,
    PolicyValidateResponse,
    SandboxAuditIngestResponse,
    SelfCheckResponse,
)
from shift_left.models.schema import (
    ApprovalRecord,
    BlockOverrideRecord,
    ChangeStateResult,
    DeploymentGateResult,
    Finding,
    FindingStatusUpdate,
    FindingWaiverRecord,
    PullRequestPolicyDecision,
    ReviewRequest,
    ReviewResult,
    TerraformPlanRecord,
)
from shift_left.policy.loader import PolicyValidationError, load_and_validate_policies
from shift_left.antares.audit_callback_auth import AuditCallbackTokenStore, verify_sandbox_audit_ingest
from shift_left.investigations.store import InvestigationStore
from shift_left.review.service import ReviewService
from shift_left.triage.service import AntaresTriageService
from shift_left.sovereignty.checks import assert_startup_ok, run_startup_checks
from shift_left.sovereignty.network import EgressGuard
from shift_left.sovereignty.runtime import assert_no_remote_inference_fallback
from shift_left.ui.router import UiLoginRequired, mount_ui_static, router as ui_router
from shift_left.ui.sovereignty import assert_ui_bind_allowed

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


class PolicyValidateRequest(BaseModel):
    policy: PolicyConfig


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    commit_sha: str


class BlockOverrideRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    commit_sha: str
    justification: str
    policy_id: str | None = None


class FindingWaiverRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    commit_sha: str
    finding_id: str
    reason: str


class AntaresTriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str
    ref: str
    task_cwe: str | None = None
    task_cwe_description: str | None = None
    advisory_cve: str | None = None


class InvestigationLaunchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str
    ref: str
    task_cwe: str | None = None
    task_cwe_description: str | None = None
    advisory_cve: str | None = None
    exclude_test_paths: bool = True
    snapshot_scope: Literal["full", "pr_changed"] = "full"
    snapshot_base_ref: str = "main"


class InvestigationBatchLaunchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str
    ref: str
    source: Literal["profiled", "top25", "custom"] = "top25"
    custom_cwes: list[str] = Field(default_factory=list)
    selected_cwes: list[str] | None = None
    confirmed_large_batch: bool = False
    exclude_test_paths: bool = True
    snapshot_scope: Literal["full", "pr_changed"] = "full"
    snapshot_base_ref: str = "main"


class CandidateDispositionUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disposition: str
    note: str | None = None


class PlanGenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    commit_sha: str


class SandboxCommandAuditIngest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str
    subject: str
    investigation_id: str
    command: str
    exit_code: int
    output_truncated: str
    truncated: bool
    recorded_at: str
    charged: bool = True
    duplicate_of_turn: int | None = None
    command_id: str | None = None
    phase: str = "completed"


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    if config.distribution.auto_update:
        raise RuntimeError("auto_update must remain false — updates are operator-initiated only")
    if config.distribution.telemetry:
        raise RuntimeError("telemetry is absent from this project — do not enable")

    assert_no_remote_inference_fallback(os.environ)
    assert_ui_bind_allowed(config)
    logger.info("Running startup self-check...")
    assert_startup_ok(config)
    app.state.config = config
    app.state.review_service = ReviewService(config)
    investigation_store = InvestigationStore(
        config.investigations.sqlite_path,
        retention_days=config.investigations.retention_days,
        audit=app.state.review_service.audit,
    )
    app.state.investigation_store = investigation_store
    app.state.audit_callback_tokens = AuditCallbackTokenStore()
    app.state.triage_service = AntaresTriageService(
        config,
        audit=app.state.review_service.audit,
        audit_callback_tokens=app.state.audit_callback_tokens,
    )
    app.state.token_store = app.state.review_service.token_store

    from shift_left.investigations.cancel_registry import InvestigationCancelRegistry
    from shift_left.investigations.runner import InvestigationQueueRunner

    app.state.investigation_cancel_registry = InvestigationCancelRegistry()
    reaped = investigation_store.reap_orphaned_running(actor=SYSTEM_ACTOR)
    if reaped:
        logger.warning("Reaped %s orphaned running investigation(s) after restart", len(reaped))

    runner = InvestigationQueueRunner(
        config=config,
        store=investigation_store,
        triage=app.state.triage_service,
        audit=app.state.review_service.audit,
        cancel_registry=app.state.investigation_cancel_registry,
        audit_callback_tokens=app.state.audit_callback_tokens,
    )
    app.state.investigation_runner = runner
    runner.start()

    service: ReviewService = app.state.review_service
    service.audit.log(
        actor=SYSTEM_ACTOR,
        action="config.policy_validated",
        subject="startup",
        details={"policy_count": len(config.policy.rules)},
    )
    if not config.policy.approval.separation_of_duties_enforced:
        service.audit.log(
            actor=SYSTEM_ACTOR,
            action="config.separation_of_duties_disabled",
            subject="policy.approval",
            details={
                "separation_of_duties_enforced": False,
                "note": "Approver may equal commit author — rule disabled by configuration.",
            },
        )
    if config.rbac.allow_self_approval:
        logger.warning(
            "RBAC allow_self_approval=true — separation of duties disabled (development only; "
            "unsuitable for production)"
        )
        service.audit.log(
            actor=SYSTEM_ACTOR,
            action="config.rbac_allow_self_approval_enabled",
            subject="rbac",
            details={
                "allow_self_approval": True,
                "note": "Development escape hatch — commit author may approve own changes.",
            },
        )
    logger.info("Shift-Left orchestrator ready (no telemetry, local inference only)")
    yield
    runner = getattr(app.state, "investigation_runner", None)
    if runner is not None:
        await runner.stop()


app = FastAPI(
    title="Shift-Left Review Orchestrator",
    version="0.3.0",
    description=(
        "Local PR review API on the operator host. Findings and policy decisions "
        "require human review and are not compliance verdicts. Advisory model findings "
        "are omitted from POST /api/v1/review by default; retrieve them from "
        "GET /api/v1/findings/{owner}/{repo}/{pr_number} or "
        "GET /api/v1/pr/{owner}/{repo}/{pr_number}/context. "
        "There is no Forgejo webhook listener on this process — Actions jobs call "
        "POST /api/v1/review with a review-capable bearer token. "
        "Unauthenticated: GET /health and GET /self-check."
    ),
    lifespan=lifespan,
    openapi_url="/openapi.json",
    docs_url=None,
    redoc_url=None,
    servers=[
        {
            "url": "http://127.0.0.1:8080",
            "description": (
                "Operator-host loopback. The orchestrator binds locally and is not "
                "reachable from GitHub Pages or other remote clients."
            ),
        }
    ],
)

app.include_router(ui_api_router)
app.include_router(ui_router)
mount_ui_static(app)


@app.exception_handler(UiLoginRequired)
async def ui_login_required_handler(request: Request, exc: UiLoginRequired) -> RedirectResponse:
    return RedirectResponse(
        url=f"/ui/login?next={quote(exc.next_path, safe='')}",
        status_code=303,
    )


async def _reject_extra_actor_fields(request: Request) -> None:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    try:
        body = await request.json()
    except Exception:
        return
    if isinstance(body, dict):
        reject_client_actor_fields(body)


@app.get("/health", response_model=HealthResponse)
async def health():
    service: ReviewService = app.state.review_service
    details = await service.health_details()
    status_code = 200 if details.get("ready") else 503
    return {
        "status": "ok" if status_code == 200 else "degraded",
        **details,
    }


@app.get("/self-check", response_model=SelfCheckResponse)
async def self_check():
    config = app.state.config
    results = run_startup_checks(config)
    return {
        "ok": all(item.ok for item in results),
        "checks": [{"name": r.name, "ok": r.ok, "message": r.message} for r in results],
    }


@app.post("/api/v1/review", response_model=ReviewResult)
async def review_pull_request(
    request: ReviewRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.REVIEW))],
):
    if app.state.config.policy.human_review_required is False:
        raise HTTPException(
            status_code=500,
            detail="human_review_required=false is forbidden — auto-approve is not supported",
        )

    service: ReviewService = app.state.review_service
    try:
        result = await service.review_pull_request(request)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Review failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    from shift_left.ui.api_presentation import redact_review_result_for_api

    service.audit.log(
        actor=auth.actor,
        action="review.requested",
        subject=f"{request.owner}/{request.repo}/PR-{request.pr_number}",
        details={"token_id": auth.token_id},
    )
    return redact_review_result_for_api(
        result,
        omit_advisory=app.state.config.advisory_suppression.omit_from_review_api,
    )


@app.post("/api/v1/investigations", response_model=InvestigationLaunchResponse)
async def launch_investigation_api(
    request: InvestigationLaunchRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.TRIAGE))],
):
    from shift_left.investigations.launch import LaunchRejectedError, LaunchRequest, launch_investigation

    config = app.state.config
    store: InvestigationStore = app.state.investigation_store
    triage: AntaresTriageService = app.state.triage_service
    try:
        result = await launch_investigation(
            config=config,
            store=store,
            triage=triage,
            actor=auth.actor,
            request=LaunchRequest(
                repo=request.repo,
                ref=request.ref,
                task_cwe=request.task_cwe,
                task_cwe_description=request.task_cwe_description,
                advisory_cve=request.advisory_cve,
                exclude_test_paths=request.exclude_test_paths,
                snapshot_scope=request.snapshot_scope,
                snapshot_base_ref=request.snapshot_base_ref,
            ),
        )
    except LaunchRejectedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "investigation_id": result.record.investigation_id,
        "state": result.record.state.value,
        "resolved_commit_sha": result.record.resolved_commit_sha,
        "snapshot_bytes": result.snapshot_bytes,
        "snapshot_warn": result.snapshot_warn,
        "cwe_hint": result.cwe_hint,
    }


@app.post("/api/v1/investigation-batches", response_model=InvestigationBatchLaunchResponse)
async def launch_investigation_batch_api(
    request: InvestigationBatchLaunchRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.TRIAGE))],
):
    from shift_left.investigations.batch_launch import BatchLaunchRequest, launch_investigation_batch
    from shift_left.investigations.git_checkout import GitCheckoutError

    config = app.state.config
    store: InvestigationStore = app.state.investigation_store
    triage: AntaresTriageService = app.state.triage_service
    try:
        result = await launch_investigation_batch(
            config=config,
            store=store,
            triage=triage,
            actor=auth.actor,
            request=BatchLaunchRequest(
                repo=request.repo,
                ref=request.ref,
                source=request.source,
                custom_cwes=tuple(request.custom_cwes),
                selected_cwes=(
                    tuple(request.selected_cwes) if request.selected_cwes is not None else None
                ),
                confirmed_large_batch=request.confirmed_large_batch,
                exclude_test_paths=request.exclude_test_paths,
                snapshot_scope=request.snapshot_scope,
                snapshot_base_ref=request.snapshot_base_ref,
            ),
        )
    except LaunchRejectedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GitCheckoutError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "batch_id": result.batch.batch_id,
        "source": result.batch.source,
        "investigation_ids": list(result.investigation_ids),
        "investigation_count": len(result.investigation_ids),
        "estimated_wall_clock_seconds": result.estimated_wall_clock_seconds,
        "top25_survivor_count": result.top25_survivor_count,
        "snapshot_bytes": result.snapshot_bytes,
    }


@app.post("/api/v1/investigations/{investigation_id}/cancel", response_model=InvestigationStateResponse)
async def cancel_investigation_api(
    investigation_id: str,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.TRIAGE))],
):
    from shift_left.investigations.lifecycle import LifecycleRejectedError, cancel_investigation

    try:
        record = await cancel_investigation(
            store=app.state.investigation_store,
            triage=app.state.triage_service,
            cancel_registry=app.state.investigation_cancel_registry,
            investigation_id=investigation_id,
            actor=auth.actor,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except LifecycleRejectedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"investigation_id": record.investigation_id, "state": record.state.value}


@app.post("/api/v1/investigations/{investigation_id}/rerun", response_model=InvestigationStateResponse)
async def rerun_investigation_api(
    investigation_id: str,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.TRIAGE))],
):
    from shift_left.investigations.launch import LaunchRejectedError
    from shift_left.investigations.lifecycle import rerun_investigation

    try:
        record = await rerun_investigation(
            config=app.state.config,
            store=app.state.investigation_store,
            triage=app.state.triage_service,
            investigation_id=investigation_id,
            actor=auth.actor,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except LaunchRejectedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "investigation_id": record.investigation_id,
        "originating_investigation_id": record.originating_investigation_id,
        "state": record.state.value,
        "resolved_commit_sha": record.resolved_commit_sha,
    }


@app.patch(
    "/api/v1/investigations/{investigation_id}/candidates/{submission_rank}/disposition",
    response_model=CandidateDispositionResponse,
)
async def update_investigation_candidate_disposition_api(
    investigation_id: str,
    submission_rank: int,
    request: CandidateDispositionUpdateRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.TRIAGE))],
):
    from shift_left.investigations.disposition import (
        DispositionUpdateError,
        parse_disposition,
        update_candidate_disposition,
    )

    store: InvestigationStore = app.state.investigation_store
    try:
        disposition = parse_disposition(request.disposition)
    except DispositionUpdateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        candidate = update_candidate_disposition(
            store,
            investigation_id=investigation_id,
            submission_rank=submission_rank,
            disposition=disposition,
            actor=auth.actor,
            note=request.note,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "investigation_id": investigation_id,
        "submission_rank": candidate.submission_rank,
        "file_path": candidate.file_path,
        "disposition": candidate.disposition.value,
        "disposition_actor": candidate.disposition_actor,
        "disposition_at": candidate.disposition_at.isoformat() if candidate.disposition_at else None,
        "disposition_note": candidate.disposition_note,
    }


@app.post("/api/v1/triage/antares", response_model=AntaresTriageResponse)
async def antares_triage(
    request: AntaresTriageRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.TRIAGE))],
):
    service: AntaresTriageService = app.state.triage_service
    review: ReviewService = app.state.review_service
    try:
        localization, analysis = await service.run_triage(
            repo=request.repo,
            ref=request.ref,
            cwe=request.task_cwe,
            cwe_description=request.task_cwe_description,
            advisory_cve=request.advisory_cve,
            actor=auth.actor,
            audit_store=review.audit,
        )
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    review.audit.log(
        actor=auth.actor,
        action="triage.antares.completed",
        subject=f"{request.repo}@{request.ref}",
        details={
            "cwe": localization.cwe_queried,
            "outcome": localization.outcome,
            "candidate_count": len(localization.ranked_files),
            "token_id": auth.token_id,
        },
    )
    low, high = service.estimated_latency_seconds(1)
    from shift_left.ui.api_presentation import redact_antares_triage_for_api

    return redact_antares_triage_for_api(
        {
            "localization": localization,
            "analysis": analysis,
            "latency_estimate_seconds": {"low": low, "high": high},
            "note": "Advisory triage only — never gates a merge.",
        }
    )


@app.get("/api/v1/findings/{owner}/{repo}/{pr_number}", response_model=FindingsListResponse)
async def list_findings(owner: str, repo: str, pr_number: int):
    from shift_left.ui.api_presentation import serialize_findings_for_api_with_provenance

    service: ReviewService = app.state.review_service
    repo_slug = f"{owner}/{repo}"
    pr_ref = f"PR-{pr_number}"
    findings = service._store.list_for_pr(repo_slug, pr_ref)
    return await serialize_findings_for_api_with_provenance(findings, service._git)


@app.patch("/api/v1/findings/{finding_id}/status", response_model=Finding)
async def update_finding_status(
    finding_id: str,
    update: FindingStatusUpdate,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.TRIAGE))],
):
    service: ReviewService = app.state.review_service
    try:
        updated = service.update_finding_status(finding_id, update, actor=auth.actor)
    except LookupError:
        raise HTTPException(status_code=404, detail="Finding not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    from shift_left.ui.config_redaction import redact_finding_for_display

    return redact_finding_for_display(updated)


@app.get("/api/v1/policy", response_model=PolicyDocumentResponse)
async def get_policy():
    config = app.state.config
    return {
        "policy": config.policy.model_dump(mode="json"),
        "note": (
            "Policy changes require editing config/shift-left.yaml and restarting. "
            "Policy decisions are advisory — not compliance verdicts."
        ),
    }


@app.post("/api/v1/policy/validate", response_model=PolicyValidateResponse)
async def validate_policy(body: PolicyValidateRequest):
    try:
        policies = load_and_validate_policies(body.policy)
    except PolicyValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "policy_count": len(policies),
        "precedence": (
            "Enabled policies evaluated in YAML order; first match per finding; "
            "PR decision = strictest action (block > flag > pass); "
            "default_action when no match."
        ),
    }


@app.get(
    "/api/v1/policy/decision/{owner}/{repo}/{pr_number}",
    response_model=PullRequestPolicyDecision,
)
async def get_policy_decision(
    owner: str,
    repo: str,
    pr_number: int,
    commit_sha: str | None = None,
):
    from shift_left.policy.finding_waiver import apply_waivers_to_decision

    service: ReviewService = app.state.review_service
    repo_slug = f"{owner}/{repo}"
    pr_ref = f"PR-{pr_number}"
    if commit_sha:
        decision = service._policy_decisions.for_commit(repo_slug, pr_ref, commit_sha)
    else:
        decision = service._policy_decisions.latest_for_pr(repo_slug, pr_ref)
    if decision is None:
        raise HTTPException(status_code=404, detail="No policy decision recorded for this PR")
    if commit_sha:
        findings = service._store.list_for_pr(repo_slug, pr_ref)
        active_waivers = service.waivers.active_for_commit(repo_slug, pr_ref, commit_sha)
        decision = apply_waivers_to_decision(decision, findings, active_waivers).effective_decision
    return decision


@app.post("/api/v1/approvals/{owner}/{repo}/{pr_number}", response_model=ApprovalRecord)
async def grant_approval(
    owner: str,
    repo: str,
    pr_number: int,
    body: ApprovalRequest,
    request: Request,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.APPROVE))],
):
    await _reject_extra_actor_fields(request)
    service: ReviewService = app.state.review_service
    repo_slug = f"{owner}/{repo}"
    pr_ref = f"PR-{pr_number}"
    try:
        record = await service.approvals.grant_approval(
            repo=repo_slug,
            pr_ref=pr_ref,
            commit_sha=body.commit_sha,
            approver=auth.actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    service.audit.log(
        actor=auth.actor,
        action="approval.granted",
        subject=f"{repo_slug}/{pr_ref}",
        details={
            "commit_sha": body.commit_sha,
            "policy_decision": record.policy_decision.value,
            "commit_author": record.commit_author,
            "approver_matches_author": record.approver_matches_author,
            "separation_of_duties_result": record.separation_of_duties_result,
            "self_approval_permitted": record.separation_of_duties_result
            == "rbac_self_approval_permitted",
            "token_id": auth.token_id,
        },
    )
    state = service.changes.compute_state(
        repo=repo_slug,
        pr_ref=pr_ref,
        commit_sha=body.commit_sha,
        pr_number=pr_number,
    )
    service.changes.audit_state_transition(
        actor=auth.actor,
        repo=repo_slug,
        pr_ref=pr_ref,
        commit_sha=body.commit_sha,
        state=state.state,
        reason=state.reason,
    )
    from shift_left.ui.api_presentation import redact_approval_record_for_api

    return redact_approval_record_for_api(record)


@app.delete("/api/v1/approvals/{owner}/{repo}/{pr_number}", response_model=ApprovalRevokeResponse)
async def revoke_approval(
    owner: str,
    repo: str,
    pr_number: int,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.APPROVE))],
):
    service: ReviewService = app.state.review_service
    repo_slug = f"{owner}/{repo}"
    pr_ref = f"PR-{pr_number}"
    count = service.approvals.revoke_approval(repo_slug, pr_ref, actor=auth.actor)
    service.audit.log(
        actor=auth.actor,
        action="approval.revoked",
        subject=f"{repo_slug}/{pr_ref}",
        details={"count": count, "token_id": auth.token_id},
    )
    return {"revoked": count}


@app.post("/api/v1/overrides/{owner}/{repo}/{pr_number}", response_model=BlockOverrideRecord)
async def grant_block_override(
    owner: str,
    repo: str,
    pr_number: int,
    body: BlockOverrideRequest,
    request: Request,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.OVERRIDE))],
):
    await _reject_extra_actor_fields(request)
    service: ReviewService = app.state.review_service
    repo_slug = f"{owner}/{repo}"
    pr_ref = f"PR-{pr_number}"
    try:
        record = await service.approvals.grant_block_override(
            repo=repo_slug,
            pr_ref=pr_ref,
            commit_sha=body.commit_sha,
            actor=auth.actor,
            justification=body.justification,
            policy_id=body.policy_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    service.audit.log(
        actor=auth.actor,
        action="override.exercised",
        subject=f"{repo_slug}/{pr_ref}",
        details={
            "commit_sha": body.commit_sha,
            "justification": body.justification,
            "policy_id": body.policy_id,
            "token_id": auth.token_id,
        },
    )
    return record


@app.post("/api/v1/waivers/{owner}/{repo}/{pr_number}", response_model=FindingWaiverRecord)
async def grant_finding_waiver(
    owner: str,
    repo: str,
    pr_number: int,
    body: FindingWaiverRequest,
    request: Request,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
):
    await _reject_extra_actor_fields(request)
    if auth.has_capability(TokenCapability.APPROVE):
        capability_used = TokenCapability.APPROVE
    elif auth.has_capability(TokenCapability.TRIAGE):
        capability_used = TokenCapability.TRIAGE
    else:
        raise HTTPException(status_code=403, detail="triage or approve capability required")
    service: ReviewService = app.state.review_service
    repo_slug = f"{owner}/{repo}"
    pr_ref = f"PR-{pr_number}"
    try:
        record = await service.waivers.grant_waiver(
            repo=repo_slug,
            pr_ref=pr_ref,
            commit_sha=body.commit_sha,
            finding_id=body.finding_id,
            actor=auth.actor,
            reason=body.reason,
            capability_used=capability_used,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return record


@app.get("/api/v1/gate/{owner}/{repo}/{pr_number}", response_model=DeploymentGateResult)
async def deployment_gate(owner: str, repo: str, pr_number: int, commit_sha: str = Query(...)):
    service: ReviewService = app.state.review_service
    repo_slug = f"{owner}/{repo}"
    pr_ref = f"PR-{pr_number}"
    return await service.gate.evaluate_and_publish(
        owner=owner,
        repo_name=repo,
        repo_slug=repo_slug,
        pr_ref=pr_ref,
        commit_sha=commit_sha,
        pr_number=pr_number,
    )


@app.get("/api/v1/changes", response_model=ConfigChangeListResponse)
async def list_config_changes(
    request: Request,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
):
    service: ReviewService = request.app.state.review_service
    changes = await service.changes.list_changes(auth=auth)
    return {"changes": changes, "count": len(changes)}


@app.get("/api/v1/changes/{owner}/{repo}/{pr_number}/state", response_model=ChangeStateResult)
async def change_state(
    owner: str,
    repo: str,
    pr_number: int,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
):
    service: ReviewService = app.state.review_service
    try:
        return await service.changes.state_for_pr(owner=owner, repo=repo, pr_number=pr_number)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/v1/changes/{owner}/{repo}/{pr_number}/plan", response_model=TerraformPlanRecord)
async def generate_terraform_plan(
    owner: str,
    repo: str,
    pr_number: int,
    body: PlanGenerateRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.DEPLOY))],
):
    service: ReviewService = app.state.review_service
    repo_slug = f"{owner}/{repo}"
    pr_ref = f"PR-{pr_number}"
    try:
        record = await service.deployment.generate_plan(
            repo=repo_slug,
            pr_ref=pr_ref,
            commit_sha=body.commit_sha,
            actor=auth.actor,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    state = service.changes.compute_state(
        repo=repo_slug,
        pr_ref=pr_ref,
        commit_sha=body.commit_sha,
        pr_number=pr_number,
    )
    service.changes.audit_state_transition(
        actor=auth.actor,
        repo=repo_slug,
        pr_ref=pr_ref,
        commit_sha=body.commit_sha,
        state=state.state,
        reason=state.reason,
    )
    return record


@app.post(
    "/api/v1/internal/antares/sandbox-command-audit",
    response_model=SandboxAuditIngestResponse,
)
async def ingest_sandbox_command_audit(
    request: Request,
    body: SandboxCommandAuditIngest,
):
    from shift_left.antares.sandbox_audit import persist_sandbox_command_audit

    verify_sandbox_audit_ingest(request)

    service: ReviewService = app.state.review_service
    event = body.model_dump(exclude={"actor", "subject"})
    persist_sandbox_command_audit(
        service.audit,
        actor=body.actor,
        subject=body.subject,
        events=[event],
    )
    investigation_store: InvestigationStore | None = getattr(
        app.state, "investigation_store", None
    )
    if investigation_store is not None and body.investigation_id:
        from shift_left.investigations.schema import InvestigationState

        record = investigation_store.get(body.investigation_id)
        if record is not None and record.state == InvestigationState.RUNNING:
            updated = False
            if body.phase == "completed" and body.command_id:
                updated = investigation_store.complete_trace_turn(
                    body.investigation_id,
                    command_id=body.command_id,
                    exit_status=int(body.exit_code),
                    output_truncated=str(body.output_truncated),
                    charged=body.charged,
                    duplicate_of_turn=body.duplicate_of_turn,
                )
            if not updated:
                turn_index = investigation_store.count_trace_turns(body.investigation_id)
                investigation_store.append_trace_turn(
                    body.investigation_id,
                    turn_index=turn_index,
                    command=str(body.command),
                    exit_status=int(body.exit_code),
                    output_truncated=str(body.output_truncated),
                    charged=body.charged,
                    duplicate_of_turn=body.duplicate_of_turn,
                    command_id=body.command_id,
                    phase=body.phase,
                )
            if body.charged:
                investigation_store.update_terminal_calls_used(
                    body.investigation_id,
                    investigation_store.count_trace_charged_turns(body.investigation_id),
                )
    return {"status": "ok"}


@app.get("/api/v1/audit/events", response_model=AuditEventListResponse)
async def list_audit_events(
    actor: str | None = None,
    action: str | None = None,
    subject_prefix: str | None = None,
    since: datetime | None = None,
    limit: int = Query(default=200, le=1000),
):
    service: ReviewService = app.state.review_service
    events = service.audit.list_events(
        actor=actor,
        action=action,
        subject_prefix=subject_prefix,
        since=since,
        limit=limit,
    )
    from shift_left.ui.api_presentation import redact_audit_events_for_api

    investigation_store: InvestigationStore | None = getattr(
        app.state, "investigation_store", None
    )
    return {
        "events": redact_audit_events_for_api(
            events,
            investigation_store=investigation_store,
        )
    }


@app.get("/api/v1/audit/export", response_model=AuditExportResponse)
async def export_audit_events():
    """Portable JSON export — works with runtime egress blocked."""
    service: ReviewService = app.state.review_service
    from shift_left.ui.api_presentation import redact_audit_events_for_api

    with EgressGuard(allowed_hosts=frozenset({"127.0.0.1", "localhost", "::1"})):
        payload: dict[str, Any] = {
            "exported_at": datetime.now().astimezone().isoformat(),
            "integrity": {
                "append_only": True,
                "tamper_evidence": "none — hash chaining planned for Phase 6",
            },
            "events": redact_audit_events_for_api(service.audit.export_all()),
        }
    return JSONResponse(content=payload)


from shift_left.api.route_docs import apply_openapi_metadata, build_openapi_document  # noqa: E402

apply_openapi_metadata(app)


def custom_openapi() -> dict:
    if app.openapi_schema:
        return app.openapi_schema
    app.openapi_schema = build_openapi_document(app)
    return app.openapi_schema


app.openapi = custom_openapi


def main() -> None:
    config = load_config()
    uvicorn.run(
        "shift_left.main:app",
        host=config.orchestrator.host,
        port=config.orchestrator.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
