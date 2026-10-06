"""API endpoints added for the web UI — server-side data only."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from shift_left.api.openapi_models import (
    ApprovalListResponse,
    FindingsListResponse,
    JsonObjectResponse,
    TokenIdentityResponse,
)
from shift_left.auth.context import AuthContext, TokenCapability
from shift_left.auth.deps import get_auth_context, require_capability
from shift_left.config import resolve_repo_root
from shift_left.review.service import ReviewService
from shift_left.sovereignty.network import run_egress_probe
from shift_left.system.services import ServiceAction, ServiceName
from shift_left.system.settings import RBAC_DISABLE_PHRASE, RBAC_ENABLE_PHRASE

router = APIRouter(prefix="/api/v1", tags=["ui-support"])


def _egress_probe_status(probe, *, skip_probe: bool, probe_disabled: bool) -> dict[str, Any]:
    if skip_probe:
        return {
            "state": "skipped_connected_dev",
            "ok": True,
            "blocked": None,
            "message": (
                "Probe intentionally skipped (SHIFT_LEFT_SKIP_EGRESS_PROBE) on a connected development "
                "host — runtime sovereignty still enforced by deny_egress and the port-scoped allowlist."
            ),
            "skipped": True,
        }
    if probe_disabled:
        return {
            "state": "disabled",
            "ok": True,
            "blocked": None,
            "message": "Probe disabled via SHIFT_LEFT_EGRESS_PROBE=0.",
            "skipped": True,
        }
    if probe is None:
        return {
            "state": "not_run",
            "ok": None,
            "blocked": None,
            "message": "Egress probe was not executed.",
            "skipped": False,
        }
    if probe.ok:
        return {
            "state": "blocked",
            "ok": True,
            "blocked": True,
            "message": probe.message,
            "skipped": False,
        }
    return {
        "state": "unexpected_allow",
        "ok": False,
        "blocked": False,
        "message": probe.message,
        "skipped": False,
    }


class Tier3SettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    settings: dict[str, Any]


class RbacSelfApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    confirmation_phrase: str


class ServiceLifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: ServiceName
    action: ServiceAction
    start_dependency_chain: bool = False


class StartAllPrerequisitesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include_degraded: bool = True


class ReferenceSyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fetch_nvd: bool = False
    confirmation_phrase: str | None = None


class ImmutableSettingsProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    settings: dict[str, Any] = Field(default_factory=dict)


def _service(request: Request) -> ReviewService:
    return request.app.state.review_service


def _apply_config_reload(request: Request, service: ReviewService) -> None:
    from shift_left.system.compose_cli import invalidate_compose_cli_cache
    from shift_left.system.topology import invalidate_topology_cache

    new_config = service.settings._store.reload_app_config()
    request.app.state.config = new_config
    service.refresh_config(new_config)
    invalidate_topology_cache()
    invalidate_compose_cli_cache()


@router.get("/me", response_model=TokenIdentityResponse)
async def current_session(auth: Annotated[AuthContext, Depends(get_auth_context)]) -> dict[str, Any]:
    from shift_left.auth.context import TokenCapability

    held: list[str] = []
    for cap in TokenCapability:
        if auth.has_capability(cap):
            held.append(cap.value)
    return {"actor": auth.actor, "capabilities": sorted(set(held)), "token_id": auth.token_id}


@router.get("/findings", response_model=FindingsListResponse)
async def list_findings_filtered(
    request: Request,
    repo: str | None = None,
    pr_ref: str | None = None,
    target_kind: str | None = None,
    policy_severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
    limit: int = Query(default=200, le=1000),
) -> dict[str, Any]:
    service = _service(request)
    findings = service._store.list_filtered(
        repo=repo,
        pr_ref=pr_ref,
        target_kind=target_kind,
        policy_severity=policy_severity,
        status=status,
        source=source,
        limit=limit,
    )
    from shift_left.ui.api_presentation import serialize_findings_for_api

    payload = serialize_findings_for_api(findings)
    payload["count"] = len(findings)
    return payload


@router.get("/pr/{owner}/{repo}/{pr_number}/context", response_model=JsonObjectResponse)
async def pr_review_context(
    request: Request,
    owner: str,
    repo: str,
    pr_number: int,
) -> dict[str, Any]:
    service = _service(request)
    try:
        context = await service.build_pr_review_context(owner=owner, repo=repo, pr_number=pr_number)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    from shift_left.ui.api_presentation import redact_pr_review_context_for_api

    return redact_pr_review_context_for_api(context)


@router.get("/approvals/{owner}/{repo}/{pr_number}", response_model=ApprovalListResponse)
async def list_approvals(
    request: Request,
    owner: str,
    repo: str,
    pr_number: int,
) -> dict[str, Any]:
    service = _service(request)
    repo_slug = f"{owner}/{repo}"
    pr_ref = f"PR-{pr_number}"
    records = service.approvals._approvals.list_for_pr(repo_slug, pr_ref)
    from shift_left.ui.api_presentation import redact_approval_records_for_api

    return {"approvals": redact_approval_records_for_api(records)}


@router.get("/system/status", response_model=JsonObjectResponse)
async def system_status(request: Request, refresh: bool = Query(default=False)) -> dict[str, Any]:
    service = _service(request)
    config = request.app.state.config
    health = await service.health_details(force_refresh=refresh)
    skip_probe = os.environ.get("SHIFT_LEFT_SKIP_EGRESS_PROBE", "").lower() in {"1", "true", "yes"}
    probe_disabled = os.environ.get("SHIFT_LEFT_EGRESS_PROBE", "true").lower() in {"0", "false", "no"}
    fs = config.models.foundation_sec
    probe = run_egress_probe(timeout=1.0) if not skip_probe and not probe_disabled else None
    topology_report = service.service_lifecycle.topology_report()
    compose_cli = service.service_lifecycle.compose_cli_report()
    fmc = config.deployment.fmc
    services = await service.service_lifecycle.status_all()
    egress_paths = [
        {
            "path": "orchestrator_runtime",
            "description": "Loopback model services and bundled Forgejo (default allowed endpoints)",
            "internet_egress": False,
        },
        {
            "path": "reference_sync_nvd",
            "description": "Operator-initiated NVD/CVE sync when explicitly requested",
            "internet_egress": True,
            "operator_initiated": True,
        },
        {
            "path": "fmc_management_plane",
            "description": (
                "terraform plan against FMC management center (in-org infrastructure, "
                "not public internet egress)"
            ),
            "internet_egress": False,
            "enabled": fmc.enabled,
            "endpoint": fmc.allowed_endpoint,
        },
    ]
    settings = service.settings
    return {
        "health": health,
        "services": services,
        "settings": {
            "tier1": settings.tier1_snapshot(),
            "tier3_form": settings.tier3_form(),
            "rbac_phrases": {
                "enable": RBAC_ENABLE_PHRASE,
                "disable": RBAC_DISABLE_PHRASE,
            },
        },
        "sovereignty": {
            "deny_egress": config.sovereignty.deny_egress,
            "runtime_allowed_endpoints": list(config.sovereignty.runtime_allowed_endpoints),
            "immutable_note": settings.tier1_snapshot()["immutable_note"],
            "egress_probe": _egress_probe_status(probe, skip_probe=skip_probe, probe_disabled=probe_disabled),
            "egress_paths": egress_paths,
        },
        "rbac": {
            "allow_self_approval": config.rbac.allow_self_approval,
            "note": (
                "Development only — separation of duties disabled while true."
                if config.rbac.allow_self_approval
                else "Separation of duties enforced at API (author cannot approve by default)."
            ),
        },
        "models": {
            "antares": {
                "enabled": config.models.antares.enabled,
                "installed": config.models.antares.installed or config.antares_triage.installed,
                "load_strategy": config.models.antares.load_strategy,
                "local_path": config.models.antares.local_path,
                "hf_repo_id": config.models.antares.hf_repo_id,
                "recycle_after_runs": config.models.antares.agent.recycle_after_runs,
            },
            "foundation_sec": {
                "enabled": fs.enabled,
                "load_strategy": fs.load_strategy,
                "service_url": fs.service_url,
                "gguf_glob": fs.gguf_glob_low_memory if fs.use_low_memory else fs.gguf_glob,
                "quant_label": fs.quant_label_low_memory if fs.use_low_memory else fs.quant_label,
                "n_ctx": fs.max_context_tokens,
                "use_low_memory": fs.use_low_memory,
            },
            "inventory": health.get("models_inventory", {}),
        },
        "audit": {
            "retention_days": config.audit.retention_days,
            "note": "Retention pruning destroys history — export before prune.",
        },
        "config_diagnostics": {
            "legacy_path_rewrites": [
                {
                    "key": rewrite.key,
                    "original": rewrite.original,
                    "resolved": rewrite.resolved,
                }
                for rewrite in config.legacy_path_rewrites
            ],
            "omit_from_pr_comments": config.advisory_suppression.omit_from_pr_comments,
        },
        "topology": service.service_lifecycle.topology(),
        "topology_report": topology_report.to_dict(),
        "compose_cli": compose_cli,
        "prerequisites": health.get("prerequisites"),
        "dependency_graph": service.service_lifecycle.dependency_graph(),
    }


@router.get("/system/prerequisites", response_model=JsonObjectResponse)
async def system_prerequisites(
    request: Request,
    refresh: bool = Query(default=False),
) -> dict[str, Any]:
    service = _service(request)
    health = await service.health_details(force_refresh=refresh)
    return health.get("prerequisites") or {}


@router.patch("/system/settings/tier3", response_model=JsonObjectResponse)
async def update_tier3_settings(
    request: Request,
    body: Tier3SettingsRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.ADMIN))],
) -> dict[str, Any]:
    service = _service(request)
    try:
        result = service.settings.apply_tier3(updates=body.settings, actor=auth.actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _apply_config_reload(request, service)
    return result


@router.patch("/system/settings/rbac/allow-self-approval", response_model=JsonObjectResponse)
async def update_allow_self_approval(
    request: Request,
    body: RbacSelfApprovalRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.ADMIN))],
) -> dict[str, Any]:
    service = _service(request)
    try:
        result = service.settings.set_allow_self_approval(
            enabled=body.enabled,
            confirmation_phrase=body.confirmation_phrase,
            actor=auth.actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _apply_config_reload(request, service)
    return result


@router.post("/system/settings/immutable-probe", response_model=JsonObjectResponse)
async def immutable_settings_probe(
    request: Request,
    body: ImmutableSettingsProbe,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.ADMIN))],
) -> dict[str, Any]:
    """Explicitly refuse Tier-1 sovereignty mutations."""
    service = _service(request)
    try:
        service.settings.reject_immutable_write(body.settings)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    raise HTTPException(status_code=400, detail="No immutable settings supplied.")


@router.post("/system/services/action", response_model=JsonObjectResponse)
async def service_lifecycle_action(
    request: Request,
    body: ServiceLifecycleRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.ADMIN))],
) -> dict[str, Any]:
    service = _service(request)
    lifecycle = service.service_lifecycle
    if body.start_dependency_chain and body.action in {"start", "restart"}:
        assessment = await lifecycle.assess_start(body.service)
        if assessment["blocking_dependencies"]:
            return await lifecycle.start_all_prerequisites(
                actor=auth.actor,
                include_degraded=False,
            )
    try:
        return await lifecycle.run_action(
            service=body.service,
            action=body.action,
            actor=auth.actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/system/services/start-all", response_model=JsonObjectResponse)
async def start_all_prerequisites(
    request: Request,
    body: StartAllPrerequisitesRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.ADMIN))],
) -> dict[str, Any]:
    service = _service(request)
    return await service.service_lifecycle.start_all_prerequisites(
        actor=auth.actor,
        include_degraded=body.include_degraded,
    )


@router.post("/system/reference/sync", response_model=JsonObjectResponse)
async def reference_sync(
    request: Request,
    body: ReferenceSyncRequest,
    auth: Annotated[AuthContext, Depends(require_capability(TokenCapability.ADMIN))],
) -> dict[str, Any]:
    service = _service(request)
    config = request.app.state.config
    if body.fetch_nvd and body.confirmation_phrase != "SYNC WITH NVD EGRESS":
        raise HTTPException(
            status_code=400,
            detail="NVD fetch requires confirmation_phrase: SYNC WITH NVD EGRESS",
        )
    from shift_left.reference.sync import sync_reference_cache

    cache_dir = Path(config.reference_data.cache_dir)
    if not cache_dir.is_absolute():
        cache_dir = resolve_repo_root() / cache_dir
    seed_dir = resolve_repo_root() / "reference-seed"
    nvd_key = os.environ.get(config.reference_data.nvd_api_key_env or "NVD_API_KEY")
    manifest = sync_reference_cache(
        cache_dir,
        seed_dir=seed_dir if seed_dir.is_dir() else None,
        fetch_nvd=body.fetch_nvd,
        nvd_api_key=nvd_key,
    )
    service.audit.log(
        actor=auth.actor,
        action="reference.sync",
        subject=str(cache_dir),
        details={
            "fetch_nvd": body.fetch_nvd,
            "operator_initiated_egress": body.fetch_nvd,
            "newest_last_modified": manifest.get("newest_last_modified"),
        },
    )
    return {"manifest": manifest, "operator_initiated_egress": body.fetch_nvd}
