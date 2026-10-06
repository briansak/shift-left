"""Shift-Left local web UI routes (server-rendered)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.responses import Response

from shift_left.auth.context import AuthContext, TokenCapability
from shift_left.auth.deps import (
    TOKEN_COOKIE_NAME,
    authenticate_token,
    get_auth_context,
    reject_client_actor_fields,
    require_capability,
    resolve_request_token,
)
from shift_left.handlers.config.coverage_report import (
    coverage_view_rows,
    load_handler_coverage_report,
    parse_coverage_table_rows,
    model_cwe_advisory_summary,
)
from shift_left.policy.waiver_policy import required_waiver_capability
from shift_left.ui.cwe_dictionary import cwe_dictionary_json
from shift_left.ui.system_view import (
    build_config_view,
    build_evidence_view,
    build_lifecycle_feedback,
    build_triage_view,
)
from shift_left.ui.target_detail_view import build_target_detail_view
from shift_left.ui.target_changes_view import build_changes_panel
from shift_left.ui.target_config_view import build_config_panel
from shift_left.ui.target_history_view import build_history_panel
from shift_left.ui.cwe_reference_view import build_cwe_reference_list_view
from shift_left.ui.investigation_view import (
    build_investigation_detail_live_state,
    build_investigation_detail_view,
    build_investigation_list_live_state,
    build_investigation_list_view,
    build_investigation_trace_fragment,
    build_investigation_trace_view,
    build_launch_form_view,
)
from shift_left.investigations.disposition import (
    DispositionUpdateError,
    parse_disposition,
    update_candidate_disposition,
)
from shift_left.investigations.batch_launch import (
    BatchLaunchRequest,
    launch_investigation_batch,
    preview_investigation_batch,
)
from shift_left.investigations.git_checkout import GitCheckoutError
from shift_left.investigations.batch_lifecycle import BatchLifecycleRejectedError, cancel_investigation_batch
from shift_left.investigations.launch import LaunchRejectedError, LaunchRequest, launch_investigation
from shift_left.investigations.lifecycle import LifecycleRejectedError, cancel_investigation, rerun_investigation
from shift_left.ui.batch_view import build_investigation_batch_view
from shift_left.investigations.preflight import build_launch_preflight
from shift_left.investigations.store import InvestigationStore
from shift_left.models.schema import FindingStatus, FindingStatusUpdate
from shift_left.review.service import ReviewService
from shift_left.system.services import ServiceLifecycleManager
from shift_left.triage.service import AntaresTriageService
from shift_left.ui.labels import sanitize_advisory_prose, sanitize_triage_text
from shift_left.ui.presentation import (
    can,
    capability_set,
    enrichment_badge,
    finding_policy_decision,
    format_advisory,
    policy_action_label,
    policy_severity_class,
    policy_severity_label,
)
from shift_left.ui.sovereignty import assert_loopback_client

logger = logging.getLogger(__name__)


def _form_values(form: Any) -> dict[str, Any]:
    catalog = [str(value).strip() for value in form.getlist("catalog_cwes") if str(value).strip()]
    selected = [str(value).strip() for value in form.getlist("selected_cwes") if str(value).strip()]
    custom_raw = str(form.get("custom_cwes") or "")
    parsed_custom = tuple(
        part.strip()
        for part in custom_raw.replace("\n", ",").split(",")
        if part.strip()
    )
    source = str(form.get("source") or form.get("batch_source") or "single").strip() or "single"
    if source == "custom" and not parsed_custom:
        parsed_custom = tuple(catalog or selected)
    return {
        "repo": str(form.get("repo") or "").strip(),
        "ref": str(form.get("ref") or "").strip(),
        "source": source,
        "task_cwe": str(form.get("task_cwe") or "").strip(),
        "task_cwe_description": str(form.get("task_cwe_description") or "").strip(),
        "advisory_cve": str(form.get("advisory_cve") or "").strip(),
        "exclude_test_paths": "1" in [str(value) for value in form.getlist("exclude_test_paths")]
        if form.getlist("exclude_test_paths")
        else True,
        "snapshot_scope": str(form.get("snapshot_scope") or "full").strip() or "full",
        "snapshot_base_ref": str(form.get("snapshot_base_ref") or "main").strip() or "main",
        "selected_cwes": tuple(selected),
        "previewed": str(form.get("previewed") or "") == "1",
        "custom_cwes": parsed_custom,
        "confirmed_large_batch": str(form.get("confirmed_large_batch") or "") == "1",
    }


async def _investigations_page(
    request: Request,
    auth: AuthContext,
    *,
    launch_form,
    page: int = 1,
    status_code: int = 200,
) -> HTMLResponse:
    store: InvestigationStore = request.app.state.investigation_store
    config = request.app.state.config
    runner = getattr(request.app.state, "investigation_runner", None)
    list_view = build_investigation_list_view(
        store,
        config,
        runner=runner,
        page=page,
        launch_form=launch_form,
    )
    return templates.TemplateResponse(
        request,
        "investigations.html",
        _ctx(request, auth, list_view=list_view),
        status_code=status_code,
    )


async def _launch_form_from_error(
    request: Request,
    *,
    error: str,
    fields: dict[str, Any] | None = None,
    preview=None,
):
    config = request.app.state.config
    store: InvestigationStore = request.app.state.investigation_store
    triage: AntaresTriageService = request.app.state.triage_service
    preflight = await build_launch_preflight(config, triage._client)
    fields = fields or {}
    return build_launch_form_view(
        preflight,
        error=error,
        source=str(fields.get("source") or "single"),
        snapshot_scope=str(fields.get("snapshot_scope") or "full"),
        snapshot_base_ref=str(fields.get("snapshot_base_ref") or "main"),
        repo=str(fields.get("repo") or ""),
        ref=str(fields.get("ref") or ""),
        default_task_cwe=str(fields.get("task_cwe") or ""),
        default_task_cwe_description=str(fields.get("task_cwe_description") or ""),
        exclude_test_paths=bool(fields.get("exclude_test_paths", True)),
        queue_depth=store.count_queued(),
        queue_depth_cap=config.investigations.queue_depth_cap,
        preview=preview,
        selected_catalog_cwes=tuple(fields.get("custom_cwes") or ()),
    )


def _batch_request_from_fields(fields: dict[str, Any]) -> BatchLaunchRequest:
    source = fields["source"]
    selected = fields["selected_cwes"]
    selected_arg: tuple[str, ...] | None
    if source in {"top25", "profiled"} and fields["previewed"]:
        selected_arg = selected
    elif source == "custom":
        selected_arg = None
    else:
        selected_arg = None
    return BatchLaunchRequest(
        repo=fields["repo"],
        ref=fields["ref"],
        source=source,
        custom_cwes=fields["custom_cwes"],
        selected_cwes=selected_arg,
        confirmed_large_batch=fields["confirmed_large_batch"],
        exclude_test_paths=fields["exclude_test_paths"],
        snapshot_scope=fields["snapshot_scope"],
        snapshot_base_ref=fields["snapshot_base_ref"],
    )

_UI_DIR = Path(__file__).resolve().parent
_jinja_env = Environment(
    loader=FileSystemLoader(str(_UI_DIR / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
    cache_size=0,
)
templates = Jinja2Templates(env=_jinja_env)
templates.env.filters["advisory"] = format_advisory
templates.env.filters["triage_text"] = sanitize_triage_text
templates.env.globals.update(
    {
        "policy_severity_label": policy_severity_label,
        "policy_severity_class": policy_severity_class,
        "policy_action_label": policy_action_label,
    }
)

router = APIRouter(prefix="/ui", tags=["ui"])


class UiLoginRequired(Exception):
    """Browser navigation to a protected UI route without a session."""

    def __init__(self, next_path: str) -> None:
        self.next_path = next_path


def _client_host(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None


def _ui_guard(request: Request) -> None:
    config = getattr(request.app.state, "config", None)
    if config is None:
        raise HTTPException(
            status_code=503,
            detail="Orchestrator is still starting — retry in a few seconds.",
        )
    if not config.ui.enabled:
        raise HTTPException(status_code=404, detail="UI disabled")
    try:
        assert_loopback_client(config, _client_host(request))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _prefers_html_response(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    if "application/json" in accept and "text/html" not in accept:
        return False
    return True


def _safe_ui_next_path(raw: str | None) -> str:
    if not raw:
        return "/ui/targets"
    path = raw.split("?", 1)[0]
    if not path.startswith("/ui/") or path.startswith("//"):
        return "/ui/targets"
    return raw


def _ui_next_path(request: Request) -> str:
    next_url = request.url.path
    if request.url.query:
        next_url = f"{next_url}?{request.url.query}"
    return next_url


def _optional_auth(request: Request) -> AuthContext | None:
    raw = resolve_request_token(request)
    if not raw:
        return None
    try:
        return authenticate_token(request, raw)
    except HTTPException:
        return None


def _require_ui_auth(request: Request) -> AuthContext:
    _ui_guard(request)
    auth = _optional_auth(request)
    if auth is None:
        if request.method == "GET" and _prefers_html_response(request):
            raise UiLoginRequired(_ui_next_path(request))
        raise HTTPException(status_code=401, detail="Sign in with an API token")
    return auth


def _require_triage_ui_auth(request: Request) -> AuthContext:
    auth = _require_ui_auth(request)
    if not can(auth, TokenCapability.TRIAGE):
        raise HTTPException(status_code=403, detail="triage capability required")
    return auth


def ui_auth_dependency(request: Request) -> AuthContext:
    return _require_ui_auth(request)


UiAuth = Annotated[AuthContext, Depends(ui_auth_dependency)]


def _ctx(request: Request, auth: AuthContext | None, **extra: Any) -> dict[str, Any]:
    caps = capability_set(auth)
    config = getattr(request.app.state, "config", None)
    if config is None:
        raise HTTPException(
            status_code=503,
            detail="Orchestrator is still starting — retry in a few seconds.",
        )
    sod_enforced = config.policy.approval.separation_of_duties_enforced and not config.rbac.allow_self_approval
    return {
        **extra,
        "request": request,
        "auth": auth,
        "capabilities": sorted(caps),
        "can_review": "review" in caps,
        "can_triage": "triage" in caps,
        "can_approve": "approve" in caps,
        "can_deploy": "deploy" in caps,
        "can_override": "override" in caps,
        "can_admin": "admin" in caps,
        "separation_of_duties_enforced": sod_enforced,
        "rbac_allow_self_approval": config.rbac.allow_self_approval,
        "cwe_dictionary_json": cwe_dictionary_json(),
    }


@router.get("/", response_class=HTMLResponse)
async def ui_root(request: Request) -> Response:
    _ui_guard(request)
    if _optional_auth(request) is None:
        return RedirectResponse(url="/ui/login", status_code=303)
    return RedirectResponse(url="/ui/targets", status_code=303)


@router.get("/login", response_class=HTMLResponse)
async def ui_login(
    request: Request,
    error: str | None = None,
    next: str | None = None,
) -> HTMLResponse:
    _ui_guard(request)
    return templates.TemplateResponse(
        request,
        "login.html",
        _ctx(request, None, error=error, login_next=_safe_ui_next_path(next)),
    )


@router.post("/login")
async def ui_login_post(
    request: Request,
    token: Annotated[str, Form()],
    next: Annotated[str, Form()] = "",
) -> Response:
    _ui_guard(request)
    login_next = _safe_ui_next_path(next or None)
    try:
        authenticate_token(request, token.strip())
    except HTTPException:
        return templates.TemplateResponse(
            request,
            "login.html",
            _ctx(request, None, error="Invalid or revoked token", login_next=login_next),
            status_code=401,
        )
    response = RedirectResponse(url=login_next, status_code=303)
    response.set_cookie(
        TOKEN_COOKIE_NAME,
        token.strip(),
        httponly=True,
        samesite="strict",
        secure=False,
        path="/",
    )
    return response


@router.post("/logout")
async def ui_logout() -> Response:
    response = RedirectResponse(url="/ui/login", status_code=303)
    response.delete_cookie(TOKEN_COOKIE_NAME, path="/")
    return response


@router.get("/targets", response_class=HTMLResponse)
async def ui_targets(request: Request) -> HTMLResponse:
    auth = _require_ui_auth(request)
    service: ReviewService = request.app.state.review_service
    overview = await service.targets.overview(auth=auth)
    return templates.TemplateResponse(
        request,
        "targets.html",
        _ctx(request, auth, overview=overview),
    )


@router.get("/targets/new", response_class=HTMLResponse)
async def ui_target_new_form(request: Request, error: str | None = None) -> HTMLResponse:
    auth = _require_ui_auth(request)
    if not can(auth, TokenCapability.ADMIN):
        raise HTTPException(status_code=403, detail="admin capability required to define targets")
    config = request.app.state.config
    default_repo = config.gate.check_repo or ""
    return templates.TemplateResponse(
        request,
        "target_new.html",
        _ctx(
            request,
            auth,
            error=error,
            defaults={
                "branch": config.gate.protected_branch or "main",
                "repo": default_repo,
                "config_paths": "terraform/**",
                "deployment_adapter": "unconfigured",
            },
        ),
    )


@router.post("/targets/new")
async def ui_target_new_create(request: Request, auth: UiAuth) -> Response:
    if not can(auth, TokenCapability.ADMIN):
        raise HTTPException(status_code=403, detail="admin capability required to define targets")
    form = await request.form()
    service: ReviewService = request.app.state.review_service
    from shift_left.api.ui_support import _apply_config_reload
    from shift_left.targets.write import parse_config_paths

    repo = str(form.get("repo", "")).strip()
    branch = str(form.get("branch", "main")).strip() or "main"
    config_paths = parse_config_paths(str(form.get("config_paths", "")))
    repo_paths: list[str] | None = None
    if "/" in repo and repo.count("/") == 1:
        owner, repo_name = repo.split("/", 1)
        list_tree = getattr(service._git, "list_repo_tree_paths", None)
        if list_tree is not None:
            try:
                repo_paths = await list_tree(owner, repo_name, branch)
            except Exception:
                repo_paths = []

    try:
        target = service.target_writes.add_target(
            actor=auth.actor,
            display_name=str(form.get("display_name", "")),
            target_type=str(form.get("target_type", "")),
            repo=repo,
            branch=branch,
            config_paths=config_paths,
            target_id=str(form.get("target_id", "")).strip() or None,
            description=str(form.get("description", "")),
            environment=str(form.get("environment", "")),
            criticality=str(form.get("criticality", "")),
            owner=str(form.get("owner", "")),
            deployment_adapter=str(form.get("deployment_adapter", "unconfigured")),
            repo_paths=repo_paths,
        )
    except ValueError as exc:
        config = request.app.state.config
        default_repo = config.gate.check_repo or ""
        return templates.TemplateResponse(
            request,
            "target_new.html",
            _ctx(
                request,
                auth,
                error=str(exc),
                defaults={
                    "display_name": form.get("display_name", ""),
                    "target_type": form.get("target_type", ""),
                    "repo": form.get("repo", default_repo),
                    "branch": form.get("branch", "main"),
                    "config_paths": form.get("config_paths", ""),
                    "target_id": form.get("target_id", ""),
                    "description": form.get("description", ""),
                    "environment": form.get("environment", ""),
                    "criticality": form.get("criticality", ""),
                    "owner": form.get("owner", ""),
                    "deployment_adapter": form.get("deployment_adapter", "unconfigured"),
                },
            ),
            status_code=400,
        )
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Cannot write config/shift-left.yaml from the orchestrator "
                f"(config mount not writable: {exc}). "
                "Recreate the stack or fix the config volume permissions."
            ),
        ) from exc
    _apply_config_reload(request, service)
    return RedirectResponse(url=f"/ui/targets/{target.id}?notice=target-created", status_code=303)


@router.get("/targets/{target_id}", response_class=HTMLResponse)
async def ui_target_detail(
    request: Request,
    target_id: str,
    tab: str = "config",
    rev: str | None = None,
    file: str | None = None,
    path: str | None = None,
    diff_base: str | None = None,
    diff_head: str | None = None,
    action_filter: str | None = None,
    notice: str | None = None,
    error: str | None = None,
) -> HTMLResponse:
    auth = _require_ui_auth(request)
    service: ReviewService = request.app.state.review_service
    detail = await service.targets.detail(
        target_id,
        auth=auth,
        tab=tab,
        revision=rev,
        selected_file=file,
        path_filter=path or "",
        diff_base=diff_base,
        diff_head=diff_head,
    )
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Unknown target: {target_id}")
    plan_allowed, plan_reason = service.deployment.target_plan_status(detail.target)
    if plan_allowed:
        gate_ok, gate_reason = await service.targets.commit_allows_plan(
            detail.target.repo,
            detail.declared_head_sha,
        )
        if not gate_ok:
            plan_reason = f"Cannot generate plan: {gate_reason}"
    detail.plan_refused_reason = plan_reason
    summary, findings_panel = build_target_detail_view(
        detail,
        service._config,
        service.waivers,
    )
    changes_panel = None
    history_panel = None
    config_panel = None
    if tab == "changes":
        changes_panel = await build_changes_panel(
            detail,
            service._config,
            target_service=service.targets,
            decisions_store=service._policy_decisions,
            approvals_store=service.approvals._approvals,
            waiver_store=service.waivers._waivers,
        )
    if tab == "history":
        history_panel = build_history_panel(
            detail,
            service.audit,
            action_filter=action_filter,
        )
    if tab == "config":
        config_panel = build_config_panel(detail)
    return templates.TemplateResponse(
        request,
        "target_detail.html",
        _ctx(
            request,
            auth,
            detail=detail,
            summary=summary,
            findings_panel=findings_panel,
            changes_panel=changes_panel,
            history_panel=history_panel,
            config_panel=config_panel,
            plan_stale=detail.plan_stale,
            notice=notice,
            error=error,
        ),
    )


@router.post("/targets/{target_id}/plan")
async def ui_target_plan(
    request: Request,
    target_id: str,
    auth: UiAuth,
    commit_sha: Annotated[str, Form()],
) -> Response:
    if not can(auth, TokenCapability.DEPLOY):
        raise HTTPException(status_code=403, detail="deploy capability required")
    service: ReviewService = request.app.state.review_service
    target = service._target_registry.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Unknown target: {target_id}")
    try:
        live_sha = await service.targets.live_head_sha(target)
        if live_sha != commit_sha:
            raise HTTPException(status_code=409, detail=f"Stale SHA — live head is {live_sha}")
        await service.deployment.generate_target_plan(
            target_id=target_id,
            commit_sha=commit_sha,
            actor=auth.actor,
        )
    except PermissionError as exc:
        return RedirectResponse(
            url=f"/ui/targets/{target_id}?tab=deploy&error={quote(str(exc))}",
            status_code=303,
        )
    except ValueError as exc:
        return RedirectResponse(
            url=f"/ui/targets/{target_id}?tab=deploy&error={quote(str(exc))}",
            status_code=303,
        )
    return RedirectResponse(url=f"/ui/targets/{target_id}?tab=deploy", status_code=303)


@router.get("/changes", response_class=HTMLResponse)
async def ui_config_changes(request: Request) -> HTMLResponse:
    auth = _require_ui_auth(request)
    service: ReviewService = request.app.state.review_service
    changes = await service.changes.list_changes(auth=auth)
    return templates.TemplateResponse(
        request,
        "changes.html",
        _ctx(request, auth, changes=changes),
    )


@router.get("/findings", response_class=HTMLResponse)
async def ui_findings_dashboard(
    request: Request,
    repo: str | None = None,
    pr_ref: str | None = None,
    target_kind: str | None = None,
    policy_severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
) -> HTMLResponse:
    auth = _require_ui_auth(request)
    service: ReviewService = request.app.state.review_service
    findings = service._store.list_filtered(
        repo=repo,
        pr_ref=pr_ref,
        target_kind=target_kind,
        policy_severity=policy_severity,
        status=status,
        source=source,
    )
    model_only_findings = service._store.list_model_only(limit=500)
    decisions: dict[str, Any] = {}
    for finding in findings:
        key = (finding.repo, finding.pr_ref)
        if key not in decisions:
            decisions[key] = service._policy_decisions.latest_for_pr(finding.repo, finding.pr_ref)
    rows = []
    for finding in findings:
        decision = decisions.get((finding.repo, finding.pr_ref))
        rows.append(
            {
                "finding": finding,
                "policy": finding_policy_decision(finding.id, decision),
                "enrichment_note": enrichment_badge(finding),
            }
        )
    return templates.TemplateResponse(
        request,
        "findings.html",
        _ctx(
            request,
            auth,
            rows=rows,
            model_only_findings=model_only_findings,
            filters={
                "repo": repo or "",
                "pr_ref": pr_ref or "",
                "target_kind": target_kind or "",
                "policy_severity": policy_severity or "",
                "status": status or "",
                "source": source or "",
            },
        ),
    )


@router.get("/pr/{owner}/{repo}/{pr_number}", response_class=HTMLResponse)
async def ui_pr_review(request: Request, owner: str, repo: str, pr_number: int) -> HTMLResponse:
    auth = _require_ui_auth(request)
    service: ReviewService = request.app.state.review_service
    context = await service.build_pr_review_context(owner=owner, repo=repo, pr_number=pr_number)
    gate = context["gate"]
    change_state = context["change_state"]
    analysis_incomplete = bool(getattr(gate, "analysis_incomplete", False)) or (
        change_state is not None and change_state.state.value == "validation_incomplete"
    )
    viewer_is_author = False
    if context["commit_author"] and auth.actor:
        viewer_is_author = (
            auth.actor.strip().lower() == str(context["commit_author"]).strip().lower()
        )
    sod_enforced = context["separation_of_duties_enforced"] and not context["rbac_allow_self_approval"]
    can_approve = can(auth, TokenCapability.APPROVE) and not (sod_enforced and viewer_is_author)
    approve_block_reason = None
    if can(auth, TokenCapability.APPROVE) and not can_approve:
        approve_block_reason = "Separation of duties: you are the commit author for this SHA."
    finding_rows = []
    waiver_map = context.get("waiver_for_finding") or {}
    policy_decision = context.get("policy_decision")
    for finding in context["findings"]:
        waiver = waiver_map.get(finding.id)
        if waiver is not None:
            from shift_left.ui.config_redaction import redact_display_text

            waiver = waiver.model_copy(update={"reason": redact_display_text(waiver.reason)})
        policy = finding_policy_decision(finding.id, policy_decision)
        required_cap = required_waiver_capability(
            finding,
            policy_decision.finding_decisions if policy_decision else None,
        )
        can_grant_waiver = (
            can(auth, TokenCapability.APPROVE)
            if required_cap == TokenCapability.APPROVE
            else can(auth, TokenCapability.TRIAGE) or can(auth, TokenCapability.APPROVE)
        ) and not (sod_enforced and viewer_is_author)
        finding_rows.append(
            {
                "finding": finding,
                "policy": policy,
                "enrichment_note": enrichment_badge(finding),
                "waiver": waiver,
                "required_waiver_capability": required_cap.value,
                "can_grant_waiver": can_grant_waiver,
            }
        )
    return templates.TemplateResponse(
        request,
        "pr_review.html",
        _ctx(
            request,
            auth,
            **context,
            finding_rows=finding_rows,
            analysis_incomplete=analysis_incomplete,
            viewer_is_author=viewer_is_author,
            can_approve_ui=can_approve,
            approve_block_reason=approve_block_reason,
            can_override_ui=can(auth, TokenCapability.OVERRIDE)
            and context["allow_block_override"],
            can_triage_ui=can(auth, TokenCapability.TRIAGE),
            can_approve_ui_capability=can(auth, TokenCapability.APPROVE),
            waiver_block_reason=(
                "Separation of duties: you are the commit author for this SHA."
                if sod_enforced and viewer_is_author
                else None
            ),
            can_deploy_ui=can(auth, TokenCapability.DEPLOY),
            sod_enforced=sod_enforced,
        ),
    )


@router.post("/pr/{owner}/{repo}/{pr_number}/finding/{finding_id}/status")
async def ui_update_finding_status(
    request: Request,
    owner: str,
    repo: str,
    pr_number: int,
    finding_id: str,
    auth: UiAuth,
    status: Annotated[str, Form()],
    rationale: Annotated[str, Form()] = "",
) -> Response:
    if not can(auth, TokenCapability.TRIAGE):
        raise HTTPException(status_code=403, detail="triage capability required")
    service: ReviewService = request.app.state.review_service
    try:
        parsed_status = FindingStatus(status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid status") from exc
    if parsed_status in {FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK}:
        if not rationale.strip():
            raise HTTPException(status_code=400, detail="Rationale required for this status")
    update = FindingStatusUpdate(status=parsed_status, rationale=rationale.strip() or None)
    try:
        service.update_finding_status(finding_id, update, actor=auth.actor)
    except LookupError:
        raise HTTPException(status_code=404, detail="Finding not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(url=f"/ui/pr/{owner}/{repo}/{pr_number}", status_code=303)


@router.post("/pr/{owner}/{repo}/{pr_number}/finding/{finding_id}/waiver")
async def ui_grant_finding_waiver(
    request: Request,
    owner: str,
    repo: str,
    pr_number: int,
    finding_id: str,
    auth: UiAuth,
    commit_sha: Annotated[str, Form()],
    reason: Annotated[str, Form()],
) -> Response:
    if not can(auth, TokenCapability.TRIAGE) and not can(auth, TokenCapability.APPROVE):
        raise HTTPException(status_code=403, detail="triage or approve capability required")
    capability_used = (
        TokenCapability.APPROVE
        if can(auth, TokenCapability.APPROVE)
        else TokenCapability.TRIAGE
    )
    service: ReviewService = request.app.state.review_service
    try:
        await service.waivers.grant_waiver(
            repo=f"{owner}/{repo}",
            pr_ref=f"PR-{pr_number}",
            commit_sha=commit_sha,
            finding_id=finding_id,
            actor=auth.actor,
            reason=reason,
            capability_used=capability_used,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(url=f"/ui/pr/{owner}/{repo}/{pr_number}", status_code=303)


@router.post("/pr/{owner}/{repo}/{pr_number}/approve")
async def ui_grant_approval(
    request: Request,
    owner: str,
    repo: str,
    pr_number: int,
    auth: UiAuth,
    commit_sha: Annotated[str, Form()],
) -> Response:
    if not can(auth, TokenCapability.APPROVE):
        raise HTTPException(status_code=403, detail="approve capability required")
    service: ReviewService = request.app.state.review_service
    try:
        await service.approvals.grant_approval(
            repo=f"{owner}/{repo}",
            pr_ref=f"PR-{pr_number}",
            commit_sha=commit_sha,
            approver=auth.actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(url=f"/ui/pr/{owner}/{repo}/{pr_number}", status_code=303)


@router.post("/pr/{owner}/{repo}/{pr_number}/override")
async def ui_grant_override(
    request: Request,
    owner: str,
    repo: str,
    pr_number: int,
    auth: UiAuth,
    commit_sha: Annotated[str, Form()],
    justification: Annotated[str, Form()],
) -> Response:
    if not can(auth, TokenCapability.OVERRIDE):
        raise HTTPException(status_code=403, detail="override capability required")
    reject_client_actor_fields({})
    service: ReviewService = request.app.state.review_service
    try:
        await service.approvals.grant_block_override(
            repo=f"{owner}/{repo}",
            pr_ref=f"PR-{pr_number}",
            commit_sha=commit_sha,
            actor=auth.actor,
            justification=justification,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(url=f"/ui/pr/{owner}/{repo}/{pr_number}", status_code=303)


@router.post("/pr/{owner}/{repo}/{pr_number}/plan")
async def ui_generate_plan(
    request: Request,
    owner: str,
    repo: str,
    pr_number: int,
    auth: UiAuth,
    commit_sha: Annotated[str, Form()],
) -> Response:
    if not can(auth, TokenCapability.DEPLOY):
        raise HTTPException(status_code=403, detail="deploy capability required")
    service: ReviewService = request.app.state.review_service
    repo_slug = f"{owner}/{repo}"
    pr_ref = f"PR-{pr_number}"
    try:
        await service.deployment.generate_plan(
            repo=repo_slug,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            actor=auth.actor,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(url=f"/ui/pr/{owner}/{repo}/{pr_number}", status_code=303)


@router.get("/cwe", response_class=HTMLResponse)
async def ui_cwe_reference(
    request: Request,
    page: int = Query(default=1, ge=1),
    q: str = Query(default=""),
    abstraction: str = Query(default=""),
    tractability: str = Query(default=""),
    top25: str = Query(default=""),
    handler: str = Query(default=""),
    language: str = Query(default=""),
    language_mode: str = Query(default=""),
) -> HTMLResponse:
    auth = _require_ui_auth(request)
    caps = capability_set(auth)
    reference_view = build_cwe_reference_list_view(
        page=page,
        q=q,
        abstraction=abstraction,
        tractability=tractability,
        top25_only=top25 == "1",
        handler_only=handler == "1",
        language=language,
        language_mode=language_mode if language_mode in {"", "specific", "includes_agnostic", "agnostic_only"} else "",
        can_launch_investigation="triage" in caps,
    )
    return templates.TemplateResponse(
        request,
        "cwe_reference.html",
        _ctx(request, auth, reference_view=reference_view),
    )


@router.get("/coverage", response_class=HTMLResponse)
async def ui_coverage(request: Request) -> HTMLResponse:
    auth = _require_ui_auth(request)
    report = load_handler_coverage_report()
    rows = coverage_view_rows(report) if report else []
    parse_coverage_rows = parse_coverage_table_rows(report) if report else []
    findings = request.app.state.review_service._store.list_filtered(limit=5000)
    model_cwe_advisory = model_cwe_advisory_summary(findings)
    return templates.TemplateResponse(
        request,
        "coverage.html",
        _ctx(
            request,
            auth,
            report=report,
            coverage_rows=rows,
            parse_coverage_rows=parse_coverage_rows,
            model_cwe_advisory=model_cwe_advisory,
        ),
    )


@router.get("/policy", response_class=HTMLResponse)
async def ui_policy(request: Request) -> HTMLResponse:
    auth = _require_ui_auth(request)
    config = request.app.state.config
    return templates.TemplateResponse(
        request,
        "policy.html",
        _ctx(
            request,
            auth,
            policy=config.policy,
            note="Policies are loaded from config/shift-left.yaml — edit config and restart to change.",
        ),
    )


@router.get("/audit", response_class=HTMLResponse)
async def ui_audit(
    request: Request,
    actor: str | None = None,
    action: str | None = None,
    subject_prefix: str | None = None,
    limit: int = Query(default=200, le=1000),
) -> HTMLResponse:
    auth = _require_ui_auth(request)
    service: ReviewService = request.app.state.review_service
    events = service.audit.list_events(
        actor=actor,
        action=action,
        subject_prefix=subject_prefix,
        limit=limit,
    )
    config = request.app.state.config
    return templates.TemplateResponse(
        request,
        "audit.html",
        _ctx(
            request,
            auth,
            events=events,
            filters={"actor": actor or "", "action": action or "", "subject_prefix": subject_prefix or ""},
            retention_days=config.audit.retention_days,
        ),
    )


def _system_notice_message(notice: str | None) -> str | None:
    if not notice:
        return None
    return {
        "settings-saved": "Tier 3 settings saved.",
        "rbac-saved": "RBAC settings updated.",
        "reference-synced": "Reference cache synced.",
    }.get(notice)


async def _render_system(
    request: Request,
    auth: AuthContext,
    *,
    active_tab: str,
    refresh: bool = False,
    notice: str | None = None,
) -> HTMLResponse:
    from shift_left.api.ui_support import system_status

    status = await system_status(request, refresh=refresh)
    can_admin = can(auth, TokenCapability.ADMIN)
    return templates.TemplateResponse(
        request,
        "system.html",
        _ctx(
            request,
            auth,
            status=status,
            active_tab=active_tab,
            notice=_system_notice_message(notice),
            triage=build_triage_view(
                status,
                can_admin=can_admin,
                lifecycle_feedback=build_lifecycle_feedback(dict(request.query_params)),
            ),
            config_view=build_config_view(status, can_admin=can_admin),
            evidence_view=build_evidence_view(status, can_admin=can_admin),
        ),
    )


@router.get("/system", response_class=HTMLResponse)
async def ui_system_triage(
    request: Request,
    notice: str | None = None,
    refresh: bool = Query(default=False),
) -> HTMLResponse:
    auth = _require_ui_auth(request)
    return await _render_system(
        request, auth, active_tab="triage", refresh=refresh, notice=notice
    )


@router.get("/system/config", response_class=HTMLResponse)
async def ui_system_config(
    request: Request,
    notice: str | None = None,
    refresh: bool = Query(default=False),
) -> HTMLResponse:
    auth = _require_ui_auth(request)
    return await _render_system(
        request, auth, active_tab="config", refresh=refresh, notice=notice
    )


@router.get("/system/evidence", response_class=HTMLResponse)
async def ui_system_evidence(
    request: Request,
    notice: str | None = None,
    refresh: bool = Query(default=False),
) -> HTMLResponse:
    auth = _require_ui_auth(request)
    return await _render_system(
        request, auth, active_tab="evidence", refresh=refresh, notice=notice
    )


@router.get("/health", response_class=HTMLResponse)
async def ui_health_redirect(request: Request) -> RedirectResponse:
    _require_ui_auth(request)
    query = request.url.query
    target = "/ui/system" + (f"?{query}" if query else "")
    return RedirectResponse(url=target, status_code=301)


@router.post("/system/settings/tier3")
async def ui_system_tier3_settings(request: Request, auth: UiAuth) -> Response:
    if not can(auth, TokenCapability.ADMIN):
        raise HTTPException(status_code=403, detail="admin capability required")
    form = await request.form()
    updates: dict[str, object] = {
        "models.foundation_sec.use_low_memory": form.get("use_low_memory") == "true",
        "models.foundation_sec.max_context_tokens": int(form.get("max_context_tokens", 4096)),
        "models.foundation_sec.load_strategy": str(form.get("foundation_sec_load_strategy")),
        "models.antares.load_strategy": str(form.get("antares_load_strategy")),
        "models.antares.agent.recycle_after_runs": int(form.get("recycle_after_runs", 10)),
        "enrichment.enabled": form.get("enrichment_enabled") == "true",
        "enrichment.enrich_findings": form.get("enrich_findings") == "true",
        "enrichment.generate_review_summary": form.get("generate_review_summary") == "true",
    }
    mapping = {
        "foundation_sec_service_url": "models.foundation_sec.service_url",
        "foundation_sec_local_path": "models.foundation_sec.local_path",
        "foundation_sec_local_path_q4": "models.foundation_sec.local_path_low_memory",
        "antares_service_url": "models.antares.service_url",
        "antares_local_path": "models.antares.local_path",
        "reference_cache_dir": "reference_data.cache_dir",
        "findings_sqlite_path": "findings_store.sqlite_path",
    }
    for form_key, config_key in mapping.items():
        value = str(form.get(form_key, "")).strip()
        if value:
            updates[config_key] = value
    service: ReviewService = request.app.state.review_service
    from shift_left.api.ui_support import _apply_config_reload

    try:
        service.settings.apply_tier3(updates=updates, actor=auth.actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Cannot write config/shift-left.yaml from the orchestrator container "
                f"(config mount not writable: {exc}). "
                "Recreate the stack: docker-compose up -d orchestrator"
            ),
        ) from exc
    _apply_config_reload(request, service)
    return RedirectResponse(url="/ui/system/config?notice=settings-saved", status_code=303)


@router.post("/system/settings/rbac")
async def ui_system_rbac_settings(request: Request, auth: UiAuth) -> Response:
    if not can(auth, TokenCapability.ADMIN):
        raise HTTPException(status_code=403, detail="admin capability required")
    form = await request.form()
    enabled = form.get("enabled") == "true"
    phrase = str(form.get("confirmation_phrase", ""))
    service: ReviewService = request.app.state.review_service
    from shift_left.api.ui_support import _apply_config_reload

    try:
        service.settings.set_allow_self_approval(
            enabled=enabled,
            confirmation_phrase=phrase,
            actor=auth.actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Cannot write config/shift-left.yaml from the orchestrator container "
                f"(config mount not writable: {exc}). "
                "Recreate the stack: docker-compose up -d orchestrator"
            ),
        ) from exc
    _apply_config_reload(request, service)
    return RedirectResponse(url="/ui/system/config?notice=rbac-saved", status_code=303)


@router.api_route("/system/service/{service_name}/{action_name}", methods=["GET", "POST"])
async def ui_system_service_action(
    request: Request,
    service_name: str,
    action_name: str,
    auth: UiAuth,
    start_chain: str | None = Query(default=None),
) -> Response:
    if not can(auth, TokenCapability.ADMIN):
        raise HTTPException(status_code=403, detail="admin capability required")
    service: ReviewService = request.app.state.review_service
    lifecycle = service.service_lifecycle
    if service_name not in lifecycle.ALLOWED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Unknown service: {service_name}")
    if action_name not in ServiceLifecycleManager.ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action_name}")
    feasibility = lifecycle.start_feasibility(service_name)  # type: ignore[arg-type]
    if action_name in {"start", "restart"} and feasibility.get("feasibility") != "start":
        return RedirectResponse(
            url=(
                f"/ui/system?refresh=true&notice=host-native-control"
                f"&service={service_name}&action={action_name}"
            ),
            status_code=303,
        )
    try:
        if start_chain == "true" and action_name in {"start", "restart"}:
            result = await lifecycle.start_all_prerequisites(actor=auth.actor, include_degraded=False)
        else:
            result = await lifecycle.run_action(
                service=service_name,  # type: ignore[arg-type]
                action=action_name,  # type: ignore[arg-type]
                actor=auth.actor,
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    outcome = result.get("outcome", "unknown")
    error = str(
        result.get("detail")
        or (result.get("verification") or {}).get("error")
        or ""
    )
    phase = "verification" if outcome == "verification_timeout" else (
        "command" if outcome == "command_failed" else ""
    )
    steps = f"{service_name}:{outcome}"
    query = {
        "refresh": "true",
        "notice": "service-action",
        "outcome": outcome,
        "service": service_name,
        "action": action_name,
        "phase": phase,
        "error": error[:400],
        "steps": steps,
    }
    return RedirectResponse(
        url="/ui/system?" + "&".join(f"{quote(key)}={quote(value)}" for key, value in query.items() if value),
        status_code=303,
    )


@router.api_route("/system/services/start-all", methods=["GET", "POST"])
async def ui_system_start_all(request: Request, auth: UiAuth) -> Response:
    if not can(auth, TokenCapability.ADMIN):
        raise HTTPException(status_code=403, detail="admin capability required")
    service: ReviewService = request.app.state.review_service
    result = await service.service_lifecycle.start_all_prerequisites(
        actor=auth.actor,
        include_degraded=True,
    )
    outcome = result.get("outcome", "unknown")
    failed = result.get("failed_service") or ""
    phase = result.get("failed_phase") or ""
    started = ",".join(
        step["service"]
        for step in result.get("steps", [])
        if step.get("phase") == "complete"
    )
    skipped = ",".join(
        step["service"]
        for step in result.get("steps", [])
        if step.get("phase") == "skipped"
    )
    error = str(result.get("error") or "")
    if not error and failed:
        for step in reversed(result.get("steps", [])):
            if step.get("service") == failed:
                error = str(
                    step.get("error")
                    or (step.get("verification") or {}).get("error")
                    or step.get("command_outcome")
                    or ""
                )
                break
    steps = ";".join(
        f"{step['service']}:{step.get('outcome') or step.get('phase') or 'unknown'}"
        for step in result.get("steps", [])
    )
    query = {
        "refresh": "true",
        "notice": "start-all",
        "outcome": outcome,
        "failed": failed,
        "phase": phase,
        "started": started,
        "skipped": skipped,
        "error": error[:400],
        "steps": steps,
    }
    return RedirectResponse(
        url="/ui/system?" + "&".join(f"{quote(key)}={quote(value)}" for key, value in query.items() if value),
        status_code=303,
    )


@router.post("/system/reference/sync")
async def ui_system_reference_sync(request: Request, auth: UiAuth) -> Response:
    if not can(auth, TokenCapability.ADMIN):
        raise HTTPException(status_code=403, detail="admin capability required")
    form = await request.form()
    fetch_nvd = form.get("fetch_nvd") == "true"
    phrase = str(form.get("confirmation_phrase", ""))
    if fetch_nvd and phrase != "SYNC WITH NVD EGRESS":
        raise HTTPException(status_code=400, detail="NVD fetch requires confirmation phrase.")
    import os
    from pathlib import Path

    from shift_left.config import resolve_repo_root
    from shift_left.reference.sync import sync_reference_cache

    service: ReviewService = request.app.state.review_service
    config = request.app.state.config
    cache_dir = Path(config.reference_data.cache_dir)
    if not cache_dir.is_absolute():
        cache_dir = resolve_repo_root() / cache_dir
    seed_dir = resolve_repo_root() / "reference-seed"
    nvd_key = os.environ.get(config.reference_data.nvd_api_key_env or "NVD_API_KEY")
    sync_reference_cache(
        cache_dir,
        seed_dir=seed_dir if seed_dir.is_dir() else None,
        fetch_nvd=fetch_nvd,
        nvd_api_key=nvd_key,
    )
    service.audit.log(
        actor=auth.actor,
        action="reference.sync",
        subject=str(cache_dir),
        details={"fetch_nvd": fetch_nvd, "operator_initiated_egress": fetch_nvd},
    )
    return RedirectResponse(url="/ui/system/evidence?notice=reference-synced", status_code=303)


@router.get("/triage")
async def ui_triage_redirect() -> RedirectResponse:
    return RedirectResponse(url="/ui/investigations", status_code=301)


@router.get("/investigations/live-state.json")
async def ui_investigations_list_live_state(
    request: Request,
    page: int = Query(default=1, ge=1),
) -> JSONResponse:
    _require_triage_ui_auth(request)
    store: InvestigationStore = request.app.state.investigation_store
    runner = getattr(request.app.state, "investigation_runner", None)
    payload = build_investigation_list_live_state(store, runner, page=page)
    return JSONResponse(payload)


@router.get("/investigations/{investigation_id}/live-state.json")
async def ui_investigation_detail_live_state(
    request: Request,
    investigation_id: str,
) -> JSONResponse:
    _require_triage_ui_auth(request)
    store: InvestigationStore = request.app.state.investigation_store
    payload = build_investigation_detail_live_state(store, investigation_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return JSONResponse(payload)


@router.get("/investigations", response_class=HTMLResponse)
async def ui_investigations_list(
    request: Request,
    page: int = Query(default=1, ge=1),
    notice: str | None = None,
    error: str | None = None,
    task_cwe: str = Query(default=""),
    task_cwe_description: str = Query(default=""),
) -> HTMLResponse:
    auth = _require_triage_ui_auth(request)
    config = request.app.state.config
    store: InvestigationStore = request.app.state.investigation_store
    triage: AntaresTriageService = request.app.state.triage_service
    preflight = await build_launch_preflight(config, triage._client)
    launch_form = build_launch_form_view(
        preflight,
        error=error,
        notice=notice,
        default_task_cwe=task_cwe,
        default_task_cwe_description=task_cwe_description,
        queue_depth=store.count_queued(),
        queue_depth_cap=config.investigations.queue_depth_cap,
    )
    return await _investigations_page(request, auth, launch_form=launch_form, page=page)


@router.post("/investigations/preview", response_class=HTMLResponse)
async def ui_investigations_preview(request: Request) -> HTMLResponse:
    auth = _require_triage_ui_auth(request)
    config = request.app.state.config
    store: InvestigationStore = request.app.state.investigation_store
    triage: AntaresTriageService = request.app.state.triage_service
    fields = _form_values(await request.form())
    source = fields["source"]
    if source not in {"top25", "profiled", "custom"}:
        launch_form = await _launch_form_from_error(
            request,
            error="Preview is available for Top 25, profiled, and custom sources.",
            fields=fields,
        )
        return await _investigations_page(request, auth, launch_form=launch_form, status_code=400)
    try:
        preview = await preview_investigation_batch(
            config=config,
            store=store,
            triage=triage,
            request=_batch_request_from_fields(fields),
        )
    except (LaunchRejectedError, GitCheckoutError) as exc:
        launch_form = await _launch_form_from_error(request, error=str(exc), fields=fields)
        return await _investigations_page(request, auth, launch_form=launch_form, status_code=400)
    preflight = await build_launch_preflight(config, triage._client)
    launch_form = build_launch_form_view(
        preflight,
        source=source,
        snapshot_scope=fields["snapshot_scope"],
        snapshot_base_ref=fields["snapshot_base_ref"],
        repo=fields["repo"],
        ref=fields["ref"],
        default_task_cwe=fields["task_cwe"],
        default_task_cwe_description=fields["task_cwe_description"],
        exclude_test_paths=fields["exclude_test_paths"],
        queue_depth=store.count_queued(),
        queue_depth_cap=config.investigations.queue_depth_cap,
        preview=preview,
        selected_catalog_cwes=fields["custom_cwes"],
    )
    return await _investigations_page(request, auth, launch_form=launch_form)


@router.post("/investigations", response_class=HTMLResponse)
async def ui_investigations_launch(request: Request) -> HTMLResponse:
    auth = _require_triage_ui_auth(request)
    config = request.app.state.config
    store: InvestigationStore = request.app.state.investigation_store
    triage: AntaresTriageService = request.app.state.triage_service
    fields = _form_values(await request.form())
    source = fields["source"]
    try:
        if source == "single":
            await launch_investigation(
                config=config,
                store=store,
                triage=triage,
                actor=auth.actor,
                request=LaunchRequest(
                    repo=fields["repo"],
                    ref=fields["ref"],
                    task_cwe=fields["task_cwe"] or None,
                    task_cwe_description=fields["task_cwe_description"] or None,
                    advisory_cve=fields["advisory_cve"] or None,
                    exclude_test_paths=fields["exclude_test_paths"],
                    snapshot_scope=fields["snapshot_scope"],
                    snapshot_base_ref=fields["snapshot_base_ref"],
                ),
            )
            return RedirectResponse(
                url="/ui/investigations?notice=Investigation+queued",
                status_code=303,
            )
        if source in {"top25", "profiled"} and not fields["previewed"]:
            raise LaunchRejectedError(
                "Preview members against this repo and ref before launching a batch."
            )
        if source not in {"top25", "profiled", "custom"}:
            raise LaunchRejectedError(f"Unknown source: {source!r}")
        result = await launch_investigation_batch(
            config=config,
            store=store,
            triage=triage,
            actor=auth.actor,
            request=_batch_request_from_fields(fields),
        )
    except (LaunchRejectedError, GitCheckoutError) as exc:
        preview = None
        if source in {"top25", "profiled"} and fields["previewed"]:
            try:
                preview = await preview_investigation_batch(
                    config=config,
                    store=store,
                    triage=triage,
                    request=_batch_request_from_fields(fields),
                )
            except (LaunchRejectedError, GitCheckoutError):
                preview = None
        launch_form = await _launch_form_from_error(
            request, error=str(exc), fields=fields, preview=preview
        )
        return await _investigations_page(request, auth, launch_form=launch_form, status_code=400)
    return RedirectResponse(
        url=f"/ui/investigations/batches/{result.batch.batch_id}?notice=Batch+queued",
        status_code=303,
    )


@router.post("/investigations/batch", response_class=HTMLResponse)
async def ui_investigations_batch_launch(request: Request) -> HTMLResponse:
    return await ui_investigations_launch(request)


@router.get("/investigations/batches/{batch_id}", response_class=HTMLResponse)
async def ui_investigation_batch_detail(
    request: Request,
    batch_id: str,
) -> HTMLResponse:
    auth = _require_triage_ui_auth(request)
    store: InvestigationStore = request.app.state.investigation_store
    batch = store.get_batch(batch_id)
    if batch is None:
        raise HTTPException(status_code=404, detail="Batch not found")
    batch_view = build_investigation_batch_view(store, batch)
    return templates.TemplateResponse(
        request,
        "investigation_batch.html",
        _ctx(request, auth, batch_view=batch_view),
    )


@router.post("/investigations/batches/{batch_id}/cancel", response_class=HTMLResponse)
async def ui_investigation_batch_cancel(
    request: Request,
    batch_id: str,
) -> HTMLResponse:
    auth = _require_triage_ui_auth(request)
    try:
        await cancel_investigation_batch(
            store=request.app.state.investigation_store,
            triage=request.app.state.triage_service,
            cancel_registry=request.app.state.investigation_cancel_registry,
            batch_id=batch_id,
            actor=auth.actor,
        )
    except BatchLifecycleRejectedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError:
        raise HTTPException(status_code=404, detail="Batch not found")
    return RedirectResponse(
        url=f"/ui/investigations/batches/{batch_id}?notice=Batch+cancelled",
        status_code=303,
    )


@router.post("/investigations/{investigation_id}/cancel", response_class=HTMLResponse)
async def ui_investigation_cancel(
    request: Request,
    investigation_id: str,
) -> HTMLResponse:
    auth = _require_triage_ui_auth(request)
    try:
        await cancel_investigation(
            store=request.app.state.investigation_store,
            triage=request.app.state.triage_service,
            cancel_registry=request.app.state.investigation_cancel_registry,
            investigation_id=investigation_id,
            actor=auth.actor,
        )
    except LifecycleRejectedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return RedirectResponse(
        url=f"/ui/investigations/{investigation_id}?notice=Investigation+cancelled",
        status_code=303,
    )


@router.post("/investigations/{investigation_id}/rerun", response_class=HTMLResponse)
async def ui_investigation_rerun(
    request: Request,
    investigation_id: str,
) -> HTMLResponse:
    auth = _require_triage_ui_auth(request)
    try:
        record = await rerun_investigation(
            config=request.app.state.config,
            store=request.app.state.investigation_store,
            triage=request.app.state.triage_service,
            investigation_id=investigation_id,
            actor=auth.actor,
        )
    except LaunchRejectedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return RedirectResponse(
        url=f"/ui/investigations/{record.investigation_id}?notice=Re-run+queued",
        status_code=303,
    )


@router.get("/investigations/{investigation_id}", response_class=HTMLResponse)
async def ui_investigation_detail(
    request: Request,
    investigation_id: str,
) -> HTMLResponse:
    auth = _require_triage_ui_auth(request)
    config = request.app.state.config
    store: InvestigationStore = request.app.state.investigation_store
    review: ReviewService = request.app.state.review_service
    detail = build_investigation_detail_view(
        store,
        review.audit,
        config,
        investigation_id,
        can_edit_disposition=can(auth, TokenCapability.TRIAGE),
    )
    if detail is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return templates.TemplateResponse(
        request,
        "investigation_detail.html",
        _ctx(request, auth, detail=detail),
    )


@router.post(
    "/investigations/{investigation_id}/candidates/{submission_rank}/disposition",
    response_class=HTMLResponse,
)
async def ui_investigation_candidate_disposition(
    request: Request,
    investigation_id: str,
    submission_rank: int,
    disposition: Annotated[str, Form()],
    note: Annotated[str, Form()] = "",
) -> Response:
    auth = _require_triage_ui_auth(request)
    store: InvestigationStore = request.app.state.investigation_store
    try:
        parsed = parse_disposition(disposition)
    except DispositionUpdateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        update_candidate_disposition(
            store,
            investigation_id=investigation_id,
            submission_rank=submission_rank,
            disposition=parsed,
            actor=auth.actor,
            note=note or None,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return RedirectResponse(
        url=f"/ui/investigations/{investigation_id}?notice=Disposition+updated",
        status_code=303,
    )


@router.get("/investigations/{investigation_id}/trace", response_class=HTMLResponse)
async def ui_investigation_trace(
    request: Request,
    investigation_id: str,
    fragment: bool = Query(default=False),
) -> HTMLResponse:
    auth = _require_triage_ui_auth(request)
    store: InvestigationStore = request.app.state.investigation_store
    if fragment:
        built = build_investigation_trace_fragment(store, investigation_id)
        if built is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        trace_turn_count, trace_turns = built
        return templates.TemplateResponse(
            request,
            "investigation_trace_fragment.html",
            _ctx(
                request,
                auth,
                trace_turns=trace_turns,
                trace_turn_count=trace_turn_count,
            ),
        )
    built = build_investigation_trace_view(store, investigation_id)
    if built is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    detail, trace_turns = built
    return templates.TemplateResponse(
        request,
        "investigation_trace.html",
        _ctx(request, auth, detail=detail, trace_turns=trace_turns),
    )


def mount_ui_static(app) -> None:
    static_dir = _UI_DIR / "static"
    app.mount("/ui/static", StaticFiles(directory=str(static_dir)), name="ui-static")
