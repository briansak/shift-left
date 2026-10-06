"""OpenAPI metadata applied to orchestrator routes before the spec is emitted.

``docs/openapi.yaml`` and ``docs/openapi.json`` are generated from the FastAPI
app. Do not hand-edit those files.
"""

from __future__ import annotations

import copy
from typing import Any, Literal

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
from pydantic import BaseModel

from shift_left.api.openapi_models import (
    REVIEW_REQUEST_EXAMPLE,
    REVIEW_RESPONSE_EXAMPLE,
    SYNTHETIC_TOKEN,
    AntaresTriageResponse,
    ApprovalListResponse,
    ApprovalRecord,
    ApprovalRevokeResponse,
    AuditEventListResponse,
    AuditExportResponse,
    BlockOverrideRecord,
    CandidateDispositionResponse,
    ChangeStateResult,
    ConfigChangeListResponse,
    DeploymentGateResult,
    Finding,
    FindingsListResponse,
    FindingWaiverRecord,
    HealthResponse,
    InvestigationBatchLaunchResponse,
    InvestigationLaunchResponse,
    InvestigationStateResponse,
    JsonObjectResponse,
    PolicyDocumentResponse,
    PolicyValidateResponse,
    PullRequestPolicyDecision,
    ReviewResult,
    SandboxAuditIngestResponse,
    SelfCheckResponse,
    TerraformPlanRecord,
    TokenIdentityResponse,
)

TAG_REVIEW = "Review"
TAG_FINDINGS = "Findings"
TAG_POLICY_GATE = "Policy and Gate"
TAG_APPROVALS = "Approvals and Waivers"
TAG_INVESTIGATIONS = "Investigations"
TAG_AUDIT = "Audit"
TAG_SYSTEM = "System"
TAG_INTERNAL = "Internal"

AuthKind = Literal[
    "none",
    "any_token",
    "review",
    "triage",
    "approve",
    "override",
    "deploy",
    "admin",
    "triage_or_approve",
    "slat_or_triage",
    "ui_cookie",
]

Audience = Literal["automation", "ui", "internal"]

SECURITY_SCHEME_NAME = "shiftLeftToken"

SECURITY_SCHEME: dict[str, Any] = {
    "type": "http",
    "scheme": "bearer",
    "bearerFormat": "slt_",
    "description": (
        "Operator API token minted by `./shift-left token mint` "
        f"(example value `{SYNTHETIC_TOKEN}`, never a live token).\n\n"
        "Send `Authorization: Bearer slt_…` or `X-Shift-Left-Token: slt_…`. "
        "Actor identity always comes from the token; JSON bodies must not include "
        "`actor` or `approver`.\n\n"
        "Capabilities (also see docs/auth-tokens.md):\n"
        "- **review** — `POST /api/v1/review`\n"
        "- **triage** — finding status, non-BLOCK waivers, investigations\n"
        "- **approve** — grant/revoke approvals; BLOCK-level waivers\n"
        "- **admin** — all of the above, plus system settings and service lifecycle\n"
        "- **override** — block overrides when `policy.allow_block_override` is true\n"
        "- **deploy** — plan-only Terraform\n\n"
        "`admin` implies the others. The API listens on loopback of the operator host; "
        "a hosted OpenAPI page cannot call it."
    ),
}

SERVERS: list[dict[str, str]] = [
    {
        "url": "http://127.0.0.1:8080",
        "description": (
            "Operator-host loopback. The orchestrator binds locally and is not "
            "reachable from GitHub Pages or other remote clients."
        ),
    }
]

OPENAPI_TAGS: list[dict[str, Any]] = [
    {
        "name": TAG_REVIEW,
        "description": "Automation: run a PR review and read config-change workflow state.",
    },
    {
        "name": TAG_FINDINGS,
        "description": "Automation: stored handler and advisory findings for a PR.",
    },
    {
        "name": TAG_POLICY_GATE,
        "description": "Automation: policy document, recorded decisions, and the deployment gate.",
    },
    {
        "name": TAG_APPROVALS,
        "description": "Automation: SHA-bound approvals, waivers, and block overrides.",
    },
    {
        "name": TAG_INVESTIGATIONS,
        "description": "Automation: Antares CWE localization. Advisory only; never a merge gate.",
    },
    {
        "name": TAG_AUDIT,
        "description": "Automation: append-only audit log (redacted).",
    },
    {
        "name": TAG_SYSTEM,
        "description": (
            "Liveness plus operator system JSON used by the local UI. "
            "`GET /health` and `GET /self-check` are unauthenticated; the rest need a token."
        ),
    },
    {
        "name": TAG_INTERNAL,
        "description": (
            "Not for CI automation. Includes the Antares sandbox callback "
            "(`slat_…` token), UI-backing JSON (`/api/v1/me`, PR context, system pages), "
            "and server-rendered `/ui/*` HTML."
        ),
    },
]


def _auth_sentence(kind: AuthKind) -> str:
    mapping = {
        "none": "Unauthenticated.",
        "any_token": "Requires any valid bearer token (no specific capability).",
        "review": "Requires the **review** capability.",
        "triage": "Requires the **triage** capability.",
        "approve": "Requires the **approve** capability.",
        "override": "Requires the **override** capability.",
        "deploy": "Requires the **deploy** capability.",
        "admin": "Requires the **admin** capability.",
        "triage_or_approve": (
            "Requires **triage** or **approve**. BLOCK-level registry findings need **approve**."
        ),
        "slat_or_triage": (
            "Internal callback: `Authorization: Bearer slat_…` (per-run sandbox secret) "
            "or a **triage**-capable `slt_…` token. Not a UI session."
        ),
        "ui_cookie": (
            "UI-backing: operator login cookie (`shift_left_token`), not a CI bearer token. "
            "Not intended as an automation API."
        ),
    }
    return mapping[kind]


def _audience_sentence(audience: Audience) -> str:
    if audience == "automation":
        return "Intended for automation (CI, scripts)."
    if audience == "ui":
        return "UI-backing route for the local operator UI — not for CI automation."
    return "Internal service-to-service route — not for operators or CI."


class RouteDoc:
    __slots__ = ("tag", "summary", "description", "response_model", "auth", "audience", "html")

    def __init__(
        self,
        tag: str,
        summary: str,
        description: str,
        *,
        response_model: type[BaseModel] | None = None,
        auth: AuthKind,
        audience: Audience,
        html: bool = False,
    ) -> None:
        extra = f"{_audience_sentence(audience)} {_auth_sentence(auth)}"
        self.tag = tag
        self.summary = summary
        self.description = f"{description.rstrip()} {extra}".strip()
        self.response_model = response_model
        self.auth = auth
        self.audience = audience
        self.html = html


ROUTE_DOCS: dict[tuple[str, str], RouteDoc] = {
    ("GET", "/health"): RouteDoc(
        TAG_SYSTEM,
        "Health",
        "Liveness and readiness of the orchestrator and its local dependencies.",
        response_model=HealthResponse,
        auth="none",
        audience="automation",
    ),
    ("GET", "/self-check"): RouteDoc(
        TAG_SYSTEM,
        "Startup self-check",
        "Runs the same startup checks as process boot (sovereignty, models, git).",
        response_model=SelfCheckResponse,
        auth="none",
        audience="automation",
    ),
    ("POST", "/api/v1/review"): RouteDoc(
        TAG_REVIEW,
        "Review a pull request",
        "Fetch the PR diff, run deterministic handlers, evaluate policy, persist findings, "
        "and publish the gate status. Advisory (model-only) findings and `review_summary` are "
        "omitted from the response when `advisory_suppression.omit_from_review_api` is true "
        "(the default). Retrieve advisory findings from GET /api/v1/findings/{owner}/{repo}/{pr_number} "
        "or GET /api/v1/pr/{owner}/{repo}/{pr_number}/context.",
        response_model=ReviewResult,
        auth="review",
        audience="automation",
    ),
    ("GET", "/api/v1/findings/{owner}/{repo}/{pr_number}"): RouteDoc(
        TAG_FINDINGS,
        "List findings for a pull request",
        "Returns stored findings for the PR, including advisory findings, with secret redaction applied. "
        "This handler does not declare a token dependency in code.",
        response_model=FindingsListResponse,
        auth="none",
        audience="automation",
    ),
    ("PATCH", "/api/v1/findings/{finding_id}/status"): RouteDoc(
        TAG_FINDINGS,
        "Update finding status",
        "Set a finding status (open, acknowledged, false_positive, accepted_risk, resolved). "
        "`false_positive` and `accepted_risk` require a rationale.",
        response_model=Finding,
        auth="triage",
        audience="automation",
    ),
    ("GET", "/api/v1/policy"): RouteDoc(
        TAG_POLICY_GATE,
        "Read loaded policy",
        "Returns the in-memory policy document. Editing YAML and restarting the orchestrator "
        "is required to change it. This handler does not declare a token dependency in code.",
        response_model=PolicyDocumentResponse,
        auth="none",
        audience="automation",
    ),
    ("POST", "/api/v1/policy/validate"): RouteDoc(
        TAG_POLICY_GATE,
        "Validate a policy document",
        "Checks a candidate policy for load-time errors without applying it. "
        "This handler does not declare a token dependency in code.",
        response_model=PolicyValidateResponse,
        auth="none",
        audience="automation",
    ),
    ("GET", "/api/v1/policy/decision/{owner}/{repo}/{pr_number}"): RouteDoc(
        TAG_POLICY_GATE,
        "Read policy decision",
        "Latest (or SHA-specific) policy decision for a PR. When `commit_sha` is supplied, "
        "active waivers are applied. This handler does not declare a token dependency in code.",
        response_model=PullRequestPolicyDecision,
        auth="none",
        audience="automation",
    ),
    ("POST", "/api/v1/approvals/{owner}/{repo}/{pr_number}"): RouteDoc(
        TAG_APPROVALS,
        "Grant approval",
        "Bind a human approval to a commit SHA. Client-supplied actor fields are rejected.",
        response_model=ApprovalRecord,
        auth="approve",
        audience="automation",
    ),
    ("DELETE", "/api/v1/approvals/{owner}/{repo}/{pr_number}"): RouteDoc(
        TAG_APPROVALS,
        "Revoke approval",
        "Revoke approvals on the PR.",
        response_model=ApprovalRevokeResponse,
        auth="approve",
        audience="automation",
    ),
    ("GET", "/api/v1/approvals/{owner}/{repo}/{pr_number}"): RouteDoc(
        TAG_APPROVALS,
        "List approvals",
        "Approval records for a PR with redacted snapshots. UI-backing JSON; usable from scripts too. "
        "This handler does not declare a token dependency in code.",
        response_model=ApprovalListResponse,
        auth="none",
        audience="ui",
    ),
    ("POST", "/api/v1/overrides/{owner}/{repo}/{pr_number}"): RouteDoc(
        TAG_APPROVALS,
        "Override a block decision",
        "Record a block override with justification. Also requires `policy.allow_block_override=true`.",
        response_model=BlockOverrideRecord,
        auth="override",
        audience="automation",
    ),
    ("POST", "/api/v1/waivers/{owner}/{repo}/{pr_number}"): RouteDoc(
        TAG_APPROVALS,
        "Grant a finding waiver",
        "SHA-bound waiver identified by path, construct key, and weakness class.",
        response_model=FindingWaiverRecord,
        auth="triage_or_approve",
        audience="automation",
    ),
    ("GET", "/api/v1/gate/{owner}/{repo}/{pr_number}"): RouteDoc(
        TAG_POLICY_GATE,
        "Evaluate and publish the deployment gate",
        "Computes allow/block for the given commit SHA and publishes commit status `shift-left/gate`. "
        "This handler does not declare a token dependency in code.",
        response_model=DeploymentGateResult,
        auth="none",
        audience="automation",
    ),
    ("GET", "/api/v1/changes"): RouteDoc(
        TAG_REVIEW,
        "List config changes",
        "Open PRs the viewer can see, with server-computed workflow state.",
        response_model=ConfigChangeListResponse,
        auth="any_token",
        audience="ui",
    ),
    ("GET", "/api/v1/changes/{owner}/{repo}/{pr_number}/state"): RouteDoc(
        TAG_REVIEW,
        "Change workflow state",
        "Server-computed state for one PR. Clients must not derive this locally.",
        response_model=ChangeStateResult,
        auth="any_token",
        audience="automation",
    ),
    ("POST", "/api/v1/changes/{owner}/{repo}/{pr_number}/plan"): RouteDoc(
        TAG_REVIEW,
        "Generate a Terraform plan",
        "Plan-only FMC Terraform against the configured workdir. Apply is not implemented.",
        response_model=TerraformPlanRecord,
        auth="deploy",
        audience="automation",
    ),
    ("POST", "/api/v1/investigations"): RouteDoc(
        TAG_INVESTIGATIONS,
        "Launch an Antares investigation",
        "Queue one CWE localization run against a materialized snapshot. Not part of the merge gate.",
        response_model=InvestigationLaunchResponse,
        auth="triage",
        audience="automation",
    ),
    ("POST", "/api/v1/investigation-batches"): RouteDoc(
        TAG_INVESTIGATIONS,
        "Launch an investigation batch",
        "Queue multiple CWE queries (profiled, top25, or custom).",
        response_model=InvestigationBatchLaunchResponse,
        auth="triage",
        audience="automation",
    ),
    ("POST", "/api/v1/investigations/{investigation_id}/cancel"): RouteDoc(
        TAG_INVESTIGATIONS,
        "Cancel an investigation",
        "Request cancel. In-flight model generation may finish the current turn before stopping.",
        response_model=InvestigationStateResponse,
        auth="triage",
        audience="automation",
    ),
    ("POST", "/api/v1/investigations/{investigation_id}/rerun"): RouteDoc(
        TAG_INVESTIGATIONS,
        "Rerun an investigation",
        "Launch a new run from an existing investigation's inputs.",
        response_model=InvestigationStateResponse,
        auth="triage",
        audience="automation",
    ),
    (
        "PATCH",
        "/api/v1/investigations/{investigation_id}/candidates/{submission_rank}/disposition",
    ): RouteDoc(
        TAG_INVESTIGATIONS,
        "Set candidate disposition",
        "Record a human disposition on a ranked candidate file.",
        response_model=CandidateDispositionResponse,
        auth="triage",
        audience="automation",
    ),
    ("POST", "/api/v1/triage/antares"): RouteDoc(
        TAG_INVESTIGATIONS,
        "Run Antares triage (legacy entry)",
        "Synchronous CWE localization. Prefer POST /api/v1/investigations for queued UI-backed runs.",
        response_model=AntaresTriageResponse,
        auth="triage",
        audience="automation",
    ),
    ("POST", "/api/v1/internal/antares/sandbox-command-audit"): RouteDoc(
        TAG_INTERNAL,
        "Ingest sandbox command audit",
        "Called by antares-server at command dispatch and again when execute returns.",
        response_model=SandboxAuditIngestResponse,
        auth="slat_or_triage",
        audience="internal",
    ),
    ("GET", "/api/v1/audit/events"): RouteDoc(
        TAG_AUDIT,
        "List audit events",
        "Filter by actor, action, subject_prefix, since. Default limit 200, max 1000. Redacted. "
        "This handler does not declare a token dependency in code.",
        response_model=AuditEventListResponse,
        auth="none",
        audience="automation",
    ),
    ("GET", "/api/v1/audit/export"): RouteDoc(
        TAG_AUDIT,
        "Export audit events",
        "Full JSON export of the audit log with redaction applied. No pagination. "
        "This handler does not declare a token dependency in code.",
        response_model=AuditExportResponse,
        auth="none",
        audience="automation",
    ),
    ("GET", "/api/v1/me"): RouteDoc(
        TAG_INTERNAL,
        "Current token identity",
        "Actor, capabilities, and token id for the bearer token.",
        response_model=TokenIdentityResponse,
        auth="any_token",
        audience="ui",
    ),
    ("GET", "/api/v1/findings"): RouteDoc(
        TAG_INTERNAL,
        "Filter findings",
        "Cross-PR finding list with optional filters. Advisory findings are included. "
        "Limit default 200, max 1000. This handler does not declare a token dependency in code.",
        response_model=FindingsListResponse,
        auth="none",
        audience="ui",
    ),
    ("GET", "/api/v1/pr/{owner}/{repo}/{pr_number}/context"): RouteDoc(
        TAG_INTERNAL,
        "PR review context",
        "Findings, file views, policy, gate, and analysis failure details for the PR review page. "
        "This handler does not declare a token dependency in code.",
        response_model=JsonObjectResponse,
        auth="none",
        audience="ui",
    ),
    ("GET", "/api/v1/system/status"): RouteDoc(
        TAG_SYSTEM,
        "System status",
        "Health, service lifecycle, sovereignty probe, and settings snapshots for the system page. "
        "This handler does not declare a token dependency in code.",
        response_model=JsonObjectResponse,
        auth="none",
        audience="ui",
    ),
    ("GET", "/api/v1/system/prerequisites"): RouteDoc(
        TAG_SYSTEM,
        "Prerequisite report",
        "The prerequisite subset of system status. This handler does not declare a token dependency in code.",
        response_model=JsonObjectResponse,
        auth="none",
        audience="ui",
    ),
    ("PATCH", "/api/v1/system/settings/tier3"): RouteDoc(
        TAG_SYSTEM,
        "Update operator-mutable settings",
        "Validated updates to model paths, load strategy, and related keys. "
        "Quant and path changes still need a model-server restart.",
        response_model=JsonObjectResponse,
        auth="admin",
        audience="ui",
    ),
    ("PATCH", "/api/v1/system/settings/rbac/allow-self-approval"): RouteDoc(
        TAG_SYSTEM,
        "Toggle self-approval",
        "Development-only RBAC escape hatch. Requires a confirmation phrase.",
        response_model=JsonObjectResponse,
        auth="admin",
        audience="ui",
    ),
    ("POST", "/api/v1/system/settings/immutable-probe"): RouteDoc(
        TAG_SYSTEM,
        "Probe immutable settings",
        "Always refuses sovereignty/install mutations. Used by the UI to show that those keys are locked.",
        response_model=JsonObjectResponse,
        auth="admin",
        audience="ui",
    ),
    ("POST", "/api/v1/system/services/action"): RouteDoc(
        TAG_SYSTEM,
        "Start, stop, or restart a named service",
        "Fixed allowlisted Compose/model-server actions.",
        response_model=JsonObjectResponse,
        auth="admin",
        audience="ui",
    ),
    ("POST", "/api/v1/system/services/start-all"): RouteDoc(
        TAG_SYSTEM,
        "Start prerequisite services",
        "Start the dependency chain for a healthy stack.",
        response_model=JsonObjectResponse,
        auth="admin",
        audience="ui",
    ),
    ("POST", "/api/v1/system/reference/sync"): RouteDoc(
        TAG_SYSTEM,
        "Sync reference data",
        "Refresh the local CVE/CWE cache. NVD fetch requires confirmation phrase `SYNC WITH NVD EGRESS`.",
        response_model=JsonObjectResponse,
        auth="admin",
        audience="ui",
    ),
}

UI_SUMMARIES: dict[tuple[str, str], str] = {
    ("GET", "/ui/"): "UI home",
    ("GET", "/ui/login"): "Login form",
    ("POST", "/ui/login"): "Submit login",
    ("POST", "/ui/logout"): "Log out",
    ("GET", "/ui/targets"): "Managed targets list",
    ("GET", "/ui/targets/new"): "New target form",
    ("POST", "/ui/targets/new"): "Create managed target",
    ("GET", "/ui/targets/{target_id}"): "Target detail",
    ("POST", "/ui/targets/{target_id}/plan"): "Generate plan from target page",
    ("GET", "/ui/changes"): "Changes list",
    ("GET", "/ui/findings"): "Findings list",
    ("GET", "/ui/pr/{owner}/{repo}/{pr_number}"): "PR review page",
    ("POST", "/ui/pr/{owner}/{repo}/{pr_number}/finding/{finding_id}/status"): "Update finding status from UI",
    ("POST", "/ui/pr/{owner}/{repo}/{pr_number}/finding/{finding_id}/waiver"): "Grant waiver from UI",
    ("POST", "/ui/pr/{owner}/{repo}/{pr_number}/approve"): "Approve from UI",
    ("POST", "/ui/pr/{owner}/{repo}/{pr_number}/override"): "Override from UI",
    ("POST", "/ui/pr/{owner}/{repo}/{pr_number}/plan"): "Generate plan from PR page",
    ("GET", "/ui/cwe"): "CWE reference catalog",
    ("GET", "/ui/coverage"): "Handler coverage",
    ("GET", "/ui/policy"): "Policy page",
    ("GET", "/ui/audit"): "Audit log",
    ("GET", "/ui/system"): "System health",
    ("GET", "/ui/system/config"): "System configuration",
    ("GET", "/ui/system/evidence"): "System evidence",
    ("GET", "/ui/health"): "Health page (alias)",
    ("POST", "/ui/system/settings/tier3"): "Save operator-mutable settings from UI",
    ("POST", "/ui/system/settings/rbac"): "Save RBAC override from UI",
    ("POST", "/ui/system/reference/sync"): "Sync reference data from UI",
    ("GET", "/ui/system/service/{service_name}/{action_name}"): "Service lifecycle form",
    ("POST", "/ui/system/service/{service_name}/{action_name}"): "Run service lifecycle action from UI",
    ("GET", "/ui/system/services/start-all"): "Start-all services form",
    ("POST", "/ui/system/services/start-all"): "Start all prerequisite services from UI",
    ("GET", "/ui/triage"): "Redirect to investigations",
    ("GET", "/ui/investigations/live-state.json"): "Investigations live state",
    ("GET", "/ui/investigations/{investigation_id}/live-state.json"): "Investigation live state",
    ("GET", "/ui/investigations"): "Investigations list and launch form",
    ("POST", "/ui/investigations/preview"): "Preview investigation launch",
    ("POST", "/ui/investigations"): "Launch investigation from UI",
    ("POST", "/ui/investigations/batch"): "Launch investigation batch from UI",
    ("GET", "/ui/investigations/batches/{batch_id}"): "Investigation batch detail",
    ("POST", "/ui/investigations/batches/{batch_id}/cancel"): "Cancel investigation batch",
    ("POST", "/ui/investigations/{investigation_id}/cancel"): "Cancel investigation from UI",
    ("POST", "/ui/investigations/{investigation_id}/rerun"): "Rerun investigation from UI",
    ("GET", "/ui/investigations/{investigation_id}"): "Investigation detail",
    (
        "POST",
        "/ui/investigations/{investigation_id}/candidates/{submission_rank}/disposition",
    ): "Set candidate disposition from UI",
    ("GET", "/ui/investigations/{investigation_id}/trace"): "Investigation trace",
}

_HTML_RESPONSE: dict[str, Any] = {
    "description": "HTML page or redirect for the local operator UI. Not an automation API.",
    "content": {"text/html": {"schema": {"type": "string"}}},
}

_JSON_OBJECT_RESPONSE: dict[str, Any] = {
    "description": "JSON used by the local operator UI. Not an automation API.",
    "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}},
}


def iter_api_routes(app: FastAPI):
    for route in app.routes:
        if isinstance(route, APIRoute):
            yield route
            continue
        original = getattr(route, "original_router", None)
        if original is None:
            continue
        for inner in original.routes:
            if isinstance(inner, APIRoute):
                yield inner


def apply_openapi_metadata(app: FastAPI) -> None:
    app.openapi_tags = OPENAPI_TAGS
    app.servers = SERVERS
    for route in iter_api_routes(app):
        methods = {method.upper() for method in (route.methods or set())}
        methods.discard("HEAD")
        for method in methods:
            key = (method, route.path)
            doc = ROUTE_DOCS.get(key)
            if doc is not None:
                route.tags = [doc.tag]
                route.summary = doc.summary
                route.description = doc.description
                if doc.response_model is not None and route.response_model is None:
                    route.response_model = doc.response_model
                continue
            if key in UI_SUMMARIES:
                route.tags = [TAG_INTERNAL]
                route.summary = UI_SUMMARIES[key]
                route.description = (
                    f"{UI_SUMMARIES[key]}. {_audience_sentence('ui')} {_auth_sentence('ui_cookie')}"
                )


def _operation_id(method: str, path: str) -> str:
    cleaned = (
        path.strip("/")
        .replace("{", "")
        .replace("}", "")
        .replace("/", "_")
        .replace("-", "_")
        or "root"
    )
    return f"{method.lower()}_{cleaned}"


def _security_for_auth(kind: AuthKind) -> list[dict[str, list[str]]] | list[dict]:
    if kind in {"none", "ui_cookie"}:
        return []
    return [{SECURITY_SCHEME_NAME: []}]


def _strip_token_header_params(operation: dict[str, Any]) -> None:
    params = operation.get("parameters")
    if not params:
        return
    kept = [
        item
        for item in params
        if not (
            item.get("in") == "header"
            and str(item.get("name", "")).lower() in {"authorization", "x-shift-left-token"}
        )
    ]
    if kept:
        operation["parameters"] = kept
    else:
        operation.pop("parameters", None)


def _inject_model_schema(
    components: dict[str, Any],
    operation: dict[str, Any],
    model: type[BaseModel],
    *,
    description: str,
) -> None:
    schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
    defs = schema.pop("$defs", {}) or schema.pop("definitions", {}) or {}
    schemas = components.setdefault("schemas", {})
    for name, definition in defs.items():
        schemas.setdefault(name, definition)
    model_name = model.__name__
    if "$ref" in schema and not defs:
        pass
    else:
        schemas.setdefault(model_name, schema)
    operation.setdefault("responses", {})
    operation["responses"]["200"] = {
        "description": description,
        "content": {
            "application/json": {
                "schema": {"$ref": f"#/components/schemas/{model_name}"},
            }
        },
    }


def _attach_review_examples(operation: dict[str, Any]) -> None:
    request_body = operation.get("requestBody") or {}
    content = request_body.get("content") or {}
    app_json = content.get("application/json")
    if isinstance(app_json, dict):
        app_json["examples"] = {
            "synthetic": {
                "summary": "Synthetic review request",
                "value": copy.deepcopy(REVIEW_REQUEST_EXAMPLE),
            }
        }
    responses = operation.setdefault("responses", {})
    ok = responses.setdefault("200", {})
    ok["description"] = (
        "Review result. Advisory (model-only) findings and `review_summary` are omitted "
        "by default (`advisory_suppression.omit_from_review_api`). Handler findings remain "
        "and drive policy."
    )
    ok_content = ok.setdefault("content", {}).setdefault("application/json", {})
    ok_content["examples"] = {
        "handler_block_advisory_omitted": {
            "summary": "Handler BLOCK with advisory findings omitted",
            "description": (
                "Advisory findings are omitted by default. The `message` field notes how many "
                "were stripped. Retrieve them from GET /api/v1/findings/{owner}/{repo}/{pr_number}."
            ),
            "value": copy.deepcopy(REVIEW_RESPONSE_EXAMPLE),
        }
    }


def build_openapi_document(app: FastAPI) -> dict[str, Any]:
    apply_openapi_metadata(app)
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=OPENAPI_TAGS,
    )
    schema["openapi"] = "3.1.0"
    schema["servers"] = SERVERS
    components = schema.setdefault("components", {})
    schemes = components.setdefault("securitySchemes", {})
    schemes[SECURITY_SCHEME_NAME] = SECURITY_SCHEME

    paths = schema.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.startswith("x-") or not isinstance(operation, dict):
                continue
            key = (method.upper(), path)
            operation["operationId"] = _operation_id(method, path)
            doc = ROUTE_DOCS.get(key)
            if doc is not None:
                operation["tags"] = [doc.tag]
                operation["summary"] = doc.summary
                operation["description"] = doc.description
                operation["security"] = _security_for_auth(doc.auth)
                _strip_token_header_params(operation)
                if doc.response_model is not None:
                    _inject_model_schema(
                        components,
                        operation,
                        doc.response_model,
                        description=doc.summary,
                    )
                if key == ("POST", "/api/v1/review"):
                    _attach_review_examples(operation)
                continue
            if key in UI_SUMMARIES or path.startswith("/ui"):
                operation["tags"] = [TAG_INTERNAL]
                operation["summary"] = UI_SUMMARIES.get(key) or operation.get("summary") or "Operator UI"
                operation["description"] = (
                    f"{operation['summary']}. {_audience_sentence('ui')} {_auth_sentence('ui_cookie')}"
                )
                operation["security"] = []
                if path.endswith(".json"):
                    operation["responses"] = {"200": copy.deepcopy(_JSON_OBJECT_RESPONSE)}
                else:
                    operation["responses"] = {"200": copy.deepcopy(_HTML_RESPONSE)}
    return schema


def missing_route_metadata(app: FastAPI) -> list[str]:
    """Return method+path strings that lack summary, description, tag, or a 200 schema."""
    apply_openapi_metadata(app)
    spec = build_openapi_document(app)
    missing: list[str] = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.startswith("x-") or not isinstance(operation, dict):
                continue
            label = f"{method.upper()} {path}"
            if not (operation.get("summary") or "").strip():
                missing.append(f"{label}: summary")
            if not (operation.get("description") or "").strip():
                missing.append(f"{label}: description")
            if not operation.get("tags"):
                missing.append(f"{label}: tag")
            responses = operation.get("responses") or {}
            ok = responses.get("200") or responses.get(200) or {}
            content = ok.get("content") or {}
            has_schema = False
            for media in content.values():
                if isinstance(media, dict) and media.get("schema"):
                    has_schema = True
            if not has_schema:
                missing.append(f"{label}: response model")
    return missing
