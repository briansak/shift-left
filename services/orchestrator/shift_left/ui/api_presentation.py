"""API and outbound presentation redaction for config-derived text.

Stored findings and audit records remain raw; every JSON/API reader applies
:redfunc:`shift_left.ui.config_redaction.redact_finding_for_display` (or helpers
here) before returning data to clients.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shift_left.handlers.config.secret_values import (
    SecretValueSet,
    extract_secret_values_from_content,
    merged_secret_values,
)
from shift_left.models.schema import ApprovalRecord, AuditEvent, Finding, ReviewResult
from shift_left.ui.config_redaction import (
    FINDING_CONFIG_TEXT_FIELDS,
    redact_display_text,
    redact_finding_for_display,
)
from shift_left.ui.secret_value_provenance import (
    SecretResolutionCache,
    build_secret_index_for_findings,
    provenance_for_finding_fields,
    secrets_for_indexed_finding,
    secrets_from_finding_fields,
)


@dataclass(frozen=True)
class ApiConfigTextSurface:
    """A FastAPI route that may return config-derived text in its JSON body."""

    method: str
    path: str
    field_paths: tuple[str, ...]
    redaction_fn: str


@dataclass(frozen=True)
class ApiConfigTextRequestSurface:
    """A FastAPI route that accepts config-derived text in its JSON request body."""

    method: str
    path: str
    field_paths: tuple[str, ...]
    redaction_fn: str


@dataclass(frozen=True)
class NonApiConfigTextSurface:
    """HTML, export, or CLI surfaces that may emit config-derived text."""

    kind: str
    path: str
    field_paths: tuple[str, ...]
    redaction_fn: str


API_CONFIG_TEXT_SURFACES: tuple[ApiConfigTextSurface, ...] = (
    ApiConfigTextSurface(
        "POST",
        "/api/v1/review",
        ("findings[].evidence", "findings[].description", "findings[].model_context"),
        "redact_review_result_for_api (handler findings only; advisory omitted)",
    ),
    ApiConfigTextSurface(
        "GET",
        "/api/v1/findings/{owner}/{repo}/{pr_number}",
        ("findings[].evidence", "findings[].description", "findings[].model_context"),
        "serialize_findings_for_api_with_provenance",
    ),
    ApiConfigTextSurface(
        "PATCH",
        "/api/v1/findings/{finding_id}/status",
        ("evidence", "description", "model_context"),
        "redact_finding_for_display",
    ),
    ApiConfigTextSurface(
        "GET",
        "/api/v1/findings",
        ("findings[].evidence", "findings[].description", "findings[].model_context"),
        "serialize_findings_for_api",
    ),
    ApiConfigTextSurface(
        "GET",
        "/api/v1/pr/{owner}/{repo}/{pr_number}/context",
        (
            "findings[].evidence",
            "findings[].description",
            "findings[].model_context",
            "model_only_findings[].evidence",
            "model_only_findings[].description",
            "file_views[].lines[].text",
        ),
        "redact_pr_review_context_for_api",
    ),
    ApiConfigTextSurface(
        "GET",
        "/api/v1/approvals/{owner}/{repo}/{pr_number}",
        ("approvals[].findings_snapshot[].evidence", "approvals[].findings_snapshot[].description"),
        "redact_approval_records_for_api",
    ),
    ApiConfigTextSurface(
        "POST",
        "/api/v1/approvals/{owner}/{repo}/{pr_number}",
        ("findings_snapshot[].evidence", "findings_snapshot[].description"),
        "redact_approval_record_for_api",
    ),
    ApiConfigTextSurface(
        "POST",
        "/api/v1/triage/antares",
        ("localization.exploration_trace", "localization.summary_text", "analysis"),
        "redact_antares_triage_for_api",
    ),
    ApiConfigTextSurface(
        "POST",
        "/api/v1/changes/{owner}/{repo}/{pr_number}/plan",
        ("output_text",),
        "deployment.terraform_plan.sanitize_secrets",
    ),
    ApiConfigTextSurface(
        "GET",
        "/api/v1/audit/events",
        ("events[].details",),
        "redact_audit_events_for_api",
    ),
    ApiConfigTextSurface(
        "GET",
        "/api/v1/audit/export",
        ("events[].details",),
        "redact_audit_events_for_api",
    ),
)

API_CONFIG_TEXT_REQUEST_SURFACES: tuple[ApiConfigTextRequestSurface, ...] = (
    ApiConfigTextRequestSurface(
        "POST",
        "/api/v1/internal/antares/sandbox-command-audit",
        ("command", "output_truncated"),
        "persist_sandbox_command_audit",
    ),
)

NON_API_CONFIG_TEXT_SURFACES: tuple[NonApiConfigTextSurface, ...] = (
    NonApiConfigTextSurface(
        "html",
        "/ui/targets/{target_id}",
        (
            "declared_files[].lines[].text",
            "findings[].matched_snippet",
            "changes[].diff_lines[].text",
            "findings[].waiver.reason",
        ),
        "target_detail_view + diff_view + config_redaction",
    ),
    NonApiConfigTextSurface(
        "html",
        "/ui/pr/{owner}/{repo}/{pr_number}",
        ("file_views[].lines[].text", "findings[].evidence", "finding_rows[].waiver.reason"),
        "diff_view + config_redaction",
    ),
    NonApiConfigTextSurface(
        "html",
        "/ui/coverage",
        (),
        "handler-coverage.json only (no live config text)",
    ),
    NonApiConfigTextSurface(
        "html",
        "/ui/audit",
        ("history_events[].payload_json",),
        "target_history_view._redact_audit_details",
    ),
    NonApiConfigTextSurface(
        "html",
        "/ui/investigations/{investigation_id}",
        (
            "candidates[].file_path",
            "trace_turns[].command",
            "trace_turns[].output_truncated",
        ),
        "investigation_view + config_redaction",
    ),
    NonApiConfigTextSurface(
        "html",
        "/ui/investigations/{investigation_id}/trace",
        (
            "trace_turns[].command",
            "trace_turns[].output_truncated",
        ),
        "investigation_view + config_redaction",
    ),
    NonApiConfigTextSurface(
        "download",
        "/api/v1/audit/export",
        ("events[].details",),
        "redact_audit_events_for_api",
    ),
    NonApiConfigTextSurface(
        "outbound",
        "forgejo_pr_comment",
        ("description", "evidence", "model_context"),
        "review.service._format_comment (handler findings only; advisory omitted)",
    ),
    NonApiConfigTextSurface(
        "outbound",
        "forgejo_commit_status",
        (),
        "gate.service description = DeploymentGateResult.reason (no finding bodies)",
    ),
    NonApiConfigTextSurface(
        "cli",
        "shift-left status",
        (),
        "prerequisite health only (no config bodies)",
    ),
)

API_ROUTES_WITHOUT_CONFIG_TEXT: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/health"),
        ("GET", "/self-check"),
        ("GET", "/api/v1/policy"),
        ("POST", "/api/v1/policy/validate"),
        ("GET", "/api/v1/policy/decision/{owner}/{repo}/{pr_number}"),
        ("DELETE", "/api/v1/approvals/{owner}/{repo}/{pr_number}"),
        ("POST", "/api/v1/overrides/{owner}/{repo}/{pr_number}"),
        ("POST", "/api/v1/waivers/{owner}/{repo}/{pr_number}"),
        ("GET", "/api/v1/gate/{owner}/{repo}/{pr_number}"),
        ("GET", "/api/v1/changes"),
        ("GET", "/api/v1/changes/{owner}/{repo}/{pr_number}/state"),
        ("GET", "/api/v1/me"),
        ("POST", "/api/v1/investigations"),
        ("POST", "/api/v1/investigation-batches"),
        ("POST", "/api/v1/investigations/{investigation_id}/cancel"),
        ("POST", "/api/v1/investigations/{investigation_id}/rerun"),
        (
            "PATCH",
            "/api/v1/investigations/{investigation_id}/candidates/{submission_rank}/disposition",
        ),
        ("GET", "/api/v1/system/status"),
        ("GET", "/api/v1/system/prerequisites"),
        ("PATCH", "/api/v1/system/settings/tier3"),
        ("PATCH", "/api/v1/system/settings/rbac/allow-self-approval"),
        ("POST", "/api/v1/system/settings/immutable-probe"),
        ("POST", "/api/v1/system/services/action"),
        ("POST", "/api/v1/system/services/start-all"),
        ("POST", "/api/v1/system/reference/sync"),
    }
)


def _secret_index_from_file_views(file_views: list[dict[str, Any]]) -> dict[str, SecretValueSet]:
    index: dict[str, SecretValueSet] = {}
    for item in file_views:
        path = item.get("path")
        stored = item.get("secret_values")
        if path and isinstance(stored, SecretValueSet):
            index[path] = stored
    return index


def _secrets_for_finding(
    finding: Any,
    secret_index: dict[str, SecretValueSet] | dict[tuple[str, str], SecretValueSet],
) -> SecretValueSet:
    if isinstance(finding, Finding) and secret_index and all(
        isinstance(key, tuple) for key in secret_index
    ):
        return secrets_for_indexed_finding(finding, secret_index)
    file_path = getattr(finding, "file_path", None)
    if isinstance(finding, dict):
        file_path = file_path or finding.get("file_path")
    secrets = merged_secret_values(secret_index, path=file_path) if secret_index else SecretValueSet.empty()
    if isinstance(finding, Finding):
        return secrets.merge(secrets_from_finding_fields(finding))
    parts: list[str] = []
    for field in FINDING_CONFIG_TEXT_FIELDS:
        value = getattr(finding, field, None) if not isinstance(finding, dict) else finding.get(field)
        if value:
            parts.append(str(value))
    if parts:
        secrets = secrets.merge(
            extract_secret_values_from_content("\n".join(parts), path=file_path)
        )
    return secrets


def redact_audit_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_display_text(value)
    if isinstance(value, dict):
        return {key: redact_audit_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_audit_value(item) for item in value]
    return value


def redact_audit_event_for_api(event: AuditEvent | dict[str, Any]) -> AuditEvent | dict[str, Any]:
    if isinstance(event, AuditEvent):
        return event.model_copy(update={"details": redact_audit_value(event.details)})
    merged = dict(event)
    if "details" in merged:
        merged["details"] = redact_audit_value(merged["details"])
    return merged


def redact_audit_events_for_api(
    events: list[Any],
    *,
    investigation_store: Any | None = None,
) -> list[Any]:
    from shift_left.investigations.audit_refs import annotate_investigation_audit_reference

    presented: list[Any] = []
    for item in events:
        redacted = redact_audit_event_for_api(item)
        presented.append(annotate_investigation_audit_reference(redacted, investigation_store))
    return presented


def redact_review_result_for_api(
    result: ReviewResult,
    *,
    omit_advisory: bool = True,
) -> ReviewResult:
    """Secret-redact and strip advisory findings from the CI review response.

    Foundation-Sec / Antares findings remain in the store and UI. ``POST /api/v1/review``
    is a Forgejo Actions contract (response body is written to the job log).
    """
    from shift_left.ui.advisory_line_attribution import is_advisory_finding

    secret_index: dict[str, SecretValueSet] = {}
    if omit_advisory:
        handler_findings = [item for item in result.findings if not is_advisory_finding(item)]
    else:
        handler_findings = list(result.findings)
    omitted = len(result.findings) - len(handler_findings)
    message = result.message
    if omitted:
        message = (
            f"{message} {omitted} advisory finding(s) omitted from this response "
            "— review them in the Shift-Left UI."
        )
    return result.model_copy(
        update={
            "findings": [
                redact_finding_for_display(
                    item,
                    secret_values=_secrets_for_finding(item, secret_index),
                )
                for item in handler_findings
            ],
            "review_summary": None if omit_advisory else result.review_summary,
            "message": message,
        }
    )


def redact_pr_review_context_for_api(context: dict[str, Any]) -> dict[str, Any]:
    payload = dict(context)
    secret_index = _secret_index_from_file_views(payload.get("file_views") or [])
    if "findings" in payload:
        payload["findings"] = [
            redact_finding_for_display(
                item,
                secret_values=_secrets_for_finding(item, secret_index),
            )
            for item in payload["findings"]
        ]
    if "model_only_findings" in payload:
        payload["model_only_findings"] = [
            redact_finding_for_display(
                item,
                secret_values=_secrets_for_finding(item, secret_index),
            )
            for item in payload["model_only_findings"]
        ]
    sanitized_views: list[dict[str, Any]] = []
    for view in payload.get("file_views") or []:
        sanitized = dict(view)
        sanitized.pop("secret_values", None)
        sanitized_views.append(sanitized)
    if sanitized_views:
        payload["file_views"] = sanitized_views
    return payload


def redact_approval_record_for_api(record: ApprovalRecord) -> ApprovalRecord:
    secret_index: dict[str, SecretValueSet] = {}
    snapshot = [
        redact_finding_for_display(
            item,
            secret_values=_secrets_for_finding(item, secret_index),
        )
        if isinstance(item, (Finding, dict))
        else item
        for item in record.findings_snapshot
    ]
    return record.model_copy(update={"findings_snapshot": snapshot})


def redact_approval_records_for_api(records: list[ApprovalRecord]) -> list[ApprovalRecord]:
    return [redact_approval_record_for_api(item) for item in records]


def redact_antares_triage_for_api(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    localization = dict(result.get("localization") or {})
    if localization.get("exploration_trace"):
        localization["exploration_trace"] = redact_display_text(str(localization["exploration_trace"]))
    if localization.get("summary_text"):
        localization["summary_text"] = redact_display_text(str(localization["summary_text"]))
    result["localization"] = localization
    if result.get("analysis") is not None:
        if isinstance(result["analysis"], str):
            result["analysis"] = redact_display_text(result["analysis"])
    return result


def serialize_findings_for_api(findings: list[Finding]) -> dict[str, Any]:
    """Finding-field extraction only (no git re-read); always reports provenance."""
    secret_index: dict[str, SecretValueSet] = {}
    redacted = [
        redact_finding_for_display(
            item,
            secret_values=_secrets_for_finding(item, secret_index),
        )
        for item in findings
    ]
    return {
        "findings": redacted,
        "value_redaction_provenance": [
            {
                "finding_id": item.id,
                "source": "finding_fields",
                "commit_sha": item.commit_sha,
                "file_path": item.file_path,
                "message": provenance_for_finding_fields(item).message,
            }
            for item in findings
        ],
    }


async def serialize_findings_for_api_with_provenance(
    findings: list[Finding],
    git: Any,
) -> dict[str, Any]:
    """Serialize stored findings with git-backed secret resolution when possible."""
    cache = SecretResolutionCache()
    index, partial_provenance = await build_secret_index_for_findings(findings, git, cache=cache)
    redacted = [
        redact_finding_for_display(
            item,
            secret_values=secrets_for_indexed_finding(item, index),
        )
        for item in findings
    ]
    provenance_by_id = {item.finding_id: item for item in partial_provenance}
    payload: dict[str, Any] = {
        "findings": redacted,
        "value_redaction_provenance": [
            {
                "finding_id": finding.id,
                "source": provenance_by_id.get(finding.id).source
                if finding.id in provenance_by_id
                else "commit_file",
                "commit_sha": finding.commit_sha,
                "file_path": finding.file_path,
                "message": provenance_by_id.get(finding.id).message
                if finding.id in provenance_by_id
                else None,
            }
            for finding in findings
        ],
    }
    return payload
