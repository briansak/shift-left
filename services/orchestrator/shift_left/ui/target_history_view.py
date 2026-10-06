"""Presentation models for the managed target History tab (governance timeline)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from shift_left.config import ManagedTargetConfig
from shift_left.models.schema import AuditEvent
from shift_left.targets.service import TargetDetail
from shift_left.ui.config_redaction import redact_display_text
from shift_left.ui.timefmt import relative_time

# Canonical audit actions shown on the target History tab. Every action here must
# have an entry in ACTION_RENDERERS (enforced by tests).
TARGET_HISTORY_ACTIONS: frozenset[str] = frozenset(
    {
        "policy.decision_rendered",
        "waiver.granted",
        "waiver.used",
        "waiver.expired",
        "waiver.expired_batch",
        "approval.granted",
        "approval.invalidated",
        "managed_target.created",
        "managed_target.edited",
        "deployment.plan_generated",
        "deployment.target_plan_generated",
        "deployment.plan_invalidated",
        "settings.changed",
        "settings.rbac_allow_self_approval",
        "config.policy_validated",
        "review.completed",
    }
)

_POLICY_CONFIG_ACTIONS = frozenset(
    {
        "settings.changed",
        "settings.rbac_allow_self_approval",
        "config.policy_validated",
    }
)

_AUDIT_FETCH_LIMIT = 2000


@dataclass(frozen=True)
class TargetHistoryDetailField:
    label: str
    value: str


@dataclass(frozen=True)
class TargetHistoryRow:
    event_id: str
    timestamp_label: str
    type_label: str
    type_pill_class: str
    actor: str
    short_sha: str
    summary: str
    changes_href: str | None = None
    dev_mode: bool = False
    detail_fields: tuple[TargetHistoryDetailField, ...] = field(default_factory=tuple)
    payload_json: str = ""


@dataclass(frozen=True)
class TargetHistoryPanel:
    declared_head_sha: str
    declared_head_short: str
    rows: tuple[TargetHistoryRow, ...]
    total_event_count: int
    displayed_event_count: int
    audit_fetch_truncated: bool
    filtered: bool
    active_action_filter: str | None
    filter_options: tuple[tuple[str, str], ...]


def _short_sha(sha: str | None) -> str:
    if not sha:
        return "—"
    return sha[:7]


def _commit_sha_from_event(event: AuditEvent) -> str | None:
    details = event.details
    for key in ("commit_sha", "new_commit_sha", "prior_commit_sha"):
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _changes_href(target_id: str, commit_sha: str | None) -> str | None:
    if not commit_sha:
        return None
    return f"/ui/targets/{target_id}?tab=changes"


def _payload_json(details: dict[str, Any]) -> str:
    redacted = _redact_audit_details(details)
    return json.dumps(redacted, indent=2, sort_keys=True, default=str)


def _redact_audit_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_display_text(value)
    if isinstance(value, dict):
        return {key: _redact_audit_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_audit_value(item) for item in value]
    return value


def _redact_audit_details(details: dict[str, Any]) -> dict[str, Any]:
    return {key: _redact_audit_value(value) for key, value in details.items()}


def _detail_fields(details: dict[str, Any]) -> tuple[TargetHistoryDetailField, ...]:
    fields: list[TargetHistoryDetailField] = []
    for key in sorted(details):
        value = details[key]
        if isinstance(value, (dict, list)):
            rendered = json.dumps(_redact_audit_value(value), sort_keys=True, default=str)
        else:
            rendered = redact_display_text(str(value))
        fields.append(TargetHistoryDetailField(label=key, value=rendered))
    return tuple(fields)


def _waiver_identity(details: dict[str, Any]) -> str:
    rule_id = details.get("rule_id") or "—"
    file_path = details.get("file_path") or "—"
    line_start = details.get("line_start")
    line = f":{line_start}" if line_start is not None else ""
    target_kind = details.get("target_kind") or "—"
    return f"{target_kind} · {rule_id} · {file_path}{line}"


def _gate_decision_sources(details: dict[str, Any]) -> str:
    outcome = str(details.get("pr_decision") or "—").upper()
    block_findings = details.get("block_findings") or []
    sources: list[str] = []
    if isinstance(block_findings, list):
        for item in block_findings:
            if not isinstance(item, dict):
                continue
            source = item.get("decision_source")
            if source:
                sources.append(str(source))
    if sources:
        return f"{outcome} — {', '.join(sources)}"
    explanation = details.get("explanation")
    if explanation:
        return f"{outcome} — {explanation}"
    return outcome


def _event_matches_target(event: AuditEvent, target: ManagedTargetConfig) -> bool:
    if event.subject == f"target/{target.id}":
        return True
    if event.details.get("target_id") == target.id:
        return True
    if event.subject.startswith(f"{target.repo}/"):
        return True
    if event.action in _POLICY_CONFIG_ACTIONS:
        if event.action == "settings.changed":
            subject = event.subject or ""
            return subject.startswith(("policy.", "gate.", "routing.", "rbac."))
        return True
    return False


def _render_policy_decision(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    commit_sha = _commit_sha_from_event(event)
    outcome = str(details.get("pr_decision") or "—").upper()
    pill = (
        "status-pill--danger"
        if outcome == "BLOCK"
        else "status-pill--warn"
        if outcome == "FLAG"
        else "status-pill--healthy"
    )
    fields = (
        TargetHistoryDetailField(label="Outcome", value=outcome),
        TargetHistoryDetailField(label="Decision source", value=_gate_decision_sources(details)),
        TargetHistoryDetailField(label="Commit SHA", value=commit_sha or "—"),
        TargetHistoryDetailField(label="Subject", value=event.subject),
    )
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Gate decision",
        type_pill_class=pill,
        actor=event.actor,
        short_sha=_short_sha(commit_sha),
        summary=f"Policy decision {outcome} for {event.subject}",
        changes_href=_changes_href(target_id, commit_sha),
        detail_fields=fields,
        payload_json=_payload_json(details),
    )


def _render_waiver_granted(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    commit_sha = _commit_sha_from_event(event)
    self_granted = bool(details.get("self_granted"))
    capability = str(details.get("granted_with_capability") or "—")
    reason = str(details.get("reason") or "—")
    fields = (
        TargetHistoryDetailField(label="Reason", value=reason),
        TargetHistoryDetailField(label="Granted with capability", value=capability),
        TargetHistoryDetailField(label="Bound SHA", value=commit_sha or "—"),
        TargetHistoryDetailField(label="Finding identity", value=_waiver_identity(details)),
    )
    if self_granted:
        fields = fields + (
            TargetHistoryDetailField(
                label="Self-approval",
                value="Self-granted waiver (rbac.allow_self_approval).",
            ),
        )
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Waiver granted",
        type_pill_class="status-pill--warn",
        actor=event.actor,
        short_sha=_short_sha(commit_sha),
        summary=f"Waiver for {details.get('rule_id', '—')} — {reason}",
        changes_href=_changes_href(target_id, commit_sha),
        dev_mode=self_granted,
        detail_fields=fields,
        payload_json=_payload_json(details),
    )


def _render_waiver_used(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    commit_sha = _commit_sha_from_event(event)
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Waiver used",
        type_pill_class="status-pill--warn",
        actor=event.actor,
        short_sha=_short_sha(commit_sha),
        summary=f"Waiver applied for {details.get('rule_id', '—')} at gate check",
        changes_href=_changes_href(target_id, commit_sha),
        dev_mode=bool(details.get("self_granted")),
        detail_fields=(
            TargetHistoryDetailField(label="Reason", value=str(details.get("reason") or "—")),
            TargetHistoryDetailField(
                label="Granted with capability",
                value=str(details.get("granted_with_capability") or "—"),
            ),
            TargetHistoryDetailField(label="Bound SHA", value=commit_sha or "—"),
            TargetHistoryDetailField(label="Finding identity", value=_waiver_identity(details)),
        ),
        payload_json=_payload_json(details),
    )


def _render_waiver_expired(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    prior_sha = str(details.get("prior_commit_sha") or "")
    new_sha = str(details.get("new_commit_sha") or "")
    reason = str(details.get("reason") or "Waiver expired — bound SHA superseded.")
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Waiver expired",
        type_pill_class="status-pill--warn",
        actor=event.actor,
        short_sha=_short_sha(new_sha or prior_sha),
        summary=f"Waiver for {details.get('rule_id', '—')} expired ({reason})",
        changes_href=_changes_href(target_id, new_sha or prior_sha),
        detail_fields=(
            TargetHistoryDetailField(label="Expiry reason", value=reason),
            TargetHistoryDetailField(label="Prior bound SHA", value=prior_sha or "—"),
            TargetHistoryDetailField(label="Superseding SHA", value=new_sha or "—"),
            TargetHistoryDetailField(label="Finding identity", value=_waiver_identity(details)),
        ),
        payload_json=_payload_json(details),
    )


def _render_waiver_expired_batch(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    commit_sha = _commit_sha_from_event(event)
    count = details.get("count", 0)
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Waivers expired",
        type_pill_class="status-pill--warn",
        actor=event.actor,
        short_sha=_short_sha(commit_sha),
        summary=f"{count} waiver(s) expired on new commit",
        changes_href=_changes_href(target_id, commit_sha),
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_approval_granted(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    commit_sha = _commit_sha_from_event(event)
    policy = str(details.get("policy_decision") or "—").upper()
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Approval granted",
        type_pill_class="status-pill--healthy",
        actor=event.actor,
        short_sha=_short_sha(commit_sha),
        summary=f"Approval recorded for {policy} policy at {commit_sha[:7] if commit_sha else '—'}",
        changes_href=_changes_href(target_id, commit_sha),
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_approval_invalidated(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    commit_sha = _commit_sha_from_event(event)
    count = details.get("count", 1)
    reason = (
        f"{count} approval(s) invalidated by new commit {commit_sha[:7] if commit_sha else '—'}"
    )
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Approval invalidated",
        type_pill_class="status-pill--warn",
        actor=event.actor,
        short_sha=_short_sha(commit_sha),
        summary=reason,
        changes_href=_changes_href(target_id, commit_sha),
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_target_created(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Target created",
        type_pill_class="status-pill--healthy",
        actor=event.actor,
        short_sha="—",
        summary=f"Managed target {target_id} registered",
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_target_edited(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Target edited",
        type_pill_class="status-pill--warn",
        actor=event.actor,
        short_sha="—",
        summary=f"Managed target {target_id} configuration updated",
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_plan_generated(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    commit_sha = _commit_sha_from_event(event)
    destroy = details.get("summary_destroy", 0)
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Plan run",
        type_pill_class="status-pill--healthy",
        actor=event.actor,
        short_sha=_short_sha(commit_sha),
        summary=f"Terraform plan generated ({destroy} to destroy)",
        changes_href=_changes_href(target_id, commit_sha),
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_target_plan_generated(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    commit_sha = _commit_sha_from_event(event)
    destroy = details.get("summary_destroy", 0)
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Target plan run",
        type_pill_class="status-pill--healthy",
        actor=event.actor,
        short_sha=_short_sha(commit_sha),
        summary=f"Target plan generated ({destroy} to destroy)",
        changes_href=_changes_href(target_id, commit_sha),
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_plan_invalidated(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    commit_sha = _commit_sha_from_event(event)
    count = details.get("count", 0)
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Plan invalidated",
        type_pill_class="status-pill--warn",
        actor=event.actor,
        short_sha=_short_sha(commit_sha),
        summary=f"{count} deployment plan(s) invalidated by new commit",
        changes_href=_changes_href(target_id, commit_sha),
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_settings_changed(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Policy config change",
        type_pill_class="status-pill--warn",
        actor=event.actor,
        short_sha="—",
        summary=f"Setting {event.subject} updated",
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_rbac_self_approval(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    enabled = details.get("new")
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="RBAC policy change",
        type_pill_class="status-pill--warn",
        actor=event.actor,
        short_sha="—",
        summary=f"rbac.allow_self_approval set to {enabled}",
        dev_mode=bool(enabled),
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_policy_validated(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    count = details.get("policy_count", 0)
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Policy validated",
        type_pill_class="status-pill--healthy",
        actor=event.actor,
        short_sha="—",
        summary=f"Policy pack validated ({count} rules loaded)",
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


def _render_review_completed(event: AuditEvent, target: ManagedTargetConfig, target_id: str) -> TargetHistoryRow:
    details = event.details
    commit_sha = _commit_sha_from_event(event)
    decision = str(details.get("policy_decision") or "—").upper()
    finding_count = details.get("finding_count", 0)
    return TargetHistoryRow(
        event_id=event.id,
        timestamp_label=relative_time(event.timestamp),
        type_label="Config validated",
        type_pill_class="status-pill--healthy",
        actor=event.actor,
        short_sha=_short_sha(commit_sha),
        summary=f"Validation completed — {decision}, {finding_count} finding(s)",
        changes_href=_changes_href(target_id, commit_sha),
        detail_fields=_detail_fields(details),
        payload_json=_payload_json(details),
    )


ActionRenderer = Callable[[AuditEvent, ManagedTargetConfig, str], TargetHistoryRow]

ACTION_RENDERERS: dict[str, ActionRenderer] = {
    "policy.decision_rendered": _render_policy_decision,
    "waiver.granted": _render_waiver_granted,
    "waiver.used": _render_waiver_used,
    "waiver.expired": _render_waiver_expired,
    "waiver.expired_batch": _render_waiver_expired_batch,
    "approval.granted": _render_approval_granted,
    "approval.invalidated": _render_approval_invalidated,
    "managed_target.created": _render_target_created,
    "managed_target.edited": _render_target_edited,
    "deployment.plan_generated": _render_plan_generated,
    "deployment.target_plan_generated": _render_target_plan_generated,
    "deployment.plan_invalidated": _render_plan_invalidated,
    "settings.changed": _render_settings_changed,
    "settings.rbac_allow_self_approval": _render_rbac_self_approval,
    "config.policy_validated": _render_policy_validated,
    "review.completed": _render_review_completed,
}


def _filter_options() -> tuple[tuple[str, str], ...]:
    labels = {
        "policy.decision_rendered": "Gate decision",
        "waiver.granted": "Waiver granted",
        "waiver.used": "Waiver used",
        "waiver.expired": "Waiver expired",
        "waiver.expired_batch": "Waivers expired (batch)",
        "approval.granted": "Approval granted",
        "approval.invalidated": "Approval invalidated",
        "managed_target.created": "Target created",
        "managed_target.edited": "Target edited",
        "deployment.plan_generated": "Plan run",
        "deployment.target_plan_generated": "Target plan run",
        "deployment.plan_invalidated": "Plan invalidated",
        "settings.changed": "Policy config change",
        "settings.rbac_allow_self_approval": "RBAC policy change",
        "config.policy_validated": "Policy validated",
        "review.completed": "Config validated",
    }
    return tuple((action, labels.get(action, action)) for action in sorted(TARGET_HISTORY_ACTIONS))


def build_history_panel(
    detail: TargetDetail,
    audit_store: Any,
    *,
    action_filter: str | None = None,
) -> TargetHistoryPanel:
    if TARGET_HISTORY_ACTIONS != frozenset(ACTION_RENDERERS):
        missing = TARGET_HISTORY_ACTIONS - set(ACTION_RENDERERS)
        extra = set(ACTION_RENDERERS) - TARGET_HISTORY_ACTIONS
        raise RuntimeError(f"History renderer mismatch: missing={missing}, extra={extra}")

    fetched = audit_store.list_events(limit=_AUDIT_FETCH_LIMIT)
    audit_fetch_truncated = len(fetched) >= _AUDIT_FETCH_LIMIT
    target = detail.target
    target_id = target.id

    matched: list[AuditEvent] = []
    for event in fetched:
        if event.action not in TARGET_HISTORY_ACTIONS:
            continue
        if not _event_matches_target(event, target):
            continue
        matched.append(event)

    total_event_count = len(matched)
    if action_filter:
        matched = [event for event in matched if event.action == action_filter]

    rows: list[TargetHistoryRow] = []
    for event in matched:
        renderer = ACTION_RENDERERS[event.action]
        rows.append(renderer(event, target, target_id))

    return TargetHistoryPanel(
        declared_head_sha=detail.declared_head_sha,
        declared_head_short=detail.declared_head_short,
        rows=tuple(rows),
        total_event_count=total_event_count,
        displayed_event_count=len(rows),
        audit_fetch_truncated=audit_fetch_truncated,
        filtered=bool(action_filter),
        active_action_filter=action_filter,
        filter_options=_filter_options(),
    )
