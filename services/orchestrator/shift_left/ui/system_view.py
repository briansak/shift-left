"""System page view models — read-only rendering over existing health/status payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from shift_left.system.service_dependencies import SERVICE_PREREQUISITE_CHECKS
from shift_left.system.settings import REQUIRES_MODEL_RESTART, REQUIRES_ORCHESTRATOR_RESTART
from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_Q4_K_M, VERIFIED_FOUNDATION_SEC_Q8_0

CategoryLabel = Literal["critical", "config", "code", "advisory"]
RowKind = Literal["check", "disagreement"]
StatusKey = Literal["ok", "failed", "advisory_failed", "disagreement", "skipped"]

_GROUP_ORDER = ("critical", "degraded_config", "degraded_code", "advisory", "deployment")
_CATEGORY_MAP: dict[str, CategoryLabel] = {
    "critical": "critical",
    "degraded_config": "config",
    "degraded_code": "code",
    "advisory": "advisory",
    "deployment": "advisory",
}
_STATUS_SORT = {"failed": 0, "timed_out": 0, "disagreement": 1, "advisory_failed": 2, "skipped": 3, "ok": 4}
_OVERALL_PILL = {"healthy": "OK", "degraded": "DEGRADED", "failed": "FAILED"}


@dataclass(frozen=True)
class SystemStatusCard:
    overall_pill: str
    overall_tone: Literal["healthy", "degraded", "failed"]
    failing_components: tuple[str, ...]
    capability_pills: tuple[str, ...]
    remediation_command: str | None
    cache_relative: str
    cache_ttl_seconds: int


@dataclass(frozen=True)
class ServiceAction:
    label: str
    service: str
    action: str
    method: Literal["post", "start_chain"]


@dataclass(frozen=True)
class SystemHealthRow:
    row_id: str
    check_name: str
    category: CategoryLabel
    status_key: StatusKey
    status_label: str
    duration_ms: int
    remediation_text: str | None
    remediation_command: str | None
    row_kind: RowKind
    disagreement_note: str | None = None
    error_detail: str | None = None
    service_actions: tuple[ServiceAction, ...] = ()
    host_native_command: str | None = None


@dataclass(frozen=True)
class LifecycleStepFeedback:
    service: str
    code: str
    label: str
    tone: Literal["healthy", "warn", "danger", "neutral"]


@dataclass(frozen=True)
class LifecycleFeedback:
    kind: Literal["start-all", "service-action", "host-native"]
    code: str
    title: str
    tone: Literal["healthy", "warn", "danger"]
    message: str
    error: str | None
    failed_service: str | None
    failed_phase: str | None
    started_services: tuple[str, ...]
    skipped_services: tuple[str, ...]
    steps: tuple[LifecycleStepFeedback, ...]
    host_command: str | None = None


@dataclass(frozen=True)
class SystemTriageView:
    status_card: SystemStatusCard
    health_rows: tuple[SystemHealthRow, ...]
    passing_count: int
    topology_line: str
    show_start_all: bool
    lifecycle_feedback: LifecycleFeedback | None = None


@dataclass(frozen=True)
class SystemConfigField:
    key: str
    label: str
    tier: str
    tier_reason: str
    value_display: str
    input_name: str | None
    input_type: Literal["text", "number", "checkbox", "select"]
    options: tuple[str, ...] = ()
    requires_restart: str | None = None
    staged: bool | None = None
    staged_label: str | None = None
    inline_note: str | None = None
    error: str | None = None
    disabled: bool = False


@dataclass(frozen=True)
class SystemConfigGroup:
    title: str
    tier_note: str
    fields: tuple[SystemConfigField, ...]


@dataclass(frozen=True)
class SystemConfigNotice:
    tone: Literal["warn"]
    title: str
    message: str
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class SystemConfigView:
    groups: tuple[SystemConfigGroup, ...]
    can_edit: bool
    inventory: dict[str, Any]
    rbac_allow_self_approval: bool
    rbac_note: str
    rbac_phrases: dict[str, str]
    notices: tuple[SystemConfigNotice, ...] = ()


@dataclass(frozen=True)
class GgufChecksumRow:
    profile: str
    path: str
    staged: bool
    expected_sha256: str
    files: tuple[str, ...]


@dataclass(frozen=True)
class SystemEvidenceView:
    egress_paths: tuple[dict[str, Any], ...]
    egress_probe: dict[str, Any]
    tier1: dict[str, Any]
    gguf_rows: tuple[GgufChecksumRow, ...]
    reference_cache: dict[str, Any]
    audit_retention_days: int
    can_sync_reference: bool


def _parse_checked_at(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        normalized = raw.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _relative_time(raw: str | None) -> str:
    checked = _parse_checked_at(raw)
    if checked is None:
        return "unknown"
    if checked.tzinfo is None:
        checked = checked.replace(tzinfo=UTC)
    delta = datetime.now(UTC) - checked.astimezone(UTC)
    seconds = int(max(0, delta.total_seconds()))
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 120:
        return f"{minutes}m ago"
    hours = minutes // 60
    return f"{hours}h ago"


def _flatten_checks(prereq: dict[str, Any]) -> list[dict[str, Any]]:
    groups = prereq.get("groups") or {}
    flattened: list[dict[str, Any]] = []
    for group_key in _GROUP_ORDER:
        for item in groups.get(group_key) or []:
            flattened.append({**item, "_group": group_key})
    return flattened


def _category_for(check: dict[str, Any]) -> CategoryLabel:
    return _CATEGORY_MAP.get(str(check.get("_group") or check.get("criticality")), "advisory")


def _status_key(check: dict[str, Any]) -> StatusKey:
    if check.get("skipped_reason"):
        return "skipped"
    if check.get("ok"):
        return "ok"
    status = str(check.get("status") or "failed")
    if status == "advisory_failed":
        return "advisory_failed"
    return "failed"


def _status_label(key: StatusKey) -> str:
    return {
        "ok": "OK",
        "failed": "FAILED",
        "advisory_failed": "ADVISORY",
        "disagreement": "MISMATCH",
        "skipped": "SKIPPED",
    }[key]


def _compose_remediation_command(service_name: str) -> str:
    return f"docker compose up -d {service_name}"


def _remediation_command(check: dict[str, Any], services_by_name: dict[str, dict[str, Any]]) -> str | None:
    service_name = check.get("remediation_service")
    action = check.get("remediation_action")
    if service_name and action:
        svc = services_by_name.get(service_name) or {}
        if svc.get("start_feasibility") == "detect_only":
            return f"./shift-left model {action} {service_name}"
        if svc.get("start_feasibility") == "start" and service_name in {
            "postgres",
            "forgejo",
            "forgejo-runner",
        }:
            return _compose_remediation_command(service_name)
    remediation = str(check.get("remediation") or "").strip()
    if remediation.startswith("./shift-left"):
        return remediation.split("\n", 1)[0].strip()
    for line in remediation.splitlines():
        stripped = line.strip()
        if stripped.startswith("./shift-left"):
            return stripped
    return None


def _service_actions(
    check: dict[str, Any],
    services_by_name: dict[str, dict[str, Any]],
    *,
    can_admin: bool,
) -> tuple[ServiceAction, ...]:
    if not can_admin:
        return ()
    service_name = check.get("remediation_service")
    action = check.get("remediation_action")
    if not service_name or not action:
        return ()
    svc = services_by_name.get(service_name)
    if not svc:
        return ()
    if svc.get("start_feasibility") == "start":
        return (ServiceAction(label=action, service=service_name, action=action, method="post"),)
    return ()


def _host_native_command(check: dict[str, Any], services_by_name: dict[str, dict[str, Any]]) -> str | None:
    service_name = check.get("remediation_service")
    action = check.get("remediation_action")
    if not service_name or not action:
        return None
    svc = services_by_name.get(service_name) or {}
    if svc.get("start_feasibility") == "detect_only":
        return f"./shift-left model {action} {service_name}"
    return None


def build_merged_health_rows(
    checks: list[dict[str, Any]],
    services: list[dict[str, Any]],
    *,
    can_admin: bool,
) -> list[SystemHealthRow]:
    services_by_name = {str(item["service"]): item for item in services}
    checks_by_id = {str(item["id"]): item for item in checks}
    consumed_services: set[str] = set()
    rows: list[SystemHealthRow] = []

    for check in checks:
        service_name = check.get("remediation_service")
        svc = services_by_name.get(service_name) if service_name else None
        if svc and service_name:
            consumed_services.add(service_name)
            running = bool(svc.get("running"))
            check_ok = bool(check.get("ok"))
            if check_ok and not running and svc.get("start_feasibility") in {"start", "detect_only"}:
                rows.append(
                    SystemHealthRow(
                        row_id=f"disagreement-{check['id']}",
                        check_name=check.get("name") or check["id"],
                        category=_category_for(check),
                        status_key="disagreement",
                        status_label=_status_label("disagreement"),
                        duration_ms=int(check.get("duration_ms") or 0),
                        remediation_text=(
                            f"Health check passed but {svc.get('display_name') or service_name} "
                            "is not running."
                        ),
                        remediation_command=_host_native_command(check, services_by_name),
                        row_kind="disagreement",
                        disagreement_note=(
                            f"{check.get('name')}: prerequisite ok=true, service running=false"
                        ),
                        service_actions=_service_actions(check, services_by_name, can_admin=can_admin),
                        host_native_command=_host_native_command(check, services_by_name),
                    )
                )
                continue
            if not check_ok and not running:
                status_key = _status_key(check)
                rows.append(
                    SystemHealthRow(
                        row_id=check["id"],
                        check_name=check.get("name") or check["id"],
                        category=_category_for(check),
                        status_key=status_key,
                        status_label=_status_label(status_key),
                        duration_ms=int(check.get("duration_ms") or 0),
                        remediation_text=check.get("remediation"),
                        remediation_command=_remediation_command(check, services_by_name),
                        row_kind="check",
                        error_detail=check.get("error"),
                        service_actions=_service_actions(check, services_by_name, can_admin=can_admin),
                        host_native_command=_host_native_command(check, services_by_name),
                    )
                )
                continue

        status_key = _status_key(check)
        rows.append(
            SystemHealthRow(
                row_id=check["id"],
                check_name=check.get("name") or check["id"],
                category=_category_for(check),
                status_key=status_key,
                status_label=_status_label(status_key),
                duration_ms=int(check.get("duration_ms") or 0),
                remediation_text=check.get("remediation"),
                remediation_command=_remediation_command(check, services_by_name),
                row_kind="check",
                error_detail=check.get("error"),
                service_actions=_service_actions(check, services_by_name, can_admin=can_admin),
                host_native_command=_host_native_command(check, services_by_name),
            )
        )

    for svc in services:
        name = str(svc.get("service") or "")
        if not name or name in consumed_services:
            continue
        if svc.get("running"):
            continue
        mapped_check_id = SERVICE_PREREQUISITE_CHECKS.get(name)  # type: ignore[arg-type]
        if mapped_check_id:
            mapped = checks_by_id.get(mapped_check_id)
            if mapped and mapped.get("ok"):
                continue
        rows.append(
            SystemHealthRow(
                row_id=f"service-{name}",
                check_name=str(svc.get("display_name") or name),
                category="advisory",
                status_key="failed",
                status_label="STOPPED",
                duration_ms=0,
                remediation_text=svc.get("feasibility_note"),
                remediation_command=(
                    _compose_remediation_command(name)
                    if svc.get("start_feasibility") == "start"
                    and name in {"postgres", "forgejo", "forgejo-runner"}
                    else (
                        f"./shift-left model start {name}"
                        if svc.get("start_feasibility") == "detect_only"
                        else None
                    )
                ),
                row_kind="check",
                error_detail=svc.get("error"),
                service_actions=tuple(
                    ServiceAction(label=action, service=name, action=action, method="post")
                    for action in (svc.get("actions_available") or [])
                    if can_admin and svc.get("start_feasibility") == "start"
                ),
            )
        )

    def sort_key(row: SystemHealthRow) -> tuple[int, str]:
        order = _STATUS_SORT.get(row.status_key, 5)
        return (order, row.check_name.lower())

    return sorted(rows, key=sort_key)


def build_status_card(status: dict[str, Any]) -> SystemStatusCard:
    health = status.get("health") or {}
    prereq = status.get("prerequisites") or health.get("prerequisites") or {}
    overall = str(health.get("overall_state") or "failed")
    checks = _flatten_checks(prereq)
    failing = [
        str(item.get("name") or item.get("id"))
        for item in checks
        if not item.get("ok") and not item.get("skipped_reason")
    ]
    services_by_name = {str(item["service"]): item for item in status.get("services") or []}
    remediation_command = None
    for item in checks:
        if item.get("ok"):
            continue
        remediation_command = _remediation_command(item, services_by_name)
        if remediation_command:
            break
    cache = prereq.get("cache") or {}
    return SystemStatusCard(
        overall_pill=_OVERALL_PILL.get(overall, overall.upper()),
        overall_tone=overall if overall in {"healthy", "degraded", "failed"} else "failed",
        failing_components=tuple(failing),
        capability_pills=tuple(health.get("affected_capabilities") or []),
        remediation_command=remediation_command,
        cache_relative=_relative_time(prereq.get("report_generated_at")),
        cache_ttl_seconds=int(cache.get("ttl_seconds") or 30),
    )


_OUTCOME_TONE: dict[str, Literal["healthy", "warn", "danger"]] = {
    "chain_complete": "healthy",
    "verified_healthy": "healthy",
    "chain_stopped": "danger",
    "verification_timeout": "danger",
    "command_failed": "danger",
    "detect_only": "warn",
    "host-native-control": "warn",
}

_OUTCOME_LABELS: dict[str, str] = {
    "chain_complete": "All startable services started",
    "chain_stopped": "Start chain stopped",
    "verified_healthy": "Service healthy",
    "verification_timeout": "Health check timed out",
    "command_failed": "Start command failed",
    "detect_only": "Host-native control required",
    "host-native-control": "Host-native control required",
}


def _split_csv(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _step_tone(code: str) -> Literal["healthy", "warn", "danger", "neutral"]:
    if code in {"verified_healthy", "complete", "ok", "chain_complete"}:
        return "healthy"
    if code in {"skipped", "detect_only", "not_applicable"}:
        return "warn"
    if code in {"verification_timeout", "command_failed", "failed", "chain_stopped"}:
        return "danger"
    return "neutral"


def _parse_lifecycle_steps(raw: str | None) -> tuple[LifecycleStepFeedback, ...]:
    if not raw:
        return ()
    steps: list[LifecycleStepFeedback] = []
    for entry in raw.split(";"):
        if not entry or ":" not in entry:
            continue
        service, code = entry.split(":", 1)
        steps.append(
            LifecycleStepFeedback(
                service=service.strip(),
                code=code.strip(),
                label=code.strip().replace("_", " ").upper(),
                tone=_step_tone(code.strip()),
            )
        )
    return tuple(steps)


def build_lifecycle_feedback(params: dict[str, str]) -> LifecycleFeedback | None:
    notice = params.get("notice")
    if notice == "start-all":
        outcome = params.get("outcome") or "unknown"
        tone = _OUTCOME_TONE.get(outcome, "warn")
        failed = params.get("failed") or None
        phase = params.get("phase") or None
        error = params.get("error") or None
        started = _split_csv(params.get("started"))
        skipped = _split_csv(params.get("skipped"))
        steps = _parse_lifecycle_steps(params.get("steps"))
        message = _OUTCOME_LABELS.get(outcome, outcome.replace("_", " "))
        if failed and phase:
            message = f"{message} at {failed} ({phase})"
        return LifecycleFeedback(
            kind="start-all",
            code=outcome,
            title="Start all prerequisites",
            tone=tone,
            message=message,
            error=error,
            failed_service=failed,
            failed_phase=phase,
            started_services=started,
            skipped_services=skipped,
            steps=steps,
        )
    if notice == "service-action":
        outcome = params.get("outcome") or "unknown"
        service = params.get("service") or "service"
        action = params.get("action") or "start"
        tone = _OUTCOME_TONE.get(outcome, "warn")
        error = params.get("error") or None
        phase = params.get("phase") or None
        message = f"{action} {service}: {_OUTCOME_LABELS.get(outcome, outcome)}"
        return LifecycleFeedback(
            kind="service-action",
            code=outcome,
            title=f"Service action — {service}",
            tone=tone,
            message=message,
            error=error,
            failed_service=service if tone == "danger" else None,
            failed_phase=phase,
            started_services=(),
            skipped_services=(),
            steps=_parse_lifecycle_steps(params.get("steps")),
        )
    if notice == "host-native-control":
        service = params.get("service") or "service"
        action = params.get("action") or "start"
        command = f"./shift-left model {action} {service}"
        return LifecycleFeedback(
            kind="host-native",
            code="host-native-control",
            title=f"Host-native — {service}",
            tone="warn",
            message="This service cannot be started from the containerized orchestrator.",
            error=None,
            failed_service=service,
            failed_phase="feasibility",
            started_services=(),
            skipped_services=(service,),
            steps=(),
            host_command=command,
        )
    return None


def build_topology_line(status: dict[str, Any]) -> str:
    prereq = status.get("prerequisites") or status.get("health", {}).get("prerequisites") or {}
    topo = status.get("topology_report") or prereq.get("topology_report") or {}
    chain = " → ".join(status.get("dependency_graph", {}).get("critical_pipeline_chain") or [])
    parts = [
        f"Topology: {status.get('topology') or prereq.get('topology') or '—'}",
        f"control {topo.get('service_control_mode') or '—'}",
        f"models {topo.get('model_hosting') or '—'}",
    ]
    if chain:
        parts.append(f"chain {chain}")
    return " · ".join(parts)


def build_triage_view(
    status: dict[str, Any],
    *,
    can_admin: bool,
    lifecycle_feedback: LifecycleFeedback | None = None,
) -> SystemTriageView:
    prereq = status.get("prerequisites") or status.get("health", {}).get("prerequisites") or {}
    checks = _flatten_checks(prereq)
    services = list(status.get("services") or [])
    rows = build_merged_health_rows(checks, services, can_admin=can_admin)
    passing = sum(1 for row in rows if row.status_key == "ok")
    overall = str(status.get("health", {}).get("overall_state") or "failed")
    return SystemTriageView(
        status_card=build_status_card(status),
        health_rows=tuple(rows),
        passing_count=passing,
        topology_line=build_topology_line(status),
        show_start_all=can_admin and overall in {"failed", "degraded"},
        lifecycle_feedback=lifecycle_feedback,
    )


def _restart_label(setting_key: str) -> str | None:
    if setting_key in REQUIRES_MODEL_RESTART:
        return "model server restart"
    if setting_key in REQUIRES_ORCHESTRATOR_RESTART:
        return "orchestrator restart"
    return None


def _config_field(
    *,
    key: str,
    label: str,
    tier: str,
    tier_reason: str,
    value_display: str,
    input_name: str | None = None,
    input_type: Literal["text", "number", "checkbox", "select"] = "text",
    options: tuple[str, ...] = (),
    staged: bool | None = None,
    staged_label: str | None = None,
    inline_note: str | None = None,
    error: str | None = None,
    disabled: bool = False,
) -> SystemConfigField:
    return SystemConfigField(
        key=key,
        label=label,
        tier=tier,
        tier_reason=tier_reason,
        value_display=value_display,
        input_name=input_name,
        input_type=input_type,
        options=options,
        requires_restart=_restart_label(key),
        staged=staged,
        staged_label=staged_label,
        inline_note=inline_note,
        error=error,
        disabled=disabled,
    )


def build_config_view(status: dict[str, Any], *, can_admin: bool) -> SystemConfigView:
    form = status.get("settings", {}).get("tier3_form") or {}
    fs = form.get("foundation_sec") or {}
    ant = form.get("antares") or {}
    paths = form.get("paths") or {}
    enr = form.get("enrichment") or {}
    inv = status.get("models", {}).get("inventory") or status.get("health", {}).get("models_inventory") or {}
    q8_staged = bool(inv.get("q8_0_staged"))
    q4_staged = bool(inv.get("q4_k_m_staged"))
    use_low_memory = bool(fs.get("use_low_memory"))
    active_profile_staged = bool(inv.get("active_profile_staged", inv.get("active_weights_present")))
    active_missing = not active_profile_staged

    foundation_fields = (
        _config_field(
            key="models.foundation_sec.use_low_memory",
            label="Quant profile",
            tier="Tier 3",
            tier_reason="Runtime model weights — validated write, affects inference path.",
            value_display="Q4_K_M (low-memory)" if use_low_memory else "Q8_0 (default)",
            input_name="use_low_memory",
            input_type="checkbox",
            inline_note=(
                f"Recommended: {inv.get('recommended_profile')}. "
                f"{inv.get('measured_note')}"
            ),
            error=(
                "Active profile weights are not staged locally."
                if active_missing
                else None
            ),
            disabled=not q4_staged,
        ),
        _config_field(
            key="models.foundation_sec.max_context_tokens",
            label="n_ctx",
            tier="Tier 3",
            tier_reason="Context window for Foundation-Sec chunks.",
            value_display=str(fs.get("max_context_tokens")),
            input_name="max_context_tokens",
            input_type="number",
        ),
        _config_field(
            key="models.foundation_sec.load_strategy",
            label="Load strategy",
            tier="Tier 3",
            tier_reason="On-demand unloads weights between reviews to save RAM.",
            value_display=str(fs.get("load_strategy")),
            input_name="foundation_sec_load_strategy",
            input_type="select",
            options=("on_demand", "resident_for_run"),
        ),
        _config_field(
            key="models.foundation_sec.service_url",
            label="Service URL",
            tier="Tier 3",
            tier_reason="Must match loopback allowlist for local inference.",
            value_display=str(fs.get("service_url")),
            input_name="foundation_sec_service_url",
            input_type="text",
        ),
        _config_field(
            key="models.foundation_sec.local_path",
            label="Q8_0 weights path",
            tier="Tier 3",
            tier_reason="Host path to staged Q8_0 GGUF directory.",
            value_display=str(fs.get("local_path")),
            input_name="foundation_sec_local_path",
            input_type="text",
            staged=q8_staged,
            staged_label="staged" if q8_staged else "not staged",
            error=(
                "Weights not staged"
                if not q8_staged and not use_low_memory and not active_profile_staged
                else None
            ),
        ),
        _config_field(
            key="models.foundation_sec.local_path_low_memory",
            label="Q4_K_M weights path",
            tier="Tier 3",
            tier_reason="Host path to staged Q4_K_M GGUF directory.",
            value_display=str(fs.get("local_path_low_memory")),
            input_name="foundation_sec_local_path_q4",
            input_type="text",
            staged=q4_staged,
            staged_label="staged" if q4_staged else "not staged",
            error=(
                "Weights not staged"
                if not q4_staged and use_low_memory and not active_profile_staged
                else None
            ),
            inline_note=(
                f"Stage: {fs.get('q4_staging_command')}" if not q4_staged else None
            ),
        ),
    )

    antares_fields = (
        _config_field(
            key="models.antares.load_strategy",
            label="Load strategy",
            tier="Tier 3",
            tier_reason="Advisory triage only — not part of PR gate.",
            value_display=str(ant.get("load_strategy")),
            input_name="antares_load_strategy",
            input_type="select",
            options=("on_demand", "resident_for_run"),
        ),
        _config_field(
            key="models.antares.service_url",
            label="Service URL",
            tier="Tier 3",
            tier_reason="Loopback Antares inference endpoint.",
            value_display=str(ant.get("service_url")),
            input_name="antares_service_url",
            input_type="text",
        ),
        _config_field(
            key="models.antares.local_path",
            label="Weights directory",
            tier="Tier 3",
            tier_reason="Staged Antares weights (optional).",
            value_display=str(ant.get("local_path")),
            input_name="antares_local_path",
            input_type="text",
            staged=bool(status.get("models", {}).get("antares", {}).get("installed")),
            staged_label=(
                "installed"
                if status.get("models", {}).get("antares", {}).get("installed")
                else "not installed"
            ),
        ),
        _config_field(
            key="models.antares.agent.recycle_after_runs",
            label="Recycle after runs",
            tier="Tier 3",
            tier_reason="Transformer memory hygiene for long triage sessions.",
            value_display=str(ant.get("recycle_after_runs")),
            input_name="recycle_after_runs",
            input_type="number",
        ),
    )

    rewrite_notes = {
        item.get("key"): (
            f"Rewritten from legacy path {item.get('original')} → {item.get('resolved')}"
        )
        for item in (status.get("config_diagnostics") or {}).get("legacy_path_rewrites") or []
        if isinstance(item, dict) and item.get("key")
    }

    storage_fields = (
        _config_field(
            key="reference_data.cache_dir",
            label="Reference cache directory",
            tier="Tier 3",
            tier_reason="Local CVE/CWE cache — orchestrator restart required.",
            value_display=str(paths.get("reference_cache_dir")),
            input_name="reference_cache_dir",
            input_type="text",
            inline_note=rewrite_notes.get("reference_data.cache_dir"),
        ),
        _config_field(
            key="findings_store.sqlite_path",
            label="Findings store (SQLite)",
            tier="Tier 3",
            tier_reason="Gate findings persistence — orchestrator restart required.",
            value_display=str(paths.get("findings_sqlite_path")),
            input_name="findings_sqlite_path",
            input_type="text",
            inline_note=rewrite_notes.get("findings_store.sqlite_path"),
        ),
    )

    enrichment_fields = (
        _config_field(
            key="enrichment.enabled",
            label="Enrichment enabled",
            tier="Tier 3",
            tier_reason="Advisory prose — excluded from deterministic gate.",
            value_display="yes" if enr.get("enabled") else "no",
            input_name="enrichment_enabled",
            input_type="checkbox",
        ),
        _config_field(
            key="enrichment.enrich_findings",
            label="Enrich findings",
            tier="Tier 3",
            tier_reason="Model-generated finding context.",
            value_display="yes" if enr.get("enrich_findings") else "no",
            input_name="enrich_findings",
            input_type="checkbox",
        ),
        _config_field(
            key="enrichment.generate_review_summary",
            label="Generate review summary",
            tier="Tier 3",
            tier_reason="Reviewer summary block on PR comments.",
            value_display="yes" if enr.get("generate_review_summary") else "no",
            input_name="generate_review_summary",
            input_type="checkbox",
        ),
    )

    groups = (
        SystemConfigGroup(
            title="Foundation-Sec",
            tier_note="Tier 3 — mutable with validation; quant/path changes need model server restart.",
            fields=foundation_fields,
        ),
        SystemConfigGroup(
            title="Antares",
            tier_note="Tier 3 — optional advisory triage; not merge-gate authoritative.",
            fields=antares_fields,
        ),
        SystemConfigGroup(
            title="Storage & cache",
            tier_note="Tier 3 — path changes require orchestrator restart.",
            fields=storage_fields,
        ),
        SystemConfigGroup(
            title="Enrichment",
            tier_note="Tier 3 — advisory-only model prose.",
            fields=enrichment_fields,
        ),
    )

    diagnostics = status.get("config_diagnostics") or {}
    notices: list[SystemConfigNotice] = []
    if diagnostics.get("omit_from_pr_comments") is False:
        notices.append(
            SystemConfigNotice(
                tone="warn",
                title="Advisory findings will appear on PR comments",
                message=(
                    "advisory_suppression.omit_from_pr_comments is false. Foundation-Sec "
                    "advisory findings measured ~12% recall with 50-65% of evidence not "
                    "present in the input file. Foundry Constitution II names operator-burying "
                    "as a recorded production failure."
                ),
            )
        )
    rewrites = [
        item
        for item in diagnostics.get("legacy_path_rewrites") or []
        if isinstance(item, dict) and item.get("original") and item.get("resolved")
    ]
    if rewrites:
        notices.append(
            SystemConfigNotice(
                tone="warn",
                title="Legacy data paths rewritten",
                message=(
                    "Operator YAML used /shift-left/data or /data paths that were remapped "
                    "onto SHIFT_LEFT_DATA_DIR."
                ),
                details=tuple(
                    f"{item.get('key')}: {item.get('original')} → {item.get('resolved')}"
                    for item in rewrites
                ),
            )
        )

    return SystemConfigView(
        groups=groups,
        can_edit=can_admin,
        inventory=inv,
        rbac_allow_self_approval=bool(status.get("rbac", {}).get("allow_self_approval")),
        rbac_note=str(status.get("rbac", {}).get("note") or ""),
        rbac_phrases=status.get("settings", {}).get("rbac_phrases") or {},
        notices=tuple(notices),
    )


def build_evidence_view(status: dict[str, Any], *, can_admin: bool) -> SystemEvidenceView:
    inv = status.get("models", {}).get("inventory") or {}
    gguf_rows = (
        GgufChecksumRow(
            profile="Q8_0",
            path=str(inv.get("q8_0_path") or VERIFIED_FOUNDATION_SEC_Q8_0["local_path_default"]),
            staged=bool(inv.get("q8_0_staged")),
            expected_sha256=VERIFIED_FOUNDATION_SEC_Q8_0["sha256"],
            files=tuple(inv.get("q8_0_files") or ()),
        ),
        GgufChecksumRow(
            profile="Q4_K_M",
            path=str(inv.get("q4_k_m_path") or VERIFIED_FOUNDATION_SEC_Q4_K_M["local_path_default"]),
            staged=bool(inv.get("q4_k_m_staged")),
            expected_sha256=VERIFIED_FOUNDATION_SEC_Q4_K_M["sha256"],
            files=tuple(inv.get("q4_k_m_files") or ()),
        ),
    )
    health = status.get("health") or {}
    return SystemEvidenceView(
        egress_paths=tuple(status.get("sovereignty", {}).get("egress_paths") or []),
        egress_probe=status.get("sovereignty", {}).get("egress_probe") or {},
        tier1=status.get("settings", {}).get("tier1") or {},
        gguf_rows=gguf_rows,
        reference_cache=health.get("reference_cache") or {},
        audit_retention_days=int(status.get("audit", {}).get("retention_days") or 0),
        can_sync_reference=can_admin,
    )
