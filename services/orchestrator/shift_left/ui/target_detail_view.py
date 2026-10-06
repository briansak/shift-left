"""Presentation models for the managed target detail page."""

from __future__ import annotations

from dataclasses import dataclass, field

from shift_left.approval.waiver_service import FindingWaiverService
from shift_left.config import AppConfig, RoutingConfig
from shift_left.handlers.config.hcl_parse import compute_hcl_coverage
from shift_left.handlers.config.parser_scope import TARGET_TYPE_PARSER_GLOBS
from shift_left.handlers.config.rules.registry import ALL_RULES, rule_by_id, rules_for_target_type
from shift_left.models.schema import Finding, FindingSource, FindingWaiverRecord, PolicySeverity
from shift_left.handlers.config.secret_values import (
    SecretValueSet,
    build_secret_value_index,
    extract_secret_values_from_content,
    merged_secret_values,
)
from shift_left.ui.advisory_line_attribution import (
    AdvisoryLocation,
    is_advisory_finding,
    resolve_advisory_location,
    summarize_advisory_attribution,
)
from shift_left.ui.config_redaction import redact_display_text
from shift_left.policy.handler_trace import handler_rule_id_from_trace
from shift_left.policy.finding_waiver import waiver_matches_finding
from shift_left.policy.waiver_policy import is_unclaimed_finding
from shift_left.routing.globmatch import matches_any
from shift_left.routing.path_claim import PathClaim, classify_path
from shift_left.targets.service import TargetDetail

_DISABLED_RULE_REASONS: dict[str, str] = {
    "ASA-003": (
        "enabled=False in registry (permit-without-log is too noisy for production gating)."
    ),
    "FTD-007": (
        "Legitimate internal and lab ALLOW rules often omit intrusion policy "
        "during staged rollouts; rule remains in registry for optional enablement."
    ),
}


@dataclass(frozen=True)
class RuleGapRow:
    rule_id: str
    cwe: str
    reason: str


@dataclass(frozen=True)
class TargetSummaryMetrics:
    rules_active: int
    rules_disabled: int
    rule_gaps: tuple[RuleGapRow, ...]
    findings_total: int
    findings_block: int
    findings_flag: int
    findings_advisory: int
    advisory_parser_resolved: int
    advisory_unanchored: int
    parse_coverage_label: str
    parse_coverage_percent: str | None
    parse_coverage_meta: str | None
    parse_coverage_failed: bool
    rules_evaluated: int


@dataclass(frozen=True)
class UnclaimedScopeBanner:
    paths: tuple[str, ...]
    remedy_text: str


@dataclass(frozen=True)
class TargetFindingRow:
    finding_id: str
    rule_id: str | None
    cwe: str
    severity_pill: str | None
    source_kind: str
    location: str
    location_source: str | None
    location_unverified: bool
    title: str
    waiver: FindingWaiverRecord | None
    remediation: str | None
    resolved_detail: str | None
    matched_snippet: str | None
    cwe_unrecognized: bool = False


@dataclass(frozen=True)
class TargetFindingsPanel:
    unclaimed_banner: UnclaimedScopeBanner | None
    blocking: tuple[TargetFindingRow, ...] = field(default_factory=tuple)
    flagged: tuple[TargetFindingRow, ...] = field(default_factory=tuple)
    advisory: tuple[TargetFindingRow, ...] = field(default_factory=tuple)
    rules_evaluated: int = 0
    has_table_findings: bool = False


def _disabled_rules_for_target_type(target_type: str) -> list[RuleGapRow]:
    gaps: list[RuleGapRow] = []
    for rule in ALL_RULES:
        if rule.registry_status != "disabled" or rule.target_type != target_type or not rule.counts_as_coverage_gap:
            continue
        gaps.append(
            RuleGapRow(
                rule_id=rule.id,
                cwe=rule.cwe,
                reason=_DISABLED_RULE_REASONS.get(rule.id, rule.description),
            )
        )
    return sorted(gaps, key=lambda item: item.rule_id)


def _unclaimed_remedy_text(routing: RoutingConfig) -> str:
    config_globs = ", ".join(routing.config_globs) or "(none)"
    parser_globs = ", ".join(routing.routing_parser_claim_globs) or "(none)"
    exclusion_globs = ", ".join(routing.pr_gate_exclusion_globs) or "(none)"
    return (
        "Scope failure — not a configuration defect. Claim the path in "
        f"routing.config_globs ({config_globs}), ensure it matches "
        f"routing.routing_parser_claim_globs ({parser_globs}) when a structural "
        f"parser applies, or add routing.pr_gate_exclusion_globs ({exclusion_globs}) "
        "for an explicit gate exclusion."
    )


def _scope_unclaimed_paths(detail: TargetDetail, routing: RoutingConfig) -> list[str]:
    paths: list[str] = []
    for item in detail.declared_files:
        path = item.get("path") or ""
        if not path:
            continue
        if classify_path(path, routing) == PathClaim.UNCLAIMED:
            paths.append(path)
    return sorted(paths)


def _is_advisory_finding(finding: Finding) -> bool:
    return is_advisory_finding(finding)


def _advisory_location(
    finding: Finding,
    file_contents: dict[str, str],
) -> AdvisoryLocation:
    return resolve_advisory_location(finding, file_contents.get(finding.file_path))


def _location_label(
    finding: Finding,
    *,
    file_contents: dict[str, str] | None = None,
) -> tuple[str, str | None, bool]:
    if _is_advisory_finding(finding):
        resolved = resolve_advisory_location(
            finding,
            (file_contents or {}).get(finding.file_path),
        )
        return (
            resolved.display_location,
            resolved.location_source,
            resolved.location_unverified,
        )
    if finding.line_range:
        return f"{finding.file_path} L{finding.line_range.start}", "handler", False
    return finding.file_path, "handler", False


def _severity_group(finding: Finding) -> str:
    if _is_advisory_finding(finding):
        return "advisory"
    rule_id = handler_rule_id_from_trace(finding.trace)
    rule = rule_by_id(rule_id) if rule_id else None
    if rule is not None:
        return "blocking" if rule.severity == "block" else "flagged"
    if finding.policy_severity in {PolicySeverity.CRITICAL, PolicySeverity.HIGH}:
        return "blocking"
    return "flagged"


def _snippet_for_finding(
    finding: Finding,
    file_contents: dict[str, str],
    secret_index: dict[str, SecretValueSet],
    *,
    advisory_location: AdvisoryLocation | None = None,
) -> str | None:
    secrets = merged_secret_values(secret_index, path=finding.file_path)
    if finding.evidence:
        evidence_secrets = extract_secret_values_from_content(
            finding.evidence,
            path=finding.file_path,
        )
        secrets = secrets.merge(evidence_secrets)
        return redact_display_text(
            finding.evidence.strip(),
            path=finding.file_path,
            secret_values=secrets,
        )
    content = file_contents.get(finding.file_path)
    if not content:
        return None
    if _is_advisory_finding(finding):
        resolved = advisory_location or resolve_advisory_location(finding, content)
        if resolved.parser_resolved_line is not None:
            line_no = resolved.parser_resolved_line
            lines = content.splitlines()
            if 1 <= line_no <= len(lines):
                block = lines[line_no - 1].strip()
                if block:
                    return redact_display_text(
                        block,
                        path=finding.file_path,
                        secret_values=secrets,
                    )
        return None
    if not finding.line_range:
        return None
    lines = content.splitlines()
    start = max(finding.line_range.start - 1, 0)
    end = min(finding.line_range.end, len(lines))
    if start >= len(lines):
        return None
    block = "\n".join(lines[start:end]).strip()
    if not block:
        return None
    return redact_display_text(block, path=finding.file_path, secret_values=secrets)


def _redact_waiver_for_display(waiver: FindingWaiverRecord) -> FindingWaiverRecord:
    return waiver.model_copy(update={"reason": redact_display_text(waiver.reason)})


def _waiver_for_finding(
    finding: Finding,
    waivers: list[FindingWaiverRecord],
) -> FindingWaiverRecord | None:
    for waiver in waivers:
        if waiver_matches_finding(waiver, finding):
            return waiver
    return None


def _collect_waivers(
    findings: list[Finding],
    waiver_service: FindingWaiverService,
) -> list[FindingWaiverRecord]:
    seen: set[str] = set()
    active: list[FindingWaiverRecord] = []
    for finding in findings:
        key = (finding.repo, finding.pr_ref, finding.commit_sha)
        bucket_key = f"{key}"
        if bucket_key in seen:
            continue
        seen.add(bucket_key)
        active.extend(
            waiver_service.active_for_commit(finding.repo, finding.pr_ref, finding.commit_sha)
        )
    return active


def _head_findings(detail: TargetDetail) -> list[Finding]:
    head_sha = detail.declared_head_sha
    scoped = [item for item in detail.findings if item.commit_sha == head_sha]
    return scoped if scoped else detail.findings[:50]


def _declared_file_contents(detail: TargetDetail) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for item in detail.declared_files:
        path = item.get("path") or ""
        lines = item.get("lines") or []
        if not path:
            continue
        content = "\n".join(line.get("text", "") for line in lines)
        rows.append((path, content))
    return rows


def _acl_parse_coverage(contents: list[str]) -> tuple[int, int]:
    try:
        from shift_left.handlers.config.parsers.asa.parser import acl_parse_coverage
    except ImportError:
        return 0, 0
    parsed_total = 0
    acl_total = 0
    for content in contents:
        if not content.strip():
            continue
        parsed, total = acl_parse_coverage(content)
        parsed_total += parsed
        acl_total += total
    return parsed_total, acl_total


def _cli_parse_coverage(contents: list[str], *, module: str) -> tuple[int, int]:
    try:
        if module == "ios_xe":
            from shift_left.handlers.config.parsers.ios_xe.parser import cli_parse_coverage
        else:
            from shift_left.handlers.config.parsers.nx_os.parser import cli_parse_coverage
    except ImportError:
        return 0, 0
    parsed_total = 0
    cli_total = 0
    for content in contents:
        if not content.strip():
            continue
        parsed, total = cli_parse_coverage(content)
        parsed_total += parsed
        cli_total += total
    return parsed_total, cli_total


def _ios_xe_cli_parse_coverage(contents: list[str]) -> tuple[int, int]:
    return _cli_parse_coverage(contents, module="ios_xe")


def _nx_os_cli_parse_coverage(contents: list[str]) -> tuple[int, int]:
    return _cli_parse_coverage(contents, module="nx_os")


def _format_coverage(percent_value: float, parsed: int, total: int, unit: str) -> tuple[str, str | None]:
    from shift_left.handlers.config.coverage_report import format_parse_coverage_summary

    return format_parse_coverage_summary(parsed, total, percent_value, unit)


def _parse_coverage_for_target(
    detail: TargetDetail,
) -> tuple[str, str | None, str | None, bool]:
    target_type = detail.target.target_type
    files = _declared_file_contents(detail)

    if target_type == "cisco_secure_firewall":
        rules_contents = [content for path, content in files if path.endswith(".rules")]
        parsed, total = _acl_parse_coverage(rules_contents)
        if total == 0:
            return "Parse coverage", None, "No evaluable ACL lines at declared HEAD", False
        ratio = parsed / total
        percent, meta = _format_coverage(ratio, parsed, total, "evaluable ACL lines")
        return "Parse coverage", percent, meta, False

    if target_type in {"cisco_ios_xe", "cisco_nx_os"}:
        globs = TARGET_TYPE_PARSER_GLOBS.get(target_type, ())
        cli_contents = [
            content for path, content in files if matches_any(path, list(globs))
        ]
        coverage_fn = (
            _ios_xe_cli_parse_coverage
            if target_type == "cisco_ios_xe"
            else _nx_os_cli_parse_coverage
        )
        parsed, total = coverage_fn(cli_contents)
        if total == 0:
            return "CLI parse coverage", None, "No evaluable CLI lines at declared HEAD", False
        ratio = parsed / total
        percent, meta = _format_coverage(ratio, parsed, total, "evaluable CLI lines")
        return "CLI parse coverage", percent, meta, False

    if target_type in {"cisco_ftd", "generic_terraform"}:
        globs = TARGET_TYPE_PARSER_GLOBS.get(target_type, ())
        hcl_contents = [
            content for path, content in files if matches_any(path, list(globs))
        ]
        coverage = compute_hcl_coverage(hcl_contents, target_type=target_type)
        label = "HCL parse coverage"
        if coverage.failed:
            meta = (
                f"Parse failure — {coverage.parse_failure_files} file(s) "
                "could not be interpreted"
            )
            return label, None, meta, True
        if coverage.total_resource_blocks == 0:
            return label, None, "No HCL resources at declared HEAD", False
        ratio = coverage.parsed_resources / coverage.total_resource_blocks
        percent, meta = _format_coverage(
            ratio,
            coverage.parsed_resources,
            coverage.total_resource_blocks,
            "HCL resources",
        )
        if coverage.uncovered_provider_prefixes:
            prefixes = ", ".join(coverage.uncovered_provider_prefixes)
            meta = f"{meta}; uncovered provider prefixes: {prefixes}"
        return label, percent, meta, False

    file_count = len(detail.config_file_rows)
    return (
        "Declared config",
        str(file_count),
        f"{file_count} file(s) at declared HEAD",
        False,
    )


def _parse_coverage_from_declared(
    detail: TargetDetail,
) -> tuple[str, str | None, str | None, bool]:
    return _parse_coverage_for_target(detail)


def build_summary_metrics(
    detail: TargetDetail,
    *,
    table_findings: TargetFindingsPanel,
    file_contents: dict[str, str] | None = None,
) -> TargetSummaryMetrics:
    target_type = detail.target.target_type
    active_rules = len(rules_for_target_type(target_type))
    gaps = _disabled_rules_for_target_type(target_type)
    coverage_label, parse_percent, parse_meta, parse_failed = _parse_coverage_from_declared(detail)
    contents = file_contents or {}
    if not contents:
        for item in detail.declared_files:
            path = item.get("path") or ""
            lines = item.get("lines") or []
            if path:
                contents[path] = "\n".join(line.get("text", "") for line in lines)
    advisory_attribution = summarize_advisory_attribution(_head_findings(detail), contents)
    return TargetSummaryMetrics(
        rules_active=active_rules,
        rules_disabled=len(gaps),
        rule_gaps=tuple(gaps),
        findings_total=(
            len(table_findings.blocking)
            + len(table_findings.flagged)
            + len(table_findings.advisory)
        ),
        findings_block=len(table_findings.blocking),
        findings_flag=len(table_findings.flagged),
        findings_advisory=len(table_findings.advisory),
        advisory_parser_resolved=advisory_attribution.parser_resolved,
        advisory_unanchored=advisory_attribution.unanchored,
        parse_coverage_label=coverage_label,
        parse_coverage_percent=parse_percent,
        parse_coverage_meta=parse_meta,
        parse_coverage_failed=parse_failed,
        rules_evaluated=active_rules,
    )


def build_findings_panel(
    detail: TargetDetail,
    config: AppConfig,
    waiver_service: FindingWaiverService,
) -> TargetFindingsPanel:
    routing = config.routing
    findings = _head_findings(detail)
    file_contents: dict[str, str] = {}
    secret_index: dict[str, SecretValueSet] = {}
    for item in detail.declared_files:
        path = item.get("path") or ""
        lines = item.get("lines") or []
        if path:
            file_contents[path] = "\n".join(line.get("text", "") for line in lines)
            stored = item.get("secret_values")
            if isinstance(stored, SecretValueSet):
                secret_index[path] = stored

    scope_paths = _scope_unclaimed_paths(detail, routing)
    store_unclaimed = [
        item.file_path
        for item in findings
        if is_unclaimed_finding(item) and item.file_path not in scope_paths
    ]
    banner_paths = tuple(sorted(set(scope_paths) | set(store_unclaimed)))
    banner = None
    if banner_paths:
        banner = UnclaimedScopeBanner(
            paths=banner_paths,
            remedy_text=_unclaimed_remedy_text(routing),
        )

    waivers = _collect_waivers(findings, waiver_service)
    blocking: list[TargetFindingRow] = []
    flagged: list[TargetFindingRow] = []
    advisory: list[TargetFindingRow] = []

    for finding in findings:
        if is_unclaimed_finding(finding):
            continue
        group = _severity_group(finding)
        rule_id = handler_rule_id_from_trace(finding.trace)
        rule = rule_by_id(rule_id) if rule_id else None
        is_advisory = group == "advisory"
        display_cwe = finding.handler_asserted_cwe or finding.model_asserted_cwe or "—"
        cwe_unrecognized = (
            finding.handler_asserted_cwe is None
            and finding.model_asserted_cwe is not None
            and finding.model_cwe_recognized is False
        )
        advisory_location = (
            _advisory_location(finding, file_contents) if is_advisory else None
        )
        location, location_source, location_unverified = _location_label(
            finding,
            file_contents=file_contents,
        )
        row = TargetFindingRow(
            finding_id=finding.id,
            rule_id=rule_id,
            cwe=display_cwe,
            severity_pill=None if is_advisory else ("block" if group == "blocking" else "flag"),
            source_kind="advisory" if is_advisory else "deterministic",
            location=location,
            location_source=location_source,
            location_unverified=location_unverified,
            title=finding.title,
            waiver=_redact_waiver_for_display(waiver)
            if (waiver := _waiver_for_finding(finding, waivers))
            else None,
            remediation=rule.remediation if rule else None,
            resolved_detail=finding.description if finding.description != finding.title else None,
            matched_snippet=_snippet_for_finding(
                finding,
                file_contents,
                secret_index,
                advisory_location=advisory_location,
            ),
            cwe_unrecognized=cwe_unrecognized,
        )
        if is_advisory:
            advisory.append(row)
        elif group == "blocking":
            blocking.append(row)
        else:
            flagged.append(row)

    rules_evaluated = len(rules_for_target_type(detail.target.target_type))
    has_table = bool(blocking or flagged or advisory)
    return TargetFindingsPanel(
        unclaimed_banner=banner,
        blocking=tuple(blocking),
        flagged=tuple(flagged),
        advisory=tuple(advisory),
        rules_evaluated=rules_evaluated,
        has_table_findings=has_table,
    )


def build_target_detail_view(
    detail: TargetDetail,
    config: AppConfig,
    waiver_service: FindingWaiverService,
) -> tuple[TargetSummaryMetrics, TargetFindingsPanel]:
    findings_panel = build_findings_panel(detail, config, waiver_service)
    summary = build_summary_metrics(detail, table_findings=findings_panel)
    return summary, findings_panel
