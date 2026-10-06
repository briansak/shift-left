"""Presentation models for the managed target Configuration tab."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from shift_left.config import ManagedTargetConfig
from shift_left.handlers.config.hcl_parse import parse_hcl_content
from shift_left.models.schema import Finding, PolicySeverity
from shift_left.policy.handler_trace import handler_rule_id_from_trace
from shift_left.targets.service import TargetDetail
from shift_left.handlers.config.secret_values import extract_secret_values_from_content
from shift_left.ui.advisory_line_attribution import (
    is_advisory_finding,
    resolve_advisory_location,
)
from shift_left.ui.config_redaction import redact_config_line

_HCL_TARGET_TYPES = frozenset({"cisco_ftd", "generic_terraform"})
_ASA_TARGET_TYPE = "cisco_secure_firewall"
_IOS_XE_TARGET_TYPE = "cisco_ios_xe"
_NX_OS_TARGET_TYPE = "cisco_nx_os"

_UNPARSE_RULE_BY_TARGET = {
    _ASA_TARGET_TYPE: "ASA-007",
    _IOS_XE_TARGET_TYPE: "IOS-001",
    _NX_OS_TARGET_TYPE: "NXOS-001",
    "cisco_ftd": "FTD-008",
}


@dataclass(frozen=True)
class UnanchoredAdvisoryView:
    finding_id: str
    title: str
    findings_href: str


@dataclass(frozen=True)
class ConfigLineView:
    num: int
    text: str
    finding_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    finding_ids: tuple[str, ...] = field(default_factory=tuple)
    severity_class: str | None = None
    findings_href: str | None = None
    unparsed: bool = False
    reference_notes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class HclResourceBlockView:
    resource_type: str
    name: str
    header_line: int
    lines: tuple[ConfigLineView, ...]


@dataclass(frozen=True)
class TargetConfigFileCard:
    path: str
    head_sha: str
    head_short: str
    parse_coverage_label: str
    view_mode: str
    lines: tuple[ConfigLineView, ...] = field(default_factory=tuple)
    resource_blocks: tuple[HclResourceBlockView, ...] = field(default_factory=tuple)
    unanchored_advisories: tuple[UnanchoredAdvisoryView, ...] = field(default_factory=tuple)
    selected: bool = False


@dataclass(frozen=True)
class TargetConfigPanel:
    declared_head_sha: str
    declared_head_short: str
    files: tuple[TargetConfigFileCard, ...]
    declare_hint: str


def _short_sha(sha: str) -> str:
    return sha[:7] if sha else "—"


def _head_findings(detail: TargetDetail) -> list[Finding]:
    head_sha = detail.declared_head_sha
    scoped = [item for item in detail.findings if item.commit_sha == head_sha]
    return scoped if scoped else detail.findings[:50]


def _severity_gutter_class(finding: Finding) -> str:
    if finding.policy_severity in {PolicySeverity.CRITICAL, PolicySeverity.HIGH}:
        return "target-config-gutter--block"
    if finding.policy_severity in {PolicySeverity.MEDIUM, PolicySeverity.LOW}:
        return "target-config-gutter--flag"
    return "target-config-gutter--info"


def _advisory_gutter_label(finding: Finding) -> str:
    return finding.model_asserted_cwe or "ADV"


def _findings_by_line(
    findings: list[Finding],
    file_path: str,
    file_content: str,
) -> dict[int, list[Finding]]:
    by_line: dict[int, list[Finding]] = {}
    for finding in findings:
        if finding.file_path != file_path:
            continue
        if is_advisory_finding(finding):
            resolved = resolve_advisory_location(finding, file_content)
            if resolved.location_source != "parser_resolved":
                continue
            anchor_lines = resolved.parser_resolved_lines or (
                (resolved.parser_resolved_line,) if resolved.parser_resolved_line else ()
            )
            for line_no in anchor_lines:
                by_line.setdefault(line_no, []).append(finding)
            continue
        if not finding.line_range:
            continue
        for line_no in range(finding.line_range.start, finding.line_range.end + 1):
            by_line.setdefault(line_no, []).append(finding)
    return by_line


def _unanchored_advisories_for_file(
    findings: list[Finding],
    *,
    target_id: str,
    file_path: str,
    file_content: str,
) -> tuple[UnanchoredAdvisoryView, ...]:
    rows: list[UnanchoredAdvisoryView] = []
    for finding in findings:
        if not is_advisory_finding(finding) or finding.file_path != file_path:
            continue
        resolved = resolve_advisory_location(finding, file_content)
        if resolved.location_source != "unanchored":
            continue
        rows.append(
            UnanchoredAdvisoryView(
                finding_id=finding.id,
                title=finding.title,
                findings_href=f"/ui/targets/{target_id}?tab=findings#finding-{finding.id}",
            )
        )
    return tuple(rows)


def _file_parse_coverage_label(target_type: str, content: str) -> str:
    if target_type == _ASA_TARGET_TYPE:
        from shift_left.handlers.config.parsers.asa.parser import acl_parse_coverage

        parsed, total = acl_parse_coverage(content)
        if total == 0:
            return "No evaluable ACL lines"
        return f"{parsed} of {total} evaluable lines"
    if target_type in {_IOS_XE_TARGET_TYPE, _NX_OS_TARGET_TYPE}:
        if target_type == _IOS_XE_TARGET_TYPE:
            from shift_left.handlers.config.parsers.ios_xe.parser import cli_parse_coverage
        else:
            from shift_left.handlers.config.parsers.nx_os.parser import cli_parse_coverage

        parsed, total = cli_parse_coverage(content)
        if total == 0:
            return "No evaluable CLI lines"
        return f"{parsed} of {total} evaluable lines"
    if target_type in _HCL_TARGET_TYPES:
        status = parse_hcl_content(content)
        if status.resource_block_count == 0:
            return "No HCL resources"
        if status.parsed is None:
            return f"0 of {status.resource_block_count} HCL resources (parse failure)"
        from shift_left.handlers.config.hcl_parse import iter_hcl_resources

        parsed_count = len(iter_hcl_resources(status.parsed))
        return f"{parsed_count} of {status.resource_block_count} HCL resources"
    return "—"


def _unparsed_lines(target_type: str, content: str) -> set[int]:
    unparsed: set[int] = set()
    if target_type == _ASA_TARGET_TYPE:
        from shift_left.handlers.config.parsers.asa.parser import parse_asa_config

        config = parse_asa_config(content)
        for item in config.unparsed_access_list_lines:
            unparsed.add(item.line_no)
    elif target_type == _IOS_XE_TARGET_TYPE:
        from shift_left.handlers.config.parsers.ios_xe.parser import parse_ios_xe_config

        parsed = parse_ios_xe_config(content)
        for item in parsed.unparsed_lines:
            unparsed.add(item.line_no)
    elif target_type == _NX_OS_TARGET_TYPE:
        from shift_left.handlers.config.parsers.nx_os.parser import parse_nx_os_config

        parsed = parse_nx_os_config(content)
        for item in parsed.unparsed_lines:
            unparsed.add(item.line_no)
    return unparsed


def _format_asa_network_values(
    name: str,
    *,
    networks: dict,
    network_groups: dict,
    stack: tuple[str, ...] = (),
) -> tuple[str, ...] | None:
    from shift_left.handlers.config.parsers.asa.parser import NetworkObject, NetworkObjectGroup

    if name in stack:
        return None
    obj = networks.get(name)
    if obj is not None:
        values: list[str] = []
        for line in obj.body_lines:
            tokens = line.split()
            if len(tokens) >= 3 and tokens[0] == "host":
                values.append(tokens[1])
            elif len(tokens) >= 3 and tokens[0] == "subnet":
                values.append(f"{tokens[1]}/{tokens[2]}")
            elif len(tokens) >= 2 and tokens[0] == "range":
                values.append(f"{tokens[1]}-{tokens[2]}")
        return tuple(values) if values else ("(object)",)

    group: NetworkObjectGroup | None = network_groups.get(name)
    if group is None:
        return None
    values: list[str] = []
    for member in group.members:
        if member.kind == "network-object" and member.value:
            values.append(member.value.replace("host:", "").replace("net:", ""))
        elif member.kind == "object" and member.ref:
            nested = _format_asa_network_values(
                member.ref,
                networks=networks,
                network_groups=network_groups,
                stack=stack + (name,),
            )
            if nested:
                values.extend(nested)
        elif member.kind == "group-object" and member.ref:
            nested = _format_asa_network_values(
                member.ref,
                networks=networks,
                network_groups=network_groups,
                stack=stack + (name,),
            )
            if nested:
                values.extend(nested)
        elif member.kind == "any":
            values.append("any")
    return tuple(values) if values else ("(group)",)


def _asa_reference_notes(content: str, target_type: str) -> dict[int, tuple[str, ...]]:
    if target_type != _ASA_TARGET_TYPE:
        return {}
    from shift_left.handlers.config.parsers.asa.parser import parse_asa_config
    from shift_left.handlers.config.parsers.asa.resolver import is_unresolvable_ace, resolve_asa_config

    config = parse_asa_config(content)
    resolved = resolve_asa_config(config)
    networks = {item.name: item for item in config.network_objects}
    network_groups = {item.name: item for item in config.network_object_groups}
    notes: dict[int, list[str]] = {}

    for entry in config.access_list_entries:
        line_notes: list[str] = []
        ace = resolved.ace_resolutions.get(entry.line_no)
        if entry.source_kind == "object-group":
            values = _format_asa_network_values(
                entry.source, networks=networks, network_groups=network_groups
            )
            if values is None or (ace and ace.source.failure):
                line_notes.append(
                    f"object-group {entry.source} → unresolved - breadth unknown (ASA-007)"
                )
            else:
                line_notes.append(f"object-group {entry.source} → {', '.join(values)}")
        if entry.destination_kind == "object-group":
            values = _format_asa_network_values(
                entry.destination, networks=networks, network_groups=network_groups
            )
            if values is None or (ace and ace.destination.failure):
                line_notes.append(
                    f"object-group {entry.destination} → unresolved - breadth unknown (ASA-007)"
                )
            else:
                line_notes.append(f"object-group {entry.destination} → {', '.join(values)}")
        if entry.service_group_ref:
            if ace and ace.service and ace.service.failure:
                line_notes.append(
                    f"object-group {entry.service_group_ref} → unresolved - breadth unknown (ASA-007)"
                )
        if ace and is_unresolvable_ace(ace) and not line_notes:
            line_notes.append("unresolved - breadth unknown (ASA-007)")
        if line_notes:
            notes[entry.line_no] = line_notes
    return {line: tuple(items) for line, items in notes.items()}


def _ios_xe_reference_notes(content: str, target_type: str) -> dict[int, tuple[str, ...]]:
    if target_type != _IOS_XE_TARGET_TYPE:
        return {}
    from shift_left.handlers.config.parsers.ios_xe.parser import parse_ios_xe_config

    parsed = parse_ios_xe_config(content)
    notes: dict[int, list[str]] = {}
    for entry in parsed.access_list_entries:
        ace = parsed.ace_resolutions.get(entry.line_no)
        if ace is None:
            continue
        line_notes: list[str] = []
        if entry.source_kind == "object-group":
            if ace.unresolved:
                line_notes.append(
                    f"object-group {entry.source} → unresolved - breadth unknown (IOS-001)"
                )
            elif ace.source_values:
                line_notes.append(f"object-group {entry.source} → {', '.join(ace.source_values)}")
        if entry.destination_kind == "object-group":
            if ace.unresolved:
                line_notes.append(
                    f"object-group {entry.destination} → unresolved - breadth unknown (IOS-001)"
                )
            elif ace.destination_values:
                line_notes.append(
                    f"object-group {entry.destination} → {', '.join(ace.destination_values)}"
                )
        if line_notes:
            notes[entry.line_no] = line_notes
    for item in parsed.unresolved_references:
        notes.setdefault(item.line_no, []).append(
            f"{item.ref_kind} {item.ref_name} → unresolved - breadth unknown (IOS-001)"
        )
    return {line: tuple(items) for line, items in notes.items()}


def _nx_os_reference_notes(content: str, target_type: str) -> dict[int, tuple[str, ...]]:
    if target_type != _NX_OS_TARGET_TYPE:
        return {}
    from shift_left.handlers.config.parsers.nx_os.parser import parse_nx_os_config

    parsed = parse_nx_os_config(content)
    notes: dict[int, list[str]] = {}
    for entry in parsed.access_list_entries:
        ace = parsed.ace_resolutions.get(entry.line_no)
        if ace is None:
            continue
        line_notes: list[str] = []
        if entry.source_kind == "object-group":
            if ace.unresolved:
                line_notes.append(
                    f"addr group {entry.source} → unresolved - breadth unknown (NXOS-001)"
                )
            elif ace.source_values:
                line_notes.append(f"addr group {entry.source} → {', '.join(ace.source_values)}")
        if entry.destination_kind == "object-group":
            if ace.unresolved:
                line_notes.append(
                    f"addr group {entry.destination} → unresolved - breadth unknown (NXOS-001)"
                )
            elif ace.destination_values:
                line_notes.append(
                    f"addr group {entry.destination} → {', '.join(ace.destination_values)}"
                )
        if line_notes:
            notes[entry.line_no] = line_notes
    for item in parsed.unresolved_references:
        notes.setdefault(item.line_no, []).append(
            f"{item.ref_kind} {item.ref_name} → unresolved - breadth unknown (NXOS-001)"
        )
    return {line: tuple(items) for line, items in notes.items()}


def _reference_notes(content: str, target_type: str) -> dict[int, tuple[str, ...]]:
    asa = _asa_reference_notes(content, target_type)
    ios = _ios_xe_reference_notes(content, target_type)
    nxos = _nx_os_reference_notes(content, target_type)
    merged: dict[int, list[str]] = {}
    for source in (asa, ios, nxos):
        for line_no, items in source.items():
            merged.setdefault(line_no, []).extend(items)
    return {line: tuple(dict.fromkeys(items)) for line, items in merged.items()}


def _build_line_views(
    content: str,
    *,
    target_id: str,
    target_type: str,
    file_path: str,
    findings: list[Finding],
    line_offset: int = 0,
    line_filter: set[int] | None = None,
) -> tuple[ConfigLineView, ...]:
    findings_map = _findings_by_line(findings, file_path, content)
    unparsed = _unparsed_lines(target_type, content)
    ref_notes = _reference_notes(content, target_type)
    secret_values = extract_secret_values_from_content(content, path=file_path)
    rows: list[ConfigLineView] = []
    for index, raw in enumerate(content.splitlines(), start=1):
        if line_filter is not None and index not in line_filter:
            continue
        line_findings = findings_map.get(index, [])
        rule_ids: list[str] = []
        finding_ids: list[str] = []
        severity_class: str | None = None
        findings_href: str | None = None
        for finding in line_findings:
            rule_id = handler_rule_id_from_trace(finding.trace)
            if rule_id and rule_id not in rule_ids:
                rule_ids.append(rule_id)
            elif is_advisory_finding(finding):
                label = _advisory_gutter_label(finding)
                if label not in rule_ids:
                    rule_ids.append(label)
            if finding.id not in finding_ids:
                finding_ids.append(finding.id)
            if severity_class is None:
                severity_class = _severity_gutter_class(finding)
            if findings_href is None:
                findings_href = f"/ui/targets/{target_id}?tab=findings#finding-{finding.id}"
        rows.append(
            ConfigLineView(
                num=index + line_offset,
                text=redact_config_line(raw, line_no=index, secret_values=secret_values),
                finding_rule_ids=tuple(rule_ids),
                finding_ids=tuple(finding_ids),
                severity_class=severity_class,
                findings_href=findings_href,
                unparsed=index in unparsed and not rule_ids,
                reference_notes=ref_notes.get(index, ()),
            )
        )
    return tuple(rows)


_RESOURCE_START = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)


def _hcl_resource_line_ranges(content: str) -> list[tuple[str, str, int, set[int]]]:
    lines = content.splitlines()
    blocks: list[tuple[str, str, int, set[int]]] = []
    index = 0
    while index < len(lines):
        match = _RESOURCE_START.match(lines[index])
        if not match:
            index += 1
            continue
        resource_type, name = match.group(1), match.group(2)
        depth = 1
        line_numbers = {index + 1}
        cursor = index + 1
        while cursor < len(lines) and depth > 0:
            depth += lines[cursor].count("{") - lines[cursor].count("}")
            line_numbers.add(cursor + 1)
            cursor += 1
        blocks.append((resource_type, name, index + 1, line_numbers))
        index = cursor
    return blocks


def _build_hcl_blocks(
    content: str,
    *,
    target_id: str,
    target_type: str,
    file_path: str,
    findings: list[Finding],
) -> tuple[HclResourceBlockView, ...]:
    all_lines = _build_line_views(
        content,
        target_id=target_id,
        target_type=target_type,
        file_path=file_path,
        findings=findings,
    )
    line_by_num = {line.num: line for line in all_lines}
    blocks: list[HclResourceBlockView] = []
    for resource_type, name, header_line, line_nums in _hcl_resource_line_ranges(content):
        block_lines = tuple(line_by_num[num] for num in sorted(line_nums) if num in line_by_num)
        blocks.append(
            HclResourceBlockView(
                resource_type=resource_type,
                name=name,
                header_line=header_line,
                lines=block_lines,
            )
        )
    if blocks:
        return tuple(blocks)
    return (
        HclResourceBlockView(
            resource_type="(file)",
            name=file_path.split("/")[-1],
            header_line=1,
            lines=all_lines,
        ),
    )


def _file_content(detail: TargetDetail, path: str) -> str:
    for item in detail.declared_files:
        if item.get("path") == path:
            lines = item.get("lines") or []
            return "\n".join(line.get("text", "") for line in lines)
    return ""


def build_config_panel(detail: TargetDetail) -> TargetConfigPanel:
    target = detail.target
    findings = _head_findings(detail)
    selected = detail.selected_file
    paths = [item.get("path") or "" for item in detail.declared_files if item.get("path")]
    if selected and selected not in paths:
        selected = paths[0] if paths else None
    elif not selected and paths:
        selected = paths[0]

    cards: list[TargetConfigFileCard] = []
    for path in paths:
        content = _file_content(detail, path)
        is_hcl = target.target_type in _HCL_TARGET_TYPES
        if is_hcl:
            resource_blocks = _build_hcl_blocks(
                content,
                target_id=target.id,
                target_type=target.target_type,
                file_path=path,
                findings=findings,
            )
            lines: tuple[ConfigLineView, ...] = ()
            view_mode = "hcl"
        else:
            lines = _build_line_views(
                content,
                target_id=target.id,
                target_type=target.target_type,
                file_path=path,
                findings=findings,
            )
            resource_blocks = ()
            view_mode = "cli"
        cards.append(
            TargetConfigFileCard(
                path=path,
                head_sha=detail.declared_head_sha,
                head_short=detail.declared_head_short,
                parse_coverage_label=_file_parse_coverage_label(target.target_type, content),
                view_mode=view_mode,
                lines=lines,
                resource_blocks=resource_blocks,
                unanchored_advisories=_unanchored_advisories_for_file(
                    findings,
                    target_id=target.id,
                    file_path=path,
                    file_content=content,
                ),
                selected=path == selected,
            )
        )

    declare_hint = (
        "Add config_paths globs under managed_targets.targets in shift-left.yaml "
        "that match files in this repository."
    )
    return TargetConfigPanel(
        declared_head_sha=detail.declared_head_sha,
        declared_head_short=detail.declared_head_short,
        files=tuple(cards),
        declare_hint=declare_hint,
    )
