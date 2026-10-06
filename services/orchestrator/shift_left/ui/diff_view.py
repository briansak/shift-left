"""Build IDE-style file views from unified diffs for the PR review UI."""

from __future__ import annotations

from shift_left.diff.extractor import parse_unified_diff
from shift_left.models.schema import Finding, LineRange
from shift_left.policy.handler_trace import handler_rule_id_from_trace
from shift_left.handlers.config.secret_values import extract_secret_values_from_content
from shift_left.ui.advisory_line_attribution import is_advisory_finding
from shift_left.ui.config_redaction import HclRedactionState, redact_config_line


def build_diff_file_views(
    diff_text: str,
    findings: list[Finding],
) -> list[dict]:
    highlight_ranges: dict[str, list[LineRange]] = {}
    rule_ids_by_path_line: dict[str, dict[int, list[str]]] = {}
    for finding in findings:
        if is_advisory_finding(finding) or not finding.line_range:
            continue
        rule_id = handler_rule_id_from_trace(finding.trace)
        if not rule_id:
            continue
        highlight_ranges.setdefault(finding.file_path, []).append(finding.line_range)
        line_map = rule_ids_by_path_line.setdefault(finding.file_path, {})
        for line_no in range(finding.line_range.start, finding.line_range.end + 1):
            line_map.setdefault(line_no, [])
            if rule_id not in line_map[line_no]:
                line_map[line_no].append(rule_id)

    files: list[dict] = []
    for changed in parse_unified_diff(diff_text, include_removed=True):
        ranges = highlight_ranges.get(changed.path, [])
        line_rules = rule_ids_by_path_line.get(changed.path, {})
        hcl_state = HclRedactionState() if _is_hcl_path(changed.path) else None
        file_text = "\n".join(
            (raw[1:] if raw else "")
            for hunk in changed.hunks
            for raw in hunk.content.splitlines()
        )
        secret_values = extract_secret_values_from_content(file_text, path=changed.path)
        lines: list[dict] = []
        line_num = 1
        for hunk in changed.hunks:
            line_num = hunk.new_start
            for raw in hunk.content.splitlines():
                prefix = raw[:1] if raw else " "
                content = _redact_diff_line(
                    raw[1:] if raw else "",
                    changed.path,
                    hcl_state,
                    line_no=line_num if prefix != "-" else None,
                    secret_values=secret_values,
                )
                if prefix == "-":
                    lines.append(
                        {
                            "num": None,
                            "prefix": prefix,
                            "text": content,
                            "highlight": False,
                            "removed": True,
                            "finding_marker": False,
                            "finding_rule_ids": [],
                        }
                    )
                    continue
                in_range = any(
                    item.start <= line_num <= item.end for item in ranges
                ) if prefix != "-" else False
                rule_ids = line_rules.get(line_num, []) if in_range else []
                if prefix == "+":
                    lines.append(
                        {
                            "num": line_num,
                            "prefix": prefix,
                            "text": content,
                            "highlight": in_range,
                            "removed": False,
                            "finding_marker": in_range,
                            "finding_rule_ids": rule_ids,
                        }
                    )
                    line_num += 1
                    continue
                lines.append(
                    {
                        "num": line_num,
                        "prefix": " ",
                        "text": content,
                        "highlight": in_range,
                        "removed": False,
                        "finding_marker": in_range,
                        "finding_rule_ids": rule_ids,
                    }
                )
                line_num += 1
        files.append(
            {
                "path": changed.path,
                "language": _language_for_path(changed.path),
                "lines": lines,
                "secret_values": secret_values,
            }
        )
    return files


def build_static_file_view(path: str, content: str) -> dict:
    hcl_state = HclRedactionState() if _is_hcl_path(path) else None
    secret_values = extract_secret_values_from_content(content, path=path)
    lines: list[dict] = []
    for index, raw in enumerate(content.splitlines(), start=1):
        lines.append(
            {
                "num": index,
                "prefix": " ",
                "text": _redact_diff_line(
                    raw, path, hcl_state, line_no=index, secret_values=secret_values
                ),
                "highlight": False,
                "removed": False,
                "finding_marker": False,
            }
        )
    return {
        "path": path,
        "language": _language_for_path(path),
        "lines": lines,
        "secret_values": secret_values,
    }


def _is_hcl_path(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith((".tf", ".tfvars", ".hcl"))


def _redact_diff_line(
    text: str,
    path: str,
    hcl_state: HclRedactionState | None,
    *,
    line_no: int | None = None,
    secret_values=None,
) -> str:
    if hcl_state is not None:
        return hcl_state.redact_line(
            text,
            line_no=line_no or 1,
            secret_values=secret_values,
        )
    return redact_config_line(text, line_no=line_no, secret_values=secret_values)


def _language_for_path(path: str) -> str | None:
    if path.endswith(".tf") or path.endswith(".tfvars") or path.endswith(".hcl"):
        return "terraform"
    if path.endswith((".yaml", ".yml")):
        return "yaml"
    if path.endswith(".json"):
        return "json"
    if path.endswith(".conf") or path.endswith(".cfg"):
        return "nginx"
    return None
