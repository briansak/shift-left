"""Load handler evaluation coverage for operator review."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shift_left.config import resolve_repo_root
from shift_left.handlers.config.rules.registry import ALL_RULES
from shift_left.models.schema import Finding
from shift_left.ui.cwe_dictionary import unrecognized_model_cwe_tally

REPORT_REL_PATH = Path("validation") / "reports" / "handler-coverage.json"

# Small corpora make percentage headlines misleading (e.g. 19/21 vs 91/92 ACL lines).
PARSE_COVERAGE_COUNT_ONLY_THRESHOLD = 30


def parse_coverage_line_parts(
    target_type: str,
    metrics: dict[str, Any],
) -> tuple[int, int, int, str]:
    """Return (parsed, total, remarks, unit_label) for a handler-coverage row."""
    if target_type in {"cisco_ios_xe", "cisco_nx_os"}:
        return (
            int(metrics["parsed_cli_lines"]),
            int(metrics["total_evaluable_cli_lines"]),
            0,
            "evaluable CLI lines",
        )
    if target_type in {"cisco_ftd", "generic_terraform"}:
        return (
            int(metrics["parsed_resources"]),
            int(metrics["total_resource_blocks"]),
            int(metrics.get("parse_failure_files", 0)),
            "HCL resources",
        )
    return (
        int(metrics["parsed_acl_lines"]),
        int(metrics["total_acl_bearing_lines"]),
        int(metrics.get("remark_acl_lines", 0)),
        "evaluable ACL lines",
    )


def format_parse_coverage_summary(
    parsed: int,
    total: int,
    ratio: float,
    unit: str,
) -> tuple[str, str | None]:
    """Return (primary_display, optional_meta) for UI and CLI tables."""
    count_phrase = f"{parsed} of {total} {unit}"
    if total < PARSE_COVERAGE_COUNT_ONLY_THRESHOLD:
        return count_phrase, None
    return f"{ratio * 100:.1f}%", count_phrase


def parse_coverage_table_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Rows for the handler coverage UI parse-coverage table."""
    rows: list[dict[str, Any]] = []
    for target_type, metrics in sorted(report.get("parse_coverage", {}).items()):
        parsed, total, remarks, unit = parse_coverage_line_parts(target_type, metrics)
        ratio = float(metrics.get("parse_coverage_ratio", 0.0 if total == 0 else parsed / total))
        coverage, _ = format_parse_coverage_summary(parsed, total, ratio, unit)
        rows.append(
            {
                "target_type": target_type,
                "parsed": parsed,
                "total": total,
                "remarks": remarks,
                "coverage": coverage,
            }
        )
    return rows


def handler_coverage_report_path() -> Path:
    return resolve_repo_root() / REPORT_REL_PATH


def load_handler_coverage_report() -> dict[str, Any] | None:
    path = handler_coverage_report_path()
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def model_cwe_advisory_summary(findings: list[Finding]) -> dict[str, Any]:
    """Tally unrecognized model CWE assertions for the coverage report."""
    return unrecognized_model_cwe_tally(findings)


def coverage_view_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Merge enabled per-rule metrics with disabled rule gaps for UI tables."""
    generated = report.get("generated_corpus", {}).get("per_rule", {})
    holdout = report.get("holdout_corpus", {}).get("per_rule", {})
    gaps = {item["rule_id"]: item for item in report.get("rule_gaps", [])}
    registry = {rule.id: rule for rule in ALL_RULES}
    rule_ids = sorted(set(generated) | set(holdout) | set(gaps) | set(registry))
    rows: list[dict[str, Any]] = []
    for rule_id in rule_ids:
        rule = registry.get(rule_id)
        gap = gaps.get(rule_id)
        if rule is not None and rule.registry_status == "enforced_prematch":
            rows.append(
                {
                    "rule_id": rule_id,
                    "status": rule.registry_status,
                    "cwe": rule.cwe,
                    "target_type": rule.target_type,
                    "severity": rule.severity,
                    "reason": "",
                    "generated": generated.get(rule_id),
                    "holdout": holdout.get(rule_id),
                }
            )
            continue
        if gap or (rule and rule.registry_status == "disabled"):
            gap = gap or {
                "rule_id": rule_id,
                "status": "disabled",
                "reason": rule.description if rule else "",
                "cwe": rule.cwe if rule else "—",
                "target_type": rule.target_type if rule else "—",
                "severity": rule.severity if rule else "—",
            }
            rows.append(
                {
                    "rule_id": rule_id,
                    "status": gap.get("status", "disabled"),
                    "cwe": gap.get("cwe", "—"),
                    "target_type": gap.get("target_type", "—"),
                    "severity": gap.get("severity", "—"),
                    "reason": gap.get("reason", ""),
                    "generated": None,
                    "holdout": None,
                }
            )
            continue
        rows.append(
            {
                "rule_id": rule_id,
                "status": "enabled",
                "cwe": rule.cwe if rule else "—",
                "target_type": rule.target_type if rule else "—",
                "severity": rule.severity if rule else "—",
                "reason": "",
                "generated": generated.get(rule_id),
                "holdout": holdout.get(rule_id),
            }
        )
    return rows
