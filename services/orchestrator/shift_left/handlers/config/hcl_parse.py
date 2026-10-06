"""Shared HCL parse availability and interpretability checks (CWE-754)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from shift_left.handlers.config.secret_values import SecretValueSet, extract_secret_values_from_content
from shift_left.handlers.config.types import ConfigRuleMatch

HCL_INTERPRETABILITY_RULE_ID = "HCL-001"
HCL_INTERPRETABILITY_TRACE = f"handler:{HCL_INTERPRETABILITY_RULE_ID}"

_RESOURCE_BLOCK_RE = re.compile(r'^\s*resource\s+"', re.MULTILINE)


@dataclass(frozen=True)
class HclParseStatus:
    available: bool
    parsed: dict[str, Any] | None
    error: str | None
    resource_block_count: int
    secret_values: SecretValueSet = field(default_factory=SecretValueSet.empty)


def count_hcl_resource_blocks(content: str) -> int:
    return len(_RESOURCE_BLOCK_RE.findall(content))


def parse_hcl_content(content: str, *, path: str | None = None) -> HclParseStatus:
    """Parse HCL content; distinguish missing parser vs syntax failure."""
    block_count = count_hcl_resource_blocks(content)
    secret_values = extract_secret_values_from_content(content, path=path)
    try:
        import hcl2
    except ImportError as exc:
        return HclParseStatus(
            available=False,
            parsed=None,
            error=str(exc),
            resource_block_count=block_count,
            secret_values=secret_values,
        )
    try:
        parsed = hcl2.loads(content)
    except Exception as exc:  # noqa: BLE001
        return HclParseStatus(
            available=True,
            parsed=None,
            error=str(exc),
            resource_block_count=block_count,
            secret_values=secret_values,
        )
    return HclParseStatus(
        available=True,
        parsed=parsed,
        error=None,
        resource_block_count=block_count,
        secret_values=secret_values,
    )


def hcl_interpretability_reason(status: HclParseStatus, *, content: str) -> str | None:
    """Return a block reason when claimed HCL cannot be interpreted deterministically."""
    if not content.strip():
        return None
    if not status.available:
        return (
            "python-hcl2 is not available — the gate cannot interpret this HCL/Terraform file."
        )
    if status.parsed is not None:
        return None
    if status.error:
        return f"HCL could not be parsed deterministically: {status.error}"
    return "HCL could not be parsed deterministically."


def hcl_interpretability_matches(
    content: str,
    *,
    line_offset: int = 0,
) -> list[ConfigRuleMatch]:
    """CWE-754 matches when parser is missing or HCL cannot be loaded."""
    status = parse_hcl_content(content)
    reason = hcl_interpretability_reason(status, content=content)
    if reason is None:
        return []
    line_count = max(1, len(content.splitlines()))
    return [
        ConfigRuleMatch(
            cwe="CWE-754",
            pattern_id=HCL_INTERPRETABILITY_RULE_ID,
            line_start=1 + line_offset,
            line_end=line_count + line_offset,
            evaluation_status="matched",
            title="HCL content could not be interpreted",
            description=reason,
            construct_key="file",
        )
    ]


def iter_hcl_resources(parsed: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    from shift_left.handlers.config.parsers.terraform_hcl import _iter_resources

    return _iter_resources(parsed)


@dataclass(frozen=True)
class HclCoverageResult:
    parsed_resources: int
    total_resource_blocks: int
    parse_failure_files: int
    empty_resources: bool
    uncovered_provider_prefixes: tuple[str, ...] = ()

    @property
    def failed(self) -> bool:
        return self.parse_failure_files > 0


def compute_hcl_coverage(
    contents: list[str],
    *,
    target_type: str = "generic_terraform",
) -> HclCoverageResult:
    """Aggregate HCL resource parse coverage across declared file bodies."""
    from shift_left.handlers.config.hcl_provider_coverage import uncovered_provider_prefixes

    parsed_resources = 0
    total_blocks = 0
    parse_failure_files = 0
    saw_content = False
    uncovered: set[str] = set()
    for content in contents:
        if not content.strip():
            continue
        saw_content = True
        status = parse_hcl_content(content)
        total_blocks += status.resource_block_count
        if hcl_interpretability_reason(status, content=content) is not None:
            parse_failure_files += 1
            continue
        parsed_resources += len(iter_hcl_resources(status.parsed or {}))
        uncovered.update(uncovered_provider_prefixes(target_type, content))
    empty_resources = saw_content and total_blocks == 0 and parse_failure_files == 0
    return HclCoverageResult(
        parsed_resources=parsed_resources,
        total_resource_blocks=total_blocks,
        parse_failure_files=parse_failure_files,
        empty_resources=empty_resources,
        uncovered_provider_prefixes=tuple(sorted(uncovered)),
    )
