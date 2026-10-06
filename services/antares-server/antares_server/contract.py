"""Strict contract validation for diff-hunk JSON responses (legacy path)."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from antares_server.cwe_catalog import cwe_in_catalog, load_cwe_catalog

logger = logging.getLogger(__name__)

_REQUIRED_FIELDS = (
    "file_path",
    "line_start",
    "line_end",
    "cwe",
    "severity",
    "confidence",
    "title",
    "description",
    "evidence",
    "trace",
)
_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_CWE_PATTERN = re.compile(r"^CWE-\d+$", re.IGNORECASE)
_FENCE_PATTERN = re.compile(r"```")


@dataclass(frozen=True)
class ContractParseResult:
    ok: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    failure_message: str | None = None
    violations: tuple[str, ...] = ()
    had_markdown_fence: bool = False


def _normalize_cwe(value: str) -> str:
    text = value.strip().upper()
    if not text.startswith("CWE-"):
        text = f"CWE-{text.replace('CWE', '').strip('-')}"
    return text


def _strip_markdown_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, count=1)
        stripped = re.sub(r"\s*```\s*$", "", stripped, count=1)
    return stripped


def _extract_json_array(text: str) -> tuple[list[Any] | None, str | None]:
    stripped = _strip_markdown_fences(text)
    start = stripped.find("[")
    if start < 0:
        return None, "response did not contain a JSON array"

    for end in range(len(stripped), start, -1):
        if stripped[end - 1] != "]":
            continue
        candidate = stripped[start:end]
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as exc:
            continue
        if not isinstance(parsed, list):
            return None, "top-level JSON value is not an array"
        return parsed, None

    return None, "JSON array is incomplete or malformed"


def _finding_fingerprint(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(item.get("file_path", "")),
        int(item["line_start"]),
        int(item["line_end"]),
        _normalize_cwe(str(item.get("cwe", ""))),
        str(item.get("title", "")).strip().lower(),
    )


def _validate_item(
    item: dict[str, Any],
    *,
    default_path: str,
    catalog: frozenset[str],
    index: int,
) -> list[str]:
    violations: list[str] = []
    prefix = f"finding[{index}]"

    for key in _REQUIRED_FIELDS:
        if key not in item:
            violations.append(f"{prefix}: missing required field {key!r}")

    file_path = item.get("file_path", default_path)
    if not isinstance(file_path, str) or not file_path.strip():
        violations.append(f"{prefix}: file_path must be a non-empty string")

    for line_key in ("line_start", "line_end"):
        value = item.get(line_key)
        if not isinstance(value, int) or value < 1:
            violations.append(f"{prefix}: {line_key} must be a positive integer")

    if (
        isinstance(item.get("line_start"), int)
        and isinstance(item.get("line_end"), int)
        and item["line_start"] > item["line_end"]
    ):
        violations.append(f"{prefix}: line_start must be <= line_end")

    cwe_raw = item.get("cwe")
    if not isinstance(cwe_raw, str) or not _CWE_PATTERN.match(cwe_raw.strip()):
        violations.append(f"{prefix}: cwe must match CWE-<id> (got {cwe_raw!r})")
    else:
        normalized = _normalize_cwe(cwe_raw)
        if not cwe_in_catalog(normalized, catalog):
            violations.append(f"{prefix}: cwe {normalized!r} not in local CWE catalog")

    severity = item.get("severity")
    if not isinstance(severity, str) or severity.lower() not in _SEVERITIES:
        violations.append(f"{prefix}: severity must be one of {sorted(_SEVERITIES)}")

    confidence = item.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
        violations.append(f"{prefix}: confidence must be a number between 0.0 and 1.0")

    for text_key in ("title", "description", "evidence", "trace"):
        value = item.get(text_key)
        if not isinstance(value, str) or not value.strip():
            violations.append(f"{prefix}: {text_key} must be a non-empty string")

    return violations


def parse_and_validate_findings(
    text: str,
    *,
    default_path: str,
    catalog: frozenset[str] | None = None,
) -> ContractParseResult:
    """
    Validate model output against the diff-hunk JSON contract.

    Contract-invalid responses must fail closed — never silently accept partial data.
    """
    catalog = catalog if catalog is not None else load_cwe_catalog()
    had_fence = bool(_FENCE_PATTERN.search(text))
    violations: list[str] = []

    if had_fence:
        violations.append("response contained markdown code fences (contract violation)")
        logger.warning("Antares response used markdown fences")

    items, parse_error = _extract_json_array(text)
    if parse_error:
        violations.append(parse_error)
        message = "; ".join(violations)
        return ContractParseResult(
            ok=False,
            failure_message=message,
            violations=tuple(violations),
            had_markdown_fence=had_fence,
        )

    assert items is not None
    if not items:
        if violations:
            return ContractParseResult(
                ok=False,
                failure_message="; ".join(violations),
                violations=tuple(violations),
                had_markdown_fence=had_fence,
            )
        return ContractParseResult(ok=True, findings=[])

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    for index, raw in enumerate(items):
        if not isinstance(raw, dict):
            violations.append(f"finding[{index}]: must be an object")
            continue
        item_violations = _validate_item(raw, default_path=default_path, catalog=catalog, index=index)
        violations.extend(item_violations)
        if item_violations:
            continue

        fingerprint = _finding_fingerprint(raw)
        if fingerprint in seen:
            violations.append(f"finding[{index}]: duplicate finding rejected")
            continue
        seen.add(fingerprint)

        normalized.append(
            {
                "file_path": raw.get("file_path", default_path),
                "line_start": int(raw["line_start"]),
                "line_end": int(raw["line_end"]),
                "cwe": _normalize_cwe(str(raw["cwe"])),
                "severity": str(raw["severity"]).lower(),
                "confidence": float(raw["confidence"]),
                "title": str(raw["title"]),
                "description": str(raw["description"]),
                "evidence": str(raw["evidence"]),
                "trace": str(raw["trace"]),
            }
        )

    if violations:
        return ContractParseResult(
            ok=False,
            failure_message="; ".join(violations),
            violations=tuple(violations),
            had_markdown_fence=had_fence,
        )

    return ContractParseResult(ok=True, findings=normalized, had_markdown_fence=had_fence)
