"""Build unified emitted-finding manifests for cross-run attribution."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from report_quant_stamping import merge_quant_metadata


def _finding_key(item: dict[str, Any]) -> tuple[str, str, int, int, str]:
    finding = item.get("finding") or item
    return (
        str(item.get("corpus") or ""),
        str(item.get("rel_path") or ""),
        int(finding.get("line_start") or 0),
        int(finding.get("line_end") or finding.get("line_start") or 0),
        str(finding.get("title") or ""),
    )


def dedupe_emitted_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, int, int, str]] = set()
    unique: list[dict[str, Any]] = []
    for item in items:
        key = _finding_key(item)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def emitted_items_from_cache(cache_path: Path) -> list[dict[str, Any]]:
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    items: list[dict[str, Any]] = []
    for record in payload.get("files") or []:
        if record.get("model_outcome") not in {
            "completed_no_findings",
            "completed_with_findings",
        }:
            continue
        for finding in record.get("model_findings") or []:
            items.append(
                {
                    "corpus": record["corpus"],
                    "rel_path": record["rel_path"],
                    "target_type": record.get("target_type"),
                    "virtual_path": record.get("virtual_path"),
                    "expected_rule_ids": record.get("expected_rule_ids") or [],
                    "finding": finding,
                }
            )
    return items


def emitted_items_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key in ("invalid_findings", "surviving_model_findings", "unlabeled_model_findings"):
        items.extend(list(report.get(key) or []))
    return dedupe_emitted_items(items)


def write_emitted_manifest(
    *,
    items: list[dict[str, Any]],
    path: Path,
    metadata: dict[str, Any],
    source_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = merge_quant_metadata(
        {
            **metadata,
            "emitted_model_findings": items,
            "summary": {
                "emitted_model_findings_count": len(items),
            },
        },
        source_report=source_report,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
