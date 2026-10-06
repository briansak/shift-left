#!/usr/bin/env python3
"""Backfill constrained_output report with surviving_model_findings and coverage metadata."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "validation" / "reports"
FINDINGS_CACHE = REPORTS / "findings-cache"
REPORT_PATH = REPORTS / "model-vs-handler-constrained-output.json"
CACHE_PATH = FINDINGS_CACHE / "constrained_output.findings.json"

sys.path.insert(0, str(ROOT / "validation"))
from emitted_findings import emitted_items_from_cache  # noqa: E402
from report_quant_stamping import apply_quant_stamping  # noqa: E402


def _survivors_from_unlabeled(report: dict[str, Any]) -> list[dict[str, Any]]:
    return list(report.get("unlabeled_model_findings") or [])


def _survivors_from_cache(cache_path: Path) -> list[dict[str, Any]]:
    items = emitted_items_from_cache(cache_path)
    invalid_keys = {
        (
            str(item.get("corpus") or ""),
            str(item.get("rel_path") or ""),
            int((item.get("finding") or {}).get("line_start") or 0),
            int((item.get("finding") or {}).get("line_end") or 0),
            str((item.get("finding") or {}).get("title") or ""),
        )
        for item in (json.loads(REPORT_PATH.read_text()).get("invalid_findings") or [])
    }
    survivors: list[dict[str, Any]] = []
    for item in items:
        finding = item.get("finding") or {}
        key = (
            str(item.get("corpus") or ""),
            str(item.get("rel_path") or ""),
            int(finding.get("line_start") or 0),
            int(finding.get("line_end") or 0),
            str(finding.get("title") or ""),
        )
        if key not in invalid_keys:
            survivors.append(item)
    return survivors


def backfill_report(report: dict[str, Any], *, cache_path: Path | None) -> dict[str, Any]:
    summary = report.setdefault("summary", {})
    emitted = int(summary.get("model_findings_emitted") or 0)
    invalid_count = len(report.get("invalid_findings") or [])
    unlabeled = report.get("unlabeled_model_findings") or []
    surviving_total = int(summary.get("model_findings_total") or 0)

    if cache_path and cache_path.is_file():
        survivors = _survivors_from_cache(cache_path)
        source = str(cache_path.relative_to(ROOT))
    else:
        survivors = _survivors_from_unlabeled(report)
        source = "unlabeled_model_findings (no findings cache)"

    stored_payloads = invalid_count + len(unlabeled)
    missing_tp_survivors = max(0, emitted - stored_payloads)

    report["surviving_model_findings"] = survivors
    report["emitted_findings_coverage"] = {
        "emitted": emitted,
        "stored_invalid": invalid_count,
        "stored_unlabeled": len(unlabeled),
        "stored_surviving": len(survivors),
        "stored_total_payloads": stored_payloads,
        "missing_tp_survivor_payloads": missing_tp_survivors,
        "surviving_total": surviving_total,
        "findings_cache": source,
        "note": (
            f"{missing_tp_survivors} TP survivor payloads were not persisted in the "
            "original report and cannot be reconstructed without a findings cache."
            if missing_tp_survivors
            else "All emitted payloads are present in the report."
        ),
    }
    report["backfilled_at"] = datetime.now(UTC).isoformat()
    return apply_quant_stamping(report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--cache", type=Path, default=CACHE_PATH)
    args = parser.parse_args()

    if not args.report.is_file():
        print(f"ERROR: report not found: {args.report}", file=sys.stderr)
        return 1

    report = json.loads(args.report.read_text(encoding="utf-8"))
    cache_path = args.cache if args.cache.is_file() else None
    if cache_path:
        print(f"Using findings cache: {cache_path.relative_to(ROOT)}")
    else:
        print("No constrained_output findings cache; documenting coverage gap.")

    updated = backfill_report(report, cache_path=cache_path)
    args.report.write_text(json.dumps(updated, indent=2), encoding="utf-8")

    coverage = updated["emitted_findings_coverage"]
    print(f"Wrote {args.report.relative_to(ROOT)}")
    print(
        f"  emitted={coverage['emitted']} stored={coverage['stored_total_payloads']} "
        f"missing_tp_survivors={coverage['missing_tp_survivor_payloads']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
