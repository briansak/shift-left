#!/usr/bin/env python3
"""Backfill quant_evaluated/quant_intended/accuracy_only on existing report artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "validation" / "reports"
VALIDATION = ROOT / "validation"
sys.path.insert(0, str(VALIDATION))

from report_quant_stamping import (  # noqa: E402
    apply_chat_template_fidelity_stamping,
    apply_quant_stamping,
    merge_quant_metadata,
)

SOURCE_REPORTS = {
    "model-vs-handler.json": REPORTS / "model-vs-handler.json",
    "model-vs-handler-platform-specific.json": REPORTS / "model-vs-handler-platform-specific.json",
    "model-vs-handler-constrained-output.json": REPORTS / "model-vs-handler-constrained-output.json",
    "model-vs-handler-platform-constrained.json": REPORTS / "model-vs-handler-platform-constrained.json",
}

DERIVED_FROM_SOURCE = {
    REPORTS / "model-vs-handler-semantic-corrected.json": REPORTS / "model-vs-handler.json",
    REPORTS / "model-vs-handler-platform-specific-semantic-corrected.json": (
        REPORTS / "model-vs-handler-platform-specific.json"
    ),
    REPORTS / "model-vs-handler-retro-constrained.json": REPORTS / "model-vs-handler.json",
    REPORTS / "model-vs-handler-platform-specific-retro-constrained.json": (
        REPORTS / "model-vs-handler-platform-specific.json"
    ),
}

EMITTED_MANIFEST_SOURCES = {
    REPORTS / "model-emitted-findings-baseline.json": REPORTS / "model-vs-handler.json",
    REPORTS / "model-emitted-findings-platform-specific.json": (
        REPORTS / "model-vs-handler-platform-specific.json"
    ),
    REPORTS / "model-emitted-findings-constrained-output.json": (
        REPORTS / "model-vs-handler-constrained-output.json"
    ),
    REPORTS / "model-emitted-findings-platform-constrained.json": (
        REPORTS / "model-vs-handler-platform-constrained.json"
    ),
}

ATTRIBUTION_SOURCES = {
    REPORTS / "model-line-attribution-baseline-emitted.json": (
        REPORTS / "model-emitted-findings-baseline.json"
    ),
    REPORTS / "model-line-attribution-platform-specific-emitted.json": (
        REPORTS / "model-emitted-findings-platform-specific.json"
    ),
    REPORTS / "model-line-attribution-constrained-output-emitted.json": (
        REPORTS / "model-emitted-findings-constrained-output.json"
    ),
    REPORTS / "model-line-attribution-platform-constrained-emitted.json": (
        REPORTS / "model-emitted-findings-platform-constrained.json"
    ),
    REPORTS / "model-line-attribution.json": REPORTS / "model-vs-handler.json",
    REPORTS / "model-line-attribution-platform-specific.json": (
        REPORTS / "model-vs-handler-platform-specific.json"
    ),
    REPORTS / "model-line-attribution-constrained-output.json": (
        REPORTS / "model-vs-handler-constrained-output.json"
    ),
    REPORTS / "model-line-attribution-platform-constrained.json": (
        REPORTS / "model-vs-handler-platform-constrained.json"
    ),
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _stamp_native_report(path: Path) -> None:
    payload = _load(path)
    stamped = apply_chat_template_fidelity_stamping(apply_quant_stamping(payload))
    path.write_text(json.dumps(stamped, indent=2), encoding="utf-8")
    print(f"stamped native report {path.relative_to(ROOT)}")


def _stamp_derived(path: Path, source_path: Path) -> None:
    payload = _load(path)
    source = _load(source_path)
    stamped = merge_quant_metadata(payload, source_report=source)
    if "source" in stamped and isinstance(stamped["source"], dict):
        stamped["source"] = merge_quant_metadata(stamped["source"], source_report=source)
    path.write_text(json.dumps(stamped, indent=2), encoding="utf-8")
    print(f"stamped derived {path.relative_to(ROOT)} from {source_path.name}")


def _stamp_all_model_reports() -> None:
    """Stamp every model-eval JSON artifact under validation/reports/."""
    patterns = ("model*.json", "platform-specific-variance*.json")
    stamped: set[Path] = set()
    for pattern in patterns:
        for path in sorted(REPORTS.glob(pattern)):
            if path in stamped:
                continue
            stamped.add(path)
            if path.name in SOURCE_REPORTS:
                _stamp_native_report(path)
            elif path in DERIVED_FROM_SOURCE:
                source = DERIVED_FROM_SOURCE[path]
                if source.is_file():
                    _stamp_derived(path, source)
            elif path in EMITTED_MANIFEST_SOURCES:
                source = EMITTED_MANIFEST_SOURCES[path]
                if source.is_file():
                    _stamp_derived(path, source)
            elif path in ATTRIBUTION_SOURCES:
                source = ATTRIBUTION_SOURCES[path]
                if source.is_file():
                    _stamp_derived(path, source)
            else:
                _stamp_native_report(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    args = parser.parse_args()

    _stamp_all_model_reports()

    comparison_json = REPORTS / "model-experiments-comparison.json"
    if comparison_json.is_file():
        _stamp_derived(comparison_json, REPORTS / "model-vs-handler.json")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
