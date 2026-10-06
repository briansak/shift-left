#!/usr/bin/env python3
"""Re-score cached Experiment D / D2 completions with legacy vs corrected CWE parser."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "validation"
sys.path.insert(0, str(VALIDATION))

from rcm_cwe_scoring import rescore_rows  # noqa: E402

REPORTS = ROOT / "validation" / "reports"
D_PATH = REPORTS / "rcm-cwe-eval.json"
D2_PATH = REPORTS / "rcm-cwe-5shot-eval.json"
OUTPUT_JSON = REPORTS / "rcm-cwe-parser-rescore.json"
OUTPUT_TXT = REPORTS / "rcm-cwe-parser-rescore.txt"


def _rows_from_report(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if "foundation_sec" in payload:
        return list(payload["foundation_sec"]["results"])
    return list((payload.get("models") or {}).get("foundation_sec", {}).get("results") or [])


def _line(label: str, legacy: dict[str, Any], corrected: dict[str, Any], newly_valid: int) -> list[str]:
    return [
        f"{label}:",
        (
            f"  legacy parser:    {legacy['correct']}/{legacy['total']} correct, "
            f"invalid={legacy['invalid_predictions']}, incorrect={legacy['incorrect']}"
        ),
        (
            f"  corrected parser: {corrected['correct']}/{corrected['total']} correct, "
            f"invalid={corrected['invalid_predictions']}, incorrect={corrected['incorrect']}"
        ),
        f"  newly valid under corrected parser (no re-inference): {newly_valid}",
    ]


def main() -> int:
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "task": "rcm_cwe_parser_rescore_cached_completions",
        "note": "Parser-only delta on pre-harness-fix cached model_response text.",
    }

    lines = [
        "=== RCM CWE parser re-score (cached completions, no re-inference) ===",
        "",
    ]

    for experiment, path, after_the_cwe_is in (
        ("D", D_PATH, False),
        ("D2", D2_PATH, True),
    ):
        if not path.is_file():
            print(f"WARNING: missing {path}", file=sys.stderr)
            continue
        rows = _rows_from_report(path)
        legacy, corrected, newly_valid = rescore_rows(rows, after_the_cwe_is=after_the_cwe_is)
        report[experiment] = {
            "source_report": str(path.relative_to(ROOT)),
            "legacy_parser": {
                k: legacy[k]
                for k in ("correct", "incorrect", "invalid_predictions", "accuracy", "per_target_type")
            },
            "corrected_parser": {
                k: corrected[k]
                for k in ("correct", "incorrect", "invalid_predictions", "accuracy", "per_target_type")
            },
            "newly_valid_under_corrected_parser": newly_valid,
        }
        lines.extend(_line(f"Experiment {experiment}", legacy, corrected, newly_valid))
        lines.append("")

    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    OUTPUT_TXT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"Wrote {OUTPUT_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
