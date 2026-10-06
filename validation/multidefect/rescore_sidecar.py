#!/usr/bin/env python3
"""Re-apply tightened VLoc ground-truth filters to an existing corpus sidecar."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

VALIDATION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(VALIDATION))

from multidefect.ground_truth import filter_ground_truth_files

SIDECAR_PATH = VALIDATION / "multidefect" / "ground-truth.json"
REPORT_PATH = VALIDATION / "reports" / "multidefect-gt-rescore.json"


def _distribution(entries: list[dict]) -> dict[int, int]:
    counts = Counter(int(entry.get("ground_truth_file_count") or 0) for entry in entries)
    return {key: counts[key] for key in sorted(counts)}


def main() -> int:
    payload = json.loads(SIDECAR_PATH.read_text(encoding="utf-8"))
    entries = list(payload.get("entries") or [])
    before = _distribution(entries)
    changed: list[dict] = []

    for entry in entries:
        prior = list(entry.get("ground_truth_files") or [])
        filtered = filter_ground_truth_files(prior)
        if filtered != prior:
            changed.append(
                {
                    "entry_id": entry["entry_id"],
                    "before_count": len(prior),
                    "after_count": len(filtered),
                    "removed": sorted(set(prior) - set(filtered)),
                    "kept": filtered,
                }
            )
        entry["ground_truth_files"] = filtered
        entry["ground_truth_file_count"] = len(filtered)

    after = _distribution(entries)
    report = {
        "sidecar": str(SIDECAR_PATH),
        "entry_count": len(entries),
        "distribution_before": before,
        "distribution_after": after,
        "changed_entry_count": len(changed),
        "changed_entries": changed,
    }
    payload["entries"] = entries
    payload["ground_truth_rescore"] = {
        "distribution_before": before,
        "distribution_after": after,
        "changed_entry_count": len(changed),
    }
    SIDECAR_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
