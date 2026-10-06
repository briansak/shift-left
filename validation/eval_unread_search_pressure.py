#!/usr/bin/env python3
"""Re-run the four found-not-submitted v3 cases with unread-search-hit pressure."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "validation"))
os.environ.setdefault("SHIFT_LEFT_REPO_ROOT", str(ROOT))
os.environ.setdefault("ANTARES_ENGINE", "llm")
os.environ.setdefault("ANTARES_SANDBOX", os.environ.get("ANTARES_SANDBOX") or "subprocess")
os.environ.setdefault("ANTARES_MODEL_PATH", str(ROOT / "models" / "1b"))
os.environ.setdefault("ANTARES_AGENT_MAX_NEW_TOKENS", "2048")
os.environ.setdefault("ANTARES_SNAPSHOT_DIR", str(ROOT / "data" / "findings" / "antares-snapshots"))

from antares_localization_multidefect import (  # noqa: E402
    MODEL_PATH,
    ROOT as HARNESS_ROOT,
    _ensure_sandbox_image,
    _run_once,
)
from antares_server.loop_control import UNREAD_SEARCH_HIT_NOTICE  # noqa: E402

SIDECAR = ROOT / "validation" / "multidefect" / "ground-truth.json"
OUT_DIR = ROOT / "validation" / "reports" / "unread-pressure-traces"
TARGETS = [
    ("CVE-2018-19787-lxml", 2),
    ("CVE-2023-23931-cryptography", 1),
    ("CVE-2024-1892-scrapy", 1),
    ("CVE-2024-1892-scrapy", 2),
]


def main() -> int:
    sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))
    by_id = {str(e["entry_id"]): e for e in sidecar["entries"]}
    if os.environ.get("ANTARES_SANDBOX", "subprocess") == "docker":
        _ensure_sandbox_image()

    from shift_left_shared.weights import load_prewarm_manifest, verify_antares_weights
    from antares_server.inference import AntaresEngine

    manifest = load_prewarm_manifest(HARNESS_ROOT)
    verify_antares_weights(MODEL_PATH, manifest)
    engine = AntaresEngine(str(MODEL_PATH), load_strategy="on_demand")
    engine.assert_model_present()
    engine.load()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    try:
        for entry_id, run_index in TARGETS:
            entry = by_id[entry_id]
            ground_truth = {str(path) for path in entry["ground_truth_files"]}
            report, metrics = _run_once(
                entry=entry,
                run_index=run_index,
                ground_truth=ground_truth,
                engine=engine,
            )
            trace = str(report.get("exploration_trace") or "")
            hits = {p.lstrip("./") for p in report.get("search_hit_files") or []}
            inspected = {p.lstrip("./") for p in report.get("inspected_files") or []}
            submitted = {p.lstrip("./") for p in metrics.ranked_files}
            gt_in_search = sorted(p for p in ground_truth if p in hits)
            unread = sorted(hits - inspected)
            row = {
                "entry_id": entry_id,
                "run": run_index,
                "ground_truth": sorted(ground_truth),
                "terminal_calls_used": metrics.terminal_calls_used,
                "failure_class": metrics.failure_class,
                "file_f1": metrics.file_f1,
                "gt_in_search": gt_in_search,
                "gt_inspected": sorted(p for p in ground_truth if p in inspected),
                "gt_submitted": sorted(p for p in ground_truth if p in submitted),
                "submitted": list(metrics.ranked_files),
                "unread_search_hits": unread,
                "unread_notice_in_trace": UNREAD_SEARCH_HIT_NOTICE in trace,
                "budget_escalation_in_trace": "[loop-control: budget-escalation]" in trace,
                "forced_submission_in_trace": "[loop-control: forced-submission]" in trace,
            }
            rows.append(row)
            (OUT_DIR / f"{entry_id}-run-{run_index}.json").write_text(
                json.dumps(report, indent=2) + "\n",
                encoding="utf-8",
            )
            print(json.dumps(row, indent=2), file=sys.stderr)
    finally:
        engine.unload()

    summary_path = ROOT / "validation" / "reports" / "unread-pressure-eval.json"
    summary_path.write_text(json.dumps({"runs": rows}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"runs": rows}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
