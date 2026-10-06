#!/usr/bin/env python3
"""Run Antares e2e smoke multiple times and summarize variance."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SMOKE_PATH = ROOT / "validation" / "antares_e2e_investigation_smoke.py"


def _load_run_smoke():
    spec = importlib.util.spec_from_file_location("antares_e2e_investigation_smoke", SMOKE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load smoke module from {SMOKE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.run_smoke

REPORT_PATH = ROOT / "validation" / "reports" / "antares-e2e-variance.json"


def _rg_succeeded_first_attempt(report: dict) -> bool:
    trace = str(report.get("exploration_trace") or "")
    marker = "<tool_response>"
    first = trace.split(marker, 1)
    if len(first) < 2:
        return False
    body = first[1].split("</tool_response>", 1)[0]
    commands = report.get("metrics", {}).get("commands") or []
    if not commands:
        return False
    first_command = str(commands[0])
    return first_command.startswith("rg ") and body.strip().startswith("exit=0")


def main() -> int:
    run_smoke = _load_run_smoke()
    runs: list[dict] = []
    for index in range(1, 6):
        report = run_smoke()
        run_path = REPORT_PATH.parent / f"antares-e2e-variance-run-{index}.json"
        run_path.write_text(json.dumps(report, indent=2))
        metrics = report["metrics"]
        runs.append(
            {
                "run": index,
                "investigation_id": metrics.get("investigation_id"),
                "terminal_calls_used": metrics.get("terminal_calls_used"),
                "duplicate_commands_suppressed": metrics.get("duplicate_commands_suppressed"),
                "total_terminal_attempts": metrics.get("total_terminal_attempts"),
                "duplicate_loop_hard_stop_fired": metrics.get("duplicate_loop_hard_stop_fired"),
                "failure_class": report.get("failure_class"),
                "budget_escalation_fired": metrics.get("budget_escalation_fired"),
                "attempt_cap_reached": metrics.get("attempt_cap_reached"),
                "trace_attempt_count": metrics.get("trace_attempt_count"),
                "trace_charged_count": metrics.get("trace_charged_count"),
                "rg_succeeded_first_attempt": _rg_succeeded_first_attempt(report),
                "wall_clock_total_s": metrics.get("wall_clock_total_s"),
                "outcome": metrics.get("outcome"),
                "seed_file_ranked_first": bool(
                    (metrics.get("ranked_files") or [None])[0] == "app/db.py"
                ),
            }
        )

    payload = {"runs": runs}
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(payload, indent=2))
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
