#!/usr/bin/env python3
"""Retroactively count degenerate-repetition detections in saved agent traces."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANTARES_SERVER = ROOT / "services" / "antares-server"
sys.path.insert(0, str(ANTARES_SERVER))

from antares_server.loop_control import detect_degenerate_repetition

_ASSISTANT_TURN = re.compile(r"Assistant:\n(.*?)(?=\n\n(?:Assistant:|$))", re.DOTALL)


def _assistant_turns(trace: str) -> list[str]:
    return [match.group(1).strip() for match in _ASSISTANT_TURN.finditer(trace)]


def _analyze_trace(trace: str) -> dict[str, object]:
    turns = _assistant_turns(trace)
    flagged = [index + 1 for index, turn in enumerate(turns) if detect_degenerate_repetition(turn)]
    return {
        "assistant_turns": len(turns),
        "degenerate_turns": flagged,
        "degenerate_turn_count": len(flagged),
        "run_would_trigger": bool(flagged),
    }


def _analyze_report(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    runs: list[dict[str, object]] = []

    if payload.get("exploration_trace"):
        trace = str(payload["exploration_trace"])
        analysis = _analyze_trace(trace)
        runs.append(
            {
                "entry_id": payload.get("entry_id"),
                "run": payload.get("metrics", {}).get("run") if isinstance(payload.get("metrics"), dict) else payload.get("run"),
                "investigation_id": payload.get("investigation_id"),
                "failure_class": (
                    payload.get("metrics", {}).get("failure_class")
                    if isinstance(payload.get("metrics"), dict)
                    else payload.get("failure_class")
                ),
                **analysis,
            }
        )
    elif "runs" in payload and isinstance(payload["runs"], list):
        for item in payload["runs"]:
            trace = str(item.get("exploration_trace") or "")
            if not trace and item.get("raw_turns"):
                trace = "\n\n".join(
                    f"Assistant:\n{turn.get('raw_verbatim', '')}"
                    for turn in item["raw_turns"]
                )
            analysis = _analyze_trace(trace)
            runs.append(
                {
                    "entry_id": item.get("entry_id"),
                    "run": item.get("run"),
                    "investigation_id": item.get("investigation_id"),
                    "failure_class": item.get("failure_class"),
                    **analysis,
                }
            )
    elif "summary" in payload:
        for entry in payload["summary"].get("per_entry", []):
            for run in entry.get("runs", []):
                trace = str(run.get("exploration_trace") or "")
                analysis = _analyze_trace(trace)
                runs.append(
                    {
                        "entry_id": entry.get("entry_id"),
                        "run": run.get("run"),
                        "investigation_id": run.get("investigation_id"),
                        "failure_class": run.get("failure_class"),
                        **analysis,
                    }
                )

    triggered = [run for run in runs if run.get("run_would_trigger")]
    return {
        "source": str(path),
        "run_count": len(runs),
        "runs_with_degenerate_turn": len(triggered),
        "total_degenerate_turns": sum(int(run.get("degenerate_turn_count") or 0) for run in runs),
        "runs": runs,
        "triggered_runs": triggered,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "reports",
        nargs="*",
        default=[
            str(ROOT / "validation" / "reports" / "antares-localization-multidefect-v2.json"),
            str(ROOT / "validation" / "reports" / "unparseable-diagnosis-max1024.json"),
        ],
        help="Benchmark or diagnostic JSON reports with exploration traces",
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "validation" / "reports" / "degenerate-repetition-analysis.json"),
    )
    args = parser.parse_args()

    summaries = []
    for report in args.reports:
        path = Path(report)
        if not path.exists():
            summaries.append({"source": str(path), "error": "file not found"})
            continue
        summaries.append(_analyze_report(path))

    output_path = Path(args.output)
    output_path.write_text(json.dumps({"reports": summaries}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summaries, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
