#!/usr/bin/env python3
"""Run platform_specific eval N times and collect TP variance."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, pstdev

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / "services" / "foundation-sec-server" / ".venv" / "bin" / "python"
EVAL = ROOT / "validation" / "eval_model.py"
REPORTS = ROOT / "validation" / "reports"


def _tp_from_report(path: Path) -> dict[str, int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    tp = fp = fn = 0
    for rules in data.get("per_target_type_per_rule", {}).values():
        for metrics in rules.values():
            model = metrics.get("model")
            if isinstance(model, dict):
                tp += int(model.get("true_positives") or 0)
                fp += int(model.get("false_positives") or 0)
                fn += int(model.get("false_negatives") or 0)
    emitted = int(data.get("summary", {}).get("model_findings_total") or 0)
    zero_files = sum(
        1
        for row in (data.get("timing") or {}).get("per_file") or []
        if int(row.get("model_finding_count") or 0) == 0
    )
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "model_findings_total": emitted,
        "files_zero_model_findings": zero_files,
    }


def _run_eval(*, quant: str, run_index: int, allow_mismatch: bool) -> Path:
    out = REPORTS / f"platform-specific-variance-{quant.lower()}-run{run_index}.json"
    cmd = [
        str(PYTHON),
        str(EVAL),
        "--prompt-variant",
        "platform_specific",
        "--report-path",
        str(out.resolve()),
    ]
    if allow_mismatch:
        cmd.append("--allow-quant-mismatch")
    print(f"=== {quant} run {run_index} ===", flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)
    return out


def main() -> int:
    runs = 3
    summary: dict = {
        "generated_at": datetime.now(UTC).isoformat(),
        "task": "platform_specific_variance",
        "temperature_note": "engine.py run_advisory_completion uses temperature=0.1",
        "runs_per_quant": runs,
        "q4_k_m": [],
        "q8_0": [],
    }
    for i in range(1, runs + 1):
        path = _run_eval(quant="Q4_K_M", run_index=i, allow_mismatch=False)
        summary["q4_k_m"].append({"run": i, "report": str(path.relative_to(ROOT)), **_tp_from_report(path)})
    for i in range(1, runs + 1):
        path = _run_eval(quant="Q8_0", run_index=i, allow_mismatch=True)
        summary["q8_0"].append({"run": i, "report": str(path.relative_to(ROOT)), **_tp_from_report(path)})

    def _stats(rows: list[dict]) -> dict:
        tps = [row["true_positives"] for row in rows]
        return {
            "tp_per_run": tps,
            "tp_mean": round(mean(tps), 2),
            "tp_stdev": round(pstdev(tps), 2) if len(tps) > 1 else 0.0,
            "tp_min": min(tps),
            "tp_max": max(tps),
        }

    summary["q4_k_m_stats"] = _stats(summary["q4_k_m"])
    summary["q8_0_stats"] = _stats(summary["q8_0"])
    out = REPORTS / "platform-specific-variance.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary["q4_k_m_stats"], indent=2))
    print(json.dumps(summary["q8_0_stats"], indent=2))
    print(f"Wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
