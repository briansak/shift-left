#!/usr/bin/env python3
"""Realistic Antares-1B CWE-89 localization benchmark on the celery corpus."""

from __future__ import annotations

import json
import os
import resource
import statistics
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANTARES_SERVER = ROOT / "services" / "antares-server"
ORCHESTRATOR = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ANTARES_SERVER, ORCHESTRATOR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from build_localization_corpus import build as build_corpus

DEFAULT_CORPUS = ROOT / "validation" / "corpus" / "localization" / "celery-corpus"
CORPUS = Path(os.environ.get("ANTARES_LOCALIZATION_CORPUS", str(DEFAULT_CORPUS)))
SIDECAR = ROOT / "validation" / "corpus" / "localization" / "ground-truth.json"
DEFAULT_REPORT = ROOT / "validation" / "reports" / "antares-localization-realistic.json"
REPORT_PATH = Path(os.environ.get("ANTARES_LOCALIZATION_REPORT", str(DEFAULT_REPORT)))
SANDBOX_IMAGE = os.environ.get("ANTARES_SANDBOX_IMAGE", "shift-left-antares-sandbox:bookworm")
MODEL_PATH = Path(os.environ.get("ANTARES_MODEL_PATH", str(ROOT / "models" / "1b")))
TOTAL_RUNS = int(os.environ.get("ANTARES_LOCALIZATION_TOTAL_RUNS", "20"))
EXCLUDE_TEST_PATHS = os.environ.get("ANTARES_LOCALIZATION_EXCLUDE_TEST_PATHS", "").strip().lower() in {
    "1",
    "true",
    "yes",
}
ATTEMPT_CAP = 20
GROUND_TRUTH_FILE = "celery/backends/database/result_filter.py"
INCOMPARABLE_PRIOR_FIGURES_NOTE = (
    "Prior benchmark figures (0.245 validation corpus, 0.418/0.462 localdemo pre-pairing) "
    "are not comparable to paired results here or to each other: they used different sandbox "
    "layouts (.git exposure), different corpus paths/commits, and (before this harness fix) "
    "the include-tests arm skipped snapshot materialization while production always materializes. "
    "Do not carry those numbers forward as baselines."
)
PUBLISHED_FILE_F1 = 0.209
PUBLISHED_PRECISION = 0.262
PUBLISHED_RECALL = 0.224


@dataclass
class RunMetrics:
    run: int = 0
    investigation_id: str = ""
    terminal_calls_used: int = 0
    terminal_budget: int = 0
    loop_control_enabled: bool = True
    adapter_identity: dict[str, str] = field(default_factory=dict)
    generation_params: dict[str, object] = field(default_factory=dict)
    total_terminal_attempts: int = 0
    duplicate_commands_suppressed: int = 0
    degenerate_repetition_rejections: int = 0
    duplicate_loop_hard_stop_fired: bool = False
    forced_submission: bool = False
    submission_salvaged: bool = False
    attempt_cap_reached: bool = False
    budget_escalation_fired: bool = False
    outcome: str = ""
    failure_class: str | None = None
    wall_clock_total_s: float = 0.0
    ranked_files: list[str] = field(default_factory=list)
    ground_truth_in_ranked: bool = False
    precision: float | None = None
    recall: float | None = None
    file_f1: float | None = None
    charged_budget_reached: bool = False
    attempt_cap_hit: bool = False
    search_hit_files: list[str] = field(default_factory=list)
    ground_truth_in_search_hits: bool = False


def _file_metrics(ranked_files: list[str], ground_truth: set[str]) -> tuple[float | None, float | None, float | None]:
    if not ground_truth:
        return None, None, None
    ranked = [path.lstrip("./") for path in ranked_files]
    tp = sum(1 for path in ranked if path in ground_truth)
    fp = len(ranked) - tp
    fn = len(ground_truth) - sum(1 for path in ground_truth if path in set(ranked))
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision is None or recall is None or (precision + recall) == 0:
        file_f1 = 0.0 if ranked else None
    else:
        file_f1 = 2 * precision * recall / (precision + recall)
    return (
        round(precision, 4) if precision is not None else None,
        round(recall, 4) if recall is not None else None,
        round(file_f1, 4) if file_f1 is not None else None,
    )


def _zero_if_unsubmitted(value: float | None) -> float:
    return value if value is not None else 0.0


def _precision_at_one(ranked_files: list[str], ground_truth: set[str]) -> float:
    if not ranked_files:
        return 0.0
    return 1.0 if ranked_files[0].lstrip("./") in ground_truth else 0.0


def _load_existing_runs() -> list[dict]:
    if not REPORT_PATH.exists():
        return []
    payload = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    return list(payload.get("runs", []))


def _summarize(
    run_metrics: list[RunMetrics],
    run_reports: list[dict],
    *,
    ground_truth: set[str],
) -> dict:
    n = len(run_metrics)
    effective_f1 = [_zero_if_unsubmitted(m.file_f1) for m in run_metrics]
    effective_precision = [_zero_if_unsubmitted(m.precision) for m in run_metrics]
    effective_recall = [_zero_if_unsubmitted(m.recall) for m in run_metrics]
    effective_p1 = [
        _precision_at_one(m.ranked_files, {path for path in ground_truth})
        if m.ranked_files
        else 0.0
        for m in run_metrics
    ]
    wall_clocks = [m.wall_clock_total_s for m in run_metrics]
    wall_sorted = sorted(wall_clocks)

    failure_counts: dict[str, int] = {}
    for metric in run_metrics:
        key = metric.failure_class or "completed"
        failure_counts[key] = failure_counts.get(key, 0) + 1

    duplicate_loop_runs = [
        (metric, report)
        for metric, report in zip(run_metrics, run_reports, strict=True)
        if metric.failure_class and metric.failure_class.startswith("duplicate_loop")
    ]
    duplicate_loop_with_search_hits = [
        pair for pair in duplicate_loop_runs if pair[0].search_hit_files
    ]

    duplicate_loop_rate = round(len(duplicate_loop_runs) / n, 4) if n else None
    duplicate_loop_search_hits_rate = (
        round(len(duplicate_loop_with_search_hits) / len(duplicate_loop_runs), 4)
        if duplicate_loop_runs
        else None
    )

    return {
        "run_count": n,
        "macro_average_file_f1_zero_unsubmitted": round(sum(effective_f1) / n, 4) if n else None,
        "stdev_file_f1_zero_unsubmitted": round(statistics.stdev(effective_f1), 4) if n > 1 else None,
        "mean_precision_zero_unsubmitted": round(sum(effective_precision) / n, 4) if n else None,
        "mean_recall_zero_unsubmitted": round(sum(effective_recall) / n, 4) if n else None,
        "mean_precision_at_one_zero_unsubmitted": round(sum(effective_p1) / n, 4) if n else None,
        "published_file_f1_reference": PUBLISHED_FILE_F1,
        "published_precision_reference": PUBLISHED_PRECISION,
        "published_recall_reference": PUBLISHED_RECALL,
        "failure_class_distribution": failure_counts,
        "duplicate_loop_rate": duplicate_loop_rate,
        "duplicate_loop_runs": len(duplicate_loop_runs),
        "duplicate_loop_with_search_hits_rate": duplicate_loop_search_hits_rate,
        "duplicate_loop_with_search_hits_runs": len(duplicate_loop_with_search_hits),
        "runs_reaching_charged_budget": sum(1 for m in run_metrics if m.charged_budget_reached),
        "runs_reaching_attempt_cap": sum(1 for m in run_metrics if m.attempt_cap_hit),
        "runs_hard_stop_fired": sum(1 for m in run_metrics if m.duplicate_loop_hard_stop_fired),
        "forced_submission_runs": sum(1 for m in run_metrics if m.forced_submission),
        "forced_submission_valid_runs": sum(
            1
            for m in run_metrics
            if m.forced_submission and m.outcome.startswith("completed")
        ),
        "submission_salvaged_runs": sum(1 for m in run_metrics if m.submission_salvaged),
        "ground_truth_in_ranked_runs": sum(1 for m in run_metrics if m.ground_truth_in_ranked),
        "mean_candidate_count": round(sum(len(m.ranked_files) for m in run_metrics) / n, 2) if n else None,
        "mean_charged_terminal_calls": round(sum(m.terminal_calls_used for m in run_metrics) / n, 2)
        if n
        else None,
        "mean_wall_clock_seconds": round(sum(m.wall_clock_total_s for m in run_metrics) / n, 2) if n else None,
        "wall_clock_seconds": {
            "min": round(wall_sorted[0], 2) if wall_sorted else None,
            "median": round(wall_sorted[len(wall_sorted) // 2], 2) if wall_sorted else None,
            "p95": round(wall_sorted[min(len(wall_sorted) - 1, int(0.95 * (len(wall_sorted) - 1)))], 2)
            if wall_sorted
            else None,
            "max": round(wall_sorted[-1], 2) if wall_sorted else None,
        },
        "investigation_wall_clock_cap_seconds": int(
            os.environ.get("ANTARES_INVESTIGATION_WALL_CLOCK_SECONDS", "300")
        ),
        "budget_bound": any(m.charged_budget_reached for m in run_metrics),
        "attempt_cap_bound": any(m.attempt_cap_hit for m in run_metrics),
    }


def _ensure_sandbox_image() -> None:
    from antares_server.docker_sandbox import docker_available

    if not docker_available():
        raise RuntimeError("Docker is required for localization benchmark")
    inspect = subprocess.run(
        ["docker", "image", "inspect", SANDBOX_IMAGE],
        capture_output=True,
        text=True,
        check=False,
    )
    if inspect.returncode == 0:
        return
    dockerfile = ANTARES_SERVER / "Dockerfile.sandbox"
    build = subprocess.run(
        ["docker", "build", "-f", str(dockerfile), "-t", SANDBOX_IMAGE, str(ROOT)],
        capture_output=True,
        text=True,
        check=False,
    )
    if build.returncode != 0:
        raise RuntimeError(f"Failed to build sandbox image: {build.stderr or build.stdout}")


def _run_once(
    *,
    run_index: int,
    ground_truth: set[str],
    engine,
    exclude_test_paths: bool,
) -> tuple[dict, RunMetrics]:
    from antares_server.agent_engine import DEFAULT_TRIAGE_SNAPSHOT_MAX_BYTES
    from antares_server.adapters import default_adapter
    from antares_server.agent_loop import run_agent_query
    from antares_server.snapshot_materialize import materialize_tree_snapshot, remove_snapshot

    investigation_id = f"antares-loc-{uuid.uuid4().hex[:12]}"
    metrics = RunMetrics(run=run_index, investigation_id=investigation_id)
    timings: list[float] = []
    source_root = CORPUS.resolve()
    snapshot_root = materialize_tree_snapshot(
        source_root,
        max_bytes=DEFAULT_TRIAGE_SNAPSHOT_MAX_BYTES,
        exclude_test_paths=exclude_test_paths,
    )
    sandbox_root = snapshot_root

    adapter = default_adapter()
    generation = adapter.generation_params()

    class Generator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            started = time.monotonic()
            raw = engine.generate_agent(
                prompt,
                temperature=temperature,
                top_p=top_p,
                max_new_tokens=int(generation["max_new_tokens"]),
            )
            timings.append(round(time.monotonic() - started, 2))
            return raw

    started = time.monotonic()
    try:
        result = run_agent_query(
            sandbox_root=sandbox_root,
            task_cwe="CWE-89",
            task_cwe_description=(
                "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
            ),
            changed_paths=[],
            generator=Generator(),
            max_terminal_attempts=ATTEMPT_CAP,
            investigation_id=investigation_id,
            adapter=adapter,
        )
    finally:
        remove_snapshot(snapshot_root)
    metrics.wall_clock_total_s = round(time.monotonic() - started, 2)
    metrics.terminal_calls_used = result.terminal_calls_used
    metrics.terminal_budget = result.terminal_budget
    metrics.loop_control_enabled = result.loop_control_enabled
    metrics.adapter_identity = dict(result.adapter_identity)
    metrics.generation_params = dict(result.generation_params)
    metrics.total_terminal_attempts = result.total_terminal_attempts
    metrics.duplicate_commands_suppressed = result.duplicate_commands_suppressed
    metrics.degenerate_repetition_rejections = result.degenerate_repetition_rejections
    metrics.duplicate_loop_hard_stop_fired = result.duplicate_loop_hard_stop_fired
    metrics.forced_submission = result.forced_submission
    metrics.submission_salvaged = result.submission_salvaged
    metrics.attempt_cap_reached = result.attempt_cap_reached
    metrics.budget_escalation_fired = result.budget_escalation_fired
    metrics.outcome = result.outcome
    metrics.failure_class = result.failure_class
    metrics.ranked_files = list(result.ranked_files)
    metrics.ground_truth_in_ranked = any(
        path in {item.lstrip("./") for item in metrics.ranked_files} for path in ground_truth
    )
    metrics.precision, metrics.recall, metrics.file_f1 = _file_metrics(metrics.ranked_files, ground_truth)
    metrics.charged_budget_reached = metrics.terminal_calls_used >= result.terminal_budget
    metrics.attempt_cap_hit = metrics.total_terminal_attempts >= ATTEMPT_CAP
    metrics.search_hit_files = sorted(result.search_hit_files)
    metrics.ground_truth_in_search_hits = any(
        path in {item.lstrip("./") for item in metrics.search_hit_files} for path in ground_truth
    )

    report = {
        "investigation_id": investigation_id,
        "metrics": metrics.__dict__,
        "exploration_trace": result.exploration_trace,
        "failure_class": result.failure_class,
        "failure_message": result.failure_message,
        "terminal_budget": result.terminal_budget,
        "loop_control_enabled": result.loop_control_enabled,
        "adapter_identity": result.adapter_identity,
        "generation_params": result.generation_params,
        "turn_timings_s": timings,
        "inspected_files": list(result.inspected_files),
        "search_hit_files": list(result.search_hit_files),
    }
    return report, metrics


def _report_stem() -> str:
    return REPORT_PATH.stem


def _reset_reports() -> None:
    stem = _report_stem()
    for path in REPORT_PATH.parent.glob(f"{stem}*.json"):
        path.unlink(missing_ok=True)


def _load_corpus_meta() -> dict:
    if CORPUS.resolve() == DEFAULT_CORPUS.resolve():
        return build_corpus()
    commit_sha = (
        subprocess.check_output(["git", "-C", str(CORPUS), "rev-parse", "HEAD"], text=True).strip()
        if (CORPUS / ".git").exists()
        else "unknown"
    )
    py_files = list(CORPUS.rglob("*.py"))
    total_bytes = sum(path.stat().st_size for path in CORPUS.rglob("*") if path.is_file())
    return {
        "repo": str(CORPUS),
        "commit_sha": commit_sha,
        "cwe": "CWE-89",
        "seeded_files": [GROUND_TRUTH_FILE],
        "corpus_path": str(CORPUS.relative_to(ROOT)) if CORPUS.is_relative_to(ROOT) else str(CORPUS),
        "exclude_test_paths": EXCLUDE_TEST_PATHS,
        "python_file_count": len(py_files),
        "size_bytes": total_bytes,
        "size_mib": round(total_bytes / (1024 * 1024), 2),
    }


def main() -> int:
    from antares_server.adapters import default_adapter

    if os.environ.get("ANTARES_LOCALIZATION_RESET", "").strip().lower() in {"1", "true", "yes"}:
        _reset_reports()
    corpus_meta = _load_corpus_meta()
    ground_truth = {str(path) for path in corpus_meta["seeded_files"]}
    _ensure_sandbox_image()

    os.environ.setdefault("ANTARES_ENGINE", "llm")
    os.environ["ANTARES_SANDBOX"] = "docker"
    os.environ["ANTARES_MODEL_PATH"] = str(MODEL_PATH)

    from shift_left_shared.weights import load_prewarm_manifest, verify_antares_weights
    from antares_server.inference import AntaresEngine

    manifest = load_prewarm_manifest(ROOT)
    verify_antares_weights(MODEL_PATH, manifest)

    engine = AntaresEngine(str(MODEL_PATH), load_strategy="on_demand")
    engine.assert_model_present()
    engine.load()

    existing_runs = _load_existing_runs()
    start_index = len(existing_runs) + 1
    if start_index > TOTAL_RUNS:
        print(f"Already have {len(existing_runs)} runs (target {TOTAL_RUNS}); nothing to do.", file=sys.stderr)
        return 0

    runs: list[dict] = list(existing_runs)
    run_reports: list[dict] = []
    run_metrics: list[RunMetrics] = []
    for index, row in enumerate(existing_runs, start=1):
        trace_path = REPORT_PATH.parent / f"{_report_stem()}-run-{index}.json"
        if trace_path.exists():
            report = json.loads(trace_path.read_text(encoding="utf-8"))
            run_reports.append(report)
            if "search_hit_files" not in row:
                row = {
                    **row,
                    "search_hit_files": report.get("search_hit_files", []),
                    "ground_truth_in_search_hits": any(
                        path in {item.lstrip("./") for item in report.get("search_hit_files", [])}
                        for path in ground_truth
                    ),
                }
        else:
            run_reports.append({"metrics": row})
        run_metrics.append(RunMetrics(**row))

    try:
        for index in range(start_index, TOTAL_RUNS + 1):
            report, metrics = _run_once(
                run_index=index,
                ground_truth=ground_truth,
                engine=engine,
                exclude_test_paths=EXCLUDE_TEST_PATHS,
            )
            trace_path = REPORT_PATH.parent / f"{_report_stem()}-run-{index}.json"
            trace_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            runs.append(report["metrics"])
            run_metrics.append(metrics)
            run_reports.append(report)
    finally:
        engine.unload()

    payload = {
        "corpus": corpus_meta,
        "adapter_identity": (
            run_metrics[0].adapter_identity
            if run_metrics
            else default_adapter().identity.to_dict()
        ),
        "generation_params": (
            run_metrics[0].generation_params
            if run_metrics
            else default_adapter().generation_params()
        ),
        "terminal_call_budget": (
            run_metrics[0].terminal_budget
            if run_metrics
            else default_adapter().terminal_budget
        ),
        "loop_control_enabled": (
            run_metrics[0].loop_control_enabled if run_metrics else True
        ),
        "attempt_cap": ATTEMPT_CAP,
        "exclude_test_paths": EXCLUDE_TEST_PATHS,
        "always_materialize_snapshot": True,
        "incomparable_prior_figures_note": INCOMPARABLE_PRIOR_FIGURES_NOTE,
        "runs": runs,
        "summary": _summarize(run_metrics, run_reports, ground_truth=ground_truth),
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
