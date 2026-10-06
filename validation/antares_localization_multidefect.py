#!/usr/bin/env python3
"""Multi-defect Antares-1B localization benchmark on real CVE fix corpora."""

from __future__ import annotations

import json
import os
import re
import statistics
import subprocess
import sys
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

from build_multidefect_corpus import SIDECAR_PATH, build as build_corpus

SIDECAR = SIDECAR_PATH
REPORT_PATH = Path(
    os.environ.get(
        "ANTARES_MULTIDEFECT_REPORT",
        str(ROOT / "validation" / "reports" / "antares-localization-multidefect.json"),
    )
)
SANDBOX_IMAGE = os.environ.get("ANTARES_SANDBOX_IMAGE", "shift-left-antares-sandbox:bookworm")
MODEL_PATH = Path(os.environ.get("ANTARES_MODEL_PATH", str(ROOT / "models" / "1b")))
RUNS_PER_ENTRY = int(os.environ.get("ANTARES_MULTIDEFECT_RUNS_PER_ENTRY", "3"))
ATTEMPT_CAP = 20
PUBLISHED_FILE_F1 = 0.209
_LOG_RUN_RE = re.compile(r"^(.+?) run (\d+)/\d+ F1=(\S+) GT=(.*)$")
# Entries whose fix commits/GT were corrected after the v2 run started.
_GT_REBUILT_ENTRY_IDS = frozenset(
    {
        "CVE-2017-18342-pyyaml",
        "CVE-2020-14343-pyyaml",
        "CVE-2021-28957-lxml",
    }
)


@dataclass
class RunMetrics:
    entry_id: str = ""
    run: int = 0
    investigation_id: str = ""
    terminal_calls_used: int = 0
    terminal_budget: int = 0
    loop_control_enabled: bool = True
    adapter_identity: dict[str, str] = field(default_factory=dict)
    generation_params: dict[str, object] = field(default_factory=dict)
    outcome: str = ""
    failure_class: str | None = None
    wall_clock_total_s: float = 0.0
    degenerate_repetition_rejections: int = 0
    trace_instrumented: bool = False
    output_token_counts: list[int] = field(default_factory=list)
    max_output_tokens: int = 0
    turns_at_output_cap: int = 0
    agent_max_new_tokens: int = 0
    turn_timings_s: list[float] = field(default_factory=list)
    exploration_trace: str = ""
    ranked_files: list[str] = field(default_factory=list)
    ground_truth_in_ranked: bool = False
    precision: float | None = None
    recall: float | None = None
    file_f1: float | None = None
    gt_files_found: list[str] = field(default_factory=list)


def _file_metrics(ranked_files: list[str], ground_truth: set[str]) -> tuple[float | None, float | None, float | None]:
    if not ground_truth:
        return None, None, None
    ranked = [path.lstrip("./") for path in ranked_files]
    ranked_set = set(ranked)
    tp = sum(1 for path in ranked if path in ground_truth)
    fp = len(ranked) - tp
    fn = len(ground_truth) - sum(1 for path in ground_truth if path in ranked_set)
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


def _cwe_description(cwe: str) -> str:
    sys.path.insert(0, str(ORCHESTRATOR))
    from shift_left.cwe.localization_candidates import localization_candidate_by_id
    from shift_left.cwe.mitre_export import mitre_weakness_meta

    catalog = localization_candidate_by_id(cwe) or {}
    meta = mitre_weakness_meta(cwe)
    name = catalog.get("name") or meta.get("name") or cwe
    return str(name)


def _report_stem() -> str:
    return REPORT_PATH.stem


def _trace_path(entry_id: str, run_index: int) -> Path:
    return REPORT_PATH.parent / f"{_report_stem()}-traces" / f"{entry_id}-run-{run_index}.json"


def _resume_log_path() -> Path:
    explicit = os.environ.get("ANTARES_MULTIDEFECT_LOG")
    if explicit:
        return Path(explicit)
    if _report_stem().endswith("-v2"):
        return REPORT_PATH.parent / "antares-localization-multidefect-v2.log"
    return REPORT_PATH.with_suffix(".log")


def _parse_resume_log() -> dict[tuple[str, int], dict[str, object]]:
    log_path = _resume_log_path()
    if not log_path.is_file():
        return {}
    completed: dict[tuple[str, int], dict[str, object]] = {}
    for line in log_path.read_text(encoding="utf-8").splitlines():
        match = _LOG_RUN_RE.match(line.strip())
        if not match:
            continue
        entry_id, run_text, f1_text, gt_text = match.groups()
        if entry_id in _GT_REBUILT_ENTRY_IDS:
            continue
        try:
            gt_files = json.loads(gt_text.replace("'", '"'))
        except json.JSONDecodeError:
            gt_files = []
        completed[(entry_id, int(run_text))] = {
            "file_f1": None if f1_text == "None" else float(f1_text),
            "gt_files_found": list(gt_files),
        }
    return completed


def _metrics_from_trace_report(report: dict[str, object]) -> RunMetrics:
    metrics_payload = dict(report.get("metrics") or {})
    metrics = RunMetrics(**metrics_payload)
    metrics.trace_instrumented = bool(report.get("trace_instrumented", True))
    metrics.output_token_counts = list(report.get("output_token_counts") or [])
    metrics.max_output_tokens = int(report.get("max_output_tokens") or 0)
    metrics.turns_at_output_cap = int(report.get("turns_at_output_cap") or 0)
    metrics.agent_max_new_tokens = int(report.get("agent_max_new_tokens") or 0)
    metrics.turn_timings_s = list(report.get("turn_timings_s") or [])
    metrics.exploration_trace = str(report.get("exploration_trace") or "")
    return metrics


def _resume_disabled() -> bool:
    return os.environ.get("ANTARES_MULTIDEFECT_NO_RESUME", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _load_existing_runs(
    entries: list[dict[str, object]],
) -> tuple[list[RunMetrics], list[dict[str, object]]]:
    if _resume_disabled():
        return [], []
    runs: list[RunMetrics] = []
    trace_reports: list[dict[str, object]] = []
    log_completed = _parse_resume_log()

    for entry in entries:
        entry_id = str(entry["entry_id"])
        for run_index in range(1, RUNS_PER_ENTRY + 1):
            trace_path = _trace_path(entry_id, run_index)
            if trace_path.is_file():
                report = json.loads(trace_path.read_text(encoding="utf-8"))
                metrics = _metrics_from_trace_report(report)
                runs.append(metrics)
                trace_reports.append(report)
                continue

            log_row = log_completed.get((entry_id, run_index))
            if log_row is None:
                continue

            ground_truth = {str(path) for path in entry.get("ground_truth_files") or []}
            ranked_set = {path.lstrip("./") for path in log_row.get("gt_files_found") or []}
            gt_found = sorted(path for path in ground_truth if path in ranked_set)
            metrics = RunMetrics(
                entry_id=entry_id,
                run=run_index,
                trace_instrumented=False,
                ranked_files=[],
                ground_truth_in_ranked=bool(gt_found),
                gt_files_found=gt_found,
                file_f1=log_row.get("file_f1"),
                recall=1.0 if gt_found and ground_truth else 0.0 if ground_truth else None,
            )
            if metrics.file_f1 is not None and metrics.ranked_files:
                metrics.precision, metrics.recall, metrics.file_f1 = _file_metrics(
                    metrics.ranked_files,
                    ground_truth,
                )
            runs.append(metrics)
            trace_reports.append(
                {
                    "entry_id": entry_id,
                    "run": run_index,
                    "trace_instrumented": False,
                    "resume_source": "log",
                    "metrics": metrics.__dict__,
                }
            )
    return runs, trace_reports


def _instrumentation_summary(runs: list[RunMetrics]) -> dict[str, object]:
    instrumented = [run for run in runs if run.trace_instrumented]
    uninstrumented = [run for run in runs if not run.trace_instrumented]
    return {
        "instrumented_run_count": len(instrumented),
        "uninstrumented_run_count": len(uninstrumented),
        "uninstrumented_runs": [
            {"entry_id": run.entry_id, "run": run.run}
            for run in uninstrumented
        ],
        "trace_directory": str(REPORT_PATH.parent / f"{_report_stem()}-traces"),
        "resume_log": str(_resume_log_path()),
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
    entry: dict[str, object],
    run_index: int,
    ground_truth: set[str],
    engine,
    changed_paths: list[str] | None = None,
    snapshot_root_override: Path | None = None,
) -> tuple[dict[str, object], RunMetrics]:
    from antares_server.agent_engine import DEFAULT_TRIAGE_SNAPSHOT_MAX_BYTES
    from antares_server.adapters import default_adapter
    from antares_server.agent_loop import run_agent_query
    from antares_server.snapshot_materialize import materialize_tree_snapshot, remove_snapshot

    entry_id = str(entry["entry_id"])
    corpus_path = ROOT / str(entry["corpus_path"])
    cwe = str(entry["cwe"])
    investigation_id = f"antares-md-{uuid.uuid4().hex[:12]}"
    metrics = RunMetrics(entry_id=entry_id, run=run_index, investigation_id=investigation_id)
    timings: list[float] = []
    output_token_counts: list[int] = []

    if snapshot_root_override is not None:
        snapshot_root = snapshot_root_override
        remove_after = False
    else:
        snapshot_root = materialize_tree_snapshot(
            corpus_path.resolve(),
            max_bytes=DEFAULT_TRIAGE_SNAPSHOT_MAX_BYTES,
            exclude_test_paths=True,
        )
        remove_after = True

    adapter = default_adapter()
    generation = adapter.generation_params()
    generation_cap = int(generation["max_new_tokens"])

    class Generator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            started = time.monotonic()
            raw = engine.generate_agent(
                prompt,
                temperature=temperature,
                top_p=top_p,
                max_new_tokens=generation_cap,
            )
            timings.append(round(time.monotonic() - started, 2))
            output_token_counts.append(
                len(engine._tokenizer.encode(raw, add_special_tokens=False))
            )
            return raw

    started = time.monotonic()
    try:
        result = run_agent_query(
            sandbox_root=snapshot_root,
            task_cwe=cwe,
            task_cwe_description=_cwe_description(cwe),
            changed_paths=list(changed_paths or []),
            generator=Generator(),
            max_terminal_attempts=ATTEMPT_CAP,
            investigation_id=investigation_id,
            adapter=adapter,
        )
    finally:
        if remove_after:
            remove_snapshot(snapshot_root)

    metrics.wall_clock_total_s = round(time.monotonic() - started, 2)
    metrics.terminal_calls_used = result.terminal_calls_used
    metrics.terminal_budget = result.terminal_budget
    metrics.loop_control_enabled = result.loop_control_enabled
    metrics.adapter_identity = dict(result.adapter_identity)
    metrics.generation_params = dict(result.generation_params)
    metrics.outcome = result.outcome
    metrics.failure_class = result.failure_class
    metrics.degenerate_repetition_rejections = result.degenerate_repetition_rejections
    metrics.exploration_trace = result.exploration_trace
    metrics.trace_instrumented = True
    metrics.output_token_counts = output_token_counts
    metrics.max_output_tokens = max(output_token_counts) if output_token_counts else 0
    metrics.turns_at_output_cap = sum(1 for count in output_token_counts if count >= generation_cap)
    metrics.agent_max_new_tokens = generation_cap
    metrics.turn_timings_s = timings
    metrics.ranked_files = list(result.ranked_files)
    ranked_set = {item.lstrip("./") for item in metrics.ranked_files}
    metrics.gt_files_found = sorted(path for path in ground_truth if path in ranked_set)
    metrics.ground_truth_in_ranked = bool(metrics.gt_files_found)
    metrics.precision, metrics.recall, metrics.file_f1 = _file_metrics(metrics.ranked_files, ground_truth)

    report = {
        "entry_id": entry_id,
        "run": run_index,
        "investigation_id": investigation_id,
        "trace_instrumented": True,
        "agent_max_new_tokens": generation_cap,
        "terminal_budget": result.terminal_budget,
        "loop_control_enabled": result.loop_control_enabled,
        "adapter_identity": result.adapter_identity,
        "generation_params": result.generation_params,
        "metrics": metrics.__dict__,
        "exploration_trace": result.exploration_trace,
        "failure_class": result.failure_class,
        "failure_message": result.failure_message,
        "turn_timings_s": timings,
        "output_token_counts": output_token_counts,
        "max_output_tokens": metrics.max_output_tokens,
        "turns_at_output_cap": metrics.turns_at_output_cap,
        "inspected_files": list(result.inspected_files),
        "search_hit_files": list(result.search_hit_files),
    }
    return report, metrics


def _abstraction_bucket(abstraction: str | None) -> str:
    value = str(abstraction or "")
    if value in {"Base", "Variant"}:
        return "Base"
    if value in {"Class", "Pillar"}:
        return "Class"
    return "Other"


def _macro_breakdown(
    entries: list[dict[str, object]],
    entry_means_by_id: dict[str, float],
    *,
    key: str,
) -> dict[str, object]:
    groups: dict[str, list[float]] = {}
    for entry in entries:
        group_key = str(entry.get(key) or "unknown")
        groups.setdefault(group_key, []).append(entry_means_by_id[str(entry["entry_id"])])
    breakdown: dict[str, object] = {}
    for group_key in sorted(groups):
        values = groups[group_key]
        breakdown[group_key] = {
            "entry_count": len(values),
            "macro_average_file_f1": round(sum(values) / len(values), 4) if values else None,
            "entry_stdev_file_f1": round(statistics.stdev(values), 4) if len(values) > 1 else None,
        }
    return breakdown


def _design_matrix(entries: list[dict[str, object]]) -> dict[str, dict[str, int]]:
    matrix: dict[str, dict[str, int]] = {}
    for entry in entries:
        repo = str(entry["repo"])
        bucket = _abstraction_bucket(str(entry.get("cwe_abstraction")))
        matrix.setdefault(repo, {"Base": 0, "Class": 0, "Other": 0})
        matrix[repo][bucket] = matrix[repo].get(bucket, 0) + 1
    return {repo: dict(counts) for repo, counts in sorted(matrix.items())}


def _summarize(entries: list[dict[str, object]], runs: list[RunMetrics]) -> dict[str, object]:
    per_entry: list[dict[str, object]] = []
    entry_means: list[float] = []
    entry_means_by_id: dict[str, float] = {}
    catalog_entries = 0
    absent_entries = 0
    pillar_class_entries = 0

    for entry in entries:
        entry_id = str(entry["entry_id"])
        entry_runs = [run for run in runs if run.entry_id == entry_id]
        f1_values = [_zero_if_unsubmitted(run.file_f1) for run in entry_runs]
        mean_f1 = sum(f1_values) / len(f1_values) if f1_values else 0.0
        entry_means.append(mean_f1)
        entry_means_by_id[entry_id] = mean_f1
        if entry.get("cwe_in_localization_catalog"):
            catalog_entries += 1
        elif entry.get("cwe_localization_flag") == "pillar_or_class":
            pillar_class_entries += 1
        else:
            absent_entries += 1
        per_entry.append(
            {
                "entry_id": entry_id,
                "cve": entry["cve"],
                "repo": entry["repo"],
                "cwe": entry["cwe"],
                "cwe_abstraction": entry.get("cwe_abstraction"),
                "cwe_in_localization_catalog": entry.get("cwe_in_localization_catalog"),
                "cwe_localization_flag": entry.get("cwe_localization_flag"),
                "ground_truth_files": entry.get("ground_truth_files"),
                "ground_truth_file_count": entry.get("ground_truth_file_count"),
                "size_mib": entry.get("size_mib"),
                "runs": [run.__dict__ for run in entry_runs],
                "mean_file_f1": round(mean_f1, 4),
                "stdev_file_f1": round(statistics.stdev(f1_values), 4) if len(f1_values) > 1 else None,
                "mean_precision": round(
                    sum(_zero_if_unsubmitted(run.precision) for run in entry_runs) / len(entry_runs),
                    4,
                ),
                "mean_recall": round(
                    sum(_zero_if_unsubmitted(run.recall) for run in entry_runs) / len(entry_runs),
                    4,
                ),
                "gt_in_ranked_runs": sum(1 for run in entry_runs if run.ground_truth_in_ranked),
                "mean_candidate_count": round(
                    sum(len(run.ranked_files) for run in entry_runs) / len(entry_runs),
                    2,
                ),
                "mean_charged_terminal_calls": round(
                    sum(run.terminal_calls_used for run in entry_runs) / len(entry_runs),
                    2,
                ),
                "failure_class_distribution": _failure_distribution(entry_runs),
            }
        )

    macro_f1 = round(sum(entry_means) / len(entry_means), 4) if entry_means else None
    design_matrix = _design_matrix(entries)
    repos_with_both = sorted(
        repo
        for repo, counts in design_matrix.items()
        if counts.get("Base", 0) and counts.get("Class", 0)
    )
    gt_counts = [int(entry.get("ground_truth_file_count") or 0) for entry in entries]
    return {
        "entry_count": len(entries),
        "runs_per_entry": RUNS_PER_ENTRY,
        "macro_average_file_f1": macro_f1,
        "entry_stdev_file_f1": round(statistics.stdev(entry_means), 4) if len(entry_means) > 1 else None,
        "published_file_f1_reference": PUBLISHED_FILE_F1,
        "published_reference_note": (
            f"Macro-average File F1 ({macro_f1}) uses real CVE fix-commit ground truth, "
            f"macro-averaged across {len(entries)} entries in "
            f"{len(design_matrix)} repos. Design matrix targets within-repo abstraction "
            "comparison; see repo_x_abstraction and macro_f1_by_repo."
        ),
        "design_matrix": {
            "repo_x_abstraction": design_matrix,
            "repos_with_both_abstractions": repos_with_both,
            "repos_with_both_count": len(repos_with_both),
        },
        "ground_truth_file_count_summary": {
            "min": min(gt_counts) if gt_counts else None,
            "max": max(gt_counts) if gt_counts else None,
            "multi_file_entries": sum(1 for count in gt_counts if count > 1),
        },
        "macro_f1_by_abstraction": _macro_breakdown(
            entries,
            entry_means_by_id,
            key="cwe_abstraction",
        ),
        "macro_f1_by_abstraction_bucket": _macro_breakdown(
            [
                {
                    **entry,
                    "cwe_abstraction": _abstraction_bucket(str(entry.get("cwe_abstraction"))),
                }
                for entry in entries
            ],
            entry_means_by_id,
            key="cwe_abstraction",
        ),
        "macro_f1_by_repo": _macro_breakdown(entries, entry_means_by_id, key="repo"),
        "cwe_catalog_coverage": {
            "in_localization_catalog": catalog_entries,
            "pillar_or_class_not_file_localizable": pillar_class_entries,
            "absent_from_catalog": absent_entries,
        },
        "trace_instrumentation": _instrumentation_summary(runs),
        "per_entry": per_entry,
    }


def _failure_distribution(runs: list[RunMetrics]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for run in runs:
        key = run.failure_class or "completed"
        counts[key] = counts.get(key, 0) + 1
    return counts


def main() -> int:
    from antares_server.adapters import default_adapter

    corpus_meta = build_corpus()
    entries = list(corpus_meta["entries"])
    if not entries:
        raise RuntimeError("No corpus entries built")

    _ensure_sandbox_image()
    os.environ.setdefault("ANTARES_ENGINE", "llm")
    os.environ["ANTARES_SANDBOX"] = "docker"
    os.environ["ANTARES_MODEL_PATH"] = str(MODEL_PATH)
    os.environ.setdefault("SHIFT_LEFT_REPO_ROOT", str(ROOT))

    from shift_left_shared.weights import load_prewarm_manifest, verify_antares_weights
    from antares_server.inference import AntaresEngine

    manifest = load_prewarm_manifest(ROOT)
    verify_antares_weights(MODEL_PATH, manifest)
    engine = AntaresEngine(str(MODEL_PATH), load_strategy="on_demand")
    engine.assert_model_present()
    engine.load()

    existing_runs, _existing_reports = _load_existing_runs(entries)
    completed_keys = {(run.entry_id, run.run) for run in existing_runs}
    all_runs: list[RunMetrics] = list(existing_runs)

    try:
        for entry in entries:
            entry_id = str(entry["entry_id"])
            ground_truth = {str(path) for path in entry["ground_truth_files"]}
            for run_index in range(1, RUNS_PER_ENTRY + 1):
                if (entry_id, run_index) in completed_keys:
                    continue
                report, metrics = _run_once(
                    entry=entry,
                    run_index=run_index,
                    ground_truth=ground_truth,
                    engine=engine,
                )
                trace_path = _trace_path(entry_id, run_index)
                trace_path.parent.mkdir(parents=True, exist_ok=True)
                trace_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
                all_runs.append(metrics)
                completed_keys.add((entry_id, run_index))
                print(
                    f"{entry_id} run {run_index}/{RUNS_PER_ENTRY} "
                    f"F1={metrics.file_f1} GT={metrics.gt_files_found} "
                    f"tokens={metrics.max_output_tokens}/{metrics.agent_max_new_tokens}",
                    file=sys.stderr,
                )
    finally:
        engine.unload()

    payload = {
        "corpus": corpus_meta,
        "adapter_identity": (
            all_runs[0].adapter_identity
            if all_runs
            else default_adapter().identity.to_dict()
        ),
        "generation_params": (
            all_runs[0].generation_params
            if all_runs
            else default_adapter().generation_params()
        ),
        "terminal_call_budget": (
            all_runs[0].terminal_budget if all_runs else default_adapter().terminal_budget
        ),
        "loop_control_enabled": (
            all_runs[0].loop_control_enabled if all_runs else True
        ),
        "attempt_cap": ATTEMPT_CAP,
        "always_materialize_snapshot": True,
        "exclude_test_paths": True,
        "gt_rebuilt_entry_ids": sorted(_GT_REBUILT_ENTRY_IDS),
        "resume_disabled": _resume_disabled(),
        "summary": _summarize(entries, all_runs),
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
