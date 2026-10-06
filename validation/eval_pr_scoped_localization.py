#!/usr/bin/env python3
"""PR-scoped localization eval: fix-commit files + same-module neighbors."""

from __future__ import annotations

import json
import os
import shutil
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "validation"))
os.environ.setdefault("SHIFT_LEFT_REPO_ROOT", str(ROOT))
os.environ.setdefault("ANTARES_ENGINE", "llm")
os.environ.setdefault("ANTARES_SANDBOX", os.environ.get("ANTARES_SANDBOX") or "subprocess")
os.environ.setdefault("ANTARES_MODEL_PATH", str(ROOT / "models" / "1b"))
os.environ.setdefault("ANTARES_AGENT_MAX_NEW_TOKENS", "2048")
os.environ.setdefault(
    "ANTARES_SNAPSHOT_DIR",
    str(ROOT / "data" / "findings" / "antares-snapshots"),
)

from antares_localization_multidefect import (  # noqa: E402
    MODEL_PATH,
    ROOT as HARNESS_ROOT,
    _ensure_sandbox_image,
    _run_once,
    _zero_if_unsubmitted,
)
from multidefect.ground_truth import is_excluded_ground_truth_path  # noqa: E402

SIDECAR = ROOT / "validation" / "multidefect" / "ground-truth.json"
V3_REPORT = ROOT / "validation" / "reports" / "antares-localization-multidefect-v3.json"
V3_TRACES = ROOT / "validation" / "reports" / "antares-localization-multidefect-v3-traces"
SNAP_ROOT = ROOT / "validation" / "corpus" / "multidefect-prscope"
TRACE_DIR = ROOT / "validation" / "reports" / "prscope-traces"
REPORT_PATH = ROOT / "validation" / "reports" / "antares-localization-prscope.json"

ENTRY_IDS = [
    "CVE-2023-30861-flask",
    "CVE-2023-47627-aiohttp",
    "CVE-2020-26137-urllib3",
    "CVE-2023-37271-restrictedpython",
    "CVE-2024-22195-jinja",
    "CVE-2024-27306-aiohttp",
    "CVE-2018-19787-lxml",
    "CVE-2021-41125-scrapy",
    "CVE-2023-46136-werkzeug",
    "CVE-2024-52804-tornado",
]
RUNS_PER_ENTRY = 3
NEIGHBOR_TARGET = 7
NEIGHBOR_MIN = 5
NEIGHBOR_MAX = 10


def _common_prefix_len(left: str, right: str) -> int:
    n = min(len(left), len(right))
    for index in range(n):
        if left[index] != right[index]:
            return index
    return n


def _neighbor_sort_key(rel: str, gt: str) -> tuple[int, str]:
    name = Path(rel).stem
    gt_name = Path(gt).stem
    return (-_common_prefix_len(name, gt_name), name)


def _py_files_in(corpus: Path, directory: Path) -> list[str]:
    if not directory.is_dir():
        return []
    files: list[str] = []
    for path in directory.glob("*.py"):
        if not path.is_file():
            continue
        rel = path.relative_to(corpus).as_posix()
        if is_excluded_ground_truth_path(rel):
            continue
        files.append(rel)
    return files


def select_neighbors(corpus: Path, gt: str) -> list[str]:
    gt_path = Path(gt)
    same_dir = [rel for rel in _py_files_in(corpus, corpus / gt_path.parent) if rel != gt]
    same_dir.sort(key=lambda rel: _neighbor_sort_key(rel, gt))
    selected = list(same_dir)
    parent = gt_path.parent.parent
    if len(selected) < NEIGHBOR_MIN and parent != gt_path.parent:
        extras = [rel for rel in _py_files_in(corpus, corpus / parent) if rel != gt and rel not in selected]
        extras.sort(key=lambda rel: _neighbor_sort_key(rel, gt))
        selected.extend(extras)
    count = min(max(NEIGHBOR_TARGET, min(len(selected), NEIGHBOR_MAX)), NEIGHBOR_MAX)
    count = min(count, len(selected))
    return selected[:count]


def build_pr_snapshot(entry: dict[str, object]) -> dict[str, object]:
    entry_id = str(entry["entry_id"])
    corpus = ROOT / str(entry["corpus_path"])
    gt = str(entry["ground_truth_files"][0])
    neighbors = select_neighbors(corpus, gt)
    snapshot_files = [gt, *neighbors]
    dest = SNAP_ROOT / entry_id
    if dest.exists():
        shutil.rmtree(dest)
    for rel in snapshot_files:
        src = corpus / rel
        if not src.is_file():
            raise FileNotFoundError(f"{entry_id}: missing {rel}")
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
    return {
        "entry_id": entry_id,
        "gt_file": gt,
        "neighbors": neighbors,
        "snapshot_files": snapshot_files,
        "snapshot_file_count": len(snapshot_files),
        "changed_paths": snapshot_files,
        "snapshot_root": str(dest),
    }


def _v3_entry_stats(v3_entry: dict[str, object]) -> dict[str, object]:
    gt = str(v3_entry["ground_truth_files"][0])
    inspect_counts: list[int] = []
    p_at_1_hits = 0
    gt_in_search = 0
    f1s: list[float] = []
    precs: list[float] = []
    recs: list[float] = []
    terms: list[int] = []
    for run in v3_entry["runs"]:
        trace_path = V3_TRACES / f"{v3_entry['entry_id']}-run-{run['run']}.json"
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        inspected = trace.get("inspected_files") or []
        inspect_counts.append(len(inspected))
        ranked = [p.lstrip("./") for p in (run.get("ranked_files") or [])]
        if ranked and ranked[0] == gt:
            p_at_1_hits += 1
        hits = {p.lstrip("./") for p in (trace.get("search_hit_files") or [])}
        if gt in hits:
            gt_in_search += 1
        f1s.append(_zero_if_unsubmitted(run.get("file_f1")))
        precs.append(_zero_if_unsubmitted(run.get("precision")))
        recs.append(_zero_if_unsubmitted(run.get("recall")))
        terms.append(int(run.get("terminal_calls_used") or 0))
    n = len(v3_entry["runs"])
    return {
        "mean_file_f1": round(sum(f1s) / n, 4),
        "mean_precision": round(sum(precs) / n, 4),
        "mean_recall": round(sum(recs) / n, 4),
        "p_at_1": round(p_at_1_hits / n, 4),
        "gt_hit_rate": round(sum(1 for run in v3_entry["runs"] if run.get("ground_truth_in_ranked")) / n, 4),
        "mean_terminal_calls": round(sum(terms) / n, 2),
        "mean_inspected_files": round(sum(inspect_counts) / n, 2),
        "runs_with_inspection": sum(1 for count in inspect_counts if count > 0),
        "gt_in_search_rate": round(gt_in_search / n, 4),
    }


def _summarize_runs(entry_id: str, gt: str, runs: list[dict[str, object]]) -> dict[str, object]:
    n = len(runs)
    f1s = [_zero_if_unsubmitted(run.get("file_f1")) for run in runs]
    precs = [_zero_if_unsubmitted(run.get("precision")) for run in runs]
    recs = [_zero_if_unsubmitted(run.get("recall")) for run in runs]
    return {
        "entry_id": entry_id,
        "mean_file_f1": round(sum(f1s) / n, 4),
        "stdev_file_f1": round(statistics.stdev(f1s), 4) if n > 1 else None,
        "mean_precision": round(sum(precs) / n, 4),
        "mean_recall": round(sum(recs) / n, 4),
        "p_at_1": round(sum(1 for run in runs if run.get("p_at_1")) / n, 4),
        "gt_hit_rate": round(sum(1 for run in runs if run.get("ground_truth_in_ranked")) / n, 4),
        "mean_terminal_calls": round(sum(int(run.get("terminal_calls_used") or 0) for run in runs) / n, 2),
        "mean_inspected_files": round(sum(int(run.get("inspected_count") or 0) for run in runs) / n, 2),
        "runs_with_inspection": sum(1 for run in runs if int(run.get("inspected_count") or 0) > 0),
        "gt_in_search_rate": round(sum(1 for run in runs if run.get("gt_in_search")) / n, 4),
        "runs": runs,
    }


def main() -> int:
    sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))
    by_id = {str(item["entry_id"]): item for item in sidecar["entries"]}
    v3 = json.loads(V3_REPORT.read_text(encoding="utf-8"))
    v3_by_id = {str(item["entry_id"]): item for item in v3["summary"]["per_entry"]}

    snapshots = []
    for entry_id in ENTRY_IDS:
        snapshots.append(build_pr_snapshot(by_id[entry_id]))
        print(json.dumps(snapshots[-1], indent=2), file=sys.stderr)

    if os.environ.get("ANTARES_SANDBOX") == "docker":
        _ensure_sandbox_image()

    from shift_left_shared.weights import load_prewarm_manifest, verify_antares_weights
    from antares_server.inference import AntaresEngine

    manifest = load_prewarm_manifest(HARNESS_ROOT)
    verify_antares_weights(MODEL_PATH, manifest)
    engine = AntaresEngine(str(MODEL_PATH), load_strategy="on_demand")
    engine.assert_model_present()
    engine.load()

    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    per_entry: list[dict[str, object]] = []
    try:
        for spec in snapshots:
            entry = by_id[str(spec["entry_id"])]
            gt = str(spec["gt_file"])
            ground_truth = {gt}
            snapshot_root = Path(str(spec["snapshot_root"]))
            changed_paths = list(spec["changed_paths"])
            runs: list[dict[str, object]] = []
            for run_index in range(1, RUNS_PER_ENTRY + 1):
                report, metrics = _run_once(
                    entry=entry,
                    run_index=run_index,
                    ground_truth=ground_truth,
                    engine=engine,
                    changed_paths=changed_paths,
                    snapshot_root_override=snapshot_root,
                )
                ranked = [path.lstrip("./") for path in metrics.ranked_files]
                inspected = [path.lstrip("./") for path in (report.get("inspected_files") or [])]
                hits = {path.lstrip("./") for path in (report.get("search_hit_files") or [])}
                row = {
                    "entry_id": spec["entry_id"],
                    "run": run_index,
                    "terminal_calls_used": metrics.terminal_calls_used,
                    "failure_class": metrics.failure_class or "completed",
                    "ranked_files": ranked,
                    "precision": metrics.precision,
                    "recall": metrics.recall,
                    "file_f1": metrics.file_f1,
                    "p_at_1": bool(ranked) and ranked[0] == gt,
                    "ground_truth_in_ranked": metrics.ground_truth_in_ranked,
                    "inspected_files": inspected,
                    "inspected_count": len(inspected),
                    "gt_in_search": gt in hits,
                    "search_hit_files": sorted(hits),
                }
                runs.append(row)
                (TRACE_DIR / f"{spec['entry_id']}-run-{run_index}.json").write_text(
                    json.dumps(report, indent=2) + "\n",
                    encoding="utf-8",
                )
                print(
                    f"{spec['entry_id']} run {run_index}/{RUNS_PER_ENTRY} "
                    f"F1={metrics.file_f1} P@1={row['p_at_1']} "
                    f"inspect={len(inspected)} term={metrics.terminal_calls_used}",
                    file=sys.stderr,
                )
            pr_stats = _summarize_runs(str(spec["entry_id"]), gt, runs)
            v3_stats = _v3_entry_stats(v3_by_id[str(spec["entry_id"])])
            per_entry.append(
                {
                    **spec,
                    "cwe": entry["cwe"],
                    "repo": entry["repo"],
                    "pr_scoped": pr_stats,
                    "full_repo_v3": v3_stats,
                    "delta_mean_file_f1": round(pr_stats["mean_file_f1"] - v3_stats["mean_file_f1"], 4),
                    "delta_p_at_1": round(pr_stats["p_at_1"] - v3_stats["p_at_1"], 4),
                    "delta_mean_inspected_files": round(
                        pr_stats["mean_inspected_files"] - v3_stats["mean_inspected_files"],
                        2,
                    ),
                    "delta_gt_in_search_rate": round(
                        pr_stats["gt_in_search_rate"] - v3_stats["gt_in_search_rate"],
                        4,
                    ),
                }
            )
    finally:
        engine.unload()

    pr_means = [float(item["pr_scoped"]["mean_file_f1"]) for item in per_entry]
    v3_means = [float(item["full_repo_v3"]["mean_file_f1"]) for item in per_entry]
    payload = {
        "methodology": (
            "PR-scoped snapshot = single-file GT from the fix commit plus 5-10 same-module "
            "unchanged neighbors. changed_paths equals the snapshot file list, matching "
            "production build_snapshot_payload (snapshot files == changed_paths)."
        ),
        "entry_count": len(per_entry),
        "runs_per_entry": RUNS_PER_ENTRY,
        "macro_average_file_f1_pr": round(sum(pr_means) / len(pr_means), 4),
        "macro_average_file_f1_v3": round(sum(v3_means) / len(v3_means), 4),
        "macro_p_at_1_pr": round(sum(float(item["pr_scoped"]["p_at_1"]) for item in per_entry) / len(per_entry), 4),
        "macro_p_at_1_v3": round(sum(float(item["full_repo_v3"]["p_at_1"]) for item in per_entry) / len(per_entry), 4),
        "mean_inspected_files_pr": round(
            sum(float(item["pr_scoped"]["mean_inspected_files"]) for item in per_entry) / len(per_entry),
            2,
        ),
        "mean_inspected_files_v3": round(
            sum(float(item["full_repo_v3"]["mean_inspected_files"]) for item in per_entry) / len(per_entry),
            2,
        ),
        "gt_in_search_rate_pr": round(
            sum(float(item["pr_scoped"]["gt_in_search_rate"]) for item in per_entry) / len(per_entry),
            4,
        ),
        "gt_in_search_rate_v3": round(
            sum(float(item["full_repo_v3"]["gt_in_search_rate"]) for item in per_entry) / len(per_entry),
            4,
        ),
        "per_entry": per_entry,
    }
    REPORT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in payload.items() if k != "per_entry"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
