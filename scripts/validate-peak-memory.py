#!/usr/bin/env python3
"""
Measure peak RSS of host-native model server processes during on_demand inference.

Samples the PIDs listening on :8090 (Antares) and :8091 (Foundation-Sec), not the
validation script process. Reports resident anonymous vs file-backed mapped pages
where the platform exposes them.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx

ROOT = Path(__file__).resolve().parents[1]

CODE_ANALYZE = {
    "repo": "validation/peak-memory",
    "pr_ref": "PM-1",
    "commit_sha": "peak",
    "files": [
        {
            "path": "app/db.py",
            "hunks": [
                {
                    "new_start": 2,
                    "new_end": 3,
                    "content": (
                        " def lookup_user(username):\n"
                        "-    query = \"SELECT * FROM users WHERE id = ?\"\n"
                        "+    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
                        "     cursor.execute(query)\n"
                    ),
                }
            ],
        }
    ],
}

CONFIG_ANALYZE = {
    "repo": "validation/peak-memory",
    "pr_ref": "PM-1",
    "commit_sha": "peak",
    "files": [
        {
            "path": "firewall/asa.rules",
            "hunks": [
                {
                    "new_start": 1,
                    "new_end": 1,
                    "content": "access-list OUT extended permit ip any any\n",
                }
            ],
        }
    ],
}


@dataclass
class SampleStats:
    rss_mib: float
    rss_peak_mib: float
    anonymous_mib: float | None = None
    file_backed_mib: float | None = None


@dataclass
class StageReport:
    baseline: SampleStats
    during: SampleStats
    after_unload: SampleStats
    samples: int
    system: dict[str, Any] = field(default_factory=dict)


def pid_listening_on(port: int) -> int:
    result = subprocess.run(
        ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f"No process listening on 127.0.0.1:{port}")
    return int(result.stdout.strip().splitlines()[0])


def memory_breakdown(pid: int) -> SampleStats:
    import psutil

    proc = psutil.Process(pid)
    info = proc.memory_info()
    rss_mib = info.rss / (1024 * 1024)
    rss_peak_mib = getattr(info, "rss", info.rss) / (1024 * 1024)
    if hasattr(info, "peak_wset") and sys.platform == "darwin":
        rss_peak_mib = max(rss_peak_mib, info.peak_wset / (1024 * 1024))

    anonymous_mib: float | None = None
    file_backed_mib: float | None = None
    try:
        anon = 0
        file_backed = 0
        for mapping in proc.memory_maps(grouped=False):
            path = getattr(mapping, "path", "") or ""
            rss = getattr(mapping, "rss", 0) or 0
            if path.startswith("/") or path.endswith((".gguf", ".safetensors", ".dylib", ".so")):
                file_backed += rss
            else:
                anon += rss
        anonymous_mib = round(anon / (1024 * 1024), 2)
        file_backed_mib = round(file_backed / (1024 * 1024), 2)
    except (psutil.AccessDenied, AttributeError):
        pass

    return SampleStats(
        rss_mib=round(rss_mib, 2),
        rss_peak_mib=round(rss_peak_mib, 2),
        anonymous_mib=anonymous_mib,
        file_backed_mib=file_backed_mib,
    )


def system_snapshot() -> dict[str, Any]:
    import psutil

    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "available_mib": round(vm.available / (1024 * 1024), 2),
        "used_mib": round(vm.used / (1024 * 1024), 2),
        "percent": vm.percent,
        "swap_used_mib": round(swap.used / (1024 * 1024), 2),
    }


def sample_while(fn: Callable[[], None], pid: int, *, interval: float = 0.1) -> tuple[SampleStats, SampleStats, SampleStats, int]:
    baseline = memory_breakdown(pid)
    peak_rss = baseline.rss_mib
    peak_anon = baseline.anonymous_mib or 0.0
    peak_file = baseline.file_backed_mib or 0.0
    samples = 0
    stop = threading.Event()

    def sampler() -> None:
        nonlocal peak_rss, peak_anon, peak_file, samples
        while not stop.is_set():
            stats = memory_breakdown(pid)
            samples += 1
            peak_rss = max(peak_rss, stats.rss_mib)
            if stats.anonymous_mib is not None:
                peak_anon = max(peak_anon, stats.anonymous_mib)
            if stats.file_backed_mib is not None:
                peak_file = max(peak_file, stats.file_backed_mib)
            time.sleep(interval)

    thread = threading.Thread(target=sampler, daemon=True)
    thread.start()
    try:
        fn()
    finally:
        stop.set()
        thread.join(timeout=2.0)

    during = SampleStats(
        rss_mib=peak_rss,
        rss_peak_mib=peak_rss,
        anonymous_mib=round(peak_anon, 2) if baseline.anonymous_mib is not None else None,
        file_backed_mib=round(peak_file, 2) if baseline.file_backed_mib is not None else None,
    )
    time.sleep(0.5)
    after = memory_breakdown(pid)
    return baseline, during, after, samples


def post_analyze(port: int, path: str) -> None:
    with httpx.Client(timeout=600.0) as client:
        resp = client.post(f"http://127.0.0.1:{port}{path}", json=CODE_ANALYZE if port == 8090 else CONFIG_ANALYZE)
        resp.raise_for_status()


def post_unload(port: int) -> None:
    with httpx.Client(timeout=120.0) as client:
        client.post(f"http://127.0.0.1:{port}/v1/unload")


def run_stage(name: str, port: int, analyze_path: str, *, second_cycle: bool = False) -> StageReport:
    pid = pid_listening_on(port)

    def work() -> None:
        post_analyze(port, analyze_path)
        post_unload(port)
        if second_cycle:
            post_analyze(port, analyze_path)
            post_unload(port)

    baseline, during, after, sample_count = sample_while(work, pid)
    return StageReport(
        baseline=baseline,
        during=during,
        after_unload=after,
        samples=sample_count,
        system=system_snapshot(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Peak RSS of model server processes")
    parser.add_argument("--json-out", type=Path, default=ROOT / "validation" / "reports" / "peak-memory-report.json")
    args = parser.parse_args()

    try:
        import psutil  # noqa: F401
    except ImportError:
        print("Install psutil in project .venv", file=sys.stderr)
        return 1

    for port, label in ((8090, "Antares"), (8091, "Foundation-Sec")):
        try:
            httpx.get(f"http://127.0.0.1:{port}/health", timeout=5.0).raise_for_status()
        except Exception as exc:
            print(f"{label} not reachable on :{port}: {exc}", file=sys.stderr)
            return 1

    report = {
        "method": "server_pid_rss_sampling",
        "note": (
            "Prior reports using RUSAGE_SELF on this script are invalid. "
            "This report samples the host-native server PIDs on :8090 and :8091."
        ),
        "platform": __import__("platform").platform(),
        "system_baseline": system_snapshot(),
        "antares": asdict(run_stage("antares", 8090, "/v1/analyze")),
        "foundation_sec_first_cycle": asdict(run_stage("foundation_sec", 8091, "/v1/analyze")),
        "foundation_sec_second_cycle": asdict(
            run_stage("foundation_sec_second", 8091, "/v1/analyze", second_cycle=True)
        ),
    }

    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
