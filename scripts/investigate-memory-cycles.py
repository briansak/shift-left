#!/usr/bin/env python3
"""Four-cycle load/infer/unload memory investigation for model servers."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

import httpx

ROOT = Path(__file__).resolve().parents[1]
_peak_path = ROOT / "scripts" / "validate-peak-memory.py"
_spec = importlib.util.spec_from_file_location("validate_peak_memory", _peak_path)
assert _spec and _spec.loader
peak_mem = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = peak_mem
_spec.loader.exec_module(peak_mem)

CONFIG_ANALYZE = peak_mem.CONFIG_ANALYZE
memory_breakdown = peak_mem.memory_breakdown
pid_listening_on = peak_mem.pid_listening_on
system_snapshot = peak_mem.system_snapshot

SQLI_ANALYZE = {
    "repo": "validation/memory",
    "pr_ref": "MEM-1",
    "commit_sha": "mem",
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


@dataclass
class CycleReport:
    cycle: int
    baseline_rss_mib: float
    peak_rss_mib: float
    peak_anonymous_mib: float | None
    peak_file_backed_mib: float | None
    after_unload_rss_mib: float
    after_unload_anonymous_mib: float | None
    swap_used_mib: float
    analyze_wall_ms: int
    unload_wall_ms: int
    server_timings_ms: dict[str, Any]


def sample_while(fn: Callable[[], None], pid: int) -> tuple[float, float | None, float | None]:
    peak_rss = 0.0
    peak_anon: float | None = None
    peak_file: float | None = None
    stop = threading.Event()

    def sampler() -> None:
        nonlocal peak_rss, peak_anon, peak_file
        while not stop.is_set():
            stats = memory_breakdown(pid)
            peak_rss = max(peak_rss, stats.rss_mib)
            if stats.anonymous_mib is not None:
                peak_anon = max(peak_anon or 0.0, stats.anonymous_mib)
            if stats.file_backed_mib is not None:
                peak_file = max(peak_file or 0.0, stats.file_backed_mib)
            time.sleep(0.05)

    thread = threading.Thread(target=sampler, daemon=True)
    thread.start()
    try:
        fn()
    finally:
        stop.set()
        thread.join(timeout=2.0)
    return peak_rss, peak_anon, peak_file


def run_cycle(
    *,
    cycle: int,
    port: int,
    payload: dict[str, Any],
    analyze_path: str = "/v1/analyze",
) -> CycleReport:
    pid = pid_listening_on(port)
    baseline = memory_breakdown(pid)
    timings: dict[str, Any] = {}
    analyze_ms = 0
    unload_ms = 0

    def work() -> None:
        nonlocal analyze_ms, unload_ms, timings
        t0 = time.monotonic()
        with httpx.Client(timeout=600.0) as client:
            resp = client.post(f"http://127.0.0.1:{port}{analyze_path}", json=payload)
            resp.raise_for_status()
            timings = resp.json().get("timings_ms") or {}
        analyze_ms = int((time.monotonic() - t0) * 1000)
        t1 = time.monotonic()
        with httpx.Client(timeout=120.0) as client:
            client.post(f"http://127.0.0.1:{port}/v1/unload")
        unload_ms = int((time.monotonic() - t1) * 1000)

    peak_rss, peak_anon, peak_file = sample_while(work, pid)
    time.sleep(0.5)
    after = memory_breakdown(pid)
    swap = system_snapshot()["swap_used_mib"]
    return CycleReport(
        cycle=cycle,
        baseline_rss_mib=baseline.rss_mib,
        peak_rss_mib=peak_rss,
        peak_anonymous_mib=peak_anon,
        peak_file_backed_mib=peak_file,
        after_unload_rss_mib=after.rss_mib,
        after_unload_anonymous_mib=after.anonymous_mib,
        swap_used_mib=swap,
        analyze_wall_ms=analyze_ms,
        unload_wall_ms=unload_ms,
        server_timings_ms=timings,
    )


def antares_retained_growth(*, cycles: int) -> list[dict[str, Any]]:
    pid = pid_listening_on(8090)
    rows: list[dict[str, Any]] = []
    for i in range(1, cycles + 1):
        cycle = run_cycle(cycle=i, port=8090, payload=SQLI_ANALYZE)
        after = memory_breakdown(pid)
        rows.append(
            {
                "cycle": i,
                "after_unload_rss_mib": after.rss_mib,
                "after_unload_anonymous_mib": after.anonymous_mib,
                "analyze_wall_ms": cycle.analyze_wall_ms,
            }
        )
    return rows


def kv_cache_estimate_mib(*, n_ctx: int, n_layers: int = 32, n_kv_heads: int = 8, head_dim: int = 128) -> float:
    """Rough FP16 KV cache: 2 * layers * n_ctx * kv_heads * head_dim * 2 bytes."""
    bytes_total = 2 * n_layers * n_ctx * n_kv_heads * head_dim * 2
    return round(bytes_total / (1024 * 1024), 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cycles", type=int, default=4)
    parser.add_argument("--antares-growth-cycles", type=int, default=10)
    parser.add_argument("--json-out", type=Path, default=ROOT / "validation" / "reports" / "memory-cycles-report.json")
    args = parser.parse_args()

    try:
        import psutil  # noqa: F401
    except ImportError:
        print("Install psutil", file=sys.stderr)
        return 1

    for port, label in ((8090, "Antares"), (8091, "Foundation-Sec")):
        httpx.get(f"http://127.0.0.1:{port}/health", timeout=5.0).raise_for_status()

    fsec_health = httpx.get("http://127.0.0.1:8091/health", timeout=5.0).json()
    n_ctx = int(fsec_health.get("n_ctx") or 8192)

    foundation_cycles = [
        asdict(run_cycle(cycle=i, port=8091, payload=CONFIG_ANALYZE)) for i in range(1, args.cycles + 1)
    ]
    antares_cycles = [
        asdict(run_cycle(cycle=i, port=8090, payload=SQLI_ANALYZE)) for i in range(1, args.cycles + 1)
    ]
    antares_growth = antares_retained_growth(cycles=args.antares_growth_cycles)

    report = {
        "system_baseline": system_snapshot(),
        "foundation_sec_health": fsec_health,
        "foundation_sec_cycles": foundation_cycles,
        "antares_cycles": antares_cycles,
        "antares_retained_growth": antares_growth,
        "kv_cache_estimates_mib": {
            "n_ctx_8192": kv_cache_estimate_mib(n_ctx=8192),
            "n_ctx_4096": kv_cache_estimate_mib(n_ctx=4096),
            "n_ctx_2048": kv_cache_estimate_mib(n_ctx=2048),
        },
        "note": (
            "Each cycle is one POST /v1/analyze + POST /v1/unload. "
            "Prior peak-memory second_cycle ran two analyzes in one stage."
        ),
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
