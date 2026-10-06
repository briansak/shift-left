#!/usr/bin/env python3
"""Re-run multidefect entries that hit unparseable_submission_loop with full trace capture."""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANTARES_SERVER = ROOT / "services" / "antares-server"
ORCHESTRATOR = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ANTARES_SERVER, ORCHESTRATOR, ROOT / "validation"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from antares_server.agent_tools import parse_agent_action_with_salvage, salvage_submit_vulnerable_files
from build_multidefect_corpus import build as build_corpus

REPORT_DIR = ROOT / "validation" / "reports"
TARGET_ENTRIES = (
    "CVE-2024-34064-jinja",
    "CVE-2024-23334-aiohttp",
)
RUNS_PER_ENTRY = int(os.environ.get("DIAGNOSE_RUNS_PER_ENTRY", "3"))
MAX_NEW_TOKENS = int(os.environ.get("ANTARES_AGENT_MAX_NEW_TOKENS", "1024"))


def _count_output_tokens(engine, text: str) -> int:
    return len(engine._tokenizer.encode(text, add_special_tokens=False))


def _analyze_raw(raw: str, engine) -> dict:
    action, salvaged = parse_agent_action_with_salvage(raw)
    salvage_only = salvage_submit_vulnerable_files(raw)
    ranked_in_raw = 0
    if '"ranked_files"' in raw:
        import re

        prefix = re.search(r'"ranked_files"\s*:\s*\[', raw)
        if prefix:
            tail = raw[prefix.end() :]
            ranked_in_raw = len(re.findall(r'"[^"\\]+(?:\\.[^"\\]*)*"', tail))
    return {
        "raw_char_len": len(raw),
        "output_token_count": _count_output_tokens(engine, raw),
        "has_submit_vulnerable_files": "submit_vulnerable_files" in raw,
        "has_ranked_files_key": '"ranked_files"' in raw,
        "has_tool_call_open": "<tool_call>" in raw,
        "has_tool_call_close": "</tool_call>" in raw,
        "ranked_paths_in_truncated_output": ranked_in_raw,
        "parse_action_type": type(action).__name__ if action else None,
        "parse_salvaged": salvaged,
        "salvage_only_files": salvage_only.ranked_files if salvage_only else [],
        "salvage_only_count": len(salvage_only.ranked_files) if salvage_only else 0,
        "raw_verbatim": raw,
    }


def _run_entry(entry: dict, engine, run_index: int, max_new_tokens: int) -> dict:
    from antares_server.agent_engine import DEFAULT_TRIAGE_SNAPSHOT_MAX_BYTES
    from antares_server.agent_loop import run_agent_query
    from antares_server.snapshot_materialize import materialize_tree_snapshot, remove_snapshot
    from antares_localization_multidefect import _cwe_description

    entry_id = str(entry["entry_id"])
    cwe = str(entry["cwe"])
    corpus_path = ROOT / str(entry["corpus_path"])
    investigation_id = f"antares-diag-{uuid.uuid4().hex[:12]}"
    raw_turns: list[dict] = []

    snapshot_root = materialize_tree_snapshot(
        corpus_path.resolve(),
        max_bytes=DEFAULT_TRIAGE_SNAPSHOT_MAX_BYTES,
        exclude_test_paths=True,
    )

    class Generator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            raw = engine.generate_agent(
                prompt,
                temperature=temperature,
                top_p=top_p,
                max_new_tokens=max_new_tokens,
            )
            raw_turns.append(_analyze_raw(raw, engine))
            return raw

    started = time.monotonic()
    try:
        result = run_agent_query(
            sandbox_root=snapshot_root,
            task_cwe=cwe,
            task_cwe_description=_cwe_description(cwe),
            changed_paths=[],
            generator=Generator(),
            max_terminal_calls=15,
            max_terminal_attempts=20,
            temperature=0.3,
            top_p=1.0,
            investigation_id=investigation_id,
        )
    finally:
        remove_snapshot(snapshot_root)

    return {
        "entry_id": entry_id,
        "run": run_index,
        "investigation_id": investigation_id,
        "max_new_tokens": max_new_tokens,
        "wall_clock_total_s": round(time.monotonic() - started, 2),
        "outcome": result.outcome,
        "failure_class": result.failure_class,
        "failure_message": result.failure_message,
        "submission_salvaged": result.submission_salvaged,
        "ranked_files": list(result.ranked_files),
        "ranked_file_count": len(result.ranked_files),
        "terminal_calls_used": result.terminal_calls_used,
        "raw_turns": raw_turns,
        "exploration_trace": result.exploration_trace,
    }


def main() -> int:
    corpus = build_corpus()
    entries = [e for e in corpus["entries"] if e["entry_id"] in TARGET_ENTRIES]
    if not entries:
        raise SystemExit(f"No entries matched {TARGET_ENTRIES}")

    os.environ.setdefault("ANTARES_ENGINE", "llm")
    os.environ["ANTARES_SANDBOX"] = "docker"
    os.environ.setdefault("SHIFT_LEFT_REPO_ROOT", str(ROOT))

    from shift_left_shared.weights import load_prewarm_manifest, verify_antares_weights
    from antares_server.inference import AntaresEngine

    model_path = Path(os.environ.get("ANTARES_MODEL_PATH", str(ROOT / "models" / "1b")))
    manifest = load_prewarm_manifest(ROOT)
    verify_antares_weights(model_path, manifest)
    engine = AntaresEngine(str(model_path), load_strategy="on_demand")
    engine.assert_model_present()
    engine.load()

    # Load successful-run candidate counts from prior benchmark for comparison.
    prior = json.loads((REPORT_DIR / "antares-localization-multidefect.json").read_text())
    prior_success_counts: dict[str, list[int]] = {}
    for pe in prior["summary"]["per_entry"]:
        eid = pe["entry_id"]
        if eid not in TARGET_ENTRIES:
            continue
        prior_success_counts[eid] = [
            len(r["ranked_files"])
            for r in pe["runs"]
            if r.get("failure_class") is None and r.get("ranked_files")
        ]

    results: list[dict] = []
    try:
        for entry in entries:
            for run_index in range(1, RUNS_PER_ENTRY + 1):
                print(f"Running {entry['entry_id']} run {run_index}...", file=sys.stderr)
                results.append(_run_entry(entry, engine, run_index, MAX_NEW_TOKENS))
    finally:
        engine.unload()

    out_path = REPORT_DIR / f"unparseable-diagnosis-max{MAX_NEW_TOKENS}.json"
    payload = {
        "max_new_tokens": MAX_NEW_TOKENS,
        "max_context_tokens_config": 8192,
        "prior_success_ranked_file_counts": prior_success_counts,
        "runs": results,
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(out_path), "runs": len(results)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
