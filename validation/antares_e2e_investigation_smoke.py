#!/usr/bin/env python3
"""Single end-to-end Antares-1B investigation smoke (CWE-89, Docker sandbox)."""

from __future__ import annotations

import json
import os
import resource
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

FIXTURE_REPO = ROOT / "validation" / "fixtures" / "antares-e2e-sqli"
SEED_FILE = "app/db.py"
REPORT_PATH = ROOT / "validation" / "reports" / "antares-e2e-investigation-smoke.json"
SANDBOX_IMAGE = os.environ.get("ANTARES_SANDBOX_IMAGE", "shift-left-antares-sandbox:bookworm")
MODEL_PATH = Path(os.environ.get("ANTARES_MODEL_PATH", str(ROOT / "models" / "1b")))


@dataclass
class TurnTiming:
    turn: int
    wall_seconds: float


@dataclass
class SmokeMetrics:
    investigation_id: str = ""
    terminal_calls_used: int = 0
    terminal_call_budget: int = 15
    commands: list[str] = field(default_factory=list)
    commands_repeat: bool = False
    duplicate_commands_suppressed: int = 0
    total_terminal_attempts: int = 0
    duplicate_loop_hard_stop_fired: bool = False
    budget_escalation_fired: bool = False
    attempt_cap_reached: bool = False
    wall_clock_total_s: float = 0.0
    turn_timings_s: list[float] = field(default_factory=list)
    peak_rss_mib: float = 0.0
    submission_tool: str | None = None
    ranked_files: list[str] = field(default_factory=list)
    seed_file_ranked: bool = False
    outcome: str = ""
    sandbox_network_none: bool = False
    sandbox_destroyed: bool = False
    trace_attempt_count: int = 0
    sandbox_audit_attempt_count: int = 0
    trace_charged_count: int = 0
    sandbox_audit_charged_count: int = 0
    reconcile_counts_match: bool = False


def _docker_available() -> bool:
    from antares_server.docker_sandbox import docker_available

    return docker_available()


def _ensure_sandbox_image() -> None:
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


def _inspect_network_mode(investigation_id: str) -> str:
    result = subprocess.run(
        ["docker", "inspect", investigation_id, "--format", "{{.HostConfig.NetworkMode}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


class InstrumentedEngine:
    def __init__(self, engine) -> None:
        self._engine = engine
        self.turn_timings: list[float] = []
        self.commands: list[str] = []

    def load(self) -> None:
        self._engine.load()

    def unload(self) -> None:
        self._engine.unload()

    def unload_after_run(self) -> dict:
        return self._engine.unload_after_run()

    def generate_agent(self, prompt: str, *, temperature: float, top_p: float) -> str:
        from antares_server.agent_tools import TerminalToolCall, parse_agent_action

        started = time.monotonic()
        raw = self._engine.generate_agent(prompt, temperature=temperature, top_p=top_p)
        self.turn_timings.append(round(time.monotonic() - started, 2))
        action = parse_agent_action(raw)
        if isinstance(action, TerminalToolCall):
            self.commands.append(action.command)
        return raw


def _rss_sampler(stop: threading.Event, peak: list[float]) -> None:
    import psutil

    proc = psutil.Process()
    while not stop.is_set():
        peak[0] = max(peak[0], proc.memory_info().rss / (1024 * 1024))
        time.sleep(0.1)


def run_smoke() -> dict:
    from antares_server.agent_loop import (
        QUERY_COMPLETED_NO_FILES,
        QUERY_COMPLETED_WITH_FILES,
        run_agent_query,
    )
    from antares_server.docker_sandbox import investigation_container_exists
    from antares_server.inference import AntaresEngine
    from shift_left.antares.sandbox_audit import persist_sandbox_command_audit
    from shift_left.investigations.reconciliation import reconcile_trace_audit
    from shift_left.investigations.schema import InvestigationState
    from shift_left.investigations.store import InvestigationStore
    from shift_left.models.database import AuditStore
    from shift_left_shared.weights import load_prewarm_manifest, verify_antares_weights

    if not _docker_available():
        raise RuntimeError("Docker is required for Antares e2e smoke")
    _ensure_sandbox_image()

    os.environ.setdefault("ANTARES_ENGINE", "llm")
    os.environ["ANTARES_SANDBOX"] = "docker"
    os.environ["ANTARES_MODEL_PATH"] = str(MODEL_PATH)

    manifest = load_prewarm_manifest(ROOT)
    verify_antares_weights(MODEL_PATH, manifest)

    from antares_server.inference import AntaresEngine as EngineClass

    engine = EngineClass(str(MODEL_PATH), load_strategy="on_demand")
    engine.assert_model_present()

    metrics = SmokeMetrics(terminal_call_budget=15)
    investigation_id = f"antares-e2e-{uuid.uuid4().hex[:12]}"
    metrics.investigation_id = investigation_id

    audit_db = ROOT / "validation" / "reports" / ".antares-e2e-audit.db"
    inv_db = ROOT / "validation" / "reports" / ".antares-e2e-investigations.db"
    audit_db.unlink(missing_ok=True)
    inv_db.unlink(missing_ok=True)
    audit = AuditStore(str(audit_db), retention_days=30)
    store = InvestigationStore(str(inv_db), audit=audit)

    store.create_investigation(
        repo="validation/antares-e2e-sqli",
        requested_ref="smoke",
        resolved_commit_sha="smoke",
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        actor="antares-e2e-smoke",
        model_variant="fdtn-ai/antares-1b",
        terminal_call_budget=15,
        investigation_id=investigation_id,
    )
    store.transition_state(investigation_id, InvestigationState.RUNNING, actor="antares-e2e-smoke")

    instrumented = InstrumentedEngine(engine)
    peak_rss = [0.0]
    stop_sampler = threading.Event()
    sampler = threading.Thread(target=_rss_sampler, args=(stop_sampler, peak_rss), daemon=True)
    sampler.start()

    network_modes: list[str] = []
    container_checks: list[bool] = []

    class Generator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            if investigation_container_exists(investigation_id):
                network_modes.append(_inspect_network_mode(investigation_id))
            return instrumented.generate_agent(prompt, temperature=temperature, top_p=top_p)

    instrumented.load()
    started = time.monotonic()
    try:
        result = run_agent_query(
            sandbox_root=FIXTURE_REPO.resolve(),
            task_cwe="CWE-89",
            task_cwe_description="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            changed_paths=[SEED_FILE],
            generator=Generator(),
            max_terminal_calls=15,
            temperature=0.3,
            top_p=1.0,
            investigation_id=investigation_id,
        )
    finally:
        instrumented.unload()
        stop_sampler.set()
        sampler.join(timeout=2.0)
        metrics.peak_rss_mib = round(max(peak_rss[0], resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024)), 1)

    metrics.wall_clock_total_s = round(time.monotonic() - started, 2)
    metrics.turn_timings_s = instrumented.turn_timings
    metrics.terminal_calls_used = result.terminal_calls_used
    metrics.duplicate_commands_suppressed = result.duplicate_commands_suppressed
    metrics.total_terminal_attempts = result.total_terminal_attempts
    metrics.duplicate_loop_hard_stop_fired = result.duplicate_loop_hard_stop_fired
    metrics.budget_escalation_fired = result.budget_escalation_fired
    metrics.attempt_cap_reached = result.attempt_cap_reached
    metrics.commands = instrumented.commands
    metrics.commands_repeat = len(metrics.commands) != len(set(metrics.commands))
    metrics.outcome = result.outcome
    metrics.ranked_files = list(result.ranked_files)
    metrics.seed_file_ranked = SEED_FILE in metrics.ranked_files
    metrics.sandbox_destroyed = not investigation_container_exists(investigation_id)
    metrics.sandbox_network_none = bool(network_modes) and all(mode == "none" for mode in network_modes)

    if result.outcome == QUERY_COMPLETED_WITH_FILES:
        metrics.submission_tool = "submit_vulnerable_files"
    elif result.outcome == QUERY_COMPLETED_NO_FILES:
        metrics.submission_tool = "submit_no_vulnerability_found"

    audit_events = [dict(entry) for entry in result.sandbox_audit]
    if audit_events:
        persist_sandbox_command_audit(
            audit,
            actor="antares-e2e-smoke",
            subject=f"investigation:{investigation_id}",
            events=audit_events,
        )
        for index, entry in enumerate(audit_events):
            store.append_trace_turn(
                investigation_id,
                turn_index=index,
                command=str(entry.get("command") or ""),
                exit_status=int(entry.get("exit_code") or 0),
                output_truncated=str(entry.get("output_truncated") or ""),
                charged=bool(entry.get("charged", True)),
                duplicate_of_turn=entry.get("duplicate_of_turn"),
            )

    reconciliation = reconcile_trace_audit(store, audit, investigation_id)
    metrics.trace_attempt_count = reconciliation.trace_attempt_count
    metrics.sandbox_audit_attempt_count = reconciliation.sandbox_audit_attempt_count
    metrics.trace_charged_count = reconciliation.trace_charged_count
    metrics.sandbox_audit_charged_count = reconciliation.sandbox_audit_charged_count
    metrics.reconcile_counts_match = reconciliation.counts_match

    return {
        "fixture_repo": str(FIXTURE_REPO),
        "seed_file": SEED_FILE,
        "model_path": str(MODEL_PATH),
        "metrics": metrics.__dict__,
        "exploration_trace": result.exploration_trace,
        "failure_class": result.failure_class,
        "failure_message": result.failure_message,
        "reconciliation": {
            "counts_match": reconciliation.counts_match,
            "divergence_note": reconciliation.divergence_note,
        },
    }


def main() -> int:
    report = run_smoke()
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    metrics = report["metrics"]
    ok = (
        metrics["sandbox_destroyed"]
        and metrics["sandbox_network_none"]
        and metrics["reconcile_counts_match"]
        and metrics["submission_tool"] == "submit_vulnerable_files"
        and metrics["seed_file_ranked"]
    )
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
