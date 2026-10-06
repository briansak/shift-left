#!/usr/bin/env python3
"""Evaluate Foundation-Sec model findings against labeled config corpora (advisory path)."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
FSEC_VENV_PY = ROOT / "services" / "foundation-sec-server" / ".venv" / "bin" / "python"
for path in (SHARED, ORCH, ROOT / "validation"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from shift_left.handlers.config.rules.registry import ALL_RULES, rule_requires_fixture_coverage  # noqa: E402
from shift_left.ui.cwe_dictionary import unrecognized_model_cwe_tally  # noqa: E402
from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_Q4_K_M  # noqa: E402

from eval_handlers import (  # noqa: E402
    GENERATED_CORPUS_DIR,
    HOLDOUT_CORPUS_DIR,
    load_corpus,
)
from constrained_finding_validation import (  # noqa: E402
    partition_constrained_findings,
    summarize_rejections,
)
from model_eval_matching import (  # noqa: E402
    MATCHER_BEST_FIT,
    MATCHER_METADATA,
    MetricCounts,
    ModelMetricCounts,
    is_model_originated,
    score_file,
)

REALDEVICE_CORPUS_DIR = ROOT / "validation" / "corpus" / "realdevice"
REPORT_PATH = ROOT / "validation" / "reports" / "model-vs-handler.json"
PLATFORM_SPECIFIC_REPORT_PATH = (
    ROOT / "validation" / "reports" / "model-vs-handler-platform-specific.json"
)
CONSTRAINED_OUTPUT_REPORT_PATH = (
    ROOT / "validation" / "reports" / "model-vs-handler-constrained-output.json"
)
PLATFORM_CONSTRAINED_REPORT_PATH = (
    ROOT / "validation" / "reports" / "model-vs-handler-platform-constrained.json"
)

CONSTRAINED_PROMPT_VARIANTS = frozenset({"constrained_output", "platform_constrained"})
PARTIAL_PATH = REPORT_PATH.with_suffix(".partial.json")

FOUNDATION_SEC_URL = "http://127.0.0.1:8091"
FOUNDATION_SEC_PORT = 8091
MODEL_MAX_CONTEXT_TOKENS = 4096
REQUIRED_QUANT_SUBSTR = "q4_k_m"
Q4_MODEL_DIR = ROOT / "models" / "foundation-sec-q4_k_m"
Q8_MODEL_DIR = ROOT / "models" / "foundation-sec-q8_0"
Q4_GGUF_FILENAME = VERIFIED_FOUNDATION_SEC_Q4_K_M["gguf_filename"]
QUANT_INTENDED = "Q4_K_M"

ACCURACY_ONLY_BANNER = (
    "╔══════════════════════════════════════════════════════════════════════╗\n"
    "║  ACCURACY-ONLY RUN: quant mismatch override active                   ║\n"
    "║  Results measure detection accuracy only — NOT demo hardware       ║\n"
    "║  performance (timing/RSS omitted).                                   ║\n"
    "╚══════════════════════════════════════════════════════════════════════╝"
)

_peak_path = ROOT / "scripts" / "validate-peak-memory.py"
_spec = importlib.util.spec_from_file_location("validate_peak_memory", _peak_path)
assert _spec and _spec.loader
_peak_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _peak_mod
_spec.loader.exec_module(_peak_mod)
pid_listening_on = _peak_mod.pid_listening_on


class PreflightError(RuntimeError):
    """Hard preflight failure — no report should be written."""


class ReportWriteError(ValueError):
    """Report failed quant stamping validation; must not be written."""


@dataclass(frozen=True)
class RuleSemantic:
    rule_id: str
    target_type: str
    cwe: str
    semantic_key: str
    defect_summary: str


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:80] or "defect"


def build_rule_semantics() -> dict[str, RuleSemantic]:
    mapping: dict[str, RuleSemantic] = {}
    for rule in ALL_RULES:
        if not rule_requires_fixture_coverage(rule):
            continue
        mapping[rule.id] = RuleSemantic(
            rule_id=rule.id,
            target_type=rule.target_type,
            cwe=rule.cwe,
            semantic_key=f"{rule.target_type}/{_slug(rule.description)}",
            defect_summary=rule.description,
        )
    return mapping


RULE_SEMANTICS = build_rule_semantics()


def _line_count(content: str) -> int:
    if not content:
        return 1
    return max(1, content.count("\n") + (0 if content.endswith("\n") else 1))


def resolve_interpreter() -> Path:
    if not FSEC_VENV_PY.is_file():
        raise PreflightError(
            f"Foundation-Sec venv interpreter missing at {FSEC_VENV_PY}. "
            "Install services/foundation-sec-server into its .venv first."
        )
    return FSEC_VENV_PY


def assert_llama_cpp(python: Path) -> str:
    result = subprocess.run(
        [str(python), "-c", "import llama_cpp; print(llama_cpp.__version__)"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise PreflightError(
            f"Interpreter {python} cannot import llama_cpp: {result.stderr.strip() or result.stdout.strip()}"
        )
    version = result.stdout.strip()
    if not version:
        raise PreflightError(f"Interpreter {python} imported llama_cpp but returned no version")
    return version


def _quant_label_from_gguf(gguf_file: str | None) -> str:
    name = str(gguf_file or "").lower()
    if "q4_k_m" in name:
        return "Q4_K_M"
    if "q8_0" in name:
        return "Q8_0"
    return "unknown"


def quant_match_from_health(server_health: dict[str, Any]) -> bool:
    if "quant_match" in server_health:
        return bool(server_health["quant_match"])
    gguf_file = str(server_health.get("gguf_file") or "").lower()
    return REQUIRED_QUANT_SUBSTR in gguf_file


def quant_stamping_from_server_health(
    server_health: dict[str, Any],
    *,
    required_quant: str = QUANT_INTENDED,
) -> dict[str, Any]:
    quant_match = quant_match_from_health(server_health)
    quant_evaluated = server_health.get("quant_evaluated") or _quant_label_from_gguf(
        server_health.get("gguf_file")
    )
    quant_intended = server_health.get("quant_intended") or required_quant
    accuracy_only = server_health.get("accuracy_only")
    if accuracy_only is None:
        accuracy_only = not quant_match
    return {
        "quant_evaluated": quant_evaluated,
        "quant_intended": quant_intended,
        "accuracy_only": bool(accuracy_only),
        "quant_match": quant_match,
    }


def apply_quant_stamping(report: dict[str, Any]) -> dict[str, Any]:
    model_config = report.setdefault("model_config", {})
    server_health = dict(model_config.get("server_health") or {})
    required_quant = str(model_config.get("required_quant") or QUANT_INTENDED)
    stamping = quant_stamping_from_server_health(
        server_health,
        required_quant=required_quant,
    )
    server_health.update(stamping)
    model_config["server_health"] = server_health
    model_config["quant_evaluated"] = stamping["quant_evaluated"]
    model_config["quant_intended"] = stamping["quant_intended"]
    model_config["accuracy_only"] = stamping["accuracy_only"]
    model_config["quant_match"] = stamping["quant_match"]
    report["quant_evaluated"] = stamping["quant_evaluated"]
    report["quant_intended"] = stamping["quant_intended"]
    report["accuracy_only"] = stamping["accuracy_only"]
    return report


def validate_report_writable(report: dict[str, Any]) -> None:
    model_config = report.get("model_config") or {}
    server_health = model_config.get("server_health") or {}
    quant_match = quant_match_from_health(server_health)

    for scope_name, scope in (("report", report), ("model_config", model_config)):
        quant_evaluated = scope.get("quant_evaluated")
        if quant_evaluated is None or quant_evaluated == "unknown":
            raise ReportWriteError(
                f"{scope_name} missing quant_evaluated; "
                "report must state which quant produced results."
            )
        if scope.get("quant_intended") is None:
            raise ReportWriteError(f"{scope_name} missing quant_intended.")
        if scope.get("accuracy_only") is None:
            raise ReportWriteError(f"{scope_name} missing accuracy_only.")

    if not quant_match:
        for scope_name, scope in (("report", report), ("model_config", model_config)):
            if scope.get("accuracy_only") is not True:
                raise ReportWriteError(
                    f"{scope_name}.accuracy_only must be true when quant_match is false."
                )
        if "timing" in report:
            raise ReportWriteError(
                "timing must be absent when quant_match is false (accuracy-only run)."
            )


def write_report(report: dict[str, Any], path: Path = REPORT_PATH) -> None:
    stamped = apply_quant_stamping(report)
    validate_report_writable(stamped)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(stamped, indent=2), encoding="utf-8")


def backfill_report_quant_stamping(path: Path = REPORT_PATH) -> dict[str, Any]:
    report = json.loads(path.read_text(encoding="utf-8"))
    stamped = apply_quant_stamping(report)
    validate_report_writable(stamped)
    path.write_text(json.dumps(stamped, indent=2), encoding="utf-8")
    return stamped


def resolve_model_layout(
    *,
    allow_quant_mismatch: bool,
) -> tuple[Path, bool, str]:
    """Return (model_dir, use_low_memory, quant_evaluated_label)."""
    if allow_quant_mismatch:
        q8_matches = sorted(Q8_MODEL_DIR.glob("*.gguf"))
        if q8_matches:
            return Q8_MODEL_DIR, False, _quant_label_from_gguf(q8_matches[0].name)

    q4_matches = sorted(Q4_MODEL_DIR.glob("*.gguf"))
    if q4_matches and REQUIRED_QUANT_SUBSTR in q4_matches[0].name.lower():
        return Q4_MODEL_DIR, True, "Q4_K_M"

    if not allow_quant_mismatch:
        raise PreflightError(
            f"No Q4_K_M GGUF under {Q4_MODEL_DIR}. "
            f"Run ./scripts/download-foundation-sec-q4-model.sh to stage {Q4_GGUF_FILENAME}, "
            "or pass --allow-quant-mismatch to evaluate on a non-target quant (accuracy-only)."
        )

    q8_matches = sorted(Q8_MODEL_DIR.glob("*.gguf"))
    if not q8_matches:
        raise PreflightError(
            f"--allow-quant-mismatch set but no GGUF found under {Q8_MODEL_DIR}."
        )
    return Q8_MODEL_DIR, False, _quant_label_from_gguf(q8_matches[0].name)


def _free_listening_port(port: int) -> None:
    try:
        pid = pid_listening_on(port)
    except RuntimeError:
        return
    print(f"Stopping existing listener on :{port} (pid={pid})", file=sys.stderr)
    subprocess.run(["kill", str(pid)], check=False)
    for _ in range(15):
        try:
            pid_listening_on(port)
        except RuntimeError:
            return
        time.sleep(1)
    raise PreflightError(f"Port {port} still in use after stopping pid={pid}")


def _server_env(
    *,
    model_dir: Path,
    use_low_memory: bool,
) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "SHIFT_LEFT_SKIP_EGRESS_PROBE": "true",
            "FOUNDATION_SEC_BIND_HOST": "127.0.0.1",
            "FOUNDATION_SEC_PORT": str(FOUNDATION_SEC_PORT),
            "FOUNDATION_SEC_MODEL_PATH": str(model_dir),
            "FOUNDATION_SEC_LOW_MEMORY": "true" if use_low_memory else "false",
            "FOUNDATION_SEC_N_CTX": str(MODEL_MAX_CONTEXT_TOKENS),
            "FOUNDATION_SEC_LOAD_STRATEGY": "on_demand",
            "PYTHONPATH": os.pathsep.join(
                [
                    str(ROOT / "services" / "foundation-sec-server"),
                    str(ROOT / "services" / "shift-left-shared"),
                    str(ROOT / "services" / "orchestrator"),
                    env.get("PYTHONPATH", ""),
                ]
            ),
        }
    )
    return env


def start_foundation_sec_server(
    python: Path,
    *,
    model_dir: Path,
    use_low_memory: bool,
) -> tuple[int, subprocess.Popen[Any]]:
    _free_listening_port(FOUNDATION_SEC_PORT)
    log_path = ROOT / ".shift-left" / "logs" / "foundation-sec-server.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = open(log_path, "a", encoding="utf-8")  # noqa: SIM115
    proc = subprocess.Popen(
        [str(python), "-m", "foundation_sec_server.main"],
        cwd=ROOT / "services" / "foundation-sec-server",
        env=_server_env(model_dir=model_dir, use_low_memory=use_low_memory),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    for _ in range(90):
        try:
            bound_pid = pid_listening_on(FOUNDATION_SEC_PORT)
            if bound_pid != proc.pid:
                raise RuntimeError(
                    f"port :{FOUNDATION_SEC_PORT} held by pid={bound_pid}, expected {proc.pid}"
                )
            return bound_pid, proc
        except RuntimeError:
            if proc.poll() is not None:
                raise PreflightError(
                    f"foundation-sec-server exited during startup (code={proc.returncode}). "
                    f"See {log_path}"
                ) from None
            time.sleep(1)
    proc.terminate()
    raise PreflightError("foundation-sec-server did not bind :8091 within 90s")


def _health(client: httpx.Client) -> dict[str, Any]:
    response = client.get(f"{FOUNDATION_SEC_URL}/health")
    response.raise_for_status()
    health = response.json()
    gguf_file = str(health.get("gguf_file") or "").lower()
    health["quant_match"] = REQUIRED_QUANT_SUBSTR in gguf_file
    return health


def _warmup_payload() -> dict[str, Any]:
    return {
        "repo": "eval/warmup",
        "pr_ref": "warmup",
        "commit_sha": "warmup",
        "max_context_tokens": MODEL_MAX_CONTEXT_TOKENS,
        "files": [
            {
                "path": "firewall/warmup.rules",
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


def run_preflight(
    client: httpx.Client,
    *,
    server_pid: int,
    allow_quant_mismatch: bool,
) -> dict[str, Any]:
    health = _health(client)
    if not health.get("quant_match"):
        if not allow_quant_mismatch:
            raise PreflightError(
                f"GET /health quant_match is false: gguf_file={health.get('gguf_file')!r}. "
                f"Required Q4_K_M ({Q4_GGUF_FILENAME}). "
                "Pass --allow-quant-mismatch for accuracy-only evaluation on another quant."
            )
        print(
            f"PREFLIGHT: quant_match=false (gguf_file={health.get('gguf_file')!r}); "
            f"--allow-quant-mismatch override active.",
            file=sys.stderr,
        )

    load_strategy = str(health.get("load_strategy") or "")
    if not health.get("loaded"):
        if load_strategy != "on_demand":
            raise PreflightError(
                f"GET /health loaded=false with load_strategy={load_strategy!r}; expected on_demand warmup."
            )
        response = client.post(f"{FOUNDATION_SEC_URL}/v1/analyze", json=_warmup_payload())
        response.raise_for_status()
        payload = response.json()
        if payload.get("outcome") == "failed":
            raise PreflightError(
                f"Warm-up inference failed: {payload.get('failure_message')}"
            )
        health = _health(client)
        # on_demand unloads after each request; warm-up success proves load + inference.
        health["inference_verified"] = True
    elif health.get("loaded"):
        health["inference_verified"] = True
    else:
        raise PreflightError("GET /health loaded=false; warm-up did not run.")

    if not health.get("quant_match") and not allow_quant_mismatch:
        raise PreflightError("GET /health quant_match=false after warm-up.")

    health["quant_evaluated"] = _quant_label_from_gguf(health.get("gguf_file"))
    health["quant_intended"] = QUANT_INTENDED
    health["accuracy_only"] = allow_quant_mismatch and not health.get("quant_match")

    chunk_budget = health.get("chunk_budget") or {}
    print("PREFLIGHT OK")
    print(f"  harness_interpreter: {sys.executable}")
    print(f"  server_interpreter:  {FSEC_VENV_PY}")
    print(f"  llama_cpp_version:   {assert_llama_cpp(FSEC_VENV_PY)}")
    print(f"  model_dir:           {health.get('model_dir')}")
    print(f"  gguf_file:           {health.get('gguf_file')}")
    print(f"  n_ctx:               {health.get('n_ctx')}")
    print(f"  chunk_budget_usable: {chunk_budget.get('usable')}")
    print(f"  server_pid:          {server_pid}")
    print(f"  loaded:              {health.get('loaded')}")
    print(f"  inference_verified:  {health.get('inference_verified')}")
    print(f"  quant_match:         {health.get('quant_match')}")
    print(f"  quant_evaluated:     {health.get('quant_evaluated')}")
    print(f"  quant_intended:      {health.get('quant_intended')}")
    print(f"  accuracy_only:       {health.get('accuracy_only')}")
    return health


def analyze_file(
    client: httpx.Client,
    *,
    virtual_path: str,
    content: str,
    corpus_name: str,
    target_type: str,
    prompt_variant: str = "baseline",
) -> dict[str, Any]:
    line_count = _line_count(content)
    payload = {
        "repo": f"eval/{corpus_name}",
        "pr_ref": f"eval/{corpus_name}",
        "commit_sha": "eval-model",
        "max_context_tokens": MODEL_MAX_CONTEXT_TOKENS,
        "prompt_variant": prompt_variant,
        "files": [
            {
                "path": virtual_path,
                "target_type": target_type,
                "hunks": [
                    {
                        "new_start": 1,
                        "new_end": line_count,
                        "content": content,
                    }
                ],
            }
        ],
    }
    response = client.post(f"{FOUNDATION_SEC_URL}/v1/analyze", json=payload)
    response.raise_for_status()
    return response.json()


def _process_rss_mib(pid: int) -> float | None:
    try:
        result = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return round(int(result.stdout.strip()) / 1024, 2)
    except (OSError, ValueError):
        return None


def _swap_used_mib() -> float | None:
    try:
        import psutil

        return round(psutil.swap_memory().used / (1024 * 1024), 2)
    except Exception:
        return None


def sample_peak_rss(pid: int, fn: Any) -> tuple[Any, float]:
    peak_rss = 0.0
    stop = threading.Event()

    def sampler() -> None:
        nonlocal peak_rss
        while not stop.is_set():
            rss = _process_rss_mib(pid)
            if rss is not None:
                peak_rss = max(peak_rss, rss)
            time.sleep(0.05)

    thread = threading.Thread(target=sampler, daemon=True)
    thread.start()
    try:
        result = fn()
    finally:
        stop.set()
        thread.join(timeout=2.0)
    return result, peak_rss


def corpus_dirs() -> list[tuple[str, Path]]:
    dirs: list[tuple[str, Path]] = [
        ("generated", GENERATED_CORPUS_DIR),
        ("holdout", HOLDOUT_CORPUS_DIR),
    ]
    if REALDEVICE_CORPUS_DIR.is_dir() and any(REALDEVICE_CORPUS_DIR.rglob("*.labels.json")):
        dirs.append(("realdevice", REALDEVICE_CORPUS_DIR))
    return dirs


def collect_file_list() -> list[tuple[str, Path, Any]]:
    files: list[tuple[str, Path, Any]] = []
    for corpus_name, corpus_dir in corpus_dirs():
        for entry in load_corpus(corpus_dir):
            files.append((corpus_name, corpus_dir, entry))
    return files


def semantics_report() -> dict[str, dict[str, str]]:
    return {
        rule_id: {
            "target_type": sem.target_type,
            "cwe": sem.cwe,
            "semantic_key": sem.semantic_key,
            "defect_summary": sem.defect_summary,
        }
        for rule_id, sem in sorted(RULE_SEMANTICS.items())
    }


PROMPT_VARIANT_CONSTRAINED_OUTPUT = "constrained_output"
PROMPT_VARIANT_PLATFORM_CONSTRAINED = "platform_constrained"


def _prompt_source(prompt_variant: str) -> str:
    if prompt_variant == "platform_specific":
        return "foundation_sec_server/prompts.py::_PLATFORM_SPECIFIC_EVAL_PROMPT"
    if prompt_variant == PROMPT_VARIANT_CONSTRAINED_OUTPUT:
        return "foundation_sec_server/prompts.py::_CONSTRAINED_OUTPUT_EVAL_PROMPT"
    if prompt_variant == PROMPT_VARIANT_PLATFORM_CONSTRAINED:
        return "foundation_sec_server/prompts.py::_PLATFORM_CONSTRAINED_EVAL_PROMPT"
    return "foundation_sec_server/engine.py::_EVAL_PROMPT (gate advisory path)"


def build_partial_report(
    *,
    server_health: dict[str, Any],
    server_pid: int,
    harness_python: str,
    server_python: str,
    llama_cpp_version: str,
    handler_stats: dict[str, dict[str, MetricCounts]],
    model_stats: dict[str, dict[str, ModelMetricCounts]],
    file_runs: list[dict[str, Any]],
    unlabeled_model_findings: list[dict[str, Any]],
    all_model_findings: list[dict[str, Any]],
    invalid_findings: list[dict[str, Any]] | None = None,
    model_findings_emitted: int | None = None,
    surviving_model_findings: list[dict[str, Any]] | None = None,
    peak_rss_mib: float,
    swap_used_mib: float | None,
    started: float,
    files_scored_successfully: int,
    files_failed: int,
    accuracy_only: bool,
    prompt_variant: str = "baseline",
) -> dict[str, Any]:
    per_rule: dict[str, dict[str, dict[str, Any]]] = {}
    sem_map = semantics_report()
    for target_type in sorted(set(handler_stats) | set(model_stats)):
        per_rule[target_type] = {}
        rule_ids = sorted(set(handler_stats.get(target_type, {})) | set(model_stats.get(target_type, {})))
        for rule_id in rule_ids:
            per_rule[target_type][rule_id] = {
                "handler": handler_stats.get(target_type, {}).get(rule_id, MetricCounts()).as_dict(),
                "model": model_stats.get(target_type, {}).get(rule_id, ModelMetricCounts()).as_dict(),
                "semantic": sem_map.get(rule_id, {}),
            }

    stamping = quant_stamping_from_server_health(server_health)
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "partial" if files_failed else "complete",
        "prompt_variant": prompt_variant,
        "semantic_matcher": MATCHER_BEST_FIT,
        "semantic_matcher_metadata": MATCHER_METADATA[MATCHER_BEST_FIT],
        "model_config": {
            "service_url": FOUNDATION_SEC_URL,
            "max_context_tokens": MODEL_MAX_CONTEXT_TOKENS,
            "required_quant": QUANT_INTENDED,
            "prompt_variant": prompt_variant,
            "prompt_source": _prompt_source(prompt_variant),
            "harness_interpreter": harness_python,
            "server_interpreter": server_python,
            "llama_cpp_version": llama_cpp_version,
            "server_health": server_health,
            "server_pid": server_pid,
        },
        "rule_semantics_mapping": sem_map,
        "per_target_type_per_rule": per_rule,
        "unlabeled_model_findings": unlabeled_model_findings,
        "unrecognized_model_asserted_cwe": unrecognized_model_cwe_tally(all_model_findings),
        "summary": {
            "files_total": len(file_runs),
            "files_scored_successfully": files_scored_successfully,
            "files_failed": files_failed,
            "corpora": [name for name, _ in corpus_dirs()],
            "model_findings_total": len(all_model_findings),
            "model_findings_emitted": model_findings_emitted or len(all_model_findings),
            "invalid_findings_count": len(invalid_findings or []),
            "unlabeled_model_findings_count": len(unlabeled_model_findings),
        },
    }
    if invalid_findings is not None:
        report["invalid_findings"] = invalid_findings
        report["invalid_findings_summary"] = summarize_rejections(invalid_findings)
    if surviving_model_findings is not None:
        report["surviving_model_findings"] = surviving_model_findings
    if prompt_variant in CONSTRAINED_PROMPT_VARIANTS:
        report["output_constraints"] = {
            "variant": prompt_variant,
            "evidence_must_be_substring": True,
            "line_range_enforced": True,
            "rejected_before_scoring": True,
        }
    if not stamping["accuracy_only"]:
        report["timing"] = {
            "total_wall_clock_ms": int((time.monotonic() - started) * 1000),
            "peak_server_rss_mib": round(peak_rss_mib, 2),
            "swap_used_mib": swap_used_mib,
            "per_file": file_runs,
        }
    return apply_quant_stamping(report)


def write_partial(report: dict[str, Any], path: Path) -> None:
    partial_path = path.with_suffix(".partial.json")
    partial_path.parent.mkdir(parents=True, exist_ok=True)
    partial_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def print_tables(report: dict[str, Any]) -> None:
    per_rule = report["per_target_type_per_rule"]
    print("\nPer target_type / rule — handler vs model (TP / FP / FN):")
    for target_type, rules in per_rule.items():
        print(f"\n  [{target_type}]")
        print(
            f"  {'Rule':<10} {'H-TP':>5} {'H-FP':>5} {'H-FN':>5}   "
            f"{'M-TP':>5} {'M-FP':>5} {'M-FN':>5}  model"
        )
        for rule_id, metrics in sorted(rules.items()):
            h = metrics["handler"]
            m = metrics["model"]
            if not any(h.values()) and m == "not_measured":
                continue
            if m == "not_measured":
                m_label = "not_measured"
                print(
                    f"  {rule_id:<10} {h['true_positives']:>5} {h['false_positives']:>5} "
                    f"{h['false_negatives']:>5}   {'—':>5} {'—':>5} {'—':>5}  {m_label}"
                )
            else:
                print(
                    f"  {rule_id:<10} {h['true_positives']:>5} {h['false_positives']:>5} "
                    f"{h['false_negatives']:>5}   {m['true_positives']:>5} {m['false_positives']:>5} "
                    f"{m['false_negatives']:>5}"
                )


def print_unlabeled(report: dict[str, Any]) -> None:
    items = report.get("unlabeled_model_findings") or []
    print(f"\nUnlabeled model findings ({len(items)}):")
    for item in items:
        finding = item["finding"]
        print(
            f"  [{item['corpus']}/{item['rel_path']}] "
            f"lines {finding.get('line_start')}-{finding.get('line_end')} "
            f"cwe={finding.get('model_asserted_cwe') or finding.get('cwe')}"
        )
        print(f"    title: {finding.get('title')}")
        print(f"    description: {finding.get('description')}")
        if finding.get("evidence"):
            print(f"    evidence: {finding.get('evidence')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-quant-mismatch",
        action="store_true",
        help=(
            "Proceed when staged weights are not Q4_K_M (accuracy-only; timing/RSS omitted). "
            "Report is stamped with quant_evaluated, quant_intended, and accuracy_only."
        ),
    )
    parser.add_argument(
        "--backfill-report",
        action="store_true",
        help="Backfill quant_evaluated/quant_intended/accuracy_only on an existing report JSON.",
    )
    parser.add_argument(
        "--prompt-variant",
        choices=("baseline", "platform_specific", PROMPT_VARIANT_CONSTRAINED_OUTPUT, PROMPT_VARIANT_PLATFORM_CONSTRAINED),
        default="baseline",
        help="Eval prompt variant (default: baseline _EVAL_PROMPT).",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=None,
        help="Write report JSON here (default: validation/reports/model-vs-handler.json).",
    )
    args = parser.parse_args()

    report_path = args.report_path or REPORT_PATH
    if args.prompt_variant == "platform_specific" and args.report_path is None:
        report_path = PLATFORM_SPECIFIC_REPORT_PATH
    if args.prompt_variant == PROMPT_VARIANT_CONSTRAINED_OUTPUT and args.report_path is None:
        report_path = CONSTRAINED_OUTPUT_REPORT_PATH
    if args.prompt_variant == PROMPT_VARIANT_PLATFORM_CONSTRAINED and args.report_path is None:
        report_path = PLATFORM_CONSTRAINED_REPORT_PATH

    if args.backfill_report:
        try:
            stamped = backfill_report_quant_stamping(REPORT_PATH)
        except FileNotFoundError:
            print(f"ERROR: report not found at {REPORT_PATH}", file=sys.stderr)
            return 1
        except ReportWriteError as exc:
            print(f"ERROR: backfill validation failed: {exc}", file=sys.stderr)
            return 1
        mc = stamped["model_config"]
        print(f"Backfilled {REPORT_PATH.relative_to(ROOT)}")
        print(
            f"  quant_evaluated={mc['quant_evaluated']} "
            f"quant_intended={mc['quant_intended']} "
            f"accuracy_only={mc['accuracy_only']}"
        )
        return 0

    allow_quant_mismatch = bool(args.allow_quant_mismatch)
    prompt_variant = str(args.prompt_variant)

    if FSEC_VENV_PY.is_file():
        try:
            if not os.path.samefile(sys.executable, FSEC_VENV_PY):
                os.execv(str(FSEC_VENV_PY), [str(FSEC_VENV_PY), *sys.argv])
        except OSError:
            pass

    if allow_quant_mismatch:
        print(ACCURACY_ONLY_BANNER, flush=True)

    started = time.monotonic()
    harness_python = str(Path(sys.executable).resolve())
    server_python = str(resolve_interpreter())

    if harness_python != server_python:
        print(
            f"NOTE: harness uses {harness_python}; server uses {server_python}. "
            "Both must import llama_cpp (verified below).",
            file=sys.stderr,
        )

    llama_cpp_version = assert_llama_cpp(Path(server_python))
    model_dir, use_low_memory, quant_evaluated_label = resolve_model_layout(
        allow_quant_mismatch=allow_quant_mismatch,
    )
    accuracy_only = allow_quant_mismatch and quant_evaluated_label != QUANT_INTENDED

    handler_stats: dict[str, dict[str, MetricCounts]] = {}
    model_stats: dict[str, dict[str, ModelMetricCounts]] = {}
    file_runs: list[dict[str, Any]] = []
    unlabeled_model_findings: list[dict[str, Any]] = []
    all_model_findings: list[dict[str, Any]] = []
    invalid_findings: list[dict[str, Any]] = []
    surviving_model_findings: list[dict[str, Any]] = []
    model_findings_emitted = 0
    enforce_output_constraints = prompt_variant in CONSTRAINED_PROMPT_VARIANTS
    peak_rss_mib = 0.0
    files_scored_successfully = 0
    files_failed = 0
    server_proc: subprocess.Popen[Any] | None = None
    server_pid: int | None = None
    server_health: dict[str, Any] = {}

    file_list = collect_file_list()
    total_files = len(file_list)

    try:
        server_pid, server_proc = start_foundation_sec_server(
            Path(server_python),
            model_dir=model_dir,
            use_low_memory=use_low_memory,
        )
        with httpx.Client(timeout=600.0) as client:
            server_health = run_preflight(
                client,
                server_pid=server_pid,
                allow_quant_mismatch=allow_quant_mismatch,
            )
            accuracy_only = bool(server_health.get("accuracy_only"))

            for index, (corpus_name, corpus_dir, entry) in enumerate(file_list, start=1):
                rel = f"{corpus_name}/{entry.rel_path}"
                content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")

                def _run() -> dict[str, Any]:
                    return analyze_file(
                        client,
                        virtual_path=entry.virtual_path,
                        content=content,
                        corpus_name=corpus_name,
                        target_type=entry.target_type,
                        prompt_variant=prompt_variant,
                    )

                t0 = time.monotonic()
                try:
                    if accuracy_only:
                        result = _run()
                        wall_ms = None
                    else:
                        result, file_peak = sample_peak_rss(server_pid, _run)
                        wall_ms = int((time.monotonic() - t0) * 1000)
                        peak_rss_mib = max(peak_rss_mib, file_peak)
                    outcome = str(result.get("outcome") or "unknown")
                    failure_message = result.get("failure_message")
                    success = outcome in {
                        "completed_no_findings",
                        "completed_with_findings",
                    }
                except Exception as exc:  # noqa: BLE001
                    wall_ms = int((time.monotonic() - t0) * 1000) if not accuracy_only else None
                    outcome = "failed"
                    failure_message = str(exc)
                    result = {}
                    success = False

                model_findings: list[dict[str, Any]] = []
                emitted_count = 0
                rejected_count = 0
                if success:
                    raw_findings = list(result.get("findings") or [])
                    emitted = [f for f in raw_findings if is_model_originated(f)]
                    emitted_count = len(emitted)
                    model_findings_emitted += emitted_count
                    file_lines = _line_count(content)
                    if enforce_output_constraints:
                        surviving, rejected = partition_constrained_findings(
                            emitted,
                            content=content,
                            line_min=1,
                            line_max=file_lines,
                        )
                        rejected_count = len(rejected)
                        for finding in rejected:
                            invalid_findings.append(
                                {
                                    "corpus": corpus_name,
                                    "rel_path": entry.rel_path,
                                    "target_type": entry.target_type,
                                    "virtual_path": entry.virtual_path,
                                    "finding": finding,
                                    "rejection_reason": finding.get("rejection_reason"),
                                }
                            )
                        model_findings = surviving
                    else:
                        model_findings = emitted
                    all_model_findings.extend(model_findings)
                    for finding in model_findings:
                        surviving_model_findings.append(
                            {
                                "corpus": corpus_name,
                                "rel_path": entry.rel_path,
                                "target_type": entry.target_type,
                                "virtual_path": entry.virtual_path,
                                "expected_rule_ids": sorted(set(entry.expected_rule_ids)),
                                "finding": finding,
                            }
                        )
                    files_scored_successfully += 1
                else:
                    files_failed += 1

                score_file(
                    matcher=MATCHER_BEST_FIT,
                    entry=entry,
                    corpus_name=corpus_name,
                    content=content,
                    model_findings=model_findings if success else None,
                    handler_stats=handler_stats,
                    model_stats=model_stats,
                    unlabeled_model_findings=unlabeled_model_findings,
                    rule_semantics=RULE_SEMANTICS,
                )

                run_record: dict[str, Any] = {
                    "index": index,
                    "corpus": corpus_name,
                    "rel_path": entry.rel_path,
                    "target_type": entry.target_type,
                    "model_outcome": outcome,
                    "model_finding_count": len(model_findings),
                    "scored": success,
                    "failure_message": failure_message,
                }
                if enforce_output_constraints:
                    run_record["model_findings_emitted"] = emitted_count
                    run_record["invalid_findings_count"] = rejected_count
                if not accuracy_only:
                    run_record["wall_clock_ms"] = wall_ms
                file_runs.append(run_record)
                if accuracy_only:
                    print(
                        f"[{index}/{total_files}] {rel} "
                        f"findings={len(model_findings)} outcome={outcome}",
                        flush=True,
                    )
                else:
                    print(
                        f"[{index}/{total_files}] {rel} {wall_ms}ms "
                        f"findings={len(model_findings)} outcome={outcome}",
                        flush=True,
                    )

                write_partial(
                    build_partial_report(
                        server_health=server_health,
                        server_pid=server_pid,
                        harness_python=harness_python,
                        server_python=server_python,
                        llama_cpp_version=llama_cpp_version,
                        handler_stats=handler_stats,
                        model_stats=model_stats,
                        file_runs=file_runs,
                        unlabeled_model_findings=unlabeled_model_findings,
                        all_model_findings=all_model_findings,
                        invalid_findings=invalid_findings if enforce_output_constraints else None,
                        model_findings_emitted=model_findings_emitted if enforce_output_constraints else None,
                        surviving_model_findings=surviving_model_findings if enforce_output_constraints else None,
                        peak_rss_mib=peak_rss_mib,
                        swap_used_mib=_swap_used_mib() if not accuracy_only else None,
                        started=started,
                        files_scored_successfully=files_scored_successfully,
                        files_failed=files_failed,
                        accuracy_only=accuracy_only,
                        prompt_variant=prompt_variant,
                    ),
                    report_path,
                )

    finally:
        if server_proc is not None and server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server_proc.kill()

    if files_scored_successfully == 0:
        print("ERROR: zero files scored successfully; refusing to write final report.", file=sys.stderr)
        return 1

    final_report = build_partial_report(
        server_health=server_health,
        server_pid=server_pid or 0,
        harness_python=harness_python,
        server_python=server_python,
        llama_cpp_version=llama_cpp_version,
        handler_stats=handler_stats,
        model_stats=model_stats,
        file_runs=file_runs,
        unlabeled_model_findings=unlabeled_model_findings,
        all_model_findings=all_model_findings,
        invalid_findings=invalid_findings if enforce_output_constraints else None,
        model_findings_emitted=model_findings_emitted if enforce_output_constraints else None,
        surviving_model_findings=surviving_model_findings if enforce_output_constraints else None,
        peak_rss_mib=peak_rss_mib,
        swap_used_mib=_swap_used_mib() if not accuracy_only else None,
        started=started,
        files_scored_successfully=files_scored_successfully,
        files_failed=files_failed,
        accuracy_only=accuracy_only,
        prompt_variant=prompt_variant,
    )
    final_report["status"] = "complete" if files_failed == 0 else "completed_with_failures"

    try:
        write_report(final_report, report_path)
    except ReportWriteError as exc:
        print(f"ERROR: refusing to write report: {exc}", file=sys.stderr)
        return 1
    partial_path = report_path.with_suffix(".partial.json")
    if partial_path.exists():
        partial_path.unlink()

    print(f"\nWrote {report_path.relative_to(ROOT)}")
    if accuracy_only:
        print(
            f"Scored {files_scored_successfully}/{total_files} files | "
            f"failed {files_failed} | accuracy-only (no timing/RSS)"
        )
    else:
        print(
            f"Scored {files_scored_successfully}/{total_files} files | "
            f"failed {files_failed} | wall-clock {final_report['timing']['total_wall_clock_ms']} ms"
        )
        print(
            f"Peak server RSS: {final_report['timing']['peak_server_rss_mib']} MiB | "
            f"swap used: {final_report['timing']['swap_used_mib']} MiB"
        )
    print(f"Unrecognized model CWE: {final_report['unrecognized_model_asserted_cwe']}")
    if enforce_output_constraints:
        summary = final_report["summary"]
        inv = final_report.get("invalid_findings_summary") or {}
        tp = fp = fn = 0
        for rules in final_report["per_target_type_per_rule"].values():
            for metrics in rules.values():
                model = metrics.get("model")
                if isinstance(model, dict):
                    tp += int(model.get("true_positives") or 0)
                    fp += int(model.get("false_positives") or 0)
                    fn += int(model.get("false_negatives") or 0)
        print(
            f"\nConstrained output (Experiment B): "
            f"emitted={summary.get('model_findings_emitted')} "
            f"rejected={summary.get('invalid_findings_count')} "
            f"surviving={summary.get('model_findings_total')}"
        )
        if inv:
            print(f"  rejection reasons: {inv}")
        print(f"  surviving model TP/FP/FN (rule-level): {tp}/{fp}/{fn}")
    print_tables(final_report)
    print_unlabeled(final_report)

    if accuracy_only:
        print(f"\n{ACCURACY_ONLY_BANNER}", flush=True)

    return 1 if files_failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PreflightError as exc:
        print(f"PREFLIGHT FAILED: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
