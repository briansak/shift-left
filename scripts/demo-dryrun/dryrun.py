#!/usr/bin/env python3
"""End-to-end operational smoke test for Shift-Left PR gate, waivers, and unclaimed paths."""

from __future__ import annotations

import argparse
import base64
import json
import os
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
REPORTS = ROOT / "validation" / "reports"
SHIFT_LEFT = ROOT / "scripts" / "shift-left"

ORCHESTRATOR_URL = os.environ.get("DRYRUN_ORCHESTRATOR_URL", "http://127.0.0.1:8080").rstrip("/")
FORGEJO_URL = os.environ.get("DRYRUN_FORGEJO_URL", "http://127.0.0.1:3000").rstrip("/")
FSEC_URL = os.environ.get("DRYRUN_FOUNDATION_SEC_URL", "http://127.0.0.1:8091").rstrip("/")
ANTARES_URL = os.environ.get("DRYRUN_ANTARES_URL", "http://127.0.0.1:8090").rstrip("/")

DEFAULT_PHASE_TIMEOUT = float(os.environ.get("DRYRUN_PHASE_TIMEOUT_SEC", "300"))
DEFAULT_COLD_RUNS = int(os.environ.get("DRYRUN_COLD_RUNS", "1"))
DEFAULT_WARM_RUNS = int(os.environ.get("DRYRUN_WARM_RUNS", "3"))
SKIP_ADVISORY = os.environ.get("DRYRUN_SKIP_ADVISORY", "").lower() in {"1", "true", "yes"}

EXPECTED_BLOCK_RULES_INITIAL = frozenset({"ASA-001", "FTD-001", "ASA-007"})

WARM_PHASE_NAMES = [
    "create_pr",
    "gate_block_deterministic",
    "gate_block_advisory",
    "waiver",
    "sha_invalidate",
    "unclaimed_cfg",
]


class DryrunError(RuntimeError):
    def __init__(self, phase: str, message: str) -> None:
        super().__init__(f"[{phase}] {message}")
        self.phase = phase


@dataclass
class DryrunCleanup:
    """Tracks demo repos and always unloads models in ``execute()``."""

    repos: list[tuple[str, str]] = field(default_factory=list)
    _deleted: set[tuple[str, str]] = field(default_factory=set)

    def register_repo(self, owner: str, name: str) -> None:
        key = (owner, name)
        if key not in self.repos:
            self.repos.append(key)

    def execute(self) -> dict[str, Any]:
        actions: list[str] = []
        errors: list[str] = []
        owner = _read_bootstrap_secret("forgejo_admin_user") or os.environ.get(
            "FORGEJO_DEFAULT_OWNER", "shift-left"
        )
        forgejo_token = os.environ.get("FORGEJO_TOKEN") or _read_bootstrap_secret("forgejo_token")

        if forgejo_token:
            fj = ForgejoClient(FORGEJO_URL, forgejo_token)
            for repo_owner, repo_name in self.repos:
                if (repo_owner, repo_name) in self._deleted:
                    continue
                try:
                    fj.delete_repo(repo_owner, repo_name)
                    self._deleted.add((repo_owner, repo_name))
                    actions.append(f"deleted forgejo repo {repo_owner}/{repo_name}")
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"delete {repo_owner}/{repo_name}: {exc}")

            try:
                for repo_name in fj.list_repos_matching(owner, "demo-dryrun"):
                    key = (owner, repo_name)
                    if key in self._deleted:
                        continue
                    try:
                        fj.delete_repo(owner, repo_name)
                        self._deleted.add(key)
                        actions.append(f"deleted orphaned forgejo repo {owner}/{repo_name}")
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"delete orphaned {owner}/{repo_name}: {exc}")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"orphan repo sweep: {exc}")
        elif self.repos:
            errors.append("FORGEJO_TOKEN unavailable — could not delete tracked demo repos")

        unload: dict[str, Any] = {}
        for label, url in (("foundation_sec", FSEC_URL), ("antares", ANTARES_URL)):
            try:
                httpx.post(f"{url}/v1/unload", timeout=30.0)
                unload[label] = "unload_requested"
            except Exception as exc:  # noqa: BLE001
                unload[label] = f"unload_failed: {exc}"
                errors.append(f"{label} unload: {exc}")

        try:
            health = httpx.get(f"{FSEC_URL}/health", timeout=10.0)
            if health.status_code == 200:
                payload = health.json()
                unload["foundation_sec_loaded_after"] = payload.get("loaded")
                if payload.get("loaded"):
                    errors.append("foundation-sec-server model still loaded after unload")
        except Exception as exc:  # noqa: BLE001
            unload["foundation_sec_health"] = str(exc)

        if unload.get("foundation_sec") == "unload_requested" or unload.get("antares") == "unload_requested":
            actions.append("unloaded foundation-sec-server and antares-server model weights")

        return {
            "actions": actions,
            "errors": errors,
            "unload": unload,
            "repos_tracked": [f"{o}/{n}" for o, n in self.repos],
            "passed": not errors,
        }


@dataclass
class MemorySample:
    peak_rss_mib: float = 0.0
    swap_used_mib: float = 0.0
    server_pids: dict[str, int] = field(default_factory=dict)


@dataclass
class PhaseResult:
    name: str
    passed: bool
    wall_seconds: float
    memory: MemorySample
    detail: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _import_peak_memory():
    import importlib.util

    path = ROOT / "scripts" / "validate-peak-memory.py"
    spec = importlib.util.spec_from_file_location("validate_peak_memory", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Python 3.14 dataclasses look up the module in sys.modules during class body.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_peak = _import_peak_memory()


def _model_server_pids() -> dict[str, int]:
    pids: dict[str, int] = {}
    for name, port in (("foundation-sec-server", 8091), ("antares-server", 8090)):
        try:
            pids[name] = _peak.pid_listening_on(port)
        except RuntimeError:
            continue
    return pids


def _sample_peak_memory(fn: Callable[[], None]) -> MemorySample:
    pids = _model_server_pids()
    peak_rss = 0.0
    stop = threading.Event()

    def sampler() -> None:
        nonlocal peak_rss
        while not stop.is_set():
            for pid in pids.values():
                try:
                    stats = _peak.memory_breakdown(pid)
                    peak_rss = max(peak_rss, stats.rss_mib)
                except Exception:  # noqa: BLE001
                    pass
            time.sleep(0.1)

    thread = threading.Thread(target=sampler, daemon=True)
    thread.start()
    try:
        fn()
    finally:
        stop.set()
        thread.join(timeout=2.0)
    swap = _peak.system_snapshot().get("swap_used_mib", 0.0)
    return MemorySample(peak_rss_mib=round(peak_rss, 2), swap_used_mib=swap, server_pids=pids)


class ForgejoClient:
    def __init__(self, base: str, token: str) -> None:
        self.base = base.rstrip("/")
        self.token = token

    def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        data = None
        headers = {"Authorization": f"token {self.token}"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.base}{path}", data=data, method=method, headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise DryrunError("forgejo", f"{method} {path} HTTP {exc.code}: {detail[:200]}") from exc

    @staticmethod
    def _ref_sha(payload: Any) -> str:
        if isinstance(payload, list):
            if not payload:
                raise DryrunError("forgejo", "empty git ref list")
            payload = payload[0]
        if not isinstance(payload, dict):
            raise DryrunError("forgejo", f"unexpected git ref payload: {type(payload).__name__}")
        obj = payload.get("object") if "object" in payload else payload
        if isinstance(obj, dict) and obj.get("sha"):
            return str(obj["sha"])
        if payload.get("sha"):
            return str(payload["sha"])
        raise DryrunError("forgejo", f"git ref missing sha: {payload!r}"[:200])

    def ensure_repo(self, owner: str, name: str) -> None:
        try:
            self._request("DELETE", f"/api/v1/repos/{owner}/{name}")
        except DryrunError:
            pass
        body = {"name": name, "auto_init": True, "private": False}
        try:
            self._request("POST", f"/api/v1/orgs/{owner}/repos", body)
        except DryrunError:
            self._request("POST", "/api/v1/user/repos", body)

    def branch_sha(self, owner: str, repo: str, branch: str) -> str:
        ref = self._request("GET", f"/api/v1/repos/{owner}/{repo}/git/refs/heads/{branch}")
        return self._ref_sha(ref)

    def delete_repo(self, owner: str, name: str) -> None:
        try:
            self._request("DELETE", f"/api/v1/repos/{owner}/{name}")
        except DryrunError:
            pass

    def upsert_file(
        self,
        owner: str,
        repo: str,
        path: str,
        content: str,
        *,
        branch: str = "main",
        message: str | None = None,
    ) -> str:
        sha = None
        try:
            existing = self._request("GET", f"/api/v1/repos/{owner}/{repo}/contents/{path}?ref={branch}")
            if isinstance(existing, dict):
                sha = existing.get("sha")
        except DryrunError:
            sha = None
        payload: dict[str, Any] = {
            "content": base64.b64encode(content.encode()).decode(),
            "message": message or f"Update {path}",
            "branch": branch,
        }
        method = "PUT"
        if sha:
            payload["sha"] = sha
        else:
            method = "POST"
        self._request(method, f"/api/v1/repos/{owner}/{repo}/contents/{path}", payload)
        ref = self._request("GET", f"/api/v1/repos/{owner}/{repo}/git/refs/heads/{branch}")
        return self._ref_sha(ref)

    def create_branch(self, owner: str, repo: str, branch: str, from_ref: str = "main") -> None:
        base = self._request("GET", f"/api/v1/repos/{owner}/{repo}/git/refs/heads/{from_ref}")
        sha = self._ref_sha(base)
        try:
            self._request(
                "POST",
                f"/api/v1/repos/{owner}/{repo}/branches",
                {"new_branch_name": branch, "old_ref_name": from_ref},
            )
        except DryrunError:
            self._request(
                "POST",
                f"/api/v1/repos/{owner}/{repo}/git/refs",
                {"ref": f"refs/heads/{branch}", "sha": sha},
            )

    def open_pr(self, owner: str, repo: str, *, head: str, base: str = "main", title: str) -> dict:
        return self._request(
            "POST",
            f"/api/v1/repos/{owner}/{repo}/pulls",
            {"title": title, "head": head, "base": base, "body": "demo-dryrun smoke PR"},
        )

    def list_repos_matching(self, owner: str, prefix: str) -> list[str]:
        names: list[str] = []
        for path in (f"/api/v1/users/{owner}/repos?limit=100", f"/api/v1/orgs/{owner}/repos?limit=100"):
            try:
                payload = self._request("GET", path)
            except DryrunError:
                continue
            if not isinstance(payload, list):
                continue
            for item in payload:
                name = str(item.get("name") or "")
                if name.startswith(prefix):
                    names.append(name)
        return sorted(set(names))


class ShiftLeftClient:
    def __init__(self, base: str, review_token: str, approve_token: str) -> None:
        self.base = base.rstrip("/")
        self.review_token = review_token
        self.approve_token = approve_token

    def review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        *,
        skip_advisory: bool = False,
    ) -> dict:
        resp = httpx.post(
            f"{self.base}/api/v1/review",
            headers={"Authorization": f"Bearer {self.review_token}"},
            json={
                "owner": owner,
                "repo": repo,
                "pr_number": pr_number,
                "commit_sha": commit_sha,
                "skip_advisory": skip_advisory,
            },
            timeout=600.0,
        )
        resp.raise_for_status()
        return resp.json()

    def gate(self, owner: str, repo: str, pr_number: int, commit_sha: str) -> dict:
        resp = httpx.get(
            f"{self.base}/api/v1/gate/{owner}/{repo}/{pr_number}",
            params={"commit_sha": commit_sha},
            timeout=60.0,
        )
        resp.raise_for_status()
        return resp.json()

    def policy_decision(self, owner: str, repo: str, pr_number: int, commit_sha: str) -> dict:
        resp = httpx.get(
            f"{self.base}/api/v1/policy/decision/{owner}/{repo}/{pr_number}",
            params={"commit_sha": commit_sha},
            timeout=60.0,
        )
        resp.raise_for_status()
        return resp.json()

    def findings(self, owner: str, repo: str, pr_number: int) -> list[dict]:
        resp = httpx.get(
            f"{self.base}/api/v1/findings/{owner}/{repo}/{pr_number}",
            timeout=60.0,
        )
        resp.raise_for_status()
        payload = resp.json()
        return list(payload.get("findings") or [])

    def grant_waiver(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        *,
        commit_sha: str,
        finding_id: str,
        reason: str,
    ) -> dict:
        resp = httpx.post(
            f"{self.base}/api/v1/waivers/{owner}/{repo}/{pr_number}",
            headers={"Authorization": f"Bearer {self.approve_token}"},
            json={
                "commit_sha": commit_sha,
                "finding_id": finding_id,
                "reason": reason,
            },
            timeout=60.0,
        )
        resp.raise_for_status()
        return resp.json()


def _read_bootstrap_secret(key: str) -> str:
    path = ROOT / ".shift-left" / "bootstrap-secrets.json"
    if not path.is_file():
        return ""
    data = json.loads(path.read_text(encoding="utf-8"))
    return str(data.get(key) or "")


def _mint_token(capabilities: str, label: str) -> str:
    env = os.environ.copy()
    env["PYTHONPATH"] = ":".join(
        [
            str(ROOT / "cli"),
            str(ROOT / "services" / "orchestrator"),
            str(ROOT / "services" / "shift-left-shared"),
            env.get("PYTHONPATH", ""),
        ]
    )
    proc = subprocess.run(
        [
            str(ROOT / ".venv" / "bin" / "python"),
            "-m",
            "shift_left_cli.main",
            "token",
            "mint",
            "--label",
            label,
            "--actor",
            "demo-dryrun",
            "--capabilities",
            capabilities,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("slt_"):
            return line.strip()
    raise DryrunError("setup", "failed to mint API token")


def _patch_config_q4_nctx() -> None:
    config_path = ROOT / "config" / "shift-left.yaml"
    if not config_path.is_file():
        raise DryrunError("cold_start", "config/shift-left.yaml missing — run ./shift-left up configure first")
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    fs = raw.setdefault("models", {}).setdefault("foundation_sec", {})
    fs["use_low_memory"] = True
    fs["max_context_tokens"] = 4096
    fs["load_strategy"] = "on_demand"
    fs["local_path_low_memory"] = "models/foundation-sec-q4_k_m"
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def _unload_model_servers() -> None:
    for url in (FSEC_URL, ANTARES_URL):
        try:
            httpx.post(f"{url}/v1/unload", timeout=30.0)
        except Exception:  # noqa: BLE001
            pass


def _wait_http_json(url: str, *, timeout: float, phase: str) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: Exception | str | None = None
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(url, timeout=5.0)
            if resp.status_code == 200:
                payload = resp.json()
                return payload if isinstance(payload, dict) else {"value": payload}
            last = f"HTTP {resp.status_code}"
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(1.0)
    raise DryrunError(phase, f"timeout waiting for {url}: {last}")


def _start_running_stack() -> None:
    """Bring Compose + host-native model servers up after ``down``.

    ``./shift-left up`` skips completed bootstrap phases, so a cold start would
    otherwise leave Forgejo, the orchestrator, and model servers stopped.
    """
    from shift_left.system.supervisor import start_service
    from shift_left_cli.preflight import ensure_docker_daemon
    from shift_left_cli.stack import start_compose_stack

    ensure_docker_daemon(ROOT, resume="./scripts/demo-dryrun/run")
    start_compose_stack(ROOT)
    start_service(ROOT, "foundation-sec-server")
    try:
        start_service(ROOT, "antares-server")
    except Exception as exc:  # noqa: BLE001
        print(f"  warning: antares-server start: {exc}", flush=True)
    _wait_http_json(f"{ORCHESTRATOR_URL}/health", timeout=180.0, phase="cold_start")
    _wait_http_json(f"{FSEC_URL}/health", timeout=60.0, phase="cold_start")


def _assert_models_unloaded() -> dict[str, Any]:
    health: dict[str, Any] = {}
    try:
        payload = _wait_http_json(f"{FSEC_URL}/health", timeout=30.0, phase="cold_start")
    except DryrunError as exc:
        raise DryrunError("cold_start", f"foundation-sec health: {exc}") from exc
    health["foundation_sec"] = payload
    if health["foundation_sec"].get("loaded"):
        raise DryrunError("cold_start", "foundation-sec-server model still loaded after cold start")
    gguf = str(health["foundation_sec"].get("gguf_file") or "")
    if "q4_k_m" not in gguf.lower():
        raise DryrunError("cold_start", f"expected Q4_K_M gguf, got {gguf!r}")
    if int(health["foundation_sec"].get("n_ctx") or 0) != 4096:
        raise DryrunError("cold_start", f"expected n_ctx=4096, got {health['foundation_sec'].get('n_ctx')}")
    try:
        aresp = httpx.get(f"{ANTARES_URL}/health", timeout=5.0)
        if aresp.status_code == 200:
            health["antares"] = aresp.json()
    except Exception:  # noqa: BLE001
        pass
    return health


def _rule_ids_from_findings(findings: list[dict]) -> set[str]:
    ids: set[str] = set()
    for item in findings:
        trace = str(item.get("trace") or "")
        if trace.startswith("handler:"):
            ids.add(trace.split(":", 1)[1])
    return ids


def _finding_by_rule(findings: list[dict], rule_id: str) -> dict | None:
    for item in findings:
        if str(item.get("trace") or "") == f"handler:{rule_id}":
            return item
    return None


def _gate_block_breakdown(stage_timings_ms: dict[str, Any]) -> dict[str, int]:
    handler_ms = int(stage_timings_ms.get("handler_eval_ms") or 0)
    handler_ms += int(stage_timings_ms.get("foundation_sec_handler_ms") or 0)
    return {
        "model_load_ms": int(stage_timings_ms.get("foundation_sec_model_load_ms") or 0),
        "inference_ms": int(stage_timings_ms.get("foundation_sec_inference_ms") or 0),
        "handler_eval_ms": handler_ms,
    }


def _assert_gate_block(review: dict, gate: dict, phase: str) -> dict[str, Any]:
    rules = _rule_ids_from_findings(review.get("findings") or [])
    missing = EXPECTED_BLOCK_RULES_INITIAL - rules
    if missing:
        traces = [
            str(item.get("trace") or "")
            for item in (review.get("findings") or [])
            if item.get("trace")
        ]
        raise DryrunError(
            phase,
            f"missing expected rule findings: {sorted(missing)}; "
            f"got traces={traces or ['<none>']}",
        )
    if str(review.get("policy_decision", {}).get("pr_decision") or "") != "block":
        raise DryrunError(phase, f"expected pr_decision=block, got {review.get('policy_decision')}")
    if gate.get("allowed") is not False:
        raise DryrunError(phase, f"expected gate allowed=false, got {gate}")
    return {"rule_ids": sorted(rules), "gate": gate}


def _run_phase(
    name: str,
    timeout: float,
    fn: Callable[[], dict[str, Any] | None],
    results: list[PhaseResult],
) -> dict[str, Any] | None:
    started = time.monotonic()
    detail: dict[str, Any] | None = None
    mem = MemorySample()
    try:

        def wrapped() -> None:
            nonlocal detail
            detail = fn() or {}

        mem = _sample_peak_memory(wrapped)
        elapsed = time.monotonic() - started
        if elapsed > timeout:
            raise DryrunError(name, f"phase exceeded timeout ({elapsed:.1f}s > {timeout}s)")
        results.append(
            PhaseResult(
                name=name,
                passed=True,
                wall_seconds=round(elapsed, 3),
                memory=mem,
                detail=detail or {},
            )
        )
        print(f"  PASS {name} ({elapsed:.1f}s, peak RSS {mem.peak_rss_mib} MiB)", flush=True)
        return detail
    except Exception as exc:  # noqa: BLE001
        elapsed = time.monotonic() - started
        msg = str(exc)
        results.append(
            PhaseResult(
                name=name,
                passed=False,
                wall_seconds=round(elapsed, 3),
                memory=mem,
                error=msg,
            )
        )
        print(f"  FAIL {name}: {msg}", flush=True)
        if isinstance(exc, DryrunError):
            raise
        raise DryrunError(name, msg) from exc


def run_cold_start(phase_timeout: float) -> dict[str, Any]:
    phases: list[PhaseResult] = []
    print("\n=== Cold start ===", flush=True)

    def cold_start() -> dict[str, Any]:
        subprocess.run([str(SHIFT_LEFT), "down"], cwd=ROOT, check=False)
        _patch_config_q4_nctx()
        # `shift-left up` is skip-happy once bootstrap phases are complete.
        _start_running_stack()
        _unload_model_servers()
        health = _assert_models_unloaded()
        return {"health": health}

    # Compose + Forgejo + orchestrator wait dominates; keep the caller's timeout as a floor.
    cold_timeout = max(phase_timeout, 600.0)
    try:
        _run_phase("cold_start", cold_timeout, cold_start, phases)
    except DryrunError:
        pass
    return {
        "passed": all(p.passed for p in phases),
        "phases": [
            {
                "name": p.name,
                "passed": p.passed,
                "wall_seconds": p.wall_seconds,
                "peak_rss_mib": p.memory.peak_rss_mib,
                "swap_used_mib": p.memory.swap_used_mib,
                "server_pids": p.memory.server_pids,
                "detail": p.detail,
                "error": p.error,
            }
            for p in phases
        ],
    }


def run_warm_iteration(
    run_index: int,
    *,
    phase_timeout: float,
    skip_advisory: bool,
    cleanup: DryrunCleanup,
    review_token: str,
    approve_token: str,
) -> dict[str, Any]:
    phases: list[PhaseResult] = []
    owner = _read_bootstrap_secret("forgejo_admin_user") or os.environ.get("FORGEJO_DEFAULT_OWNER", "shift-left")
    repo_name = f"demo-dryrun-warm-{run_index}"
    forgejo_token = os.environ.get("FORGEJO_TOKEN") or _read_bootstrap_secret("forgejo_token")
    if not forgejo_token:
        raise DryrunError("setup", "FORGEJO_TOKEN not available")

    fj = ForgejoClient(FORGEJO_URL, forgejo_token)
    sl = ShiftLeftClient(ORCHESTRATOR_URL, review_token, approve_token)

    ctx: dict[str, Any] = {"owner": owner, "repo": repo_name}

    print(f"\n=== Warm run {run_index} ===", flush=True)

    def create_pr() -> dict[str, Any]:
        fj.ensure_repo(owner, repo_name)
        cleanup.register_repo(owner, repo_name)
        fj.upsert_file(owner, repo_name, "README.md", "# demo-dryrun\n", message="Init")
        branch = "dryrun/violations"
        fj.create_branch(owner, repo_name, branch)
        fj.upsert_file(
            owner,
            repo_name,
            "firewall/edge.rules",
            (FIXTURES / "edge.rules").read_text(encoding="utf-8"),
            branch=branch,
            message="Add ASA violations",
        )
        fj.upsert_file(
            owner,
            repo_name,
            "terraform/policies/insecure.tf",
            (FIXTURES / "insecure.tf").read_text(encoding="utf-8"),
            branch=branch,
            message="Add FMC violation",
        )
        fj.upsert_file(
            owner,
            repo_name,
            "misc/unclaimed.cfg",
            (FIXTURES / "unclaimed.cfg").read_text(encoding="utf-8"),
            branch=branch,
            message="Add unclaimed cfg",
        )
        commit_sha = fj.branch_sha(owner, repo_name, branch)
        pr = fj.open_pr(owner, repo_name, head=branch, title="demo-dryrun violations")
        pr_number = int(pr["number"])
        ctx.update({"pr_number": pr_number, "commit_sha": commit_sha})
        return {"pr_number": pr_number, "commit_sha": commit_sha}

    def gate_block_deterministic() -> dict[str, Any]:
        pr_number = int(ctx["pr_number"])
        commit_sha = str(ctx["commit_sha"])
        review = sl.review(owner, repo_name, pr_number, commit_sha, skip_advisory=True)
        gate = sl.gate(owner, repo_name, pr_number, commit_sha)
        detail = _assert_gate_block(review, gate, "gate_block_deterministic")
        detail["skip_advisory"] = True
        detail["stage_timings_ms"] = review.get("stage_timings_ms") or {}
        detail["breakdown_ms"] = _gate_block_breakdown(detail["stage_timings_ms"])
        ctx["initial_findings"] = review.get("findings") or []
        return detail

    def gate_block_advisory() -> dict[str, Any]:
        pr_number = int(ctx["pr_number"])
        commit_sha = str(ctx["commit_sha"])
        review = sl.review(owner, repo_name, pr_number, commit_sha, skip_advisory=False)
        gate = sl.gate(owner, repo_name, pr_number, commit_sha)
        stage_timings = review.get("stage_timings_ms") or {}
        breakdown = _gate_block_breakdown(stage_timings)
        detail = _assert_gate_block(review, gate, "gate_block_advisory")
        detail["skip_advisory"] = False
        detail["stage_timings_ms"] = stage_timings
        detail["breakdown_ms"] = breakdown
        return detail

    review_skip = skip_advisory

    def waiver_flow() -> dict[str, Any]:
        pr_number = int(ctx["pr_number"])
        commit_sha = str(ctx["commit_sha"])
        if not ctx.get("initial_findings"):
            sl.review(owner, repo_name, pr_number, commit_sha, skip_advisory=review_skip)
        findings = sl.findings(owner, repo_name, pr_number)
        asa007 = _finding_by_rule(findings, "ASA-007")
        if asa007 is None:
            raise DryrunError("waiver", "ASA-007 finding not found")
        waiver = sl.grant_waiver(
            owner,
            repo_name,
            pr_number,
            commit_sha=commit_sha,
            finding_id=str(asa007["id"]),
            reason="demo-dryrun: waive unparsed ACE for smoke test",
        )
        if waiver.get("rule_id") != "ASA-007":
            raise DryrunError("waiver", f"unexpected waiver rule_id {waiver.get('rule_id')}")
        gate = sl.gate(owner, repo_name, pr_number, commit_sha)
        decision = sl.policy_decision(owner, repo_name, pr_number, commit_sha)
        finding_by_id = {str(f.get("id")): f for f in findings}
        blocked_rules = set()
        for item in decision.get("finding_decisions") or []:
            if str(item.get("decision")) != "block":
                continue
            finding = finding_by_id.get(str(item.get("finding_id")))
            if not finding:
                continue
            trace = str(finding.get("trace") or "")
            if trace.startswith("handler:"):
                blocked_rules.add(trace.split(":", 1)[1])
        if "ASA-007" in blocked_rules:
            raise DryrunError("waiver", "ASA-007 still blocking after waiver")
        if "ASA-001" not in blocked_rules or "FTD-001" not in blocked_rules:
            raise DryrunError("waiver", f"expected ASA-001 and FTD-001 still blocking, got {blocked_rules}")
        asa007_visible = _finding_by_rule(findings, "ASA-007")
        if asa007_visible is None:
            raise DryrunError("waiver", "ASA-007 finding no longer visible after waiver")
        if gate.get("allowed") is not False:
            raise DryrunError("waiver", "gate should remain blocked while other violations persist")
        ctx["waiver_id"] = waiver.get("id")
        return {
            "waiver_id": waiver.get("id"),
            "effective_blocked_rules": sorted(blocked_rules),
            "gate_allowed": gate.get("allowed"),
        }

    def sha_invalidate() -> dict[str, Any]:
        pr_number = int(ctx["pr_number"])
        old_sha = str(ctx["commit_sha"])
        branch = "dryrun/violations"
        content = (FIXTURES / "edge.rules").read_text(encoding="utf-8") + "\n! amended for SHA invalidation\n"
        new_sha = fj.upsert_file(
            owner,
            repo_name,
            "firewall/edge.rules",
            content,
            branch=branch,
            message="Amend ASA policy (invalidate waiver)",
        )
        sl.review(owner, repo_name, pr_number, new_sha, skip_advisory=review_skip)
        decision = sl.policy_decision(owner, repo_name, pr_number, new_sha)
        findings = sl.findings(owner, repo_name, pr_number)
        finding_by_id = {str(f.get("id")): f for f in findings}
        blocked_rules = set()
        for item in decision.get("finding_decisions") or []:
            if str(item.get("decision")) != "block":
                continue
            finding = finding_by_id.get(str(item.get("finding_id")))
            if not finding:
                continue
            trace = str(finding.get("trace") or "")
            if trace.startswith("handler:"):
                blocked_rules.add(trace.split(":", 1)[1])
        if "ASA-007" not in blocked_rules:
            raise DryrunError("sha_invalidate", "ASA-007 should block again after new commit (waiver expired)")
        ctx["commit_sha"] = new_sha
        return {"old_sha": old_sha, "new_sha": new_sha, "blocked_rules": sorted(blocked_rules)}

    def unclaimed_cfg() -> dict[str, Any]:
        pr_number = int(ctx["pr_number"])
        commit_sha = str(ctx["commit_sha"])
        branch = "dryrun/violations"
        new_sha = fj.upsert_file(
            owner,
            repo_name,
            "misc/unclaimed.cfg",
            (FIXTURES / "unclaimed.cfg").read_text(encoding="utf-8")
            + "\n! touched to confirm CWE-657 still gates\n",
            branch=branch,
            message="Touch unclaimed cfg",
        )
        review = sl.review(owner, repo_name, pr_number, new_sha, skip_advisory=review_skip)
        findings = review.get("findings") or []
        cwe657 = [
            f
            for f in findings
            if str(f.get("file_path") or "").endswith("unclaimed.cfg")
            and (
                str(f.get("handler_asserted_cwe") or f.get("cwe") or "") == "CWE-657"
                or str(f.get("trace") or "") == "handler:unclaimed-file"
            )
        ]
        if not cwe657:
            summary = [
                {
                    "path": item.get("file_path"),
                    "trace": item.get("trace"),
                    "handler_cwe": item.get("handler_asserted_cwe"),
                }
                for item in findings
            ]
            raise DryrunError(
                "unclaimed_cfg",
                f"no CWE-657 unclaimed finding on misc/unclaimed.cfg; "
                f"review findings={summary or ['<none>']}",
            )
        gate = sl.gate(owner, repo_name, pr_number, new_sha)
        if gate.get("allowed") is not False:
            raise DryrunError("unclaimed_cfg", "gate must block on unclaimed .cfg")
        ctx["commit_sha"] = new_sha
        return {"cwe657_count": len(cwe657), "gate": gate}

    try:
        _run_phase("create_pr", phase_timeout, create_pr, phases)
        _run_phase("gate_block_deterministic", phase_timeout, gate_block_deterministic, phases)
        _run_phase("gate_block_advisory", phase_timeout, gate_block_advisory, phases)
        _run_phase("waiver", phase_timeout, waiver_flow, phases)
        _run_phase("sha_invalidate", phase_timeout, sha_invalidate, phases)
        _run_phase("unclaimed_cfg", phase_timeout, unclaimed_cfg, phases)
    except DryrunError:
        pass

    return {
        "run_index": run_index,
        "passed": all(p.passed for p in phases),
        "phases": [
            {
                "name": p.name,
                "passed": p.passed,
                "wall_seconds": p.wall_seconds,
                "peak_rss_mib": p.memory.peak_rss_mib,
                "swap_used_mib": p.memory.swap_used_mib,
                "server_pids": p.memory.server_pids,
                "detail": p.detail,
                "error": p.error,
            }
            for p in phases
        ],
    }


def _phase_stats(runs: list[dict[str, Any]], phase_names: list[str]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for name in phase_names:
        times = [
            p["wall_seconds"]
            for run in runs
            for p in run.get("phases", [])
            if p["name"] == name and p["passed"] and p["wall_seconds"] > 0
        ]
        rss = [
            p["peak_rss_mib"]
            for run in runs
            for p in run.get("phases", [])
            if p["name"] == name and p["passed"]
        ]
        swap = [
            p["swap_used_mib"]
            for run in runs
            for p in run.get("phases", [])
            if p["name"] == name and p["passed"]
        ]
        if not times:
            skipped = [
                p
                for run in runs
                for p in run.get("phases", [])
                if p["name"] == name and p.get("detail", {}).get("skipped")
            ]
            if skipped:
                summary[name] = {"skipped": True, "reason": skipped[0]["detail"].get("reason")}
            continue
        entry: dict[str, Any] = {
            "wall_seconds": {
                "mean": round(statistics.mean(times), 3),
                "stdev": round(statistics.pstdev(times), 3) if len(times) > 1 else 0.0,
                "min": round(min(times), 3),
                "max": round(max(times), 3),
                "samples": times,
            },
            "peak_rss_mib": {
                "mean": round(statistics.mean(rss), 2),
                "max": round(max(rss), 2),
                "samples": rss,
            },
            "swap_used_mib": {
                "mean": round(statistics.mean(swap), 2),
                "max": round(max(swap), 2),
                "samples": swap,
            },
        }
        if name in {"gate_block_deterministic", "gate_block_advisory"}:
            breakdowns = [
                p.get("detail", {}).get("breakdown_ms", {})
                for run in runs
                for p in run.get("phases", [])
                if p["name"] == name and p["passed"] and not p.get("detail", {}).get("skipped")
            ]
            if breakdowns:
                for key in ("model_load_ms", "inference_ms", "handler_eval_ms"):
                    samples = [int(item.get(key) or 0) for item in breakdowns]
                    entry[f"{key}"] = {
                        "mean": round(statistics.mean(samples), 1),
                        "stdev": round(statistics.pstdev(samples), 1) if len(samples) > 1 else 0.0,
                        "min": min(samples),
                        "max": max(samples),
                        "samples": samples,
                    }
        summary[name] = entry
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cold-runs", type=int, default=DEFAULT_COLD_RUNS)
    parser.add_argument("--warm-runs", type=int, default=DEFAULT_WARM_RUNS)
    parser.add_argument("--phase-timeout", type=float, default=DEFAULT_PHASE_TIMEOUT)
    parser.add_argument(
        "--skip-advisory",
        action="store_true",
        default=SKIP_ADVISORY,
        help="Skip model invocation for workflow reviews; still measures deterministic gate_block",
    )
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    cleanup = DryrunCleanup()
    cold_runs: list[dict[str, Any]] = []
    warm_runs: list[dict[str, Any]] = []
    failed = False
    interrupted = False
    cleanup_report: dict[str, Any] = {"actions": [], "errors": [], "passed": True}

    try:
        for idx in range(1, args.cold_runs + 1):
            try:
                result = run_cold_start(args.phase_timeout)
            except DryrunError as exc:
                failed = True
                cold_runs.append({"run_index": idx, "passed": False, "error": str(exc), "phases": []})
                print(f"\nCold start {idx} aborted: {exc}", flush=True)
                break
            cold_runs.append(result)
            if not result.get("passed"):
                failed = True
                print(f"\nCold start {idx} aborted", flush=True)
                break

        review_token = ""
        approve_token = ""
        if not failed and args.warm_runs > 0:
            review_token = _mint_token("review", "demo-dryrun-review")
            approve_token = _mint_token("review,approve", "demo-dryrun-approve")

        if not failed:
            for idx in range(1, args.warm_runs + 1):
                try:
                    result = run_warm_iteration(
                        idx,
                        phase_timeout=args.phase_timeout,
                        skip_advisory=args.skip_advisory,
                        cleanup=cleanup,
                        review_token=review_token,
                        approve_token=approve_token,
                    )
                except DryrunError as exc:
                    failed = True
                    warm_runs.append(
                        {
                            "run_index": idx,
                            "passed": False,
                            "error": str(exc),
                            "phases": [],
                        }
                    )
                    print(f"\nWarm run {idx} aborted: {exc}", flush=True)
                    break
                warm_runs.append(result)
                if not result.get("passed"):
                    failed = True
                    print(f"\nWarm run {idx} aborted", flush=True)
                    break
    except KeyboardInterrupt:
        interrupted = True
        failed = True
        print("\nInterrupted — running cleanup", flush=True)
    finally:
        print("\n=== Cleanup (always runs) ===", flush=True)
        cleanup_report = cleanup.execute()
        for action in cleanup_report.get("actions") or []:
            print(f"  {action}", flush=True)
        for err in cleanup_report.get("errors") or []:
            print(f"  CLEANUP ERROR: {err}", flush=True)

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "task": "demo_dryrun_smoke",
        "cold_runs_requested": args.cold_runs,
        "warm_runs_requested": args.warm_runs,
        "skip_advisory": args.skip_advisory,
        "phase_timeout_sec": args.phase_timeout,
        "interrupted": interrupted,
        "cold_runs": cold_runs,
        "warm_runs": warm_runs,
        "cold_summary": _phase_stats(cold_runs, ["cold_start"]),
        "warm_summary": _phase_stats(warm_runs, WARM_PHASE_NAMES),
        "cleanup": cleanup_report,
        "all_passed": (
            not failed
            and not interrupted
            and all(r.get("passed") for r in cold_runs)
            and all(r.get("passed") for r in warm_runs)
            and cleanup_report.get("passed", False)
        ),
    }
    out = args.output or REPORTS / f"demo-dryrun-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n=== demo-dryrun summary ===", flush=True)
    print("Cold:", flush=True)
    for name, stats in report["cold_summary"].items():
        if stats.get("skipped"):
            print(f"  {name}: skipped ({stats.get('reason')})", flush=True)
            continue
        ws = stats["wall_seconds"]
        print(
            f"  {name}: mean={ws['mean']}s stdev={ws['stdev']}s "
            f"peak_rss_mean={stats['peak_rss_mib']['mean']} MiB",
            flush=True,
        )
    print("Warm:", flush=True)
    for name, stats in report["warm_summary"].items():
        if stats.get("skipped"):
            print(f"  {name}: skipped ({stats.get('reason')})", flush=True)
            continue
        ws = stats["wall_seconds"]
        line = (
            f"  {name}: mean={ws['mean']}s stdev={ws['stdev']}s "
            f"peak_rss_mean={stats['peak_rss_mib']['mean']} MiB "
            f"swap_max={stats['swap_used_mib']['max']} MiB"
        )
        if name == "gate_block_advisory" and "model_load_ms" in stats:
            line += (
                f" load_mean={stats['model_load_ms']['mean']}ms"
                f" infer_mean={stats['inference_ms']['mean']}ms"
                f" handler_mean={stats['handler_eval_ms']['mean']}ms"
            )
        print(line, flush=True)
    print(f"\nWrote {out.resolve().relative_to(ROOT.resolve())}", flush=True)
    return 1 if not report["all_passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
