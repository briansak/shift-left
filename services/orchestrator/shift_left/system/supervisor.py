"""Supervised host-native model server processes (CLI-owned PIDs)."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

MAX_RESTARTS = 3


def state_dir(root: Path) -> Path:
    env = os.environ.get("SHIFT_LEFT_STATE_DIR", ".shift-left")
    path = Path(env)
    return path if path.is_absolute() else root / path


def supervisor_path(root: Path) -> Path:
    return state_dir(root) / "supervisor.json"


def load_supervisor(root: Path) -> dict[str, Any]:
    path = supervisor_path(root)
    if not path.exists():
        return {"processes": {}}
    return json.loads(path.read_text())


def save_supervisor(root: Path, payload: dict[str, Any]) -> None:
    directory = state_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    supervisor_path(root).write_text(json.dumps(payload, indent=2) + "\n")


def supervisor_active(root: Path) -> bool:
    return supervisor_path(root).exists()


def _python(root: Path) -> Path:
    resolved_root = root.resolve()
    for name in ("python3", "python"):
        venv_py = resolved_root / ".venv" / "bin" / name
        if venv_py.is_file():
            return venv_py
    return Path(sys.executable)


def _resolve_antares_weights_dir(root: Path, antares_cfg: dict) -> Path:
    from shift_left.system.model_paths import resolve_antares_weights_dir

    return resolve_antares_weights_dir(root, antares_cfg)


def _apply_antares_model_env(root: Path, env: dict[str, str]) -> None:
    """Point host-native antares-server at staged weights under the repo."""
    import yaml

    config_path = root / "config" / "shift-left.yaml"
    antares: dict = {}
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text()) or {}
        antares = (raw.get("models") or {}).get("antares") or {}

    weights_dir = _resolve_antares_weights_dir(root, antares)
    env["ANTARES_MODEL_PATH"] = str(weights_dir)
    env.setdefault("ANTARES_BACKEND", str(antares.get("backend") or "auto"))
    env.setdefault("ANTARES_LOAD_STRATEGY", str(antares.get("load_strategy") or "on_demand"))
    env["SHIFT_LEFT_REPO_ROOT"] = str(root.resolve())
    env.setdefault(
        "ANTARES_SNAPSHOT_DIR",
        str((root / "data" / "findings" / "antares-snapshots").resolve()),
    )


def _apply_foundation_sec_model_env(root: Path, env: dict[str, str]) -> None:
    """Point host-native foundation-sec-server at staged GGUF weights under the repo."""
    import yaml

    config_path = root / "config" / "shift-left.yaml"
    fs: dict = {}
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text()) or {}
        fs = (raw.get("models") or {}).get("foundation_sec") or {}

    model_variant = str(fs.get("model_variant") or "instruct").strip().lower()
    env["FOUNDATION_SEC_MODEL_VARIANT"] = model_variant
    if model_variant == "reasoning":
        rel = fs.get("local_path_reasoning", "models/foundation-sec-reasoning-q4_k_m")
        env["FOUNDATION_SEC_LOW_MEMORY"] = "false"
        env["FOUNDATION_SEC_GGUF_GLOB"] = str(
            fs.get("gguf_glob_reasoning", "foundation-sec-8b-reasoning-q4_k_m.gguf")
        )
        env["FOUNDATION_SEC_QUANT_LABEL"] = str(
            fs.get("quant_label_reasoning", "reasoning-q4_k_m")
        )
        env["FOUNDATION_SEC_PREWARM_MANIFEST_KEY"] = "foundation-sec-reasoning"
        env["FOUNDATION_SEC_N_CTX"] = str(fs.get("max_context_tokens_reasoning", 16384))
        env["FOUNDATION_SEC_MAX_OUTPUT_TOKENS"] = str(
            fs.get("max_output_tokens_reasoning", 8192)
        )
    else:
        use_low = bool(fs.get("use_low_memory"))
        if use_low:
            rel = fs.get("local_path_low_memory", "models/foundation-sec-q4_k_m")
            env["FOUNDATION_SEC_LOW_MEMORY"] = "true"
            env["FOUNDATION_SEC_GGUF_GLOB"] = str(
                fs.get("gguf_glob_low_memory") or "foundation-sec-1.1-8b-instruct-q4_k_m.gguf"
            )
            env["FOUNDATION_SEC_QUANT_LABEL"] = str(fs.get("quant_label_low_memory") or "low-memory")
        else:
            rel = fs.get("local_path", "models/foundation-sec-q8_0")
            env["FOUNDATION_SEC_LOW_MEMORY"] = "false"
            env["FOUNDATION_SEC_GGUF_GLOB"] = str(
                fs.get("gguf_glob") or "foundation-sec-1.1-8b-instruct-q8_0.gguf"
            )
            env["FOUNDATION_SEC_QUANT_LABEL"] = str(fs.get("quant_label") or "default")
        env["FOUNDATION_SEC_N_CTX"] = str(fs.get("max_context_tokens", 8192))
        env.setdefault("FOUNDATION_SEC_LOAD_STRATEGY", str(fs.get("load_strategy") or "on_demand"))
    env["FOUNDATION_SEC_MODEL_PATH"] = str((root / rel).resolve())
    env["SHIFT_LEFT_REPO_ROOT"] = str(root.resolve())


def _service_spec(root: Path, service: str) -> tuple[Path, str, Path]:
    logs = state_dir(root) / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    if service == "foundation-sec-server":
        return root / "services" / "foundation-sec-server", "foundation_sec_server.main", logs / "foundation-sec-server.log"
    if service == "antares-server":
        return root / "services" / "antares-server", "antares_server.main", logs / "antares-server.log"
    raise ValueError(f"Unknown supervised service: {service}")


def _load_dotenv_into(root: Path, env: dict[str, str]) -> None:
    path = root / ".env"
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env.setdefault(key.strip(), value.strip())


def start_service(root: Path, service: str) -> dict[str, Any]:
    work, module, log_path = _service_spec(root, service)
    py = _python(root)
    env = os.environ.copy()
    _load_dotenv_into(root.resolve(), env)
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(root / "services" / "foundation-sec-server"),
            str(root / "services" / "antares-server"),
            str(root / "services" / "shift-left-shared"),
            str(root / "services" / "orchestrator"),
            env.get("PYTHONPATH", ""),
        ]
    )
    if service == "foundation-sec-server":
        env.setdefault("FOUNDATION_SEC_BIND_HOST", "127.0.0.1")
        _apply_foundation_sec_model_env(root, env)
    if service == "antares-server":
        env.setdefault("ANTARES_BIND_HOST", "127.0.0.1")
        _apply_antares_model_env(root, env)
    log_handle = open(log_path, "a", encoding="utf-8")  # noqa: SIM115
    proc = subprocess.Popen(
        [str(py), "-m", module],
        cwd=work,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    time.sleep(0.5)
    payload = load_supervisor(root)
    payload.setdefault("processes", {})[service] = {
        "pid": proc.pid,
        "log_path": str(log_path),
        "restart_count": 0,
    }
    save_supervisor(root, payload)
    return {"pid": proc.pid, "log_path": str(log_path)}


def stop_service(root: Path, service: str) -> None:
    payload = load_supervisor(root)
    entry = payload.get("processes", {}).pop(service, None)
    save_supervisor(root, payload)
    if not entry:
        return
    pid = int(entry["pid"])
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass


def restart_service(root: Path, service: str) -> dict[str, Any]:
    stop_service(root, service)
    return start_service(root, service)


def is_running(root: Path, service: str) -> bool:
    entry = load_supervisor(root).get("processes", {}).get(service)
    if not entry:
        return False
    pid = int(entry["pid"])
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
