"""Local operator state for idempotent ./shift-left up."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATE_DIR_NAME = ".shift-left"
STATE_FILE = "state.json"
SUPERVISOR_FILE = "supervisor.json"
CREDENTIALS_FILE = "credentials-once.json"


def state_dir(root: Path) -> Path:
    return root / STATE_DIR_NAME


def load_state(root: Path) -> dict[str, Any]:
    path = state_dir(root) / STATE_FILE
    if not path.exists():
        return {"version": 1, "completed_phases": {}, "platform": {}}
    return json.loads(path.read_text())


def save_state(root: Path, state: dict[str, Any]) -> None:
    directory = state_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    (directory / STATE_FILE).write_text(json.dumps(state, indent=2) + "\n")


def mark_phase(root: Path, phase: str, *, detail: dict[str, Any] | None = None) -> None:
    state = load_state(root)
    completed = state.setdefault("completed_phases", {})
    completed[phase] = {"at": datetime.now(timezone.utc).isoformat(), **(detail or {})}
    save_state(root, state)


def phase_complete(root: Path, phase: str) -> bool:
    return phase in load_state(root).get("completed_phases", {})


def clear_state(root: Path) -> None:
    directory = state_dir(root)
    for name in (STATE_FILE, SUPERVISOR_FILE, CREDENTIALS_FILE):
        path = directory / name
        if path.exists():
            path.unlink()


@dataclass
class SupervisorRecord:
    service: str
    pid: int
    log_path: str
    venv_path: str
    restart_count: int = 0


@dataclass
class SupervisorState:
    processes: dict[str, SupervisorRecord] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "processes": {
                name: {
                    "pid": rec.pid,
                    "log_path": rec.log_path,
                    "venv_path": rec.venv_path,
                    "restart_count": rec.restart_count,
                }
                for name, rec in self.processes.items()
            }
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> SupervisorState:
        processes = {}
        for name, item in (payload.get("processes") or {}).items():
            processes[name] = SupervisorRecord(
                service=name,
                pid=int(item["pid"]),
                log_path=str(item["log_path"]),
                venv_path=str(item.get("venv_path", "")),
                restart_count=int(item.get("restart_count", 0)),
            )
        return cls(processes=processes)


def load_supervisor(root: Path) -> SupervisorState:
    path = state_dir(root) / SUPERVISOR_FILE
    if not path.exists():
        return SupervisorState()
    return SupervisorState.from_dict(json.loads(path.read_text()))


def save_supervisor(root: Path, state: SupervisorState) -> None:
    directory = state_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / SUPERVISOR_FILE).write_text(json.dumps(state.to_dict(), indent=2) + "\n")


def credentials_shown(root: Path) -> bool:
    return (state_dir(root) / CREDENTIALS_FILE).exists()


def mark_credentials_shown(root: Path, payload: dict[str, Any]) -> None:
    directory = state_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / CREDENTIALS_FILE).write_text(json.dumps(payload, indent=2) + "\n")
