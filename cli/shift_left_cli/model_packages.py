"""Ensure host-native model server packages are installed in the repo .venv."""

from __future__ import annotations

import subprocess
from pathlib import Path


def _venv_python(root: Path) -> Path:
    py = root / ".venv" / "bin" / "python3"
    if not py.is_file():
        raise SystemExit("Missing .venv — run ./shift-left up from the repo root first.")
    return py


def ensure_foundation_sec_server_package(root: Path) -> None:
    py = _venv_python(root)
    check = subprocess.run(
        [str(py), "-c", "import foundation_sec_server"],
        cwd=root,
        capture_output=True,
    )
    if check.returncode == 0:
        return
    print("Installing foundation-sec-server into .venv (first run; may take a few minutes)…")
    subprocess.check_call(
        [
            str(py),
            "-m",
            "pip",
            "install",
            "-e",
            str(root / "services" / "shift-left-shared"),
            "-e",
            str(root / "services" / "foundation-sec-server"),
        ],
        cwd=root,
    )


def ensure_antares_server_package(root: Path) -> None:
    py = _venv_python(root)
    check = subprocess.run(
        [str(py), "-c", "import torch, antares_server"],
        cwd=root,
        capture_output=True,
    )
    if check.returncode == 0:
        return
    print(
        "Installing antares-server into .venv (includes PyTorch; first run may take several minutes)…"
    )
    subprocess.check_call(
        [
            str(py),
            "-m",
            "pip",
            "install",
            "-e",
            str(root / "services" / "shift-left-shared"),
            "-e",
            str(root / "services" / "antares-server"),
        ],
        cwd=root,
    )
