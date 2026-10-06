"""./shift-left reset — destructive local wipe."""

from __future__ import annotations

import shutil
from pathlib import Path

from shift_left_cli.state import clear_state, state_dir


def operator_reset(root: Path, *, confirmation: str) -> None:
    expected = "DESTROY SHIFT-LEFT LOCAL STATE"
    if confirmation.strip() != expected:
        raise SystemExit(f"Type exactly: {expected}")

    for relative in (".shift-left", "data/postgres", "data/forgejo", "data/forgejo-runner", "data/findings"):
        path = root / relative
        if path.exists():
            shutil.rmtree(path) if path.is_dir() else path.unlink()

    clear_state(root)
    print("Local Shift-Left state destroyed. Run ./shift-left up for a fresh install.")
