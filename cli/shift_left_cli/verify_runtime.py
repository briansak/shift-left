"""Verify runtime sovereignty: full code + config review with egress disabled."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def verify_runtime_sovereignty(root: Path, *, real_inference: bool = False) -> None:
    if real_inference:
        script = root / "scripts" / "verify-runtime-real-inference.py"
        if not script.exists():
            raise FileNotFoundError(script)
        venv_python = root / ".venv" / "bin" / "python"
        python = str(venv_python) if venv_python.is_file() else sys.executable
        print(
            "Running runtime sovereignty verification "
            "(real Antares + Foundation-Sec on loopback, egress blocked)..."
        )
        env = os.environ.copy()
        env.setdefault("SHIFT_LEFT_SKIP_EGRESS_PROBE", "1")
        result = subprocess.call([python, str(script)], cwd=root, env=env)
        if result != 0:
            raise SystemExit(result)
        print("Runtime sovereignty verification with real inference passed.")
        return

    script = root / "scripts" / "test-runtime-sovereignty.sh"
    if not script.exists():
        raise FileNotFoundError(script)
    print("Running runtime sovereignty verification (mocked inference, egress blocked)...")
    result = subprocess.call([str(script)], cwd=root)
    if result != 0:
        raise SystemExit(result)
    print("Runtime sovereignty verification passed.")
