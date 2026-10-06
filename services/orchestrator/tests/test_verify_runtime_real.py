"""Verify-runtime must not run with egress probe skipped."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def test_verify_runtime_real_rejects_skipped_egress_probe() -> None:
    script = ROOT / "scripts" / "verify-runtime-real-inference.py"
    python = ROOT / ".venv" / "bin" / "python"
    if not python.is_file():
        pytest.skip("project .venv not present")
    env = os.environ.copy()
    env["SHIFT_LEFT_SKIP_EGRESS_PROBE"] = "1"
    result = subprocess.run(
        [str(python), str(script)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "SHIFT_LEFT_SKIP_EGRESS_PROBE" in result.stdout + result.stderr
