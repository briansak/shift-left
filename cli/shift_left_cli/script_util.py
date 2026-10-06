"""Run repo shell scripts without requiring the executable bit."""

from __future__ import annotations

import subprocess
from pathlib import Path


def run_bash_script(root: Path, script: Path, *, env: dict[str, str] | None = None) -> None:
    if not script.is_file():
        raise FileNotFoundError(script)
    subprocess.check_call(["/bin/bash", str(script)], cwd=root, env=env)


def run_bash_script_capture(
    root: Path,
    script: Path,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    if not script.is_file():
        raise FileNotFoundError(script)
    return subprocess.run(
        ["/bin/bash", str(script)],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
