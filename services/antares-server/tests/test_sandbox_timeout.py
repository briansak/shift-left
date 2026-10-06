"""Sandbox timeout behavior."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from antares_server.docker_sandbox import DockerInvestigationSandbox


def test_docker_execute_surfaces_subprocess_timeout(tmp_path: Path) -> None:
    sandbox = DockerInvestigationSandbox(
        tmp_path,
        investigation_id="test-timeout-unit",
        image="shift-left-antares-sandbox:bookworm",
    )
    sandbox._container_id = "fake-container"
    with patch(
        "antares_server.docker_sandbox.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="docker exec", timeout=0.05),
    ):
        result = sandbox.execute("echo ok")
    assert result.exit_code == 124
    assert "timed out" in result.output.lower()
