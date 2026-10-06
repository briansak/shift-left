"""Docker investigation sandbox integration tests."""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from antares_server.agent_loop import run_agent_query, ScriptedTextGenerator
from antares_server.docker_sandbox import (
    DockerInvestigationSandbox,
    destroy_investigation_container,
    docker_available,
    investigation_container_exists,
)
from antares_server.sandbox import ReadOnlySandbox, new_investigation_id
from antares_server.sandbox_audit import CollectedAuditSink

SANDBOX_IMAGE = os.environ.get("ANTARES_SANDBOX_IMAGE", "shift-left-antares-sandbox:bookworm")
FIXTURES = Path(__file__).parent / "fixtures"


pytestmark = pytest.mark.skipif(not docker_available(), reason="Docker daemon not available")


def _image_ready() -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", SANDBOX_IMAGE],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


@pytest.fixture
def docker_root() -> Path:
    """Workspace in the repo tree so Docker Desktop can bind-mount on macOS."""
    base = Path(__file__).resolve().parent / ".docker-workspace"
    base.mkdir(parents=True, exist_ok=True)
    root = base / f"case-{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)
    yield root
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture(scope="module", autouse=True)
def ensure_sandbox_image() -> None:
    if _image_ready():
        return
    repo_root = Path(__file__).resolve().parents[3]
    dockerfile = repo_root / "services" / "antares-server" / "Dockerfile.sandbox"
    build = subprocess.run(
        ["docker", "build", "-f", str(dockerfile), "-t", SANDBOX_IMAGE, str(repo_root)],
        capture_output=True,
        text=True,
        check=False,
    )
    if build.returncode != 0:
        pytest.skip(f"Could not build sandbox image: {build.stderr or build.stdout}")


def test_container_network_is_none(docker_root: Path) -> None:
    inv_id = new_investigation_id("test-net")
    sandbox = DockerInvestigationSandbox(docker_root, investigation_id=inv_id, image=SANDBOX_IMAGE)
    sandbox.start()
    try:
        inspect = subprocess.run(
            ["docker", "inspect", inv_id, "--format", "{{.HostConfig.NetworkMode}}"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert inspect.stdout.strip() == "none"
    finally:
        sandbox.destroy()


def test_command_timeout_kills_exec(docker_root: Path) -> None:
    inv_id = new_investigation_id("test-timeout")
    (docker_root / "big.txt").write_text("line\n" * 8_000_000, encoding="utf-8")
    sandbox = DockerInvestigationSandbox(
        docker_root,
        investigation_id=inv_id,
        image=SANDBOX_IMAGE,
        command_timeout_seconds=0.05,
    )
    sandbox.start()
    try:
        result = sandbox.execute("grep line big.txt")
        assert result.exit_code == 124
        assert "timed out" in result.output.lower()
    finally:
        sandbox.destroy()


def test_command_output_replaces_invalid_utf8(docker_root: Path) -> None:
    inv_id = new_investigation_id("test-invalid-utf8")
    (docker_root / "binary.bin").write_bytes(b"before\x85after")
    sandbox = DockerInvestigationSandbox(
        docker_root,
        investigation_id=inv_id,
        image=SANDBOX_IMAGE,
    )
    sandbox.start()
    try:
        result = sandbox.execute("cat binary.bin")
        assert result.exit_code == 0
        assert result.output == "before\ufffdafter"
    finally:
        sandbox.destroy()


def test_memory_limit_configured(docker_root: Path) -> None:
    inv_id = new_investigation_id("test-mem")
    sandbox = DockerInvestigationSandbox(
        docker_root,
        investigation_id=inv_id,
        image=SANDBOX_IMAGE,
        memory="4g",
    )
    sandbox.start()
    try:
        inspect = subprocess.run(
            ["docker", "inspect", inv_id, "--format", "{{.HostConfig.Memory}}"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert int(inspect.stdout.strip()) == 4 * 1024 * 1024 * 1024
    finally:
        sandbox.destroy()


def test_cancel_api_removes_container_via_docker_query(docker_root: Path) -> None:
    """Cancel path force-removes the sandbox container; verify with Docker CLI, not inference."""
    from antares_server.cancellation_registry import register, request_cancel

    inv_id = new_investigation_id("test-cancel-api")
    sandbox = DockerInvestigationSandbox(docker_root, investigation_id=inv_id, image=SANDBOX_IMAGE)
    sandbox.start()
    assert investigation_container_exists(inv_id)

    register(inv_id)
    request_cancel(inv_id)
    destroy_investigation_container(inv_id)

    assert not investigation_container_exists(inv_id)
    inspect = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{inv_id}$", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert inspect.stdout.strip() == ""


def test_cancel_removes_container_during_slow_exec(docker_root: Path) -> None:
    """Container is removed on cancel even if a docker exec is in flight (host timeout bounded)."""
    import threading
    import time

    from antares_server.cancellation_registry import register, request_cancel
    from antares_server.docker_sandbox import destroy_investigation_container

    inv_id = new_investigation_id("test-cancel-exec")
    sandbox = DockerInvestigationSandbox(
        docker_root,
        investigation_id=inv_id,
        image=SANDBOX_IMAGE,
        command_timeout_seconds=30.0,
    )
    sandbox.start()
    register(inv_id)
    assert investigation_container_exists(inv_id)

    def slow_exec() -> None:
        sandbox.execute("sleep 60")

    worker = threading.Thread(target=slow_exec)
    worker.start()
    time.sleep(0.5)
    request_cancel(inv_id)
    destroy_investigation_container(inv_id)
    worker.join(timeout=5)

    assert not investigation_container_exists(inv_id)
    ps = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{inv_id}$", "--format", "{{.ID}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert ps.stdout.strip() == ""


def test_container_removed_after_failure(docker_root: Path) -> None:
    inv_id = new_investigation_id("test-rm")
    sandbox = DockerInvestigationSandbox(docker_root, investigation_id=inv_id, image=SANDBOX_IMAGE)
    sandbox.start()
    container_id = sandbox._container_id
    assert container_id
    sandbox.destroy()
    inspect = subprocess.run(
        ["docker", "inspect", container_id],
        capture_output=True,
        text=True,
        check=False,
    )
    assert inspect.returncode != 0


def test_injection_fixture_does_not_hijack_agent_loop(
    docker_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTARES_ENGINE", "scripted")
    monkeypatch.setenv("ANTARES_SANDBOX", "docker")

    repo = docker_root / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text(
        'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        encoding="utf-8",
    )
    injection = FIXTURES / "protocol_injection.txt"
    (repo / "app" / "injection.txt").write_text(injection.read_text(encoding="utf-8"), encoding="utf-8")

    class InjectionScripted(ScriptedTextGenerator):
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            self._turn += 1
            if self._turn == 1:
                return (
                    '<tool_call> {"name": "terminal", "arguments": {"command": "cat app/injection.txt"}} '
                    "</tool_call>"
                )
            return super().generate(prompt, temperature=temperature, top_p=top_p)

    generator = InjectionScripted(
        ReadOnlySandbox(repo, investigation_id=new_investigation_id()),
        task_cwe="CWE-89",
    )
    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=generator,
        max_terminal_calls=5,
    )
    assert result.outcome == "completed_with_files"
    assert result.ranked_files == ["app/db.py"]
    first_tool_response = result.exploration_trace.split("<tool_response>", 1)[1].split(
        "</tool_response>", 1
    )[0]
    assert "[quarantined:submit_vulnerable_files]" in first_tool_response
    assert "<tool_call>" not in first_tool_response
    assert result.sandbox_audit
    assert any(entry["command"] == "cat app/injection.txt" for entry in result.sandbox_audit)
