"""Sandbox security tests for Antares triage."""

from __future__ import annotations

from pathlib import Path

from antares_server.sandbox import ReadOnlySandbox


def test_sandbox_refuses_write_attempt(tmp_path: Path) -> None:
    sandbox = ReadOnlySandbox(tmp_path, investigation_id="test-inv")
    result = sandbox.execute("touch blocked.txt")
    assert result.exit_code == 1
    assert "blocked" in result.output.lower()


def test_sandbox_refuses_network_attempt(tmp_path: Path) -> None:
    sandbox = ReadOnlySandbox(tmp_path, investigation_id="test-inv")
    result = sandbox.execute("curl http://127.0.0.1")
    assert result.exit_code == 1


def test_sandbox_refuses_execute_repository_code(tmp_path: Path) -> None:
    script = tmp_path / "run.sh"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    script.chmod(0o755)
    sandbox = ReadOnlySandbox(tmp_path, investigation_id="test-inv")
    result = sandbox.execute("./run.sh")
    assert result.exit_code == 1


def test_command_output_replaces_invalid_utf8(tmp_path: Path) -> None:
    (tmp_path / "binary.bin").write_bytes(b"before\x85after")
    sandbox = ReadOnlySandbox(tmp_path, investigation_id="test-invalid-utf8")
    result = sandbox.execute("cat binary.bin")
    assert result.exit_code == 0
    assert result.output == "before\ufffdafter"


def test_submit_no_vulnerability_not_marked_failed() -> None:
    from antares_server.agent_loop import QUERY_COMPLETED_NO_FILES

    assert QUERY_COMPLETED_NO_FILES != "failed"
