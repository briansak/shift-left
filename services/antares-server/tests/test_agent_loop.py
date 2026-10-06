"""Antares agent loop and sandbox tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from antares_server.agent_engine import AgentQueryEngine, materialize_snapshot
from antares_server.agent_loop import run_agent_query, ScriptedTextGenerator
from antares_server.sandbox import ReadOnlySandbox


@pytest.fixture(autouse=True)
def scripted_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTARES_ENGINE", "scripted")
    monkeypatch.setenv("ANTARES_SANDBOX", "subprocess")


def test_sandbox_blocks_destructive_commands(tmp_path: Path) -> None:
    sandbox = ReadOnlySandbox(tmp_path)
    result = sandbox.execute("rm -rf .")
    assert result.exit_code == 1
    assert "blocked" in result.output.lower()


def test_materialize_snapshot_rejects_oversize_payload() -> None:
    with pytest.raises(ValueError, match="max_snapshot_bytes"):
        materialize_snapshot([{"path": "app/db.py", "content": "x" * 20}], max_bytes=10)


def test_scripted_agent_submits_ranked_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text(
        'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        encoding="utf-8",
    )

    generator = ScriptedTextGenerator(
        ReadOnlySandbox(repo, investigation_id="test-scripted"),
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


def test_injection_fixture_does_not_hijack_scripted_loop(tmp_path: Path) -> None:
    fixtures = Path(__file__).parent / "fixtures"
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text(
        'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        encoding="utf-8",
    )
    (repo / "app" / "injection.txt").write_text(
        (fixtures / "protocol_injection.txt").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

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
        ReadOnlySandbox(repo, investigation_id="test-injection"),
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


def test_duplicate_terminal_command_is_not_reexecuted_or_charged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text(
        'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        encoding="utf-8",
    )

    turn = 0

    class DuplicateGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            if turn <= 2:
                return '<tool_call> {"name": "terminal", "arguments": {"command": "ls"}} </tool_call>'
            return '<tool_call> {"name": "submit_no_vulnerability_found", "arguments": {}} </tool_call>'

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=DuplicateGenerator(),
        max_terminal_calls=5,
    )

    assert result.terminal_calls_used == 1
    assert result.duplicate_commands_suppressed == 1
    assert len(result.sandbox_audit) == 2
    charged = [entry for entry in result.sandbox_audit if entry.get("charged", True)]
    suppressed = [entry for entry in result.sandbox_audit if not entry.get("charged", True)]
    assert len(charged) == 1
    assert len(suppressed) == 1
    assert suppressed[0]["duplicate_of_turn"] == 1
    assert "[duplicate-command suppressed]" in result.exploration_trace
    assert "already run at turn 1" in result.exploration_trace
    assert "not charged against the terminal budget" in result.exploration_trace


def test_agent_query_engine_scripted_mode() -> None:
    class DummyEngine:
        _load_strategy = "on_demand"

        def load(self) -> None:
            return None

        def unload(self) -> None:
            return None

    engine = AgentQueryEngine(DummyEngine())
    response = engine.query(
        snapshot_files=[{"path": "app/db.py", "content": 'execute("SELECT 1")'}],
        changed_paths=["app/db.py"],
        queries=[{"task_cwe": "CWE-89", "task_cwe_description": "SQL injection"}],
    )
    assert response["outcome"] == "completed"
    assert response["localizations"][0]["ranked_files"] == ["app/db.py"]
