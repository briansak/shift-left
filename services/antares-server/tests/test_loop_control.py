"""Loop-control harness behavior in the agent loop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from antares_server.agent_loop import QUERY_FAILED, QUERY_FAILED_UNSUBMITTED, run_agent_query
from antares_server.loop_control import (
    CONSECUTIVE_DUPLICATE_HARD_STOP_THRESHOLD,
    DEFAULT_MAX_TERMINAL_ATTEMPTS,
    UNREAD_SEARCH_HIT_NOTICE,
    LoopControlState,
    detect_degenerate_repetition,
    search_hit_paths_from_output,
    unread_search_hit_files,
    with_unread_search_hit_pressure,
)


@pytest.fixture(autouse=True)
def subprocess_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTARES_SANDBOX", "subprocess")


def test_consecutive_duplicate_hard_stop_on_third_repeat(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("x = 1\n", encoding="utf-8")
    turn = 0

    class TriplicateGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            if turn <= 4:
                return '<tool_call> {"name": "terminal", "arguments": {"command": "ls"}} </tool_call>'
            return '<tool_call> {"name": "submit_no_vulnerability_found", "arguments": {}} </tool_call>'

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=TriplicateGenerator(),
        max_terminal_calls=5,
        max_terminal_attempts=10,
    )

    assert result.duplicate_loop_hard_stop_fired is True
    assert result.forced_submission is True
    assert result.failure_class is None
    assert result.outcome == "completed_no_files"
    assert "[loop-control: forced-submission]" in result.exploration_trace
    assert result.total_terminal_attempts == 4
    assert result.duplicate_commands_suppressed == 3


def test_forced_submission_after_search_hits_submits_ranked_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("cursor.execute(query)\n", encoding="utf-8")
    turn = 0

    class SearchThenSubmitGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            if turn == 1:
                return (
                    '<tool_call> {"name": "terminal", "arguments": {"command": "rg -n execute app/db.py"}} '
                    "</tool_call>"
                )
            if turn <= 4:
                return (
                    '<tool_call> {"name": "terminal", "arguments": {"command": "rg -n execute app/db.py"}} '
                    "</tool_call>"
                )
            return (
                '<tool_call> {"name": "submit_vulnerable_files", "arguments": {"ranked_files": ["app/db.py"]}} '
                "</tool_call>"
            )

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=SearchThenSubmitGenerator(),
        max_terminal_calls=15,
        max_terminal_attempts=20,
    )

    assert result.duplicate_loop_hard_stop_fired is True
    assert result.forced_submission is True
    assert result.outcome == "completed_with_files"
    assert result.ranked_files == ["app/db.py"]


def test_duplicate_hard_stop_after_search_hits_without_inspection(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("cursor.execute(query)\n", encoding="utf-8")
    turn = 0

    class SearchLoopGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            if turn == 1:
                return (
                    '<tool_call> {"name": "terminal", "arguments": {"command": "rg -n execute app/db.py"}} '
                    "</tool_call>"
                )
            return (
                '<tool_call> {"name": "terminal", "arguments": {"command": "rg -n execute app/db.py"}} '
                "</tool_call>"
            )

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=SearchLoopGenerator(),
        max_terminal_calls=15,
        max_terminal_attempts=20,
    )

    assert result.duplicate_loop_hard_stop_fired is True
    assert result.failure_class == "duplicate_loop_search_unread"
    assert "app/db.py" in result.search_hit_files
    assert result.inspected_files == []
    assert UNREAD_SEARCH_HIT_NOTICE in result.exploration_trace


def test_duplicate_hard_stop_after_inspection_is_unsubmitted(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("cursor.execute(query)\n", encoding="utf-8")
    turn = 0

    class InspectLoopGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            if turn == 1:
                return '<tool_call> {"name": "terminal", "arguments": {"command": "cat app/db.py"}} </tool_call>'
            return '<tool_call> {"name": "terminal", "arguments": {"command": "ls"}} </tool_call>'

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=InspectLoopGenerator(),
        max_terminal_calls=15,
        max_terminal_attempts=20,
    )

    assert result.duplicate_loop_hard_stop_fired is True
    assert result.failure_class == "duplicate_loop_search_unread"
    assert result.outcome == QUERY_FAILED
    assert "app/db.py" in result.inspected_files


def test_attempt_cap_ends_unsubmitted_when_files_inspected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("cursor.execute(query)\n", encoding="utf-8")
    turn = 0

    class CapGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            if turn == 1:
                return '<tool_call> {"name": "terminal", "arguments": {"command": "cat app/db.py"}} </tool_call>'
            return '<tool_call> {"name": "terminal", "arguments": {"command": "pwd"}} </tool_call>'

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=CapGenerator(),
        max_terminal_calls=15,
        max_terminal_attempts=3,
    )

    assert result.attempt_cap_reached is True
    assert result.outcome == QUERY_FAILED_UNSUBMITTED
    assert result.failure_class == "attempt_cap_exceeded_unsubmitted"
    assert "app/db.py" in result.inspected_files


def test_search_hit_paths_from_rg_output() -> None:
    hits = search_hit_paths_from_output(
        "app/db.py:10:    cursor.execute(query)\n",
        {"app/db.py"},
    )
    assert hits == ["app/db.py"]


def test_forced_submission_rejects_terminal_then_accepts_submit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("cursor.execute(query)\n", encoding="utf-8")
    turn = 0

    class TerminalThenSubmitGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            if turn <= 4:
                return '<tool_call> {"name": "terminal", "arguments": {"command": "ls"}} </tool_call>'
            if turn == 5:
                return '<tool_call> {"name": "terminal", "arguments": {"command": "pwd"}} </tool_call>'
            return (
                '<tool_call> {"name": "submit_vulnerable_files", "arguments": {"ranked_files": ["app/db.py"]}} '
                "</tool_call>"
            )

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=TerminalThenSubmitGenerator(),
        max_terminal_calls=5,
        max_terminal_attempts=10,
    )

    assert result.forced_submission is True
    assert result.outcome == "completed_with_files"
    assert result.ranked_files == ["app/db.py"]
    assert "[loop-control: terminal-rejected]" in result.exploration_trace


def test_unparseable_submission_loop_terminates(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("x = 1\n", encoding="utf-8")
    turn = 0

    class ProseGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            return "I will keep writing prose without any tool call."

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=ProseGenerator(),
        max_terminal_calls=5,
        max_terminal_attempts=10,
    )

    assert result.failure_class == "unparseable_submission_loop"
    assert "[loop-control: unparseable_submission_loop]" in result.exploration_trace


def test_wall_clock_cap_terminates(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("x = 1\n", encoding="utf-8")

    class SlowGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            return '<tool_call> {"name": "terminal", "arguments": {"command": "ls"}} </tool_call>'

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=SlowGenerator(),
        max_terminal_calls=50,
        max_terminal_attempts=50,
        max_wall_clock_seconds=0.0,
    )

    assert result.failure_class == "wall_clock_exceeded"


def test_default_thresholds() -> None:
    assert DEFAULT_MAX_TERMINAL_ATTEMPTS == 20
    assert CONSECUTIVE_DUPLICATE_HARD_STOP_THRESHOLD == 3


def test_detect_degenerate_repetition_char_substring() -> None:
    unit = "|marksafe_literal"
    repeated = unit * 12
    assert detect_degenerate_repetition(f'command "{repeated}"')


def test_detect_degenerate_repetition_token_sequence() -> None:
    tokens = " ".join(["alpha"] * 8)
    repeated = " ".join([tokens] * 12)
    assert detect_degenerate_repetition(repeated)


def test_detect_degenerate_repetition_negative() -> None:
    assert not detect_degenerate_repetition("I will keep writing prose without any tool call.")


def _degenerate_terminal_tool_call() -> str:
    command = "marksafe_literal|" * 12
    payload = json.dumps({"name": "terminal", "arguments": {"command": command}})
    return f"<tool_call> {payload} </tool_call>"


def test_degenerate_repetition_rejects_without_terminal_charge(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("x = 1\n", encoding="utf-8")
    turn = 0

    class DegenerateGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            if turn == 1:
                return (
                    '<tool_call> {"name": "terminal", "arguments": {"command": "ls"}} '
                    "</tool_call>"
                )
            if turn == 2:
                return _degenerate_terminal_tool_call()
            return (
                '<tool_call> {"name": "submit_no_vulnerability_found", "arguments": {}} '
                "</tool_call>"
            )

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=DegenerateGenerator(),
        max_terminal_calls=5,
        max_terminal_attempts=10,
    )

    assert result.terminal_calls_used == 1
    assert result.degenerate_repetition_rejections == 1
    assert result.failure_class is None
    assert result.outcome == "completed_no_files"
    assert "[malformed-command rejected]" in result.exploration_trace
    assert "not charged against the terminal budget" in result.exploration_trace


def test_degenerate_repetition_hard_stop_failure_class(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("x = 1\n", encoding="utf-8")

    class DegenerateLoopGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            return _degenerate_terminal_tool_call()

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=DegenerateLoopGenerator(),
        max_terminal_calls=5,
        max_terminal_attempts=10,
    )

    assert result.failure_class == "degenerate_repetition"
    assert result.degenerate_repetition_rejections == 3
    assert "[loop-control: degenerate_repetition]" in result.exploration_trace
    assert result.failure_class != "unparseable_submission_loop"


def test_unread_search_hit_files_excludes_inspected() -> None:
    state = LoopControlState(
        search_hit_files={"app/db.py", "app/views.py"},
        inspected_files={"app/db.py"},
    )
    assert unread_search_hit_files(state) == {"app/views.py"}


def test_unread_pressure_notice_does_not_name_files() -> None:
    state = LoopControlState(search_hit_files={"app/secret.py"})
    output = with_unread_search_hit_pressure("exit=0\nhit", state)
    assert UNREAD_SEARCH_HIT_NOTICE in output
    assert "app/secret.py" not in UNREAD_SEARCH_HIT_NOTICE
    assert output.count("app/secret.py") == 0


def test_unread_pressure_omitted_when_all_hits_inspected() -> None:
    state = LoopControlState(
        search_hit_files={"app/db.py"},
        inspected_files={"app/db.py"},
    )
    assert with_unread_search_hit_pressure("ok", state) == "ok"


def test_budget_escalation_names_unread_hits_without_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("cursor.execute(query)\n", encoding="utf-8")
    turn = 0

    class SearchThenSubmitGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            queries = (
                "rg -n execute app/db.py",
                "rg -n cursor app/db.py",
                "rg -n query app/db.py",
                "rg -n execute .",
            )
            if turn <= 4:
                command = queries[turn - 1]
                return (
                    f'<tool_call> {{"name": "terminal", "arguments": {{"command": "{command}"}}}} '
                    "</tool_call>"
                )
            return (
                '<tool_call> {"name": "submit_vulnerable_files", '
                '"arguments": {"ranked_files": ["app/db.py"]}} </tool_call>'
            )

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=SearchThenSubmitGenerator(),
        max_terminal_calls=5,
        max_terminal_attempts=20,
    )

    assert result.budget_escalation_fired is True
    assert UNREAD_SEARCH_HIT_NOTICE in result.exploration_trace
    assert "rg -n execute" in result.exploration_trace
    escalation_blocks = [
        part for part in result.exploration_trace.split("[loop-control: budget-escalation]")[1:]
    ]
    assert escalation_blocks
    notice_section = escalation_blocks[0].split("search results include")[1].split("</tool_response>")[0]
    assert "app/db.py" not in notice_section


def test_forced_submission_unread_notice_omitted_without_search_hits(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("x = 1\n", encoding="utf-8")
    turn = 0

    class LsLoopThenSubmit:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            if turn <= 4:
                return '<tool_call> {"name": "terminal", "arguments": {"command": "ls"}} </tool_call>'
            return (
                '<tool_call> {"name": "submit_no_vulnerability_found", "arguments": {}} '
                "</tool_call>"
            )

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=["app/db.py"],
        generator=LsLoopThenSubmit(),
        max_terminal_calls=5,
        max_terminal_attempts=10,
    )

    assert result.forced_submission is True
    assert UNREAD_SEARCH_HIT_NOTICE not in result.exploration_trace


def test_loop_control_off_bypasses_soft_controls(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    turn = 0

    class RepeatingGenerator:
        def generate(self, prompt: str, *, temperature: float, top_p: float) -> str:
            nonlocal turn
            turn += 1
            if turn <= 4:
                return '<tool_call> {"name": "terminal", "arguments": {"command": "ls"}} </tool_call>'
            return '<tool_call> {"name": "submit_no_vulnerability_found", "arguments": {}} </tool_call>'

    result = run_agent_query(
        sandbox_root=repo,
        task_cwe="CWE-89",
        task_cwe_description="SQL injection",
        changed_paths=[],
        generator=RepeatingGenerator(),
        max_terminal_calls=5,
        max_terminal_attempts=5,
        loop_control_enabled=False,
    )

    assert result.outcome == "completed_no_files"
    assert result.loop_control_enabled is False
    assert result.terminal_budget == 5
    assert result.terminal_calls_used == 4
    assert result.total_terminal_attempts == 4
    assert result.duplicate_commands_suppressed == 0
    assert result.forced_submission is False
    assert result.budget_escalation_fired is False
    assert all(entry.get("charged", True) for entry in result.sandbox_audit)
