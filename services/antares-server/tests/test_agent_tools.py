"""Agent tool parsing and salvage behavior."""

from __future__ import annotations

from antares_server.agent_tools import (
    SubmitVulnerableFiles,
    parse_agent_action_with_salvage,
    salvage_submit_vulnerable_files,
)


def test_salvage_truncated_submit_vulnerable_files() -> None:
    raw = (
        '<tool_call> {"name": "submit_vulnerable_files", "arguments": {"ranked_files": '
        '["app/a.py", "app/b.py", "app/c.py", "app/c.py", "app/c.py'
    )
    salvaged = salvage_submit_vulnerable_files(raw)
    assert salvaged == SubmitVulnerableFiles(ranked_files=["app/a.py", "app/b.py", "app/c.py"])


def test_parse_agent_action_with_salvage_recovers_truncated_submit() -> None:
    raw = (
        '<tool_call> {"name": "submit_vulnerable_files", "arguments": {"ranked_files": '
        '["celery/backends/database/result_filter.py", "celery/backends/cassandra.py"'
    )
    action, salvaged = parse_agent_action_with_salvage(raw)
    assert salvaged is True
    assert isinstance(action, SubmitVulnerableFiles)
    assert action.ranked_files == [
        "celery/backends/database/result_filter.py",
        "celery/backends/cassandra.py",
    ]
