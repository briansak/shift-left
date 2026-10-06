"""Sandbox audit must record the command before execute() returns."""

from __future__ import annotations

import subprocess
from pathlib import Path

from antares_server.sandbox import SubprocessInvestigationSandbox
from antares_server.sandbox_audit import (
    AUDIT_PHASE_COMPLETED,
    AUDIT_PHASE_DISPATCHED,
    ChainedAuditSink,
    CollectedAuditSink,
    SandboxCommandAudit,
)


class _ProbeSink:
    def __init__(self) -> None:
        self.events: list[SandboxCommandAudit] = []

    def record(self, event: SandboxCommandAudit) -> None:
        self.events.append(event)


def test_execute_records_dispatch_before_subprocess_returns(
    tmp_path: Path, monkeypatch: object
) -> None:
    probe = _ProbeSink()
    collected = CollectedAuditSink()
    (tmp_path / "note.txt").write_text("ok\n", encoding="utf-8")

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert [event.phase for event in probe.events] == [AUDIT_PHASE_DISPATCHED]
        assert probe.events[0].command == "cat note.txt"
        return subprocess.CompletedProcess(args=["cat", "note.txt"], returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr("antares_server.sandbox.subprocess.run", fake_run)
    sandbox = SubprocessInvestigationSandbox(
        tmp_path,
        investigation_id="inv-dispatch",
        audit_sink=ChainedAuditSink(probe, collected),
    )
    result = sandbox.execute("cat note.txt")
    assert result.exit_code == 0
    assert [event.phase for event in probe.events] == [
        AUDIT_PHASE_DISPATCHED,
        AUDIT_PHASE_COMPLETED,
    ]
    assert probe.events[0].command_id == probe.events[1].command_id
    assert len(collected.events) == 1
    assert collected.events[0].phase == AUDIT_PHASE_COMPLETED
    assert collected.events[0].output_truncated == "ok\n"


def test_policy_block_does_not_emit_dispatch(tmp_path: Path) -> None:
    collected = CollectedAuditSink()
    sandbox = SubprocessInvestigationSandbox(
        tmp_path,
        investigation_id="inv-block",
        audit_sink=collected,
    )
    result = sandbox.execute("touch blocked.txt")
    assert result.exit_code == 1
    assert len(collected.events) == 1
    assert collected.events[0].phase == AUDIT_PHASE_COMPLETED
    assert collected.events[0].command_id is None
