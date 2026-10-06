"""Streaming sandbox audit callback."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from antares_server.http_audit_sink import HttpAuditSink
from antares_server.sandbox_audit import SandboxCommandAudit


def test_http_audit_sink_posts_each_event() -> None:
    sink = HttpAuditSink(
        "http://127.0.0.1:8080/api/v1/internal/antares/sandbox-command-audit",
        actor="operator",
        subject="demo/app@main",
    )
    event = SandboxCommandAudit(
        investigation_id="antares-inv-test",
        command="ls -la",
        exit_code=0,
        output_truncated=".",
        truncated=False,
        recorded_at="2026-09-10T00:00:00+00:00",
    )

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.__enter__ = MagicMock(return_value=mock_response)
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_response) as urlopen:
        sink.record(event)

    urlopen.assert_called_once()
    request = urlopen.call_args.args[0]
    payload = json.loads(request.data.decode("utf-8"))
    assert payload["actor"] == "operator"
    assert payload["subject"] == "demo/app@main"
    assert payload["investigation_id"] == "antares-inv-test"
    assert payload["command"] == "ls -la"


def test_http_audit_sink_posts_dispatch_and_completion() -> None:
    sink = HttpAuditSink(
        "http://127.0.0.1:8080/api/v1/internal/antares/sandbox-command-audit",
        actor="operator",
        subject="demo/app@main",
    )
    dispatched = SandboxCommandAudit(
        investigation_id="antares-inv-test",
        command="ls -la",
        exit_code=0,
        output_truncated="(dispatched; waiting for sandbox)",
        truncated=False,
        recorded_at="2026-09-10T00:00:00+00:00",
        command_id="cmd-1",
        phase="dispatched",
    )
    completed = SandboxCommandAudit(
        investigation_id="antares-inv-test",
        command="ls -la",
        exit_code=0,
        output_truncated=".",
        truncated=False,
        recorded_at="2026-09-10T00:00:01+00:00",
        command_id="cmd-1",
        phase="completed",
    )

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.__enter__ = MagicMock(return_value=mock_response)
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_response) as urlopen:
        sink.record(dispatched)
        sink.record(completed)

    assert urlopen.call_count == 2
    phases = [
        json.loads(call.args[0].data.decode("utf-8"))["phase"]
        for call in urlopen.call_args_list
    ]
    assert phases == ["dispatched", "completed"]


def test_http_audit_sink_sends_audit_callback_token() -> None:
    sink = HttpAuditSink(
        "http://127.0.0.1:8080/api/v1/internal/antares/sandbox-command-audit",
        actor="operator",
        subject="demo/app@main",
        audit_token="slat_test-token",
    )
    event = SandboxCommandAudit(
        investigation_id="antares-inv-test",
        command="ls",
        exit_code=0,
        output_truncated="",
        truncated=False,
        recorded_at="2026-09-10T00:00:00+00:00",
    )

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.__enter__ = MagicMock(return_value=mock_response)
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_response) as urlopen:
        sink.record(event)

    request = urlopen.call_args.args[0]
    assert request.headers["Authorization"] == "Bearer slat_test-token"


def test_http_audit_sink_does_not_raise_on_callback_failure() -> None:
    sink = HttpAuditSink(
        "http://127.0.0.1:8080/api/v1/internal/antares/sandbox-command-audit",
        actor="operator",
        subject="demo/app@main",
    )
    event = SandboxCommandAudit(
        investigation_id="antares-inv-test",
        command="ls",
        exit_code=0,
        output_truncated="",
        truncated=False,
        recorded_at="2026-09-10T00:00:00+00:00",
    )

    with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
        sink.record(event)
