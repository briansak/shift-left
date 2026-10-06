"""Antares sandbox command audit persistence."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from shift_left.antares.audit_callback_auth import AuditCallbackTokenStore
from shift_left.antares.sandbox_audit import (
    persist_sandbox_command_audit,
    sandbox_audit_callback_url,
)
from shift_left.config import AppConfig, OrchestratorConfig
from shift_left.main import app
from shift_left.models.database import AuditStore
from shift_left.review.service import ReviewService

_SNMP_COMMUNITY = "Sup3rS3cr3tC0mm"


def test_persist_sandbox_command_audit_redacts_and_records(tmp_path) -> None:
    audit_path = tmp_path / "audit.db"
    store = AuditStore(audit_path, retention_days=30)
    persist_sandbox_command_audit(
        store,
        actor="operator",
        subject="demo/app@main",
        events=[
            {
                "investigation_id": "antares-inv-abc",
                "command": "grep password=secret app/config.py",
                "exit_code": 0,
                "output_truncated": "password=secret",
                "truncated": False,
                "recorded_at": "2026-09-10T00:00:00+00:00",
            }
        ],
    )
    events = store.list_events(action="antares.sandbox.command", limit=5)
    assert len(events) == 1
    assert events[0].action == "antares.sandbox.command"
    assert events[0].subject == "demo/app@main"
    assert "grep password" in events[0].details["command"]


def test_sandbox_audit_callback_url_defaults_to_loopback_orchestrator() -> None:
    config = AppConfig(orchestrator=OrchestratorConfig(host="127.0.0.1", port=8080))
    url = sandbox_audit_callback_url(config)
    assert url == "http://127.0.0.1:8080/api/v1/internal/antares/sandbox-command-audit"


@pytest.fixture
def audit_ingest_client(tmp_path) -> TestClient:
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1", "port": 8080},
            "ui": {"enabled": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )
    service = ReviewService(config)
    app.state.config = config
    app.state.review_service = service
    app.state.audit_callback_tokens = AuditCallbackTokenStore()
    app.state.token_store = service.token_store
    return TestClient(app)


def _audit_ingest_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "actor": "operator",
        "subject": "demo/app@main",
        "investigation_id": "antares-inv-stream",
        "command": "grep token app.py",
        "exit_code": 0,
        "output_truncated": "token=abc",
        "truncated": False,
        "recorded_at": "2026-09-10T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


def test_internal_sandbox_audit_ingest_rejects_unauthenticated_request() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/v1/internal/antares/sandbox-command-audit",
        json=_audit_ingest_payload(),
    )
    assert response.status_code == 401


def test_internal_sandbox_audit_ingest_accepts_callback_token(audit_ingest_client: TestClient) -> None:
    client = audit_ingest_client
    token = app.state.audit_callback_tokens.issue()
    response = client.post(
        "/api/v1/internal/antares/sandbox-command-audit",
        json=_audit_ingest_payload(investigation_id="antares-inv-authed"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    service = app.state.review_service
    events = service.audit.list_events(action="antares.sandbox.command", limit=20)
    assert any(event.details.get("investigation_id") == "antares-inv-authed" for event in events)


def test_internal_sandbox_audit_ingest_redacts_secret_shaped_request_body(
    audit_ingest_client: TestClient,
) -> None:
    client = audit_ingest_client
    token = app.state.audit_callback_tokens.issue()
    response = client.post(
        "/api/v1/internal/antares/sandbox-command-audit",
        json=_audit_ingest_payload(
            investigation_id="antares-inv-redacted",
            command=f"snmp-server community {_SNMP_COMMUNITY} RW",
            output_truncated=f"snmp-server community {_SNMP_COMMUNITY} RW",
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    service = app.state.review_service
    events = service.audit.list_events(action="antares.sandbox.command", limit=20)
    stored = next(
        event for event in events if event.details.get("investigation_id") == "antares-inv-redacted"
    )
    assert _SNMP_COMMUNITY not in str(stored.details["command"])
    assert _SNMP_COMMUNITY not in str(stored.details["output_truncated"])
    assert "[REDACTED]" in str(stored.details["command"]) or "[REDACTED]" in str(
        stored.details["output_truncated"]
    )


def test_internal_sandbox_audit_ingest_updates_trace_on_completion(
    audit_ingest_client: TestClient, tmp_path
) -> None:
    from shift_left.investigations.schema import InvestigationState
    from shift_left.investigations.store import InvestigationStore
    from shift_left.models.database import AuditStore

    store = InvestigationStore(str(tmp_path / "investigations.db"), audit=AuditStore(str(tmp_path / "audit.db")))
    inv_id = store.create_investigation(
        repo="example-org/example-configs",
        requested_ref="main",
        resolved_commit_sha="0" * 40,
        task_cwe="CWE-89",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    ).investigation_id
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    app.state.investigation_store = store

    client = audit_ingest_client
    token = app.state.audit_callback_tokens.issue()
    headers = {"Authorization": f"Bearer {token}"}
    dispatched = _audit_ingest_payload(
        investigation_id=inv_id,
        command="cat binary.bin",
        exit_code=0,
        output_truncated="(dispatched; waiting for sandbox)",
        command_id="cmd-dispatch-1",
        phase="dispatched",
    )
    completed = _audit_ingest_payload(
        investigation_id=inv_id,
        command="cat binary.bin",
        exit_code=0,
        output_truncated="before\ufffdafter",
        command_id="cmd-dispatch-1",
        phase="completed",
    )
    assert client.post(
        "/api/v1/internal/antares/sandbox-command-audit",
        json=dispatched,
        headers=headers,
    ).status_code == 200
    loaded = store.get(inv_id, include_children=True)
    assert loaded is not None
    assert len(loaded.trace_turns) == 1
    assert loaded.trace_turns[0].phase == "dispatched"
    assert loaded.trace_turns[0].command == "cat binary.bin"

    assert client.post(
        "/api/v1/internal/antares/sandbox-command-audit",
        json=completed,
        headers=headers,
    ).status_code == 200
    loaded = store.get(inv_id, include_children=True)
    assert loaded is not None
    assert len(loaded.trace_turns) == 1
    assert loaded.trace_turns[0].phase == "completed"
    assert loaded.trace_turns[0].output_truncated == "before\ufffdafter"

    events = app.state.review_service.audit.list_events(action="antares.sandbox.command", limit=20)
    matching = [event for event in events if event.details.get("command_id") == "cmd-dispatch-1"]
    assert {event.details.get("phase") for event in matching} == {"dispatched", "completed"}
