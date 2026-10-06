"""Read-only Investigations UI — auth, rendering, and redaction contracts."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import AppConfig
from shift_left.investigations.cancel_registry import InvestigationCancelRegistry
from shift_left.investigations.schema import CandidateDisposition, InvestigationState
from shift_left.investigations.store import InvestigationStore
from shift_left.main import app
from shift_left.review.service import ReviewService
from shift_left.triage.service import AntaresTriageService
from tests.test_phase3_hardening import FakeGit

_SNMP_COMMUNITY = "Sup3rS3cr3tC0mm"


@pytest.fixture
def investigation_ui_client(tmp_path):
    db = tmp_path / "shift-left.db"
    inv_db = tmp_path / "investigations.db"
    config = AppConfig.model_validate(
        {
            "schema_version": 11,
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": True, "require_loopback_client": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "investigations": {"sqlite_path": str(inv_db)},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
            "policy": {"allow_block_override": True},
            "antares_triage": {"enabled": True, "repos_checkout_dir": str(tmp_path / "repos")},
        }
    )
    checkout = tmp_path / "repos" / "demo" / "app"
    checkout.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=checkout, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=checkout, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=checkout, check=True)
    (checkout / "requirements.txt").write_text("sqlalchemy\n", encoding="utf-8")
    (checkout / "app").mkdir(exist_ok=True)
    (checkout / "app" / "db.py").write_text('import sqlalchemy\nsql = f"SELECT {x}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=checkout, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=checkout, check=True, capture_output=True)
    service = ReviewService(config)
    fake_git = FakeGit(author="commit-author")
    service._git = fake_git
    service._approval_service._git = fake_git
    service._gate_service._git = fake_git
    triage = AntaresTriageService(config)
    investigation_store = InvestigationStore(str(inv_db), audit=service.audit)
    app.state.config = config
    app.state.review_service = service
    app.state.triage_service = triage
    app.state.token_store = service.token_store
    app.state.investigation_store = investigation_store
    app.state.investigation_cancel_registry = InvestigationCancelRegistry()
    client = TestClient(app)
    _, token = mint_api_token(
        service.token_store,
        label="ui-triage",
        actor="operator",
        capabilities=[TokenCapability.ADMIN, TokenCapability.TRIAGE],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, token)
    return client, service, investigation_store, token


def _mint(service: ReviewService, *, actor: str, capabilities: list[TokenCapability]) -> str:
    _, plaintext = mint_api_token(
        service.token_store,
        label="cap",
        actor=actor,
        capabilities=capabilities,
    )
    return plaintext


def _seed_investigation(
    store: InvestigationStore,
    *,
    state: InvestigationState = InvestigationState.COMPLETED,
    with_candidates: bool = True,
    with_trace: bool = False,
) -> str:
    record = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha="abc111def222",
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    )
    inv_id = record.investigation_id
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    if with_candidates:
        store.set_candidates(inv_id, [(1, "src/auth.py"), (2, "src/db.py")])
    if with_trace:
        store.append_trace_turn(
            inv_id,
            turn_index=0,
            command=f"snmp-server community {_SNMP_COMMUNITY} RW",
            exit_status=0,
            output_truncated=f"snmp-server community {_SNMP_COMMUNITY} RW",
        )
    store.transition_state(inv_id, state, actor="operator")
    return inv_id


def test_triage_redirects_to_investigations(investigation_ui_client) -> None:
    client, _, _, _ = investigation_ui_client
    response = client.get("/ui/triage", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == "/ui/investigations"


def test_session_without_triage_rejected_on_list_and_detail(investigation_ui_client) -> None:
    client, service, store, _ = investigation_ui_client
    inv_id = _seed_investigation(store)
    review_token = _mint(service, actor="reviewer", capabilities=[TokenCapability.REVIEW])
    client.cookies.set(TOKEN_COOKIE_NAME, review_token)

    list_response = client.get("/ui/investigations")
    assert list_response.status_code == 403

    detail_response = client.get(f"/ui/investigations/{inv_id}")
    assert detail_response.status_code == 403


def test_list_completed_no_files_not_styled_as_failure(investigation_ui_client) -> None:
    client, _, store, _ = investigation_ui_client
    _seed_investigation(store, state=InvestigationState.COMPLETED_NO_FILES, with_candidates=False)
    _seed_investigation(store, state=InvestigationState.FAILED, with_candidates=False)

    response = client.get("/ui/investigations")
    assert response.status_code == 200
    rows = re.findall(r"<tr[^>]*>.*?</tr>", response.text, flags=re.DOTALL)
    no_files_row = next(row for row in rows if "completed_no_files" in row)
    failed_row = next(row for row in rows if re.search(r">\s*failed\s*</span>", row))
    assert "status-pill--muted" in no_files_row
    assert "status-pill--danger" not in no_files_row
    assert "status-pill--danger" in failed_row


def test_detail_advisory_banner_always_present(investigation_ui_client) -> None:
    client, _, store, _ = investigation_ui_client
    inv_id = _seed_investigation(store)
    response = client.get(f"/ui/investigations/{inv_id}")
    assert response.status_code == 200
    assert 'class="investigation-advisory-banner"' in response.text
    assert "candidate files for human review" in response.text
    assert "submission_rank" in response.text
    assert "never gate a merge" in response.text


def test_completed_no_files_renders_f1_caveat_not_empty_table(investigation_ui_client) -> None:
    client, _, store, _ = investigation_ui_client
    inv_id = _seed_investigation(
        store,
        state=InvestigationState.COMPLETED_NO_FILES,
        with_candidates=False,
    )
    response = client.get(f"/ui/investigations/{inv_id}")
    assert response.status_code == 200
    text = response.text
    assert "No candidate files surfaced" in text
    assert "File F1 on this task is 0.209" in text
    assert 'class="investigation-no-files-card"' in text
    assert "Candidate files</h2>" not in text


def test_trace_output_redacts_snmp_community(investigation_ui_client) -> None:
    client, _, store, _ = investigation_ui_client
    inv_id = _seed_investigation(store, with_trace=True)

    detail = client.get(f"/ui/investigations/{inv_id}")
    assert detail.status_code == 200
    assert _SNMP_COMMUNITY not in detail.text
    assert "investigation-trace-turn" not in detail.text

    trace_fragment = client.get(f"/ui/investigations/{inv_id}/trace?fragment=1")
    assert trace_fragment.status_code == 200
    assert _SNMP_COMMUNITY not in trace_fragment.text
    assert "snmp-server community [REDACTED]" in trace_fragment.text

    trace_page = client.get(f"/ui/investigations/{inv_id}/trace")
    assert trace_page.status_code == 200
    assert _SNMP_COMMUNITY not in trace_page.text
    assert "snmp-server community [REDACTED]" in trace_page.text


def _seed_queued_investigation(store: InvestigationStore) -> str:
    record = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha="abc111def222",
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    )
    return record.investigation_id


def test_launch_batch_uses_native_details_panel(investigation_ui_client) -> None:
    client, _, _, _ = investigation_ui_client
    response = client.get("/ui/investigations")
    assert response.status_code == 200
    text = response.text
    assert 'class="card investigation-launch-card investigation-launch-details"' in text
    assert "<summary class=\"investigation-launch-summary btn btn-ghost\">Launch investigation</summary>" in text
    assert 'id="investigation-launch-panel"' in text
    assert re.search(r'name="source" value="single"[^>]*checked', text)
    assert 'name="source" value="top25"' in text
    assert 'name="source" value="profiled"' in text
    assert 'name="source" value="custom"' in text
    assert re.search(r'name="snapshot_scope" value="full"[^>]*checked', text)
    assert 'name="snapshot_scope" value="pr_changed"' in text
    assert re.search(r'name="exclude_test_paths" value="1"[^>]*checked', text)
    assert "data-catalog-search" in text
    assert 'name="catalog_cwes"' in text
    assert "Queue depth:" in text
    assert "Estimated wall-clock" in text
    assert "62s median" in text
    assert "data-launch-queue-cap" in text
    assert re.search(r"data-launch-queue-cap>\s*10\s*<", text)
    assert "Snapshot size:" in text
    assert "Launch batch" not in text
    assert 'id="investigation-batch-panel"' not in text


def test_batch_launch_requires_preview(investigation_ui_client) -> None:
    client, _, _, _ = investigation_ui_client
    response = client.post(
        "/ui/investigations",
        data={
            "repo": "demo/app",
            "ref": "main",
            "source": "top25",
            "snapshot_scope": "full",
            "exclude_test_paths": "1",
        },
    )
    assert response.status_code == 400
    assert "Preview members" in response.text
    assert 'name="source" value="top25"' in response.text


def test_custom_batch_does_not_require_preview(investigation_ui_client) -> None:
    client, _, _, _ = investigation_ui_client
    response = client.post(
        "/ui/investigations",
        data={
            "repo": "demo/app",
            "ref": "main",
            "source": "custom",
            "snapshot_scope": "full",
            "exclude_test_paths": "1",
        },
    )
    assert response.status_code == 400
    assert "Preview members against this repo" not in response.text
    assert "Select at least one CWE from the catalog" in response.text


def test_preview_top25_renders_member_table(investigation_ui_client) -> None:
    client, _, _, _ = investigation_ui_client
    response = client.post(
        "/ui/investigations/preview",
        data={
            "repo": "demo/app",
            "ref": "main",
            "source": "top25",
            "snapshot_scope": "full",
            "exclude_test_paths": "1",
        },
    )
    assert response.status_code == 200
    text = response.text
    assert 'name="previewed" value="1"' in text
    assert "Evidence tier" in text
    assert "Tractability" in text
    assert "Top 25 rank" in text
    assert 'data-evidence-tier="language-only"' in text
    language_only_row = re.search(
        r'<tr data-evidence-tier="language-only">[\s\S]*?</tr>',
        text,
    )
    assert language_only_row is not None
    assert "checked" not in language_only_row.group(0)
    evidenced_row = re.search(
        r'<tr data-evidence-tier="(?:direct|indirect)">[\s\S]*?</tr>',
        text,
    )
    assert evidenced_row is not None
    assert "checked" in evidenced_row.group(0)
    assert "Snapshot size:" in text
    snapshot_label = text.split("data-launch-snapshot-label", 1)[1][:240]
    assert "preview to measure" not in snapshot_label
    assert "62s median" in text
    assert re.search(r'name="source" value="top25"[^>]*checked', text)


def test_runner_dead_with_queued_work_renders_warn(investigation_ui_client) -> None:
    client, _, store, _ = investigation_ui_client
    _seed_queued_investigation(store)

    response = client.get("/ui/investigations")
    assert response.status_code == 200
    text = response.text
    assert "investigation-runner-card--warn" in text
    assert "runner is not running" in text
    assert 'href="/ui/system"' in text
    assert "Queue depth" in text


def _seed_running_investigation(store: InvestigationStore, *, with_candidates: bool = True) -> str:
    record = store.create_investigation(
        repo="demo/app",
        requested_ref="main",
        resolved_commit_sha="abc111def222",
        task_cwe="CWE-843",
        actor="operator",
        model_variant="fdtn-ai/antares-1b",
    )
    inv_id = record.investigation_id
    store.transition_state(inv_id, InvestigationState.RUNNING, actor="operator")
    if with_candidates:
        store.set_candidates(inv_id, [(1, "src/auth.py"), (2, "src/db.py")])
    return inv_id


def test_polling_stops_when_no_active_investigations(investigation_ui_client) -> None:
    client, _, store, _ = investigation_ui_client
    _seed_investigation(store, state=InvestigationState.COMPLETED)

    response = client.get("/ui/investigations")
    assert response.status_code == 200
    assert 'data-investigation-live-poll="true"' not in response.text

    _seed_queued_investigation(store)
    active = client.get("/ui/investigations")
    assert 'data-investigation-live-poll="true"' in active.text
    assert "/ui/investigations/live-state.json" in active.text


def test_live_poll_updates_terminal_calls_without_full_reload(investigation_ui_client) -> None:
    client, _, store, _ = investigation_ui_client
    inv_id = _seed_running_investigation(store)

    detail = client.get(f"/ui/investigations/{inv_id}")
    assert detail.status_code == 200
    assert 'data-investigation-live-poll="true"' in detail.text
    assert 'data-investigation-disposition-note' in detail.text

    poll_js = (
        Path(__file__).resolve().parents[1]
        / "shift_left"
        / "ui"
        / "static"
        / "investigation-live-poll.js"
    ).read_text()
    assert "location.reload" not in poll_js

    first = client.get(f"/ui/investigations/{inv_id}/live-state.json")
    assert first.status_code == 200
    assert first.json()["terminal_calls_label"].startswith("0/")

    store.update_terminal_calls_used(inv_id, 4)
    second = client.get(f"/ui/investigations/{inv_id}/live-state.json")
    assert second.json()["terminal_calls_label"].startswith("4/")

    # Live poll never re-fetches the page; disposition note inputs remain in the DOM.
    detail_again = client.get(f"/ui/investigations/{inv_id}")
    assert detail_again.text.count("data-investigation-disposition-note") == detail.text.count(
        "data-investigation-disposition-note"
    )


def test_disposition_note_input_preserved_across_live_poll_interval(
    investigation_ui_client,
) -> None:
    """Poll cycles update metrics via JSON only — disposition note fields are never touched."""
    client, _, store, _ = investigation_ui_client
    inv_id = _seed_running_investigation(store)
    detail_url = f"/ui/investigations/{inv_id}"
    live_url = f"/ui/investigations/{inv_id}/live-state.json"

    detail = client.get(detail_url)
    assert 'data-investigation-disposition-note' in detail.text

    poll_js = (
        Path(__file__).resolve().parents[1]
        / "shift_left"
        / "ui"
        / "static"
        / "investigation-live-poll.js"
    ).read_text()
    assert "location.reload" not in poll_js
    assert "disposition-note" not in poll_js
    assert "investigation-disposition-form" not in poll_js

    for _ in range(3):
        store.update_terminal_calls_used(inv_id, 2)
        live = client.get(live_url)
        assert live.status_code == 200
        assert live.json()["active"] is True

    # Server-rendered form markup is stable; client-side note text is never cleared by poll JS.
    detail_after_polls = client.get(detail_url)
    assert detail_after_polls.text.count("data-investigation-disposition-note") == detail.text.count(
        "data-investigation-disposition-note"
    )


def test_trace_not_inlined_on_detail_page(investigation_ui_client) -> None:
    client, _, store, _ = investigation_ui_client
    inv_id = _seed_investigation(store, with_trace=True)

    response = client.get(f"/ui/investigations/{inv_id}")
    assert response.status_code == 200
    assert 'data-investigation-trace-fetch="/ui/investigations/' in response.text
    assert "investigation-trace-turn" not in response.text
    assert "investigation-trace-output" not in response.text


def test_disposition_update_preserves_candidate_results(investigation_ui_client) -> None:
    client, service, store, _ = investigation_ui_client
    inv_id = _seed_investigation(store)
    before = store.get(inv_id, include_children=True)
    assert before is not None
    ranks_paths = [(c.submission_rank, c.file_path) for c in before.candidates]

    response = client.post(
        f"/ui/investigations/{inv_id}/candidates/1/disposition",
        data={"disposition": "reviewed", "note": "checked"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    after = store.get(inv_id, include_children=True)
    assert after is not None
    assert [(c.submission_rank, c.file_path) for c in after.candidates] == ranks_paths
    assert after.candidates[0].disposition == CandidateDisposition.REVIEWED
    assert after.candidates[0].disposition_actor == "operator"
    assert after.candidates[0].disposition_note == "checked"

    events = service.audit.list_events(action="investigation.disposition_updated", limit=5)
    assert len(events) == 1
    details = events[0].details
    assert details["investigation_id"] == inv_id
    assert details["file_path"] == "src/auth.py"
    assert details["from_disposition"] == "open"
    assert details["to_disposition"] == "reviewed"
    assert details["actor"] == "operator"
    assert details["note"] == "checked"


def test_disposition_note_redacted_on_render(investigation_ui_client) -> None:
    client, _, store, _ = investigation_ui_client
    inv_id = _seed_investigation(store)
    store.update_candidate_disposition(
        inv_id,
        1,
        disposition=CandidateDisposition.REVIEWED,
        actor="operator",
        note=f"snmp-server community {_SNMP_COMMUNITY} RW",
    )

    response = client.get(f"/ui/investigations/{inv_id}")
    assert response.status_code == 200
    assert _SNMP_COMMUNITY not in response.text
    assert "snmp-server community [REDACTED]" in response.text


def test_open_disposition_rollup_updates_after_disposition_change(investigation_ui_client) -> None:
    client, _, store, _ = investigation_ui_client
    inv_id = _seed_investigation(store)

    list_before = client.get("/ui/investigations")
    assert list_before.status_code == 200
    assert re.search(
        r'Open dispositions</p>\s*<p class="metric-card-value">2</p>',
        list_before.text,
    )
    assert "· 2 open" in list_before.text

    client.post(
        f"/ui/investigations/{inv_id}/candidates/1/disposition",
        data={"disposition": "reviewed", "note": ""},
        follow_redirects=False,
    )

    detail = client.get(f"/ui/investigations/{inv_id}")
    assert detail.status_code == 200
    assert 'class="metric-card-label">Open dispositions</p>' in detail.text
    assert re.search(
        r'Open dispositions</p>\s*<p class="metric-card-value">1</p>',
        detail.text,
    )

    list_after = client.get("/ui/investigations")
    assert list_after.status_code == 200
    assert "· 1 open" in list_after.text
    assert re.search(
        r'Open dispositions</p>\s*<p class="metric-card-value">1</p>',
        list_after.text,
    )


def test_session_without_triage_cannot_change_disposition(investigation_ui_client) -> None:
    client, service, store, _ = investigation_ui_client
    inv_id = _seed_investigation(store)
    review_token = _mint(service, actor="reviewer", capabilities=[TokenCapability.REVIEW])
    client.cookies.set(TOKEN_COOKIE_NAME, review_token)

    ui_response = client.post(
        f"/ui/investigations/{inv_id}/candidates/1/disposition",
        data={"disposition": "reviewed", "note": ""},
    )
    assert ui_response.status_code == 403

    api_response = client.patch(
        f"/api/v1/investigations/{inv_id}/candidates/1/disposition",
        json={"disposition": "reviewed", "note": ""},
        headers={"Authorization": f"Bearer {review_token}"},
    )
    assert api_response.status_code == 403


def test_reconciliation_mismatch_renders_warn_row(investigation_ui_client) -> None:
    client, service, store, _ = investigation_ui_client
    inv_id = _seed_investigation(store, with_trace=True)
    # Trace turn without matching sandbox audit event → counts_match false
    response = client.get(f"/ui/investigations/{inv_id}")
    assert response.status_code == 200
    text = response.text
    assert 'class="investigation-reconcile-warn"' in text
    assert "Audit divergence" in text
    assert "Trace attempts (1)" in text
    assert "sandbox audit attempts (0)" in text
