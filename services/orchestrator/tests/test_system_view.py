"""Operational System view — settings tiers, lifecycle, degraded status."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import (
    AdvisorySuppressionConfig,
    AppConfig,
    CURRENT_SCHEMA_VERSION,
    LegacyPathRewrite,
    load_config,
)
from shift_left.main import app
from shift_left.review.service import ReviewService
from shift_left.system.diagnostics import diagnose_service_url_error
from shift_left.system.prerequisites import PrerequisiteCheck, PrerequisiteCriticality
from shift_left.system.settings import RBAC_DISABLE_PHRASE, RBAC_ENABLE_PHRASE
from shift_left.ui.system_view import build_config_view
from shift_left.triage.service import AntaresTriageService
from shift_left.sovereignty.network import EgressGuard
from tests.test_phase3_hardening import FakeGit


SYSTEM_ROUTES = [
    "/ui/system",
    "/ui/system/config",
    "/ui/system/evidence",
    "/api/v1/system/status",
    "/api/v1/system/prerequisites",
]


@pytest.fixture
def system_client(tmp_path, monkeypatch):
    db = tmp_path / "shift-left.db"
    cfg_path = tmp_path / "shift-left.yaml"
    cfg_path.write_text(
        f"""schema_version: {CURRENT_SCHEMA_VERSION}
orchestration: {{}}
orchestrator:
  host: 127.0.0.1
ui:
  enabled: true
  require_loopback_client: false
findings_store:
  sqlite_path: {db}
audit:
  sqlite_path: {db}
auth:
  sqlite_path: {db}
models:
  antares:
    enabled: false
  foundation_sec:
    enabled: true
    service_url: http://foundation-sec-server:8091
    gguf_glob: foundation-sec-1.1-8b-instruct-q8_0.gguf
    max_context_tokens: 8192
rbac:
  allow_self_approval: false
"""
    )
    monkeypatch.setenv("SHIFT_LEFT_CONFIG", str(cfg_path))
    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": True, "require_loopback_client": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "models": {
                "antares": {"enabled": False},
                "foundation_sec": {
                    "enabled": True,
                    "service_url": "http://foundation-sec-server:8091",
                    "gguf_glob": "foundation-sec-1.1-8b-instruct-q8_0.gguf",
                    "max_context_tokens": 8192,
                },
            },
            "rbac": {"allow_self_approval": False},
        }
    )
    service = ReviewService(config)
    fake_git = FakeGit()
    service._git = fake_git
    service._approval_service._git = fake_git
    service._gate_service._git = fake_git
    service._changes._git = fake_git
    service.system_status._git = fake_git
    service.settings._store._path = cfg_path
    service.settings._store._loaded_mtime = cfg_path.stat().st_mtime
    app.state.config = config
    app.state.review_service = service
    app.state.triage_service = AntaresTriageService(config)
    app.state.token_store = service.token_store
    client = TestClient(app)
    _, admin = mint_api_token(
        service.token_store,
        label="admin",
        actor="admin",
        capabilities=[TokenCapability.ADMIN],
    )
    _, deploy = mint_api_token(
        service.token_store,
        label="deploy",
        actor="deployer",
        capabilities=[TokenCapability.DEPLOY],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, admin)
    return client, service, cfg_path, admin, deploy


def _check(
    check_id: str,
    *,
    criticality: PrerequisiteCriticality,
    ok: bool,
    status: str = "ok",
    error: str | None = None,
) -> PrerequisiteCheck:
    return PrerequisiteCheck(
        id=check_id,
        name=check_id,
        criticality=criticality,
        ok=ok,
        status=status,
        error=error,
    )


def test_foundation_sec_dns_diagnosis() -> None:
    exc = OSError("[Errno 8] nodename nor servname provided, or not known")
    diag = diagnose_service_url_error(
        "Foundation-Sec",
        "http://foundation-sec-server:8091",
        exc,
    )
    assert diag["category"] == "dns_resolution"
    assert "foundation-sec-server" in diag["root_cause"]


@pytest.mark.asyncio
async def test_unreachable_model_server_is_degraded(system_client) -> None:
    client, service, _, _, _ = system_client
    checker = service.system_status._prerequisites

    async def fake_run(topology: str):
        return [
            _check("postgres", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
            _check("forgejo", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
            _check("forgejo_token", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
            _check("forgejo_runner", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
            _check("orchestrator_store", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
            _check("policy_config", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
            _check(
                "foundation_sec_server",
                criticality=PrerequisiteCriticality.DEGRADED_CONFIG,
                ok=False,
                status="failed",
                error="Hostname 'foundation-sec-server' cannot be resolved",
            ),
            _check("code_handlers", criticality=PrerequisiteCriticality.DEGRADED_CODE, ok=True),
        ]

    with patch.object(checker, "_run_all_checks", side_effect=fake_run):
        status = await service.health_details(force_refresh=True)
        with patch.object(checker, "_run_all_checks", side_effect=fake_run):
            page = client.get("/ui/system?refresh=true")
    assert status["overall_state"] == "degraded"
    assert "DEGRADED" in page.text
    assert "foundation_sec_server" in page.text
    assert "target-tab-strip" in page.text
    assert "Health checks" in page.text


def test_health_route_redirects_to_system(system_client) -> None:
    client, _, _, _, _ = system_client
    response = client.get("/ui/health?refresh=true", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == "/ui/system?refresh=true"


def test_unauthenticated_system_redirects_to_login(system_client) -> None:
    client, _, _, _, _ = system_client
    client.cookies.clear()
    response = client.get("/ui/system", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/login?next=%2Fui%2Fsystem"


def test_system_tabs_and_views(system_client) -> None:
    client, _, _, _, _ = system_client
    triage = client.get("/ui/system")
    assert triage.status_code == 200
    assert 'href="/ui/system/config"' in triage.text
    assert 'href="/ui/system/evidence"' in triage.text
    assert "system-status-card" in triage.text

    config = client.get("/ui/system/config")
    assert config.status_code == 200
    assert "Foundation-Sec" in config.text
    assert "Storage &amp; cache" in config.text or "Storage & cache" in config.text

    evidence = client.get("/ui/system/evidence")
    assert evidence.status_code == 200
    assert "Network paths" in evidence.text
    assert "GGUF checksums" in evidence.text


def test_triage_lifecycle_busy_hidden_by_default(system_client) -> None:
    client, _, _, _, _ = system_client
    triage = client.get("/ui/system")
    assert triage.status_code == 200
    assert 'id="system-lifecycle-busy"' in triage.text
    assert 'id="system-lifecycle-busy" class="system-lifecycle-busy" hidden' in triage.text


def test_triage_lifecycle_feedback_without_busy_state(system_client) -> None:
    client, _, _, _, _ = system_client
    triage = client.get(
        "/ui/system?notice=start-all&outcome=healthy&started=postgres,forgejo"
    )
    assert triage.status_code == 200
    assert "Start all prerequisites" in triage.text
    assert 'id="system-lifecycle-busy" class="system-lifecycle-busy" hidden' in triage.text


def test_sod_banner_in_topbar_when_self_approval_enabled(system_client) -> None:
    client, service, cfg_path, admin, _ = system_client
    client.patch(
        "/api/v1/system/settings/rbac/allow-self-approval",
        headers={"Authorization": f"Bearer {admin}"},
        json={"enabled": True, "confirmation_phrase": RBAC_ENABLE_PHRASE},
    )
    page = client.get("/ui/targets")
    assert "app-topbar-warn" in page.text
    assert "rbac.allow_self_approval" in page.text
    assert "sod-banner" not in page.text


def test_q4_k_m_not_staged(system_client, tmp_path) -> None:
    from shift_left.system.models_inventory import foundation_sec_inventory

    _, service, _, _, _ = system_client
    empty = tmp_path / "foundation-sec-q4_k_m"
    empty.mkdir()
    service._config.models.foundation_sec.local_path_low_memory = str(empty)
    inv = foundation_sec_inventory(service._config)
    assert inv["q4_k_m_staged"] is False
    assert inv["q4_k_m_files"] == []


def test_immutable_sovereignty_settings_refused(system_client) -> None:
    client, _, _, admin, _ = system_client
    response = client.post(
        "/api/v1/system/settings/immutable-probe",
        headers={"Authorization": f"Bearer {admin}"},
        json={"settings": {"sovereignty.deny_egress": False}},
    )
    assert response.status_code == 403


def test_rbac_self_approval_requires_confirmation(system_client) -> None:
    client, service, _, admin, _ = system_client
    bad = client.patch(
        "/api/v1/system/settings/rbac/allow-self-approval",
        headers={"Authorization": f"Bearer {admin}"},
        json={"enabled": True, "confirmation_phrase": "wrong"},
    )
    assert bad.status_code == 400
    good = client.patch(
        "/api/v1/system/settings/rbac/allow-self-approval",
        headers={"Authorization": f"Bearer {admin}"},
        json={"enabled": True, "confirmation_phrase": RBAC_ENABLE_PHRASE},
    )
    assert good.status_code == 200
    events = service.audit.list_events(action="settings.rbac_allow_self_approval", limit=50)
    assert events
    assert events[0].details.get("new") is True


def test_rbac_disable_writes_audit(system_client) -> None:
    client, service, _, admin, _ = system_client
    client.patch(
        "/api/v1/system/settings/rbac/allow-self-approval",
        headers={"Authorization": f"Bearer {admin}"},
        json={"enabled": True, "confirmation_phrase": RBAC_ENABLE_PHRASE},
    )
    client.patch(
        "/api/v1/system/settings/rbac/allow-self-approval",
        headers={"Authorization": f"Bearer {admin}"},
        json={"enabled": False, "confirmation_phrase": RBAC_DISABLE_PHRASE},
    )
    events = service.audit.list_events(action="settings.rbac_allow_self_approval", limit=50)
    assert any(e.details.get("new") is False for e in events)


def test_tier3_invalid_value_rejected(system_client) -> None:
    client, _, _, admin, _ = system_client
    response = client.patch(
        "/api/v1/system/settings/tier3",
        headers={"Authorization": f"Bearer {admin}"},
        json={"settings": {"models.foundation_sec.max_context_tokens": 999999}},
    )
    assert response.status_code == 400


def test_config_write_preserves_comments_and_reloads(system_client) -> None:
    pytest.importorskip("ruamel.yaml")
    client, service, cfg_path, admin, _ = system_client
    db = service._config.findings_store.sqlite_path
    cfg_path.write_text(
        f"# operator note\nschema_version: {CURRENT_SCHEMA_VERSION}\n"
        "orchestration: {}\n"
        "orchestrator:\n  host: 127.0.0.1\n"
        f"findings_store:\n  sqlite_path: {db}\n"
        f"audit:\n  sqlite_path: {db}\n"
        f"auth:\n  sqlite_path: {db}\n"
        "rbac:\n  allow_self_approval: false\n"
        "models:\n  foundation_sec:\n    enabled: true\n"
        "    gguf_glob: foundation-sec-1.1-8b-instruct-q8_0.gguf\n"
        "    max_context_tokens: 8192\n"
        "    load_strategy: on_demand\n"
    )
    response = client.patch(
        "/api/v1/system/settings/tier3",
        headers={"Authorization": f"Bearer {admin}"},
        json={"settings": {"models.foundation_sec.max_context_tokens": 4096}},
    )
    assert response.status_code == 200
    text = cfg_path.read_text()
    assert "# operator note" in text
    assert "4096" in text
    reloaded = load_config(cfg_path)
    assert reloaded.models.foundation_sec.max_context_tokens == 4096
    audits = service.audit.list_events(action="settings.changed", limit=50)
    assert any(a.details.get("old") == 8192 for a in audits)


def test_service_action_requires_admin(system_client) -> None:
    client, _, _, _, deploy = system_client
    response = client.post(
        "/api/v1/system/services/action",
        headers={"Authorization": f"Bearer {deploy}"},
        json={"service": "foundation-sec-server", "action": "start"},
    )
    assert response.status_code == 403


def test_no_client_string_in_subprocess(system_client) -> None:
    _, service, _, admin, _ = system_client
    captured: list[list[str]] = []

    def fake_run(argv, **kwargs):
        captured.append(list(argv))
        class R:
            returncode = 0
            stdout = ""
            stderr = ""

        return R()

    with patch("shift_left.system.services.subprocess.run", side_effect=fake_run):
        import asyncio

        asyncio.run(
            service.service_lifecycle.run_action(
                service="foundation-sec-server",
                action="stop",
                actor="admin",
            )
        )
    assert captured
    joined = " ".join(captured[0])
    assert "foundation_sec_server.main" in joined
    assert ";" not in joined

    client, _, _, _, _ = system_client
    rejected = client.post(
        "/api/v1/system/services/action",
        headers={"Authorization": f"Bearer {admin}"},
        json={"service": "foundation-sec-server;rm", "action": "stop"},
    )
    assert rejected.status_code == 422


def test_system_routes_egress_blocked(system_client) -> None:
    client, service, _, _, _ = system_client
    attempts: list[tuple[str, int]] = []

    async def fast_checks(topology: str):
        return [
            _check("orchestrator_store", criticality=PrerequisiteCriticality.CRITICAL, ok=True),
        ]

    def tracking_connect(address, timeout=None, source_address=None):
        host = address[0] if isinstance(address, tuple) else str(address)
        if host not in {"127.0.0.1", "localhost", "::1"}:
            attempts.append(address)
        raise OSError("blocked")

    with patch.object(service.system_status._prerequisites, "_run_all_checks", side_effect=fast_checks):
        with patch("socket.create_connection", side_effect=tracking_connect):
            with patch(
                "shift_left.api.ui_support.run_egress_probe",
                return_value=type("R", (), {"ok": True, "message": "blocked"})(),
            ):
                with EgressGuard(allowed_hosts=frozenset({"127.0.0.1", "localhost", "::1"})):
                    for path in SYSTEM_ROUTES:
                        response = client.get(path)
                        assert response.status_code == 200, path
    assert attempts == []


def test_config_view_warns_when_pr_comment_omit_disabled() -> None:
    view = build_config_view(
        {
            "settings": {"tier3_form": {}, "rbac_phrases": {}},
            "models": {"inventory": {}, "antares": {}},
            "rbac": {},
            "config_diagnostics": {"omit_from_pr_comments": False, "legacy_path_rewrites": []},
        },
        can_admin=False,
    )
    assert len(view.notices) == 1
    notice = view.notices[0]
    assert notice.tone == "warn"
    assert "omit_from_pr_comments" in notice.message
    assert "~12% recall" in notice.message
    assert "Foundry Constitution II" in notice.message


def test_config_view_surfaces_legacy_path_rewrites() -> None:
    view = build_config_view(
        {
            "settings": {
                "tier3_form": {
                    "paths": {
                        "reference_cache_dir": "/volume/reference",
                        "findings_sqlite_path": "/volume/findings.db",
                    }
                },
                "rbac_phrases": {},
            },
            "models": {"inventory": {}, "antares": {}},
            "rbac": {},
            "config_diagnostics": {
                "omit_from_pr_comments": True,
                "legacy_path_rewrites": [
                    {
                        "key": "reference_data.cache_dir",
                        "original": "/shift-left/data/reference",
                        "resolved": "/volume/reference",
                    },
                    {
                        "key": "antares_triage.repos_checkout_dir",
                        "original": "/data/repos",
                        "resolved": "/volume/repos",
                    },
                ],
            },
        },
        can_admin=False,
    )
    assert any(notice.title == "Legacy data paths rewritten" for notice in view.notices)
    details = " ".join(detail for notice in view.notices for detail in notice.details)
    assert "/shift-left/data/reference" in details
    assert "/data/repos" in details
    cache_field = next(
        field
        for group in view.groups
        for field in group.fields
        if field.key == "reference_data.cache_dir"
    )
    assert cache_field.inline_note is not None
    assert "/shift-left/data/reference" in cache_field.inline_note


def test_system_config_renders_omit_false_warning(system_client) -> None:
    client, _, _, _, _ = system_client
    app.state.config = app.state.config.model_copy(
        update={
            "advisory_suppression": AdvisorySuppressionConfig(omit_from_pr_comments=False)
        }
    )
    response = client.get("/ui/system/config")
    assert response.status_code == 200
    assert "Advisory findings will appear on PR comments" in response.text
    assert "omit_from_pr_comments" in response.text
    assert "12%" in response.text


def test_system_config_renders_legacy_path_rewrites(system_client) -> None:
    client, _, _, _, _ = system_client
    app.state.config = app.state.config.model_copy(
        update={
            "legacy_path_rewrites": [
                LegacyPathRewrite(
                    key="antares_triage.repos_checkout_dir",
                    original="/shift-left/data/repos",
                    resolved="/data/repos",
                )
            ]
        }
    )
    response = client.get("/ui/system/config")
    assert response.status_code == 200
    assert "Legacy data paths rewritten" in response.text
    assert "/shift-left/data/repos" in response.text
    assert "/data/repos" in response.text
