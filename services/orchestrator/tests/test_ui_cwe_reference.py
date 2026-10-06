"""CWE reference catalog UI."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import TOKEN_COOKIE_NAME
from shift_left.auth.tokens import mint_api_token
from shift_left.config import AppConfig
from shift_left.cwe.handler_assertions import (
    handler_asserted_cwe_ids,
    handler_asserted_in_catalog_ids,
    handler_asserted_out_of_catalog_ids,
    handler_assertions_for_cwe,
)
from shift_left.cwe.localization_candidates import localization_candidate_by_id
from shift_left.main import app
from shift_left.review.service import ReviewService
from shift_left.ui.cwe_reference_view import (
    PAGE_SIZE,
    build_cwe_reference_list_view,
    build_handler_out_of_catalog_rows,
    filter_localization_entries,
    handler_coverage_partition,
    language_mode_count,
)


@pytest.fixture
def cwe_ui_client(tmp_path):
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "schema_version": 11,
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": True, "require_loopback_client": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "investigations": {"sqlite_path": str(tmp_path / "investigations.db")},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
            "policy": {"allow_block_override": True},
            "antares_triage": {"enabled": True},
        }
    )
    service = ReviewService(config)
    app.state.config = config
    app.state.review_service = service
    app.state.token_store = service.token_store
    client = TestClient(app)
    _, token = mint_api_token(
        service.token_store,
        label="ui-review",
        actor="operator",
        capabilities=[TokenCapability.REVIEW],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, token)
    return client, service


def test_unauthenticated_session_rejected(cwe_ui_client) -> None:
    client, _ = cwe_ui_client
    client.cookies.clear()
    response = client.get("/ui/cwe", headers={"Accept": "application/json"})
    assert response.status_code == 401


def test_unauthenticated_browser_redirects_to_login(cwe_ui_client) -> None:
    client, _ = cwe_ui_client
    client.cookies.clear()
    response = client.get("/ui/cwe", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/login?next=%2Fui%2Fcwe"


def test_search_matches_id_name_and_description() -> None:
    by_id = filter_localization_entries(q="CWE-843")
    assert by_id and all("CWE-843" in entry["id"] for entry in by_id)

    by_name = filter_localization_entries(q="prototype pollution")
    assert by_name
    assert any("CWE-1321" == entry["id"] for entry in by_name)

    by_description = filter_localization_entries(q="sql command")
    assert by_description
    assert any("sql command" in entry.get("short_description", "").lower() for entry in by_description)


def test_language_modes_return_python_counts() -> None:
    assert language_mode_count("specific", "Python") == 7
    assert language_mode_count("includes_agnostic", "Python") == 643
    assert language_mode_count("agnostic_only", "Python") == 591


def test_handler_asserted_badge_matches_registry() -> None:
    assertions = handler_assertions_for_cwe("CWE-284")
    assert assertions
    assert any(item.rule_id == "ASA-001" and item.source == "config" for item in assertions)

    rows = filter_localization_entries(handler_only=True)
    assert rows
    assert all(handler_assertions_for_cwe(str(entry["id"])) for entry in rows)


def test_pagination_preserves_filters() -> None:
    view = build_cwe_reference_list_view(
        page=2,
        language="Python",
        language_mode="includes_agnostic",
    )
    assert view.page == 2
    assert view.prev_href is not None
    assert view.next_href is not None
    for href in (view.prev_href, view.next_href):
        query = parse_qs(urlparse(href).query)
        assert query.get("language", [""])[0] == "Python"
        assert query.get("language_mode", [""])[0] == "includes_agnostic"

    assert view.total_pages > 1


def test_pagination_renders_on_page_two(cwe_ui_client) -> None:
    client, _ = cwe_ui_client
    response = client.get(
        "/ui/cwe",
        params={"language": "Python", "language_mode": "includes_agnostic", "page": 2},
    )
    assert response.status_code == 200
    assert "Page 2 of" in response.text


def test_cwe_reference_page_renders_catalog(cwe_ui_client) -> None:
    client, _ = cwe_ui_client
    response = client.get("/ui/cwe")
    assert response.status_code == 200
    assert "CWE reference" in response.text
    assert "cwec_v4.20.xml" in response.text
    assert "838" in response.text
    assert "Handler rule" in response.text


def test_start_investigation_hidden_without_triage(cwe_ui_client) -> None:
    client, _ = cwe_ui_client
    response = client.get("/ui/cwe")
    assert response.status_code == 200
    assert "Start investigation" not in response.text


def test_start_investigation_visible_with_triage(tmp_path) -> None:
    db = tmp_path / "shift-left.db"
    config = AppConfig.model_validate(
        {
            "schema_version": 11,
            "orchestrator": {"host": "127.0.0.1"},
            "ui": {"enabled": True, "require_loopback_client": False},
            "findings_store": {"sqlite_path": str(db)},
            "audit": {"sqlite_path": str(db)},
            "auth": {"sqlite_path": str(db)},
            "investigations": {"sqlite_path": str(tmp_path / "investigations.db")},
            "models": {"antares": {"enabled": False}, "foundation_sec": {"enabled": False}},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
            "antares_triage": {"enabled": True},
        }
    )
    service = ReviewService(config)
    app.state.config = config
    app.state.review_service = service
    app.state.token_store = service.token_store
    client = TestClient(app)
    _, token = mint_api_token(
        service.token_store,
        label="ui-triage",
        actor="operator",
        capabilities=[TokenCapability.TRIAGE],
    )
    client.cookies.set(TOKEN_COOKIE_NAME, token)
    response = client.get("/ui/cwe")
    assert response.status_code == 200
    assert "Start investigation" in response.text
    assert "/ui/investigations?task_cwe=" in response.text


def test_page_size_constant_used_for_pagination() -> None:
    assert PAGE_SIZE == 50
    rows = filter_localization_entries()
    assert len(rows) > PAGE_SIZE


def test_every_handler_asserted_cwe_represented_exactly_once() -> None:
    view = build_cwe_reference_list_view(page=1)
    in_catalog, out_of_catalog = handler_coverage_partition()
    assert in_catalog == handler_asserted_in_catalog_ids()
    assert out_of_catalog == handler_asserted_out_of_catalog_ids()
    assert in_catalog | out_of_catalog == handler_asserted_cwe_ids()
    assert not (in_catalog & out_of_catalog)

    out_rows = build_handler_out_of_catalog_rows()
    assert {row.cwe_id for row in out_rows} == out_of_catalog
    assert {row.cwe_id for row in view.out_of_catalog_rows} == out_of_catalog
    assert out_rows[0].cwe_id == "CWE-284"
    assert out_rows[0].rule_count == 14

    for cwe_id in in_catalog:
        assert localization_candidate_by_id(cwe_id) is not None
        assert handler_assertions_for_cwe(cwe_id)
    for cwe_id in out_of_catalog:
        assert localization_candidate_by_id(cwe_id) is None
        assert handler_assertions_for_cwe(cwe_id)


def test_out_of_catalog_section_renders_on_page(cwe_ui_client) -> None:
    client, _ = cwe_ui_client
    response = client.get("/ui/cwe")
    assert response.status_code == 200
    assert "Handler-asserted CWEs outside this catalog" in response.text
    assert "6 of 12 handler-asserted CWEs are Pillar or Class" in response.text
    assert "CWE-284" in response.text
    assert "ASA-001" in response.text
