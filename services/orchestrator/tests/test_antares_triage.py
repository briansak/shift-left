"""Antares triage workflow tests."""

from __future__ import annotations

import pytest

from shift_left.config import AppConfig, resolve_antares_service_url
from shift_left.git.factory import git_http_allowed_endpoints
from shift_left.investigations.preflight import check_antares_server_available
from shift_left_shared.network import endpoint_from_url
from shift_left.policy.loader import PolicyValidationError, validate_raw_policies
from shift_left.triage.service import AntaresTriageService, PROHIBITED_TRIAGE_WORDS


def test_prohibited_wording_absent_from_triage_summary() -> None:
    text = AntaresTriageService.sanitize_output_text(
        "Candidate files for review — advisory only."
    )
    assert not PROHIBITED_TRIAGE_WORDS.search(text)


def test_localization_fields_forbidden_in_policy_rules() -> None:
    with pytest.raises(PolicyValidationError, match="forbidden field"):
        validate_raw_policies(
            [
                {
                    "id": "bad",
                    "name": "Bad",
                    "rules": [{"cwe_queried": "CWE-89"}],
                }
            ]
        )


@pytest.mark.asyncio
async def test_health_check_uses_inference_allowlist_when_triage_enabled(monkeypatch) -> None:
    """Triage must not pass an empty sovereignty list (blocks DEFAULT inference endpoints)."""
    config = AppConfig.model_validate(
        {
            "models": {"antares": {"enabled": False, "installed": True}},
            "antares_triage": {"enabled": True, "installed": True},
            "sovereignty": {"runtime_allowed_endpoints": []},
        }
    )
    service = AntaresTriageService(config)
    allowed = service._client._http._allowed_endpoints
    assert allowed is not None
    assert endpoint_from_url("http://host.docker.internal:8090") in allowed

    async def _ok_health() -> dict[str, str]:
        return {"status": "ok"}

    monkeypatch.setattr(service._client, "health", _ok_health)
    assert await check_antares_server_available(service._client) is True


def test_git_allowlist_includes_antares_when_triage_enabled_without_model_enabled() -> None:
    config = AppConfig.model_validate(
        {
            "models": {
                "antares": {
                    "enabled": False,
                    "installed": True,
                    "service_url": "http://host.docker.internal:8090",
                }
            },
            "antares_triage": {"enabled": True, "installed": True},
        }
    )
    endpoints = git_http_allowed_endpoints(config)
    assert endpoint_from_url("http://host.docker.internal:8090") in endpoints
    assert endpoint_from_url(resolve_antares_service_url(config)) in endpoints


def test_triage_accepts_1b_when_minimum_is_1b() -> None:
    config = AppConfig.model_validate(
        {
            "antares_triage": {
                "enabled": True,
                "model_variant": "fdtn-ai/antares-1b",
                "minimum_variant": "1b",
            }
        }
    )
    service = AntaresTriageService(config)
    service._assert_minimum_variant()


def test_triage_rejects_350m_when_minimum_is_1b() -> None:
    config = AppConfig.model_validate(
        {
            "antares_triage": {
                "enabled": True,
                "model_variant": "fdtn-ai/antares-350m",
                "minimum_variant": "1b",
            }
        }
    )
    service = AntaresTriageService(config)
    with pytest.raises(RuntimeError, match="350M"):
        service._assert_minimum_variant()
