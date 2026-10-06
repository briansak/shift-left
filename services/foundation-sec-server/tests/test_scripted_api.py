"""Foundation-Sec server tests (scripted engine)."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

os.environ["FOUNDATION_SEC_ENGINE"] = "scripted"

from foundation_sec_server.main import app  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def test_health_scripted_engine(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["engine"] == "scripted"


def test_analyze_permissive_firewall(client: TestClient) -> None:
    response = client.post(
        "/v1/analyze",
        json={
            "repo": "test/demo",
            "pr_ref": "PR-1",
            "commit_sha": "sha",
            "files": [
                {
                    "path": "firewall/rules.conf",
                    "hunks": [
                        {
                            "new_start": 1,
                            "new_end": 1,
                            "content": "access-list OUT extended permit ip any any",
                        }
                    ],
                }
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body.get("outcome") in {
        "completed_with_findings",
        "completed_no_findings",
    }
    findings = body["findings"]
    assert findings
    assert findings[0]["cwe"] == "CWE-284"


def test_enrich_findings_fixture_prose(client: TestClient) -> None:
    response = client.post(
        "/v1/enrich-findings",
        json={
            "findings": [
                {
                    "id": "finding-1",
                    "title": "Overly permissive firewall rule",
                    "file_path": "firewall/rules.conf",
                    "severity": "high",
                }
            ]
        },
    )
    assert response.status_code == 200
    enrichments = response.json()["enrichments"]
    assert enrichments[0]["enrichment_source"] == "scripted-fixture"
    assert enrichments[0]["model_context"].startswith("[FIXTURE]")


def test_review_summary_fixture_prose(client: TestClient) -> None:
    response = client.post(
        "/v1/review-summary",
        json={
            "findings": [
                {
                    "id": "finding-1",
                    "title": "Overly permissive firewall rule",
                }
            ]
        },
    )
    assert response.status_code == 200
    summary = response.json()["review_summary"]
    assert summary["is_advisory"] is True
    assert "[FIXTURE]" in summary["summary_text"]
