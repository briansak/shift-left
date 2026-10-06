"""Ensure Foundation-Sec server logs never persist raw config secrets."""

from __future__ import annotations

import logging
import os

import pytest
from fastapi.testclient import TestClient

os.environ["FOUNDATION_SEC_ENGINE"] = "scripted"

from foundation_sec_server.main import app  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def test_analyze_request_does_not_log_secret_config_line(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    secret_line = "snmp-server community Sup3rS3cr3tC0mm RW"
    response = client.post(
        "/v1/analyze",
        json={
            "repo": "test/demo",
            "pr_ref": "PR-1",
            "commit_sha": "sha",
            "files": [
                {
                    "path": "config/edge.cfg",
                    "hunks": [
                        {
                            "new_start": 1,
                            "new_end": 1,
                            "content": secret_line,
                        }
                    ],
                }
            ],
        },
    )
    assert response.status_code == 200
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert secret_line not in log_text
    assert "Sup3rS3cr3tC0mm" not in log_text
