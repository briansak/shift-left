"""CWE dictionary inline embedding must not allow script breakout."""

from __future__ import annotations

from unittest.mock import patch

from tests.test_ui_target_detail_view import _build_client


def test_ui_embedded_dictionary_escapes_script_breakout(tmp_path) -> None:
    client, _ = _build_client(
        tmp_path,
        target_id="edge-fw-01",
        target_type="generic_terraform",
        config_paths=["terraform/**"],
        tree_paths=["terraform/main.tf"],
        file_contents={"terraform/main.tf": 'resource "x" {}\n'},
    )
    crafted = {
        "CWE-284": {
            "id": "CWE-284",
            "name": "Crafted",
            "abstraction": "Base",
            "short_description": 'payload </script><script>alert("xss")</script>',
            "url": "https://example.invalid/284",
        }
    }

    with patch("shift_left.ui.cwe_dictionary.load_cwe_dictionary", return_value=crafted):
        response = client.get("/ui/targets/edge-fw-01")
    assert response.status_code == 200
    body = response.text
    assert 'payload </script><script>alert("xss")</script>' not in body
    assert "\\u003c/script" in body
    assert '<script id="cwe-dictionary-data" type="application/json">' in body
