"""Forgejo Actions secret API compatibility."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from shift_left_cli.forgejo_secrets import ForgejoSecretError, set_repo_secret


import urllib.error


@patch("shift_left_cli.forgejo_secrets.urllib.request.urlopen")
def test_set_repo_secret_plaintext_when_public_key_unsupported(mock_urlopen) -> None:
    captured: list[bytes] = []

    def urlopen(request, timeout=10):  # noqa: ARG001
        url = request.full_url
        if url.endswith("/actions/secrets/public-key"):
            raise urllib.error.HTTPError(url, 405, "Method Not Allowed", None, None)
        if request.method == "PUT":
            captured.append(request.data)
            response = MagicMock()
            response.status = 204
            response.__enter__ = lambda self: self
            response.__exit__ = lambda *args: None
            return response
        raise AssertionError(url)

    mock_urlopen.side_effect = urlopen
    set_repo_secret("http://localhost:3000", "tok", "o", "r", "SHIFT_LEFT_TOKEN", "slt_plain")
    assert captured
    body = json.loads(captured[0].decode())
    assert body == {"data": "slt_plain"}
    assert "key_id" not in body


@patch("shift_left_cli.forgejo_secrets._encrypt_secret", return_value="sealed")
@patch("shift_left_cli.forgejo_secrets.urllib.request.urlopen")
def test_set_repo_secret_encrypted_when_public_key_available(mock_urlopen, _mock_encrypt) -> None:
    captured: list[bytes] = []

    def urlopen(request, timeout=10):  # noqa: ARG001
        url = request.full_url
        if url.endswith("/actions/secrets/public-key"):
            payload = json.dumps({"key_id": "kid1", "key": "fixture"}).encode()
            response = MagicMock()
            response.status = 200
            response.read.return_value = payload
            response.__enter__ = lambda self: self
            response.__exit__ = lambda *args: None
            return response
        if request.method == "PUT":
            captured.append(request.data)
            response = MagicMock()
            response.status = 201
            response.__enter__ = lambda self: self
            response.__exit__ = lambda *args: None
            return response
        raise AssertionError(url)

    mock_urlopen.side_effect = urlopen
    set_repo_secret("http://localhost:3000", "tok", "o", "r", "SHIFT_LEFT_TOKEN", "slt_x")
    body = json.loads(captured[0].decode())
    assert body == {"data": "sealed", "key_id": "kid1"}


@patch("shift_left_cli.forgejo_secrets.urllib.request.urlopen")
def test_set_repo_secret_put_failure_surfaces(mock_urlopen) -> None:
    def urlopen(request, timeout=10):  # noqa: ARG001
        url = request.full_url
        if url.endswith("/actions/secrets/public-key"):
            raise urllib.error.HTTPError(url, 405, "nope", None, None)
        raise urllib.error.HTTPError(url, 403, "forbidden", None, None)

    mock_urlopen.side_effect = urlopen
    with pytest.raises(ForgejoSecretError, match="HTTP 403"):
        set_repo_secret("http://localhost:3000", "tok", "o", "r", "SHIFT_LEFT_TOKEN", "slt_x")
