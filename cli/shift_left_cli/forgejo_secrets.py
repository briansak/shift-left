"""Forgejo Actions repository secrets.

Forgejo 11.x accepts plaintext ``data`` on PUT and encrypts server-side. Some
Gitea/Forgejo builds also expose a GitHub-compatible public-key endpoint; we use
that when available and fall back to plaintext for Forgejo.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request


class ForgejoSecretError(RuntimeError):
    pass


def _nacl_modules():
    try:
        from nacl import encoding, public
    except ImportError as exc:
        raise ForgejoSecretError(
            "PyNaCl is required for encrypted Forgejo Actions secret setup. "
            "Re-run ./shift-left (refreshes .venv) or: .venv/bin/pip install pynacl"
        ) from exc
    return encoding, public


def set_repo_secret(
    base: str,
    token: str,
    owner: str,
    repo: str,
    secret_name: str,
    secret_value: str,
) -> None:
    public_key_info = _try_fetch_public_key(base, token, owner, repo)
    if public_key_info is None:
        body = json.dumps({"data": secret_value}).encode()
    else:
        key_id, public_key = public_key_info
        encrypted = _encrypt_secret(public_key, secret_value)
        body = json.dumps({"data": encrypted, "key_id": key_id}).encode()

    request = urllib.request.Request(  # noqa: S310
        f"{base.rstrip('/')}/api/v1/repos/{owner}/{repo}/actions/secrets/{secret_name}",
        data=body,
        method="PUT",
        headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status not in {201, 204}:
                raise ForgejoSecretError(f"Unexpected HTTP {response.status} setting {secret_name}")
    except urllib.error.HTTPError as exc:
        raise ForgejoSecretError(
            f"Failed to set Forgejo secret {secret_name} on {owner}/{repo}: HTTP {exc.code}"
        ) from exc


def _try_fetch_public_key(base: str, token: str, owner: str, repo: str) -> tuple[str, str] | None:
    """Return (key_id, public_key) when the server supports GitHub-style sealing."""
    request = urllib.request.Request(  # noqa: S310
        f"{base.rstrip('/')}/api/v1/repos/{owner}/{repo}/actions/secrets/public-key",
        headers={"Authorization": f"token {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code in {404, 405}:
            return None
        raise ForgejoSecretError(
            f"Failed to read Actions public key for {owner}/{repo}: HTTP {exc.code}"
        ) from exc
    key_id = str(payload.get("key_id") or "")
    public_key = str(payload.get("key") or "")
    if not key_id or not public_key:
        return None
    return key_id, public_key


def _encrypt_secret(public_key: str, secret_value: str) -> str:
    encoding, public = _nacl_modules()
    key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed = public.SealedBox(key).encrypt(secret_value.encode("utf-8"))
    return base64.b64encode(sealed).decode("utf-8")
