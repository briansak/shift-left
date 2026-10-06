"""Per-run shared secrets for Antares sandbox audit callback ingest."""

from __future__ import annotations

import hashlib
import secrets
import time

from fastapi import HTTPException, Request

from shift_left.auth.context import TokenCapability
from shift_left.auth.deps import _extract_bearer, authenticate_token

AUDIT_CALLBACK_TOKEN_PREFIX = "slat_"
_DEFAULT_TTL_SECONDS = 3600.0


def hash_audit_callback_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


class AuditCallbackTokenStore:
    """Short-lived tokens issued alongside audit_callback_url for triage runs."""

    def __init__(self, ttl_seconds: float = _DEFAULT_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._expires_at: dict[str, float] = {}

    def issue(self) -> str:
        token = f"{AUDIT_CALLBACK_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
        self._expires_at[hash_audit_callback_token(token)] = time.monotonic() + self._ttl_seconds
        return token

    def validate(self, token: str) -> bool:
        if not token.startswith(AUDIT_CALLBACK_TOKEN_PREFIX):
            return False
        digest = hash_audit_callback_token(token)
        expires_at = self._expires_at.get(digest)
        if expires_at is None:
            return False
        if time.monotonic() > expires_at:
            self._expires_at.pop(digest, None)
            return False
        return True


def verify_sandbox_audit_ingest(request: Request) -> None:
    """Require a valid API token (triage) or per-run audit callback secret."""
    raw = _extract_bearer(request.headers.get("Authorization"))
    if not raw:
        raise HTTPException(
            status_code=401,
            detail="Authorization required (Bearer slt_... API token or slat_... audit callback token)",
        )

    if raw.startswith(AUDIT_CALLBACK_TOKEN_PREFIX):
        store: AuditCallbackTokenStore = request.app.state.audit_callback_tokens
        if not store.validate(raw):
            raise HTTPException(status_code=401, detail="Invalid or expired audit callback token")
        return

    auth = authenticate_token(request, raw)
    try:
        auth.require_capability(TokenCapability.TRIAGE)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
