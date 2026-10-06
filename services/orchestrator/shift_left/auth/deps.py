"""FastAPI dependencies for token-derived identity."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Request

from shift_left.auth.context import AuthContext, TokenCapability
from shift_left.auth.tokens import TokenStore

TOKEN_COOKIE_NAME = "shift_left_token"


def _extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def get_token_store(request: Request) -> TokenStore:
    return request.app.state.token_store


def resolve_request_token(
    request: Request,
    authorization: str | None = None,
    x_shift_left_token: str | None = None,
) -> str | None:
    return (
        _extract_bearer(authorization)
        or x_shift_left_token
        or request.cookies.get(TOKEN_COOKIE_NAME)
    )


def authenticate_token(request: Request, raw: str | None) -> AuthContext:
    if not raw:
        raise HTTPException(status_code=401, detail="API token required (Authorization: Bearer slt_...)")
    store: TokenStore = request.app.state.token_store
    record = store.authenticate(raw)
    if record is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API token")
    return AuthContext(
        token_id=record.id,
        actor=record.actor,
        capabilities=record.capabilities,
    )


def get_auth_context(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_shift_left_token: Annotated[str | None, Header(alias="X-Shift-Left-Token")] = None,
) -> AuthContext:
    raw = resolve_request_token(request, authorization, x_shift_left_token)
    return authenticate_token(request, raw)


def require_capability(capability: TokenCapability):
    def dependency(auth: AuthContext = Depends(get_auth_context)) -> AuthContext:
        try:
            auth.require_capability(capability)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return auth

    return dependency


FORBIDDEN_ACTOR_FIELDS = frozenset({"actor", "approver"})


def reject_client_actor_fields(payload: dict[str, Any] | None) -> None:
    if not payload:
        return
    present = FORBIDDEN_ACTOR_FIELDS.intersection(payload.keys())
    if present:
        joined = ", ".join(sorted(present))
        raise HTTPException(
            status_code=400,
            detail=(
                f"Client-supplied identity field(s) rejected: {joined}. "
                "Actor is derived from the API token."
            ),
        )
