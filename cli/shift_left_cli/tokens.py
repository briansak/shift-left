"""Operator CLI for API token lifecycle."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from shift_left.auth.context import TokenCapability
from shift_left.auth.tokens import TokenStore, mint_api_token
from shift_left.config import load_config, resolve_auth_sqlite_path


def _load_store(root: Path) -> TokenStore:
    config_path = root / "config" / "shift-left.yaml"
    if not config_path.exists():
        config_path = root / "config" / "shift-left.example.yaml"
    config = load_config(config_path)
    return TokenStore(resolve_auth_sqlite_path(config))


def token_mint(
    root: Path,
    *,
    label: str,
    actor: str,
    capabilities: str,
    audit_store=None,
) -> None:
    caps = [TokenCapability(item.strip()) for item in capabilities.split(",") if item.strip()]
    store = _load_store(root)
    record, plaintext = mint_api_token(
        store,
        label=label,
        actor=actor,
        capabilities=caps,
    )
    if audit_store is not None:
        audit_store.log(
            actor="operator:cli",
            action="token.minted",
            subject=record.id,
            details={
                "label": label,
                "actor": actor,
                "capabilities": sorted(cap.value for cap in record.capabilities),
            },
        )
    print("Token minted (store this value — it cannot be retrieved again):")
    print(plaintext)
    print(f"Token id: {record.id}")


def token_list(root: Path) -> None:
    store = _load_store(root)
    records = store.list_tokens()
    print(json.dumps(
        [
            {
                "id": item.id,
                "label": item.label,
                "actor": item.actor,
                "capabilities": sorted(cap.value for cap in item.capabilities),
                "created_at": item.created_at.isoformat(),
                "revoked": item.revoked,
            }
            for item in records
        ],
        indent=2,
    ))


def token_revoke(root: Path, *, token_id: str, audit_store=None) -> None:
    store = _load_store(root)
    revoked = store.revoke(token_id)
    if not revoked:
        print(f"Token not found or already revoked: {token_id}", file=sys.stderr)
        raise SystemExit(1)
    if audit_store is not None:
        audit_store.log(
            actor="operator:cli",
            action="token.revoked",
            subject=token_id,
            details={"immediate": True},
        )
    print(f"Revoked token {token_id} (effective immediately)")
