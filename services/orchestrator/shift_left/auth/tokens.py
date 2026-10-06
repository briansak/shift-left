"""Hashed API token issuance and validation."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from shift_left.auth.context import TokenCapability
from shift_left.models.schema import utc_now

TOKEN_PREFIX = "slt_"


class _TokenBase(DeclarativeBase):
    pass


class ApiTokenRow(_TokenBase):
    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    label: Mapped[str] = mapped_column(String(256))
    actor: Mapped[str] = mapped_column(String(256))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    capabilities_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


@dataclass(frozen=True)
class ApiTokenRecord:
    id: str
    label: str
    actor: str
    capabilities: frozenset[TokenCapability]
    created_at: datetime
    revoked: bool


def _token_pepper() -> str:
    return os.environ.get("SHIFT_LEFT_TOKEN_PEPPER", "shift-left-dev-pepper-change-in-production")


def hash_token(plaintext: str) -> str:
    material = f"{_token_pepper()}:{plaintext}".encode()
    return hashlib.sha256(material).hexdigest()


def mint_api_token(
    store: TokenStore,
    *,
    label: str,
    actor: str,
    capabilities: list[TokenCapability],
) -> tuple[ApiTokenRecord, str]:
    if not actor.strip():
        raise ValueError("actor is required when minting a token")
    if not capabilities:
        raise ValueError("At least one capability is required")
    plaintext = f"{TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    record = store.create(
        label=label.strip(),
        actor=actor.strip(),
        capabilities=frozenset(capabilities),
        token_hash=hash_token(plaintext),
    )
    return record, plaintext


class TokenStore:
    def __init__(self, sqlite_path: str) -> None:
        from pathlib import Path

        path = Path(sqlite_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._engine = create_engine(f"sqlite:///{path}", future=True)
        _TokenBase.metadata.create_all(self._engine)
        self._session_factory = sessionmaker(self._engine, expire_on_commit=False)

    def create(
        self,
        *,
        label: str,
        actor: str,
        capabilities: frozenset[TokenCapability],
        token_hash: str,
    ) -> ApiTokenRecord:
        row = ApiTokenRow(
            id=str(uuid4()),
            label=label,
            actor=actor,
            token_hash=token_hash,
            capabilities_json=json.dumps(sorted(cap.value for cap in capabilities)),
            created_at=utc_now(),
            revoked_at=None,
        )
        with self._session_factory() as session:
            session.add(row)
            session.commit()
        return self._to_record(row)

    def authenticate(self, plaintext: str) -> ApiTokenRecord | None:
        if not plaintext.startswith(TOKEN_PREFIX):
            return None
        digest = hash_token(plaintext)
        with self._session_factory() as session:
            row = session.scalars(
                select(ApiTokenRow).where(ApiTokenRow.token_hash == digest)
            ).first()
            if row is None or row.revoked_at is not None:
                return None
            return self._to_record(row)

    def revoke(self, token_id: str) -> bool:
        with self._session_factory() as session:
            row = session.get(ApiTokenRow, token_id)
            if row is None or row.revoked_at is not None:
                return False
            row.revoked_at = utc_now()
            session.commit()
            return True

    def list_tokens(self) -> list[ApiTokenRecord]:
        with self._session_factory() as session:
            rows = session.scalars(select(ApiTokenRow).order_by(ApiTokenRow.created_at.desc())).all()
            return [self._to_record(row) for row in rows]

    @staticmethod
    def _to_record(row: ApiTokenRow) -> ApiTokenRecord:
        caps = frozenset(TokenCapability(value) for value in json.loads(row.capabilities_json or "[]"))
        return ApiTokenRecord(
            id=row.id,
            label=row.label,
            actor=row.actor,
            capabilities=caps,
            created_at=row.created_at,
            revoked=row.revoked_at is not None,
        )
