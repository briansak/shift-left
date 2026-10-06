"""Authentication context derived from API tokens."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TokenCapability(str, Enum):
    REVIEW = "review"
    TRIAGE = "triage"
    APPROVE = "approve"
    DEPLOY = "deploy"
    OVERRIDE = "override"
    ADMIN = "admin"


ALL_CAPABILITIES = frozenset(TokenCapability)


@dataclass(frozen=True)
class AuthContext:
    token_id: str
    actor: str
    capabilities: frozenset[TokenCapability]

    def has_capability(self, capability: TokenCapability) -> bool:
        if TokenCapability.ADMIN in self.capabilities:
            return True
        return capability in self.capabilities

    def require_capability(self, capability: TokenCapability) -> None:
        if not self.has_capability(capability):
            raise PermissionError(
                f"Token lacks required capability '{capability.value}' "
                f"(held: {sorted(c.value for c in self.capabilities)})"
            )
