"""Shared policy action helpers."""

from __future__ import annotations

from shift_left.models.schema import PolicyAction

_ACTION_RANK = {
    PolicyAction.PASS: 0,
    PolicyAction.FLAG: 1,
    PolicyAction.BLOCK: 2,
}


def strictest_action(actions: list[PolicyAction]) -> PolicyAction:
    if not actions:
        return PolicyAction.FLAG
    return max(actions, key=lambda item: _ACTION_RANK[item])
