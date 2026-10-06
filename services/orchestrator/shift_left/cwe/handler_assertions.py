"""Handler registry CWE assertions for reference UI cross-reference."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from shift_left.cwe.localization_candidates import localization_candidate_by_id
from shift_left.handlers.code.registry import ALL_CODE_RULES
from shift_left.handlers.config.rules.registry import ALL_RULES
from shift_left.ui.cwe_dictionary import normalize_cwe_id

HandlerAssertionSource = Literal["config", "code"]


@dataclass(frozen=True)
class HandlerAssertion:
    rule_id: str
    source: HandlerAssertionSource
    description: str
    target_type: str | None = None


@lru_cache(maxsize=1)
def handler_assertions_by_cwe() -> dict[str, list[HandlerAssertion]]:
    """Map normalized CWE id to deterministic handler rules that assert it."""
    by_cwe: dict[str, list[HandlerAssertion]] = {}
    for rule in ALL_RULES:
        cwe_id = normalize_cwe_id(rule.cwe)
        by_cwe.setdefault(cwe_id, []).append(
            HandlerAssertion(
                rule_id=rule.id,
                source="config",
                description=rule.description,
                target_type=rule.target_type,
            )
        )
    for rule in ALL_CODE_RULES:
        cwe_id = normalize_cwe_id(rule.handler_asserted_cwe)
        by_cwe.setdefault(cwe_id, []).append(
            HandlerAssertion(
                rule_id=rule.id,
                source="code",
                description=rule.description,
            )
        )
    for cwe_id in by_cwe:
        by_cwe[cwe_id].sort(key=lambda item: (item.source, item.rule_id))
    return by_cwe


@lru_cache(maxsize=1)
def handler_asserted_cwe_ids() -> frozenset[str]:
    return frozenset(handler_assertions_by_cwe().keys())


def handler_assertions_for_cwe(cwe_id: str) -> list[HandlerAssertion]:
    return list(handler_assertions_by_cwe().get(normalize_cwe_id(cwe_id), ()))


@lru_cache(maxsize=1)
def handler_asserted_in_catalog_ids() -> frozenset[str]:
    return frozenset(
        cwe_id
        for cwe_id in handler_asserted_cwe_ids()
        if localization_candidate_by_id(cwe_id) is not None
    )


@lru_cache(maxsize=1)
def handler_asserted_out_of_catalog_ids() -> frozenset[str]:
    return handler_asserted_cwe_ids() - handler_asserted_in_catalog_ids()
