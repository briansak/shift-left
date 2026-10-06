"""Validate config handler CWE identifiers against the local catalog."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from foundation_sec_server.handlers.cwe_rules import CONFIG_HANDLER_RULES
from shift_left.handlers.config.rules.registry import ALL_RULES, validate_config_rules


class UnknownHandlerCweError(ValueError):
    pass


@lru_cache(maxsize=1)
def load_handler_cwe_catalog() -> frozenset[str]:
    ids: set[str] = set()
    for key in ("REFERENCE_DATA_CACHE_DIR", "SHIFT_LEFT_REFERENCE_CACHE"):
        raw = os.environ.get(key, "").strip()
        if raw:
            base = Path(raw) / "cwe"
            if base.is_dir():
                ids.update(path.stem.upper() for path in base.glob("CWE-*.json"))
    repo_root = Path(__file__).resolve().parents[3]
    seed = repo_root / "reference-seed" / "cwe"
    if seed.is_dir():
        ids.update(path.stem.upper() for path in seed.glob("CWE-*.json"))
    return frozenset(ids)


def validate_config_handler_rules() -> None:
    catalog = load_handler_cwe_catalog()
    if not catalog:
        raise UnknownHandlerCweError("local CWE catalog is empty — sync reference data before loading handlers")
    for rule in CONFIG_HANDLER_RULES:
        cwe = rule.cwe.upper()
        if cwe not in catalog:
            raise UnknownHandlerCweError(
                f"config handler rule {rule.id}: unknown CWE {cwe!r} — not in local catalog"
            )
    validate_config_rules(ALL_RULES)


validate_config_handler_rules()
