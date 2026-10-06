"""Validate handler rule CWE identifiers against the local reference catalog."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path


class UnknownHandlerCweError(ValueError):
    """Raised when a handler rule references a CWE absent from the local catalog."""


@lru_cache(maxsize=1)
def load_handler_cwe_catalog() -> frozenset[str]:
    ids: set[str] = set()
    for key in ("REFERENCE_DATA_CACHE_DIR", "SHIFT_LEFT_REFERENCE_CACHE"):
        raw = os.environ.get(key, "").strip()
        if raw:
            base = Path(raw) / "cwe"
            if base.is_dir():
                ids.update(path.stem.upper() for path in base.glob("CWE-*.json"))
    for default in ("/data/reference",):
        base = Path(default) / "cwe"
        if base.is_dir():
            ids.update(path.stem.upper() for path in base.glob("CWE-*.json"))
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        seed = ancestor / "reference-seed" / "cwe"
        if seed.is_dir():
            ids.update(path.stem.upper() for path in seed.glob("CWE-*.json"))
            break
    return frozenset(ids)


def normalize_cwe(value: str) -> str:
    text = value.strip().upper()
    if not text.startswith("CWE-"):
        text = f"CWE-{text.replace('CWE', '').strip('-')}"
    return text


def assert_cwe_in_catalog(cwe_id: str, *, rule_id: str) -> None:
    catalog = load_handler_cwe_catalog()
    normalized = normalize_cwe(cwe_id)
    if not catalog:
        raise UnknownHandlerCweError(
            f"rule {rule_id}: local CWE catalog is empty — sync reference data before loading handlers"
        )
    if normalized not in catalog:
        raise UnknownHandlerCweError(
            f"rule {rule_id}: unknown handler_asserted_cwe {normalized!r} — not present in local CWE catalog"
        )
