"""Load CWE identifiers from the local reference-data cache (read-only)."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path


def _catalog_dirs() -> list[Path]:
    dirs: list[Path] = []
    for key in ("REFERENCE_DATA_CACHE_DIR", "SHIFT_LEFT_REFERENCE_CACHE"):
        raw = os.environ.get(key, "").strip()
        if raw:
            dirs.append(Path(raw) / "cwe")
    repo_root = Path(__file__).resolve().parents[3]
    dirs.append(repo_root / "reference-seed" / "cwe")
    dirs.append(repo_root / "data" / "reference" / "cwe")
    return dirs


@lru_cache(maxsize=1)
def load_cwe_catalog() -> frozenset[str]:
    """Return normalized CWE IDs present in the local catalog (e.g. CWE-89)."""
    ids: set[str] = set()
    for base in _catalog_dirs():
        if not base.is_dir():
            continue
        for path in base.glob("CWE-*.json"):
            ids.add(path.stem.upper())
        for path in base.glob("*.json"):
            if path.stem.upper().startswith("CWE-"):
                ids.add(path.stem.upper())
    return frozenset(ids)


def cwe_in_catalog(cwe_id: str, catalog: frozenset[str] | None = None) -> bool:
    catalog = catalog if catalog is not None else load_cwe_catalog()
    if not catalog:
        return False
    text = cwe_id.strip().upper()
    if not text.startswith("CWE-"):
        text = f"CWE-{text.replace('CWE', '').strip('-')}"
    return text in catalog
