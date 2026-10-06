"""Offline localization CWE candidate catalog for investigation launch picker."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from shift_left.config import resolve_repo_root
from shift_left.investigations.suitability import STRONG_CWES, WEAK_CWES
from shift_left.ui.cwe_dictionary import normalize_cwe_id

_CANDIDATES_REL = Path("data") / "cwe" / "localization-candidates.json"
_LOCALIZATION_ABSTRACTIONS = frozenset({"Base", "Variant"})
_TRACTABILITY_SOURCE_DOC = "models/1b/README.md"


def localization_candidates_path() -> Path:
    return resolve_repo_root() / _CANDIDATES_REL


@lru_cache(maxsize=1)
def load_localization_candidates() -> dict[str, Any]:
    """Load bundled localization candidate catalog (local file only)."""
    path = localization_candidates_path()
    if not path.is_file():
        return {"_meta": {}, "entries": []}
    return json.loads(path.read_text(encoding="utf-8"))


def localization_candidate_entries() -> list[dict[str, Any]]:
    payload = load_localization_candidates()
    entries = payload.get("entries") or []
    return [entry for entry in entries if isinstance(entry, dict)]


def localization_candidate_by_id(cwe_id: str) -> dict[str, Any] | None:
    normalized = normalize_cwe_id(cwe_id)
    for entry in localization_candidate_entries():
        if normalize_cwe_id(str(entry.get("id") or "")) == normalized:
            return entry
    return None


def entries_missing_descriptions() -> list[str]:
    missing: list[str] = []
    for entry in localization_candidate_entries():
        cwe_id = str(entry.get("id") or "")
        description = str(entry.get("short_description") or "").strip()
        if not description:
            missing.append(cwe_id)
    return sorted(missing)


def entries_with_invalid_abstraction() -> list[str]:
    invalid: list[str] = []
    for entry in localization_candidate_entries():
        abstraction = str(entry.get("abstraction") or "")
        if abstraction not in _LOCALIZATION_ABSTRACTIONS:
            invalid.append(str(entry.get("id") or ""))
    return sorted(invalid)


def entries_with_tractability_missing_citation() -> list[str]:
    missing: list[str] = []
    for entry in localization_candidate_entries():
        tractability = str(entry.get("tractability") or "")
        if tractability not in {"strong", "weak"}:
            continue
        source = str(entry.get("tractability_source") or "").strip()
        if source != _TRACTABILITY_SOURCE_DOC:
            missing.append(str(entry.get("id") or ""))
    return sorted(missing)


def tractability_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in localization_candidate_entries():
        tractability = str(entry.get("tractability") or "unrated")
        counts[tractability] = counts.get(tractability, 0) + 1
    return counts


def abstraction_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in localization_candidate_entries():
        abstraction = str(entry.get("abstraction") or "")
        counts[abstraction] = counts.get(abstraction, 0) + 1
    return counts


def rated_tractability_cwes() -> frozenset[str]:
    return STRONG_CWES | WEAK_CWES
