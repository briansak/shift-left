"""Deterministic repository profiler — scope selection, not detection."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from shift_left.config import resolve_repo_root
from shift_left.cwe.localization_candidates import localization_candidate_by_id
from shift_left.profiler.surfaces import (
    EvidenceItem,
    ManifestEvidence,
    languages_by_extension,
    load_surface_to_cwe,
    scan_callsite_surfaces,
    scan_import_surfaces,
    scan_manifests,
)
from shift_left.ui.cwe_dictionary import normalize_cwe_id

RelevanceTier = Literal["direct", "indirect", "language-only"]

_TIER_RANK = {"direct": 0, "indirect": 1, "language-only": 2}
_TRACTABILITY_RANK = {"strong": 0, "weak": 1, "unrated": 2}

_DIRECT_SURFACES = frozenset({"raw_sql_callsite"})
_INDIRECT_SURFACES = frozenset(
    {
        "database_driver",
        "orm",
        "web_framework",
        "template_engine",
        "serialization",
        "subprocess_shell",
        "http_client",
        "crypto_api",
        "file_path_api",
        "authz_api",
    }
)


@dataclass(frozen=True)
class ProfileEvidence:
    kind: Literal["manifest", "import", "callsite"]
    surface: str
    file: str | None
    line: int | None
    detail: str


@dataclass
class ProfiledCWE:
    cwe_id: str
    name: str
    tractability: str
    relevance_tier: RelevanceTier
    surfaces: list[str] = field(default_factory=list)
    evidence: list[ProfileEvidence] = field(default_factory=list)


@dataclass
class ProfileResult:
    repo_root: str
    languages: dict[str, int]
    manifest_evidence: list[ManifestEvidence]
    import_evidence: list[EvidenceItem]
    callsite_evidence: list[EvidenceItem]
    suggestions: list[ProfiledCWE]

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "repo_root": self.repo_root,
            "languages": self.languages,
            "manifest_evidence": [
                {
                    "manifest": item.manifest,
                    "entry": item.entry,
                    "surfaces": list(item.surfaces),
                }
                for item in self.manifest_evidence
            ],
            "import_evidence": [
                {
                    "surface": item.surface,
                    "file": item.file,
                    "line": item.line,
                    "detail": item.detail,
                }
                for item in self.import_evidence
            ],
            "callsite_evidence": [
                {
                    "surface": item.surface,
                    "file": item.file,
                    "line": item.line,
                    "detail": item.detail,
                }
                for item in self.callsite_evidence
            ],
            "suggestions": [
                {
                    "cwe_id": item.cwe_id,
                    "name": item.name,
                    "tractability": item.tractability,
                    "relevance_tier": item.relevance_tier,
                    "surfaces": item.surfaces,
                    "evidence": [
                        {
                            "kind": ev.kind,
                            "surface": ev.surface,
                            "file": ev.file,
                            "line": ev.line,
                            "detail": ev.detail,
                        }
                        for ev in item.evidence
                    ],
                }
                for item in self.suggestions
            ],
        }


def profile_repository(repo_root: Path) -> ProfileResult:
    """Profile a repository checkout for CWE scope suggestions."""
    repo_root = repo_root.resolve()
    languages = languages_by_extension(repo_root)
    manifest_evidence = scan_manifests(repo_root)
    import_evidence = scan_import_surfaces(repo_root)
    callsite_evidence = scan_callsite_surfaces(repo_root)
    suggestions = _build_suggestions(
        languages=languages,
        manifest_evidence=manifest_evidence,
        import_evidence=import_evidence,
        callsite_evidence=callsite_evidence,
    )
    return ProfileResult(
        repo_root=str(repo_root),
        languages=languages,
        manifest_evidence=manifest_evidence,
        import_evidence=import_evidence,
        callsite_evidence=callsite_evidence,
        suggestions=suggestions,
    )


def _build_suggestions(
    *,
    languages: dict[str, int],
    manifest_evidence: list[ManifestEvidence],
    import_evidence: list[EvidenceItem],
    callsite_evidence: list[EvidenceItem],
) -> list[ProfiledCWE]:
    surface_map = load_surface_to_cwe()
    by_cwe: dict[str, ProfiledCWE] = {}

    def ensure(cwe_id: str) -> ProfiledCWE | None:
        normalized = normalize_cwe_id(cwe_id)
        if normalized in by_cwe:
            return by_cwe[normalized]
        catalog = localization_candidate_by_id(normalized)
        if catalog is None:
            return None
        item = ProfiledCWE(
            cwe_id=normalized,
            name=str(catalog.get("name") or ""),
            tractability=str(catalog.get("tractability") or "unrated"),
            relevance_tier="language-only",
        )
        by_cwe[normalized] = item
        return item

    def attach(
        cwe_id: str,
        *,
        surface: str,
        tier: RelevanceTier,
        evidence: ProfileEvidence,
    ) -> None:
        item = ensure(cwe_id)
        if item is None:
            return
        if surface not in item.surfaces:
            item.surfaces.append(surface)
        item.evidence.append(evidence)
        if _TIER_RANK[tier] < _TIER_RANK[item.relevance_tier]:
            item.relevance_tier = tier

    for manifest in manifest_evidence:
        for surface in manifest.surfaces:
            for cwe_id in surface_map.get(surface, {}).get("cwes", []):
                attach(
                    cwe_id,
                    surface=surface,
                    tier="indirect",
                    evidence=ProfileEvidence(
                        kind="manifest",
                        surface=surface,
                        file=manifest.manifest,
                        line=None,
                        detail=manifest.entry,
                    ),
                )

    for item in import_evidence:
        for cwe_id in surface_map.get(item.surface, {}).get("cwes", []):
            attach(
                cwe_id,
                surface=item.surface,
                tier="indirect",
                evidence=ProfileEvidence(
                    kind="import",
                    surface=item.surface,
                    file=item.file,
                    line=item.line,
                    detail=item.detail,
                ),
            )

    for item in callsite_evidence:
        tier: RelevanceTier = "direct" if item.surface in _DIRECT_SURFACES else "indirect"
        for cwe_id in surface_map.get(item.surface, {}).get("cwes", []):
            attach(
                cwe_id,
                surface=item.surface,
                tier=tier,
                evidence=ProfileEvidence(
                    kind="callsite",
                    surface=item.surface,
                    file=item.file,
                    line=item.line,
                    detail=item.detail,
                ),
            )

    suggestions = [item for item in by_cwe.values() if item.evidence]
    suggestions.sort(key=_suggestion_sort_key)
    return suggestions


def _suggestion_sort_key(item: ProfiledCWE) -> tuple[int, int, str]:
    return (
        _TIER_RANK[item.relevance_tier],
        _TRACTABILITY_RANK.get(item.tractability, 99),
        item.cwe_id,
    )


@lru_cache(maxsize=1)
def load_top25_ranks() -> dict[str, int]:
    path = resolve_repo_root() / "data" / "cwe" / "cwe-top-25-2024.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        normalize_cwe_id(str(entry["id"])): int(entry["rank"])
        for entry in payload.get("entries", [])
    }


def profiler_tier_by_cwe(profile_snapshot: dict[str, Any]) -> dict[str, RelevanceTier]:
    """Map CWE id to best profiler relevance tier from a profile snapshot."""
    tiers: dict[str, RelevanceTier] = {}
    for item in profile_snapshot.get("suggestions", []):
        cwe_id = normalize_cwe_id(str(item.get("cwe_id") or ""))
        tier = str(item.get("relevance_tier") or "language-only")
        if tier not in _TIER_RANK:
            tier = "language-only"
        if cwe_id not in tiers or _TIER_RANK[tier] < _TIER_RANK[tiers[cwe_id]]:
            tiers[cwe_id] = tier  # type: ignore[assignment]
    return tiers


def sort_batch_cwes(
    items: list[tuple[str, str | None, str]],
) -> list[tuple[str, str | None, str]]:
    """Sort (cwe_id, evidence_tier, tractability) for batch enqueue order."""

    top25_ranks = load_top25_ranks()

    def key(row: tuple[str, str | None, str]) -> tuple[int, int, int, str]:
        cwe_id, tier, tractability = row
        tier_rank = _TIER_RANK.get(tier or "language-only", 99)
        tract_rank = _TRACTABILITY_RANK.get(tractability or "unrated", 99)
        top25_rank = top25_ranks.get(cwe_id, 999)
        return tier_rank, tract_rank, top25_rank, cwe_id

    return sorted(items, key=key)
