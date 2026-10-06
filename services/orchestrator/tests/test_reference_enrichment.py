"""Reference cache and enrichment unit tests."""

from __future__ import annotations

from shift_left.models.schema import (
    EnrichmentStatus,
    Finding,
    FindingSource,
    Severity,
    TargetKind,
)
from shift_left.reference.cache import ReferenceDataCache
from shift_left.reference.enricher import FindingEnricher


def test_enrichment_degrades_when_cache_empty(tmp_path) -> None:
    cache = ReferenceDataCache(tmp_path / "empty")
    enricher = FindingEnricher(cache)
    finding = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="a/b",
        pr_ref="PR-1",
        commit_sha="sha",
        file_path="x.tf",
        cwe="CWE-284",
        title="Test",
        description="Test",
        severity=Severity.HIGH,
        confidence=0.8,
    )
    enriched = enricher.enrich([finding])[0]
    assert enriched.enrichment is not None
    assert enriched.enrichment.status == EnrichmentStatus.CACHE_EMPTY


def test_enrichment_attaches_cwe_from_cache(reference_cache_dir) -> None:
    cache = ReferenceDataCache(reference_cache_dir)
    enricher = FindingEnricher(cache)
    finding = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="a/b",
        pr_ref="PR-1",
        commit_sha="sha",
        file_path="x.tf",
        cwe="CWE-284",
        title="Test",
        description="Test",
        severity=Severity.HIGH,
        confidence=0.8,
    )
    enriched = enricher.enrich([finding])[0]
    assert enriched.enrichment is not None
    assert enriched.enrichment.status == EnrichmentStatus.ENRICHED
    assert enriched.enrichment.cwe_detail
    assert "unauthorized" in enriched.enrichment.cwe_detail.lower()
