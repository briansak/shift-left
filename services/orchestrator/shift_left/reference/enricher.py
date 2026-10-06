"""Attach local CVE/CWE reference data to model findings — never uses network."""

from __future__ import annotations

import logging

from shift_left.models.schema import EnrichmentStatus, Finding, FindingEnrichment
from shift_left.reference.cache import ReferenceDataCache

logger = logging.getLogger(__name__)


class FindingEnricher:
    def __init__(self, cache: ReferenceDataCache) -> None:
        self._cache = cache

    def enrich(self, findings: list[Finding]) -> list[Finding]:
        status = self._cache.cache_status()
        if not status["present"]:
            logger.info("Reference cache empty — findings marked unenriched")
            return [self._mark_unenriched(f, EnrichmentStatus.CACHE_EMPTY) for f in findings]

        stale = status["stale"]
        base_status = EnrichmentStatus.CACHE_STALE if stale else EnrichmentStatus.ENRICHED

        enriched: list[Finding] = []
        for finding in findings:
            enriched.append(self._enrich_one(finding, status, base_status))
        return enriched

    def _mark_unenriched(self, finding: Finding, status: EnrichmentStatus) -> Finding:
        note = (
            "Reference cache empty — run 'shift-left sync-reference-data' to enable enrichment."
            if status == EnrichmentStatus.CACHE_EMPTY
            else "Reference cache stale — run sync-reference-data to refresh."
        )
        return finding.model_copy(
            update={
                "enrichment": FindingEnrichment(status=status, note=note, stale=True),
            }
        )

    def _enrich_one(
        self,
        finding: Finding,
        cache_status: dict,
        base_status: EnrichmentStatus,
    ) -> Finding:
        stale = bool(cache_status.get("stale"))
        cwe_detail: str | None = None
        cve_summaries: list[str] = []
        partial = False

        if finding.cwe:
            cwe_meta = self._cache.lookup_cwe(finding.cwe)
            if cwe_meta:
                cwe_detail = cwe_meta.get("name") or cwe_meta.get("description")
                if cwe_meta.get("description"):
                    cwe_detail = cwe_meta["description"][:800]
            else:
                partial = True

        for cve_id in finding.cve_refs:
            cve_meta = self._cache.lookup_cve(cve_id)
            if cve_meta:
                summary = cve_meta.get("summary") or cve_meta.get("description", "")
                cve_summaries.append(f"{cve_id}: {summary[:300]}")
            else:
                partial = True

        if not finding.cwe and not finding.cve_refs:
            status = base_status if not stale else EnrichmentStatus.CACHE_STALE
            if status == EnrichmentStatus.ENRICHED and not cwe_detail and not cve_summaries:
                status = EnrichmentStatus.NONE
        elif partial:
            status = EnrichmentStatus.PARTIAL
        else:
            status = base_status

        note = None
        if stale:
            note = (
                f"Reference sync completed at {cache_status.get('synced_at')}. "
                f"Newest ingested CVE lastModified: {cache_status.get('newest_last_modified')}. "
                f"Threshold: {self._cache.max_staleness_days} days."
            )
        elif status == EnrichmentStatus.PARTIAL:
            note = "Some CWE/CVE entries were not found in the local cache."

        enrichment = FindingEnrichment(
            status=status,
            cwe_detail=cwe_detail,
            cve_summaries=cve_summaries,
            reference_data_version=cache_status.get("data_version"),
            reference_synced_at=_parse_ts(cache_status.get("synced_at")),
            stale=stale,
            note=note,
        )
        return finding.model_copy(update={"enrichment": enrichment})


def _parse_ts(value: str | None):
    if not value:
        return None
    from datetime import datetime

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
