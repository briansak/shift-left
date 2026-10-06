"""Model enrichment orchestration — advisory prose only."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from shift_left.config import AppConfig, resolve_foundation_sec_service_url
from shift_left.enrichment.scripted import ScriptedEnrichmentEngine
from shift_left.http.local_client import LocalOnlyAsyncClient
from shift_left.models.schema import Finding, ReviewSummary
from shift_left.sovereignty.network import AllowedEndpoint

logger = logging.getLogger(__name__)


class EnrichmentService:
    """
    Enriches findings with advisory prose and optional review summary.

    Enrichment failure must not fail review — callers set enrichment_unavailable.
    """

    def __init__(
        self,
        config: AppConfig,
        *,
        http: LocalOnlyAsyncClient,
        allowed_endpoints: frozenset[AllowedEndpoint],
    ) -> None:
        self._config = config
        self._http = http
        self._allowed_endpoints = allowed_endpoints
        self._scripted = ScriptedEnrichmentEngine()
        self._service_url = resolve_foundation_sec_service_url(config).rstrip("/")

    @property
    def enabled(self) -> bool:
        return self._config.enrichment.enabled

    async def enrich_findings(self, findings: list[Finding]) -> tuple[list[Finding], bool]:
        """
        Apply model enrichment prose to findings.

        Returns (updated_findings, enrichment_unavailable).
        """
        if not self.enabled or not findings or not self._config.enrichment.enrich_findings:
            return findings, False

        try:
            if self._config.enrichment.engine == "scripted":
                payloads = self._scripted.enrich_findings(findings)
            else:
                payloads = await self._call_remote_enrich(findings)
            return self._merge_finding_enrichment(findings, payloads), False
        except Exception as exc:  # noqa: BLE001
            logger.warning("Finding enrichment unavailable: %s", exc)
            return findings, True

    async def generate_review_summary(
        self,
        findings: list[Finding],
    ) -> ReviewSummary | None:
        if not self.enabled or not self._config.enrichment.generate_review_summary:
            return None
        try:
            if self._config.enrichment.engine == "scripted":
                return self._scripted.generate_review_summary(findings)
            return await self._call_remote_review_summary(findings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Review summary unavailable: %s", exc)
            return None

    async def _call_remote_enrich(self, findings: list[Finding]) -> list[dict[str, Any]]:
        response = await self._http.post(
            f"{self._service_url}/v1/enrich-findings",
            json={"findings": [finding.model_dump(mode="json") for finding in findings]},
        )
        response.raise_for_status()
        data = response.json()
        return list(data.get("enrichments") or [])

    async def _call_remote_review_summary(self, findings: list[Finding]) -> ReviewSummary:
        response = await self._http.post(
            f"{self._service_url}/v1/review-summary",
            json={"findings": [finding.model_dump(mode="json") for finding in findings]},
        )
        response.raise_for_status()
        data = response.json()
        summary = data.get("review_summary") or data
        return ReviewSummary.model_validate(summary)

    @staticmethod
    def _merge_finding_enrichment(
        findings: list[Finding],
        payloads: list[dict[str, Any]],
    ) -> list[Finding]:
        by_id = {str(item.get("finding_id")): item for item in payloads if item.get("finding_id")}
        merged: list[Finding] = []
        for finding in findings:
            payload = by_id.get(finding.id)
            if not payload:
                merged.append(finding)
                continue
            generated_at = payload.get("enrichment_generated_at")
            parsed_at: datetime | None = None
            if generated_at:
                parsed_at = datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
            merged.append(
                finding.model_copy(
                    update={
                        "model_context": payload.get("model_context"),
                        "recommended_actions": list(payload.get("recommended_actions") or []),
                        "enrichment_source": payload.get("enrichment_source"),
                        "enrichment_generated_at": parsed_at,
                    }
                )
            )
        return merged
