"""Advisory model enrichment — prose excluded from determinism checks."""

from shift_left.enrichment.scripted import ScriptedEnrichmentEngine
from shift_left.enrichment.service import EnrichmentService

__all__ = ["EnrichmentService", "ScriptedEnrichmentEngine"]
