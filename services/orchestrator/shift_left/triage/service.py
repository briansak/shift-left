"""Operator-initiated Antares advisory triage — separate from the PR merge gate."""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

from shift_left.analysis.result import (
    AnalysisFailureClass,
    AnalysisStage,
    TargetAnalysisResult,
    completed_no_findings,
    failed_analysis,
)
from shift_left.antares.client import AntaresClient, PUBLISHED_FILE_F1
from shift_left.antares.sandbox_audit import (
    persist_sandbox_command_audit,
    sandbox_audit_callback_url,
)
from shift_left.config import (
    AppConfig,
    AntaresTriageConfig,
    resolve_antares_service_url,
    runtime_allowed_endpoints,
)
from shift_left.models.database import AuditStore
from shift_left.handlers.cwe_catalog import normalize_cwe
from shift_left.http.local_client import LocalOnlyAsyncClient
from shift_left.models.schema import LocalizationResult, RankedFileCandidate, TargetKind
from shift_left.reference.cache import ReferenceDataCache

logger = logging.getLogger(__name__)

PROHIBITED_TRIAGE_WORDS = re.compile(
    r"\b(vulnerabilit(y|ies)\s+found|detected|confirmed|exploit)\b",
    re.IGNORECASE,
)

ADVISORY_SUMMARY_TEMPLATE = (
    "Candidate files for review for {cwe} in {repo}@{ref}. "
    "Antares ranks files only — not line-level findings and not a merge gate signal. "
    "Published File F1 for {variant}: {file_f1}."
)


class AntaresTriageService:
    def __init__(
        self,
        config: AppConfig,
        *,
        audit: AuditStore | None = None,
        audit_callback_tokens: Any | None = None,
    ) -> None:
        self._config = config
        self._audit = audit
        self._audit_callback_tokens = audit_callback_tokens
        self._triage_cfg = config.antares_triage
        antares_cfg = config.models.antares
        self._client = AntaresClient(
            resolve_antares_service_url(config),
            timeout=float(antares_cfg.request_timeout_seconds),
            stage_timeouts=antares_cfg.stage_timeouts,
        )
        self._client._http = LocalOnlyAsyncClient(
            timeout=float(antares_cfg.request_timeout_seconds),
            allowed_endpoints=runtime_allowed_endpoints(config),
            stage_timeouts=antares_cfg.stage_timeouts,
        )
        self._reference = ReferenceDataCache(
            config.reference_data.cache_dir,
            max_staleness_days=config.reference_data.max_staleness_days,
        )

    def resolve_cwe(
        self,
        *,
        cwe: str | None,
        advisory_cve: str | None,
    ) -> tuple[str, str]:
        """Primary path: operator-supplied CWE. Optional: resolve CWE from local CVE cache."""
        if cwe:
            normalized = normalize_cwe(cwe)
            return normalized, f"operator-supplied {normalized}"

        if advisory_cve:
            detail = self._reference.lookup_cve(advisory_cve)
            if detail and detail.get("cwe_ids"):
                resolved = normalize_cwe(str(detail["cwe_ids"][0]))
                return resolved, f"resolved from local CVE cache {advisory_cve} → {resolved}"
            raise ValueError(
                f"CVE {advisory_cve!r} not present in local reference cache — "
                "supply task_cwe directly or run sync-reference-data"
            )

        raise ValueError("task_cwe is required (primary operator-supplied path)")

    def checkout_path(self, repo_slug: str) -> Path:
        owner, repo = repo_slug.split("/", 1)
        from shift_left.config import resolve_repo_relative_path

        root = resolve_repo_relative_path(self._triage_cfg.repos_checkout_dir)
        return root / owner / repo

    async def run_triage(
        self,
        *,
        repo: str,
        ref: str,
        cwe: str | None = None,
        cwe_description: str | None = None,
        advisory_cve: str | None = None,
        actor: str = "operator",
        audit_store: AuditStore | None = None,
    ) -> tuple[LocalizationResult, TargetAnalysisResult]:
        if not self._triage_cfg.enabled:
            raise RuntimeError("Antares triage is disabled in configuration")

        self._assert_minimum_variant()

        resolved_cwe, cwe_source = self.resolve_cwe(cwe=cwe, advisory_cve=advisory_cve)
        checkout = self.checkout_path(repo)
        if not checkout.is_dir():
            raise FileNotFoundError(
                f"Repo checkout not found at {checkout}. "
                "Operator must maintain a local checkout before triage "
                f"(see docs/antares-triage.md). CWE source: {cwe_source}."
            )

        agent_cfg = self._config.models.antares.agent
        started = time.monotonic()
        store = audit_store if audit_store is not None else self._audit
        audit_callback_url: str | None = None
        audit_callback_token: str | None = None
        if store is not None:
            audit_callback_url = sandbox_audit_callback_url(self._config)
            if self._audit_callback_tokens is None:
                raise RuntimeError(
                    "Audit callback token store is required when sandbox audit persistence is enabled"
                )
            audit_callback_token = self._audit_callback_tokens.issue()
        from shift_left.investigations.repo_root_paths import antares_visible_repo_root

        analysis_result, localization = await self._client.run_triage_query(
            repo=repo,
            ref=ref,
            repo_root=antares_visible_repo_root(checkout),
            task_cwe=resolved_cwe,
            task_cwe_description=cwe_description or "",
            max_terminal_calls=agent_cfg.max_terminal_calls,
            temperature=agent_cfg.temperature,
            top_p=agent_cfg.top_p,
            loop_control_enabled=agent_cfg.loop_control_enabled,
            model_variant=self._triage_cfg.model_variant,
            audit_callback_url=audit_callback_url,
            audit_callback_token=audit_callback_token,
            audit_actor=actor,
            audit_subject=f"{repo}@{ref}",
        )

        summary = ADVISORY_SUMMARY_TEMPLATE.format(
            cwe=resolved_cwe,
            repo=repo,
            ref=ref,
            variant=self._triage_cfg.model_variant,
            file_f1=PUBLISHED_FILE_F1.get(self._triage_cfg.model_variant, "unknown"),
        )
        if PROHIBITED_TRIAGE_WORDS.search(summary):
            raise RuntimeError("internal triage summary violated prohibited wording constraints")

        result = LocalizationResult(
            repo=repo,
            ref=ref,
            cwe_queried=resolved_cwe,
            ranked_files=localization.ranked_files,
            exploration_trace=localization.exploration_trace,
            turn_count=localization.turn_count,
            terminal_budget=localization.terminal_budget,
            loop_control_enabled=localization.loop_control_enabled,
            adapter_identity=localization.adapter_identity,
            generation_params=localization.generation_params,
            model_variant=self._triage_cfg.model_variant,
            model_version=self._triage_cfg.model_version,
            published_file_f1=PUBLISHED_FILE_F1.get(self._triage_cfg.model_variant),
            outcome=localization.outcome,
            summary_text=summary,
        )

        if not analysis_result.timings_ms:
            analysis_result = analysis_result.model_copy(
                update={"timings_ms": {"total": int((time.monotonic() - started) * 1000)}}
            )

        if store is not None and audit_callback_url is None and localization.sandbox_audit:
            persist_sandbox_command_audit(
                store,
                actor=actor,
                subject=f"{repo}@{ref}",
                events=[dict(entry) for entry in localization.sandbox_audit],
            )

        logger.info(
            "Antares triage completed actor=%s repo=%s ref=%s cwe=%s outcome=%s turns=%s investigation=%s",
            actor,
            repo,
            ref,
            resolved_cwe,
            result.outcome,
            result.turn_count,
            localization.investigation_id,
        )
        return result, analysis_result

    def _assert_minimum_variant(self) -> None:
        variant = self._triage_cfg.model_variant.lower()
        if "350m" in variant and self._triage_cfg.minimum_variant == "1b":
            raise RuntimeError(
                "Antares-350M is not supported for triage (published File F1 0.135). "
                "Stage Antares-1B minimum — see docs/antares-triage.md."
            )

    def estimated_latency_seconds(self, query_count: int) -> tuple[int, int]:
        low = 35 * query_count
        high = 90 * query_count
        return low, high

    @staticmethod
    def sanitize_output_text(text: str) -> str:
        return PROHIBITED_TRIAGE_WORDS.sub("[redacted]", text)
