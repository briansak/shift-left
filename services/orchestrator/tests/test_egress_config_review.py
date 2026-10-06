"""Config review with egress blocked — uses cached reference data only."""

from __future__ import annotations

import pytest

from shift_left.analysis.result import completed_with_findings
from shift_left.config import AppConfig
from shift_left.models.schema import (
    EnrichmentStatus,
    Finding,
    FindingSource,
    LineRange,
    Severity,
    TargetKind,
)
from shift_left.review.service import ReviewService
from shift_left.sovereignty.network import EgressBlockedError, EgressGuard
from shift_left.http.local_client import LocalOnlyAsyncClient

# *.yaml is config_globs but not a parser-claim extension, so the gate records
# CWE-657 and does not call Foundation-Sec. This diff is a claimed *.tf file
# with a scoped CIDR so the injected model finding is what gets cache enrichment.
CONFIG_DIFF = """diff --git a/infra/main.tf b/infra/main.tf
--- a/infra/main.tf
+++ b/infra/main.tf
@@ -1,6 +1,6 @@
 resource "aws_security_group_rule" "app_https" {
   type              = "ingress"
   from_port         = 443
   to_port           = 443
   protocol          = "tcp"
-  cidr_blocks       = ["10.1.0.0/16"]
+  cidr_blocks       = ["10.0.0.0/8"]
   security_group_id = aws_security_group.app.id
 }
"""


@pytest.mark.asyncio
async def test_config_review_completes_with_egress_blocked_and_cached_enrichment(
    tmp_path,
    reference_cache_dir,
    test_runtime_egress_endpoints,
) -> None:
    allowed = test_runtime_egress_endpoints
    config = AppConfig.model_validate(
        {
            "models": {
                "antares": {"enabled": False},
                "foundation_sec": {"enabled": True, "service_url": "http://127.0.0.1:8091"},
            },
            "reference_data": {
                "cache_dir": str(reference_cache_dir),
                "enrich_findings": True,
            },
            "findings_store": {"sqlite_path": str(tmp_path / "findings.db")},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )

    async def fake_foundation(**kwargs):
        finding = Finding(
            source=FindingSource.FOUNDATION_SEC,
            target_kind=TargetKind.CONFIG,
            repo=kwargs["repo"],
            pr_ref=kwargs["pr_ref"],
            commit_sha=kwargs["commit_sha"],
            file_path="infra/main.tf",
            line_range=LineRange(start=3, end=3),
            cwe="CWE-284",
            severity=Severity.HIGH,
            confidence=0.7,
            title="Overly permissive CIDR",
            description="0.0.0.0/0 in config diff",
        )
        return completed_with_findings(TargetKind.CONFIG, [finding])

    with EgressGuard(allowed_endpoints=allowed):
        service = ReviewService(config)
        service._foundation_sec.analyze_hunks = fake_foundation  # type: ignore[method-assign, union-attr]

        result = await service.review_diff(
            diff_text=CONFIG_DIFF,
            repo="test/demo",
            pr_ref="PR-egress-config",
            commit_sha="deadbeef",
        )

    model = next(item for item in result.findings if item.source == FindingSource.FOUNDATION_SEC)
    assert model.enrichment is not None
    assert model.enrichment.status == EnrichmentStatus.ENRICHED
    assert model.enrichment.cwe_detail

    client = LocalOnlyAsyncClient(allowed_endpoints=allowed)
    with pytest.raises(EgressBlockedError):
        await client.get("https://example.com")
