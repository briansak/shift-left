"""Full review succeeds with empty reference cache — findings marked un-enriched."""

from __future__ import annotations

import pytest

from shift_left.analysis.result import completed_no_findings
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

CODE_DIFF = """diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -1,1 +1,2 @@
-old
+cursor.execute("SELECT 1")
+new
"""


@pytest.mark.asyncio
async def test_full_review_with_empty_cache_produces_unenriched_findings_no_network(
    tmp_path,
    test_runtime_egress_endpoints,
) -> None:
    allowed = test_runtime_egress_endpoints
    config = AppConfig.model_validate(
        {
            "models": {"foundation_sec": {"enabled": False}},
            "reference_data": {
                "cache_dir": str(tmp_path / "missing-reference"),
                "enrich_findings": True,
            },
            "findings_store": {"sqlite_path": str(tmp_path / "findings.db")},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )

    with EgressGuard(allowed_endpoints=allowed):
        service = ReviewService(config)

        result = await service.review_diff(
            diff_text=CODE_DIFF,
            repo="test/demo",
            pr_ref="PR-empty-cache",
            commit_sha="deadbeef",
        )

    assert result.findings
    assert result.findings[0].enrichment is not None
    assert result.findings[0].enrichment.status == EnrichmentStatus.CACHE_EMPTY

    client = LocalOnlyAsyncClient(allowed_endpoints=allowed)
    with pytest.raises(EgressBlockedError):
        await client.get("https://example.com")
