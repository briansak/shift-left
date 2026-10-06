"""E2E: Terraform PR diff → enriched findings; advisory stays off the PR comment."""

from __future__ import annotations

from typing import Any

import pytest

from shift_left.analysis.result import completed_with_findings
from shift_left.config import AppConfig
from shift_left.foundation_sec.client import FoundationSecClient
from shift_left.git.protocol import GitBackendKind
from shift_left.models.schema import EnrichmentStatus, ReviewRequest, TargetKind
from shift_left.review.service import ReviewService

TERRAFORM_DIFF = """diff --git a/infra/main.tf b/infra/main.tf
--- a/infra/main.tf
+++ b/infra/main.tf
@@ -1,8 +1,8 @@
 resource "aws_security_group_rule" "wide_ingress" {
   type              = "ingress"
   from_port         = 0
   to_port           = 65535
   protocol          = "-1"
-  cidr_blocks       = ["10.0.0.0/8"]
+  cidr_blocks       = ["0.0.0.0/0"]
   security_group_id = aws_security_group.app.id
 }
"""


class MockGitBackend:
    kind = GitBackendKind.BUNDLED_FORGEJO
    provider_label = "mock-forgejo"
    is_sovereign = True

    def __init__(self, diff_text: str) -> None:
        self.diff_text = diff_text
        self.comments: list[str] = []

    async def get_pull_request(
        self, owner: str, repo: str, pr_number: int
    ) -> dict[str, Any]:
        return {"head": {"sha": "cafebabe"}, "number": pr_number}

    async def get_pull_diff(self, owner: str, repo: str, pr_number: int) -> str:
        return self.diff_text

    async def post_pull_request_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
    ) -> dict[str, Any]:
        self.comments.append(body)
        return {"id": len(self.comments)}

    async def health(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_terraform_pr_produces_enriched_comment(
    tmp_path,
    reference_cache_dir,
) -> None:
    from foundation_sec_server.analyzer import ConfigAnalyzer
    from foundation_sec_server.engine import ScriptedEvalEngine

    analyzer = ConfigAnalyzer(ScriptedEvalEngine())

    async def scripted_analyze_hunks(**kwargs):
        payload = [
            {
                "path": f.path,
                "hunks": [
                    {
                        "new_start": h.new_start,
                        "new_end": h.new_end,
                        "content": h.content,
                    }
                    for h in f.hunks
                ],
            }
            for f in kwargs["files"]
        ]
        raw_result = analyzer.analyze_files(payload)
        findings = [
            FoundationSecClient._normalize(
                item,
                kwargs["repo"],
                kwargs["pr_ref"],
                kwargs["commit_sha"],
            )
            for item in raw_result["findings"]
        ]
        return completed_with_findings(TargetKind.CONFIG, findings)

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

    git = MockGitBackend(TERRAFORM_DIFF)
    service = ReviewService(config)
    service._git = git
    service._foundation_sec.analyze_hunks = scripted_analyze_hunks  # type: ignore[method-assign, union-attr]

    result = await service.review_pull_request(
        ReviewRequest(owner="acme", repo="infra", pr_number=42)
    )

    assert result.findings, "expected Terraform finding from scripted engine"
    handler = next(item for item in result.findings if item.trace == "handler:TF-001")
    model = next(item for item in result.findings if item.source.value == "foundation-sec")
    assert handler.handler_asserted_cwe == "CWE-284"
    assert model.cwe == "CWE-284"
    assert model.enrichment is not None
    assert model.enrichment.status in {
        EnrichmentStatus.ENRICHED,
        EnrichmentStatus.PARTIAL,
    }
    assert model.enrichment.cwe_detail

    assert git.comments, "expected PR comment to be posted"
    comment = git.comments[0]
    assert "advisory finding(s) omitted" in comment
    assert "Shift-Left UI" in comment
    assert "CWE detail (cache)" not in comment
    assert model.title not in comment
    assert handler.title in comment
    assert "Policy decision" in comment
