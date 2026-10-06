"""On-demand load strategy: Antares and Foundation-Sec run sequentially without overlap.

The PEAK_RSS figure recorded here is **process RSS with mocked model clients** —
it validates load/unload ordering only, **not** GGUF/transformer weight residency
or capacity planning. Use ``scripts/validate-peak-memory.py`` with staged weights
for real peak memory numbers.
"""

from __future__ import annotations

import resource
import sys

import pytest

from shift_left.analysis.result import completed_no_findings, completed_with_findings
from shift_left.config import AppConfig
from shift_left.models.schema import (
    Finding,
    FindingSource,
    LineRange,
    Severity,
    TargetKind,
)
from shift_left.review.service import ReviewService

CODE_DIFF = """diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -2,3 +2,3 @@
 def lookup_user(username):
-    query = "SELECT * FROM users WHERE id = ?"
+    query = f"SELECT * FROM users WHERE username = '{username}'"
     cursor.execute(query)
"""

CONFIG_DIFF = """diff --git a/firewall/asa.rules b/firewall/asa.rules
--- a/firewall/asa.rules
+++ b/firewall/asa.rules
@@ -1,1 +1,1 @@
-access-list OUT extended permit tcp 10.0.0.0/8 any eq 443
+access-list OUT extended permit ip any any
"""

COMBINED = CODE_DIFF + "\n" + CONFIG_DIFF


def _peak_rss_bytes() -> int:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return int(usage.ru_maxrss)


def _format_peak_rss(peak_bytes: int) -> str:
    if sys.platform == "darwin":
        return f"{peak_bytes / (1024 * 1024):.2f} MiB"
    return f"{peak_bytes / 1024:.2f} MiB"


@pytest.mark.asyncio
async def test_on_demand_models_run_sequentially_without_simultaneous_residency(
    tmp_path,
    reference_cache_dir,
    capsys,
) -> None:
    timeline: list[str] = []
    rss_before = _peak_rss_bytes()

    config = AppConfig.model_validate(
        {
            "models": {
                "foundation_sec": {
                    "enabled": True,
                    "load_strategy": "on_demand",
                    "service_url": "http://127.0.0.1:18091",
                },
            },
            "reference_data": {
                "cache_dir": str(reference_cache_dir),
                "enrich_findings": True,
            },
            "findings_store": {"sqlite_path": str(tmp_path / "findings.db")},
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
        }
    )

    async def foundation_analyze(**kwargs):
        timeline.append("foundation_sec:loaded")
        finding = Finding(
            source=FindingSource.FOUNDATION_SEC,
            target_kind=TargetKind.CONFIG,
            repo=kwargs["repo"],
            pr_ref=kwargs["pr_ref"],
            commit_sha=kwargs["commit_sha"],
            file_path="firewall/asa.rules",
            line_range=LineRange(start=1, end=1),
            cwe="CWE-284",
            severity=Severity.HIGH,
            confidence=0.9,
            title="Overly permissive firewall rule (any/any ALLOW)",
            description="Permissive rule in diff",
        )
        return completed_with_findings(TargetKind.CONFIG, [finding])

    async def foundation_unload():
        timeline.append("foundation_sec:unloaded")

    service = ReviewService(config)
    service._foundation_sec.analyze_hunks = foundation_analyze  # type: ignore[method-assign, union-attr]

    original_unload_fs = service._unload_foundation_sec_if_on_demand

    async def tracked_unload_fs():
        await original_unload_fs()
        await foundation_unload()

    service._unload_foundation_sec_if_on_demand = tracked_unload_fs  # type: ignore[method-assign]

    result = await service.review_diff(
        diff_text=COMBINED,
        repo="test/demo",
        pr_ref="PR-memory",
        commit_sha="abc123",
    )

    peak_rss = max(_peak_rss_bytes(), rss_before)
    peak_label = _format_peak_rss(peak_rss)
    print(f"PEAK_RSS={peak_label} (mocked models — process RSS, not GGUF weights)")

    # dc9980ec adds deterministic config-handler findings before the model.
    # permit ip any any is ASA-001 (true positive). The mock Foundation-Sec
    # finding has no trace rule id, so it is kept beside the handler finding.
    assert len(result.findings) == 3
    by_source: dict[str, list] = {}
    for finding in result.findings:
        by_source.setdefault(finding.source.value, []).append(finding)
    assert set(by_source) == {"code-handler", "handler", "foundation-sec"}
    assert any("sqli-dynamic-query" in (item.trace or "") for item in by_source["code-handler"])
    assert any("ASA-001" in (item.trace or "") for item in by_source["handler"])
    assert by_source["foundation-sec"][0].cwe == "CWE-284"
    assert timeline == [
        "foundation_sec:loaded",
        "foundation_sec:unloaded",
    ]
    assert peak_rss > 0

    captured = capsys.readouterr()
    assert "PEAK_RSS=" in captured.out
