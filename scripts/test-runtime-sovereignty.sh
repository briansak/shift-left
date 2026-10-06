#!/usr/bin/env bash
# Runtime sovereignty test: code + config review with egress disabled.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VENV="${ROOT}/.venv-sovereignty-test"
if [[ ! -x "${VENV}/bin/python" ]]; then
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install -q -e "${ROOT}/services/shift-left-shared"
  "${VENV}/bin/pip" install -q -e "${ROOT}/services/orchestrator"
fi

echo "=== Shift-Left runtime sovereignty test ==="
echo "Full code + config review with socket egress guard enabled."
echo

export PYTHONPATH="${ROOT}/services/orchestrator${PYTHONPATH:+:$PYTHONPATH}"

"${VENV}/bin/python" - <<'PY'
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path("services/orchestrator").resolve()))

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
from shift_left.sovereignty.network import EgressBlockedError, EgressGuard
from shift_left.http.local_client import LocalOnlyAsyncClient

CODE_DIFF = """diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -2,3 +2,3 @@
 def lookup_user(username):
-    query = "SELECT * FROM users WHERE id = ?"
+    query = f"SELECT * FROM users WHERE username = '{username}'"
     cursor.execute(query)
"""

CONFIG_DIFF = """diff --git a/deploy/service.yaml b/deploy/service.yaml
--- a/deploy/service.yaml
+++ b/deploy/service.yaml
@@ -2,3 +2,3 @@
 spec:
   ports:
-    - cidr: 10.0.0.0/8
+    - cidr: 0.0.0.0/0
"""

COMBINED = CODE_DIFF + "\n" + CONFIG_DIFF


async def main():
    config = AppConfig.model_validate(
        {
            "models": {
                "antares": {"enabled": True, "service_url": "http://127.0.0.1:18090"},
                "foundation_sec": {"enabled": True, "service_url": "http://127.0.0.1:18091"},
            },
            "findings_store": {"sqlite_path": "/tmp/shift-left-sovereignty-test.db"},
            "forgejo": {"url": "http://forgejo:3000", "token": "test-token"},
        }
    )

    allowed = frozenset({"127.0.0.1", "localhost", "forgejo", "::1"})

    async def fake_foundation(**kwargs):
        return completed_with_findings(
            TargetKind.CONFIG,
            [
                Finding(
                source=FindingSource.FOUNDATION_SEC,
                target_kind=TargetKind.CONFIG,
                repo=kwargs["repo"],
                pr_ref=kwargs["pr_ref"],
                commit_sha=kwargs["commit_sha"],
                file_path="deploy/service.yaml",
                line_range=LineRange(start=3, end=3),
                handler_asserted_cwe="CWE-284",
                model_asserted_severity=Severity.HIGH,
                confidence=0.7,
                title="Overly permissive CIDR",
                description="0.0.0.0/0 in config diff",
            )
            ],
        )

    all_findings = []
    with EgressGuard(allowed_hosts=allowed):
        service = ReviewService(config)
        service._foundation_sec.analyze_hunks = fake_foundation  # type: ignore[method-assign, union-attr]

        code_result = await service.review_diff(
            diff_text=CODE_DIFF,
            repo="test/demo",
            pr_ref="PR-sovereignty-code",
            commit_sha="deadbeef",
        )
        config_result = await service.review_diff(
            diff_text=CONFIG_DIFF,
            repo="test/demo",
            pr_ref="PR-sovereignty-config",
            commit_sha="deadbeef",
        )
        all_findings = code_result.findings + config_result.findings

    code = [f for f in all_findings if f.target_kind == TargetKind.CODE]
    config_f = [f for f in all_findings if f.target_kind == TargetKind.CONFIG]
    assert code, "missing code review findings"
    assert config_f, "missing config review findings"
    print(f"Code review findings: {len(code)}")
    print(f"Config review findings: {len(config_f)}")

    client = LocalOnlyAsyncClient(allowed_hosts=allowed)
    try:
        await client.get("https://example.com")
        raise AssertionError("external HTTP was not blocked")
    except EgressBlockedError:
        print("HTTP egress to example.com correctly blocked")

    try:
        with EgressGuard(allowed_hosts=allowed):
            import socket

            socket.create_connection(("1.1.1.1", 443), timeout=1.0)
        raise AssertionError("socket egress was not blocked")
    except (EgressBlockedError, OSError):
        print("Socket egress to 1.1.1.1 correctly blocked")

    print("Runtime sovereignty test PASSED")


asyncio.run(main())
PY

echo
echo "All runtime sovereignty checks passed."
