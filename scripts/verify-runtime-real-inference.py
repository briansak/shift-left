#!/usr/bin/env python3
"""
Runtime sovereignty with real local inference (Antares + Foundation-Sec on loopback).

Requires host-native model servers on 127.0.0.1:8090 and :8091 with staged weights.
Runs full code + config review under socket/HTTP egress guards — no mocks.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "services" / "shift-left-shared", ROOT / "services" / "orchestrator"):
    sys.path.insert(0, str(path))

import httpx  # noqa: E402

from shift_left.config import AppConfig  # noqa: E402
from shift_left.http.local_client import LocalOnlyAsyncClient  # noqa: E402
from shift_left.models.schema import TargetKind  # noqa: E402
from shift_left.review.service import ReviewService  # noqa: E402
from shift_left.sovereignty.network import EgressBlockedError, EgressGuard  # noqa: E402
from shift_left_shared.network import run_egress_probe  # noqa: E402


def _assert_egress_probe_not_skipped() -> None:
    if os.environ.get("SHIFT_LEFT_SKIP_EGRESS_PROBE", "").lower() in {"1", "true", "yes"}:
        raise SystemExit(
            "SHIFT_LEFT_SKIP_EGRESS_PROBE is set — startup egress probe was bypassed. "
            "Unset it for verify-runtime --real, or use mocked ./scripts/shift-left verify-runtime."
        )


def _assert_host_egress_blocked() -> None:
    result = run_egress_probe()
    if not result.ok:
        print(f"Startup egress probe: {result.message}")
        return
    raise SystemExit(
        "Host can reach the public internet (egress probe succeeded to 1.1.1.1:443). "
        "verify-runtime --real expects an air-gapped or firewall-blocked host. "
        "On internet-connected dev machines, use mocked verify-runtime instead."
    )

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
@@ -1,2 +1,2 @@
-access-list OUT extended permit tcp 10.0.1.0/24 10.0.2.0/24 eq 443
+access-list OUT extended permit ip any any
 access-list OUT extended deny ip any any
"""

ALLOWED = frozenset(
    {
        ("127.0.0.1", 8090),
        ("127.0.0.1", 8091),
        ("localhost", 8090),
        ("localhost", 8091),
        ("::1", 8090),
        ("::1", 8091),
        ("forgejo", 3000),
    }
)


def _require_servers() -> None:
    for port, name in ((8090, "Antares"), (8091, "Foundation-Sec")):
        try:
            resp = httpx.get(f"http://127.0.0.1:{port}/health", timeout=5.0)
            resp.raise_for_status()
        except Exception as exc:
            raise SystemExit(
                f"{name} not reachable at 127.0.0.1:{port} — start host-native servers first "
                f"(see README §3 / §3b). ({exc})"
            ) from exc


async def main() -> None:
    _assert_egress_probe_not_skipped()
    _assert_host_egress_blocked()
    _require_servers()

    ref_cache = ROOT / "data" / "reference"
    if not ref_cache.is_dir():
        raise SystemExit(f"Reference cache missing at {ref_cache} — run ./scripts/shift-left sync-reference-data")

    config = AppConfig.model_validate(
        {
            "models": {
                "antares": {
                    "enabled": True,
                    "service_url": "http://127.0.0.1:8090",
                    "load_strategy": "on_demand",
                },
                "foundation_sec": {
                    "enabled": True,
                    "service_url": "http://127.0.0.1:8091",
                    "load_strategy": "on_demand",
                },
            },
            "reference_data": {
                "cache_dir": str(ref_cache),
                "enrich_findings": True,
            },
            "findings_store": {"sqlite_path": "/tmp/shift-left-verify-runtime-real.db"},
            "git": {
                "backend": "bundled-forgejo",
                "bundled": {"url": "http://forgejo:3000", "token_env": "FORGEJO_TOKEN"},
            },
        }
    )

    os.environ.setdefault("FORGEJO_TOKEN", "verify-runtime-local")

    with EgressGuard(allowed_endpoints=ALLOWED):
        service = ReviewService(config)

        code_result = await service.review_diff(
            diff_text=CODE_DIFF,
            repo="test/demo",
            pr_ref="PR-verify-runtime-code",
            commit_sha="deadbeef",
        )
        config_result = await service.review_diff(
            diff_text=CONFIG_DIFF,
            repo="test/demo",
            pr_ref="PR-verify-runtime-config",
            commit_sha="deadbeef",
        )

    code = [f for f in code_result.findings if f.target_kind == TargetKind.CODE]
    config_f = [f for f in config_result.findings if f.target_kind == TargetKind.CONFIG]

    for label, result in (("Antares", code_result), ("Foundation-Sec", config_result)):
        for analysis in result.analysis_results:
            if analysis.incomplete:
                raise SystemExit(
                    f"{label} analysis incomplete: {analysis.failure_message or analysis.failure_class}"
                )

    print(f"Code review findings: {len(code)}")
    print(f"Config review findings: {len(config_f)}")

    client = LocalOnlyAsyncClient(allowed_endpoints=ALLOWED)
    try:
        await client.get("https://example.com")
        raise SystemExit("external HTTP was not blocked")
    except EgressBlockedError:
        print("HTTP egress to example.com correctly blocked")

    try:
        with EgressGuard(allowed_endpoints=ALLOWED):
            import socket

            socket.create_connection(("1.1.1.1", 443), timeout=1.0)
        raise SystemExit("socket egress was not blocked")
    except (EgressBlockedError, OSError):
        print("Socket egress to 1.1.1.1 correctly blocked")

    print("Runtime sovereignty verification with real inference PASSED")


if __name__ == "__main__":
    asyncio.run(main())
