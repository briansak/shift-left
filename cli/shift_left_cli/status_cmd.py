"""./shift-left status — print prerequisite summary."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from shift_left_cli.up import load_dotenv


def operator_status(root: Path) -> int:
    load_dotenv(root)
    port = os.environ.get("ORCHESTRATOR_PORT", "8080")
    url = f"http://127.0.0.1:{port}/api/v1/system/prerequisites?refresh=true"
    try:
        request = urllib.request.Request(url)  # noqa: S310
        with urllib.request.urlopen(request, timeout=30) as response:
            report = json.loads(response.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return _status_offline(root)
    overall = report.get("overall_state", "unknown")
    print(f"Overall: {str(overall).upper()} — {report.get('summary', '')}")
    for check in report.get("checks") or []:
        if check.get("ok"):
            continue
        print(f"  [{check.get('criticality')}] {check.get('id')}: {check.get('error') or check.get('status')}")
    return 0 if overall == "healthy" else 1


def _status_offline(root: Path) -> int:
    config = root / "config" / "shift-left.yaml"
    if not config.exists():
        print("Setup incomplete — run ./shift-left up")
        return 1
    print("Orchestrator not reachable — run ./shift-left up or ./shift-left doctor")
    return 1
