#!/usr/bin/env python3
"""Fail CI if UI assets reference external origins."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "services" / "orchestrator"
sys.path.insert(0, str(ORCH))

from shift_left.ui.sovereignty import scan_external_asset_references  # noqa: E402


def main() -> int:
    violations = scan_external_asset_references()
    if violations:
        for item in violations:
            print(item, file=sys.stderr)
        return 1
    print("UI asset scan: no external references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
