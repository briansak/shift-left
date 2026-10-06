#!/usr/bin/env python3
"""Bundle-time compliance check — fails if license/NOTICE/attribution missing."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "shift-left-shared"))

from shift_left_shared.compliance import check_offline_bundle  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify offline bundle licensing compliance")
    parser.add_argument(
        "bundle_dir",
        type=Path,
        nargs="?",
        default=ROOT / "dist" / "offline-bundle",
        help="Offline bundle root (default: dist/offline-bundle)",
    )
    args = parser.parse_args()
    errors = check_offline_bundle(args.bundle_dir)
    if errors:
        print("Bundle compliance FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"Bundle compliance OK: {args.bundle_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
