"""Operator-run reference data sync — the ONLY component permitted egress."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def sync_reference_data(root: Path, *, fetch_nvd: bool = False) -> None:
    orchestrator_src = root / "services" / "orchestrator"
    sys.path.insert(0, str(orchestrator_src))

    from shift_left.reference.sync import sync_reference_cache

    cache_dir = root / "data" / "reference"
    seed_dir = root / "reference-seed"
    nvd_api_key = os.environ.get("NVD_API_KEY") or None

    print("Syncing local reference data (operator-initiated egress only)...")
    if fetch_nvd:
        print("Fetching/resuming NVD CVE records (API 2.0 windows + cursor)...")
        if nvd_api_key:
            print("Using NVD_API_KEY for higher rate limits.")

    manifest = sync_reference_cache(
        cache_dir,
        seed_dir=seed_dir,
        fetch_nvd=fetch_nvd,
        nvd_api_key=nvd_api_key,
        resume=True,
    )
    print(f"Reference cache updated: {cache_dir}")
    print(
        f"  version={manifest.get('data_version')} "
        f"cwe={manifest.get('cwe_count')} cve={manifest.get('cve_count')}"
    )
    print(f"  synced_at={manifest.get('synced_at')}")
    print(f"  newest_last_modified={manifest.get('newest_last_modified')}")
