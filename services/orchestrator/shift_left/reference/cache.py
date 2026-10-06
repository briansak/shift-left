"""Reference data cache — runtime read-only; populated by operator sync only."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class ReferenceDataCache:
    """
    Local CVE/CWE/advisory store.

    Runtime reads from disk only. Populated by `shift-left sync-reference-data`.
    """

    def __init__(self, cache_dir: str | Path, *, max_staleness_days: int = 30) -> None:
        self._dir = Path(cache_dir)
        self.max_staleness_days = max_staleness_days

    @property
    def manifest_path(self) -> Path:
        return self._dir / "manifest.json"

    def is_present(self) -> bool:
        return self.manifest_path.exists()

    def load_manifest(self) -> dict:
        if not self.is_present():
            return {}
        return json.loads(self.manifest_path.read_text())

    def cache_status(self) -> dict:
        manifest = self.load_manifest()
        if not manifest:
            return {
                "present": False,
                "stale": True,
                "synced_at": None,
                "newest_last_modified": None,
                "newest_last_modified_source": "cache_absent",
                "newest_last_modified_note": (
                    "No reference cache manifest — run sync from local seed or operator-initiated NVD sync."
                ),
                "data_version": None,
            }
        synced_at = manifest.get("synced_at")
        stale = self._is_stale(synced_at)
        newest = manifest.get("newest_last_modified")
        derived = False
        if newest is None and self.is_present():
            newest = self._derive_newest_last_modified()
            derived = newest is not None
        unavailable_note = None
        if newest is None:
            cve_dir = self._dir / "cve"
            if not cve_dir.is_dir():
                unavailable_note = (
                    "No cve/ directory under cache — ingest CVE JSON via sync-reference-data."
                )
            elif not any(cve_dir.glob("*.json")):
                unavailable_note = "CVE cache directory is empty — sync reference data first."
            else:
                unavailable_note = (
                    "CVE JSON files lack lastModified fields — re-sync from NVD seed or fetch."
                )
        return {
            "present": True,
            "stale": stale,
            "synced_at": synced_at,
            "newest_last_modified": newest,
            "newest_last_modified_source": (
                "manifest"
                if manifest.get("newest_last_modified")
                else "derived_from_cve_cache"
                if derived
                else "unavailable"
            ),
            "newest_last_modified_note": unavailable_note,
            "data_version": manifest.get("data_version"),
            "cwe_catalog_version": manifest.get("cwe_catalog_version"),
            "nvd_api_version": manifest.get("nvd_api_version"),
            "cve_count": manifest.get("cve_count", 0),
            "cwe_count": manifest.get("cwe_count", 0),
        }

    def _is_stale(self, synced_at: str | None) -> bool:
        if not synced_at:
            return True
        try:
            synced = datetime.fromisoformat(synced_at.replace("Z", "+00:00"))
        except ValueError:
            return True
        age_days = (datetime.now(timezone.utc) - synced.astimezone(timezone.utc)).days
        return age_days > self.max_staleness_days

    def _derive_newest_last_modified(self) -> str | None:
        """Scan ingested CVE JSON when manifest field was never written."""
        cve_dir = self._dir / "cve"
        if not cve_dir.is_dir():
            return None
        newest: str | None = None
        for path in cve_dir.glob("*.json"):
            try:
                payload = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            candidate = payload.get("lastModified") or payload.get("last_modified")
            if not candidate:
                continue
            if newest is None or str(candidate) > newest:
                newest = str(candidate)
        return newest

    def lookup_cwe(self, cwe_id: str) -> dict | None:
        normalized = cwe_id.upper().replace("CWE-", "CWE-")
        if not normalized.startswith("CWE-"):
            normalized = f"CWE-{normalized.replace('CWE', '')}"
        path = self._dir / "cwe" / f"{normalized}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def lookup_cve(self, cve_id: str) -> dict | None:
        normalized = cve_id.upper()
        path = self._dir / "cve" / f"{normalized}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())

    # Backward-compatible alias
    def enrich_cve(self, cve_id: str) -> dict | None:
        return self.lookup_cve(cve_id)
