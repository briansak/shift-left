"""NVD sync cursor and manifest fields."""

from __future__ import annotations

from pathlib import Path

from shift_left.reference.sync import sync_reference_cache


def test_sync_seed_writes_manifest_with_dual_timestamps(tmp_path, repo_root) -> None:
    cache_dir = tmp_path / "reference"
    manifest = sync_reference_cache(
        cache_dir,
        seed_dir=repo_root / "reference-seed",
        fetch_nvd=False,
    )
    assert manifest["synced_at"]
    assert "newest_last_modified" in manifest
    assert manifest["nvd_api_version"] == "nvd-api-2.0"

    on_disk = (cache_dir / "manifest.json").read_text()
    assert "synced_at" in on_disk
    assert (cache_dir / "cwe").exists()
    assert (cache_dir / "cve").exists()


def test_sync_cursor_file_created_on_nvd_fetch_attempt(tmp_path, repo_root, monkeypatch) -> None:
    cache_dir = tmp_path / "reference"

    def fake_fetch(*args, **kwargs):
        return {"added": 0, "newest_last_modified": None}

    monkeypatch.setattr("shift_left.reference.sync.sync_nvd_cves", fake_fetch)
    sync_reference_cache(
        cache_dir,
        seed_dir=repo_root / "reference-seed",
        fetch_nvd=True,
        resume=True,
    )
    assert (cache_dir / "manifest.json").exists()
