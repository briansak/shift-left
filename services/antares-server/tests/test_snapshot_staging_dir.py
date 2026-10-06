"""Snapshot staging directory selection for Docker-visible bind mounts."""

from __future__ import annotations

from pathlib import Path

import pytest

from antares_server.snapshot_materialize import _make_snapshot_dir, remove_snapshot, snapshot_staging_dir


def test_snapshot_staging_dir_uses_repo_data_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTARES_SNAPSHOT_DIR", raising=False)
    monkeypatch.setenv("SHIFT_LEFT_REPO_ROOT", str(tmp_path))

    staging = snapshot_staging_dir()
    assert staging == tmp_path / "data" / "findings" / "antares-snapshots"
    assert staging.is_dir()


def test_make_snapshot_dir_honors_explicit_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    override = tmp_path / "shared-snapshots"
    monkeypatch.setenv("ANTARES_SNAPSHOT_DIR", str(override))

    created = _make_snapshot_dir()
    try:
        assert created.is_dir()
        assert created.parent == override.resolve()
    finally:
        remove_snapshot(created)
