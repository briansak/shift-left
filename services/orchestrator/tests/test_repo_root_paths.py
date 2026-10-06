"""Host-visible repo_root mapping for containerized orchestrator + host-native Antares."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from shift_left.config import AppConfig
from shift_left.investigations import repo_root_paths
from shift_left.investigations.repo_root_paths import (
    antares_visible_repo_root,
    investigation_worktree_path,
    investigation_worktree_root,
)


@pytest.fixture(autouse=True)
def _clear_host_repo_root_cache() -> None:
    repo_root_paths._host_repo_root.cache_clear()
    yield
    repo_root_paths._host_repo_root.cache_clear()


def test_investigation_worktree_root_under_findings_db(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "schema_version": 11,
            "investigations": {"sqlite_path": str(tmp_path / "data" / "findings" / "investigations.db")},
        }
    )
    assert investigation_worktree_root(config) == tmp_path / "data" / "findings" / "investigation-worktrees"
    assert investigation_worktree_path(config, "inv-1") == (
        tmp_path / "data" / "findings" / "investigation-worktrees" / "inv-1" / "tree"
    )


def test_antares_visible_repo_root_maps_shift_left_prefix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    host = tmp_path / "host-repo"
    host.mkdir()
    monkeypatch.setenv("SHIFT_LEFT_HOST_REPO_ROOT", str(host))
    monkeypatch.setenv("SHIFT_LEFT_REPO_ROOT", "/shift-left")

    mapped = antares_visible_repo_root(Path("/shift-left/data/repos/localdemo/celery-corpus"))
    assert mapped == str(host / "data/repos/localdemo/celery-corpus")


def test_antares_visible_repo_root_maps_data_findings_worktree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    host = tmp_path / "host-repo"
    host.mkdir()
    monkeypatch.setenv("SHIFT_LEFT_HOST_REPO_ROOT", str(host))

    mapped = antares_visible_repo_root(
        Path("/data/findings/investigation-worktrees/abc/tree")
    )
    assert mapped == str(host / "data/findings/investigation-worktrees/abc/tree")


def test_antares_visible_repo_root_passthrough_without_host_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SHIFT_LEFT_HOST_REPO_ROOT", raising=False)
    monkeypatch.setattr(repo_root_paths, "_DOCKER_SOCKET", tmp_path / "missing.sock")
    local = tmp_path / "repos" / "demo" / "app"
    local.mkdir(parents=True)
    assert antares_visible_repo_root(local) == str(local.resolve())


def test_host_repo_root_from_docker_inspect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host = tmp_path / "host-repo"
    host.mkdir()
    docker_sock = tmp_path / "docker.sock"
    docker_sock.touch()
    monkeypatch.setenv("HOSTNAME", "container-1")
    monkeypatch.setattr(repo_root_paths, "_DOCKER_SOCKET", docker_sock)

    def fake_run(cmd, **kwargs):
        assert cmd[:3] == ["docker", "inspect", "container-1"]
        response = MagicMock()
        response.returncode = 0
        response.stdout = json.dumps(
            [{"Destination": "/shift-left", "Source": str(host), "Type": "bind"}]
        )
        return response

    with (
        patch.object(Path, "is_socket", return_value=True),
        patch("shift_left.investigations.repo_root_paths.subprocess.run", side_effect=fake_run),
    ):
        assert repo_root_paths._host_repo_root_from_docker_inspect() == host.resolve()
