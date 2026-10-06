"""Snapshot materialization hardening — symlinks, escapes, external hardlinks."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest

from antares_server.docker_sandbox import DockerInvestigationSandbox, docker_available
from antares_server.snapshot_materialize import (
    materialize_tree_snapshot,
    remove_snapshot,
    resolve_under_root,
)

SANDBOX_IMAGE = os.environ.get("ANTARES_SANDBOX_IMAGE", "shift-left-antares-sandbox:bookworm")


@pytest.fixture
def repo_root() -> Path:
    base = Path(__file__).resolve().parent / ".docker-workspace"
    base.mkdir(parents=True, exist_ok=True)
    root = base / f"symlink-case-{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)
    yield root
    shutil.rmtree(root, ignore_errors=True)


def _build_malicious_repo(repo: Path) -> dict[str, Path]:
    (repo / "safe.txt").write_text("safe-content\n", encoding="utf-8")
    links = {
        "passwd": repo / "link-passwd",
        "parent": repo / "link-parent",
        "docker_sock": repo / "link-docker-sock",
        "loop_a": repo / "loop-a",
        "loop_b": repo / "loop-b",
    }
    links["passwd"].symlink_to("/etc/passwd")
    links["parent"].symlink_to("../../")
    links["docker_sock"].symlink_to("/var/run/docker.sock")
    links["loop_a"].symlink_to("loop-b")
    links["loop_b"].symlink_to("loop-a")
    return links


def test_tree_snapshot_discards_symlinks(repo_root: Path) -> None:
    links = _build_malicious_repo(repo_root)
    snapshot = materialize_tree_snapshot(repo_root, max_bytes=1_000_000)
    try:
        assert (snapshot / "safe.txt").read_text(encoding="utf-8") == "safe-content\n"
        for name in links:
            assert not (snapshot / links[name].name).exists()
    finally:
        remove_snapshot(snapshot)


def test_resolve_under_root_rejects_escape(tmp_path: Path) -> None:
    root = tmp_path / "snap"
    root.mkdir()
    assert resolve_under_root(root, "app/db.py") is not None
    assert resolve_under_root(root, "../outside") is None
    assert resolve_under_root(root, "app/../../outside") is None


def test_external_hardlink_discarded(repo_root: Path) -> None:
    passwd = Path("/etc/passwd")
    if not passwd.is_file():
        pytest.skip("/etc/passwd unavailable")
    external = repo_root / "hard-passwd"
    try:
        os.link(passwd, external)
    except OSError as exc:
        pytest.skip(f"cannot create hardlink: {exc}")

    snapshot = materialize_tree_snapshot(repo_root, max_bytes=1_000_000)
    try:
        assert not (snapshot / "hard-passwd").exists()
    finally:
        remove_snapshot(snapshot)


@pytest.mark.skipif(not docker_available(), reason="Docker daemon not available")
class TestSymlinkDockerIsolation:
    @pytest.fixture(autouse=True)
    def ensure_image(self) -> None:
        result = pytest.importorskip("subprocess").run(
            ["docker", "image", "inspect", SANDBOX_IMAGE],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            repo_root = Path(__file__).resolve().parents[3]
            dockerfile = repo_root / "services" / "antares-server" / "Dockerfile.sandbox"
            build = pytest.importorskip("subprocess").run(
                ["docker", "build", "-f", str(dockerfile), "-t", SANDBOX_IMAGE, str(repo_root)],
                capture_output=True,
                text=True,
                check=False,
            )
            if build.returncode != 0:
                pytest.skip("sandbox image unavailable")

    def test_symlink_targets_absent_and_cat_fails(self, repo_root: Path) -> None:
        links = _build_malicious_repo(repo_root)
        snapshot = materialize_tree_snapshot(repo_root, max_bytes=1_000_000)
        sandbox = DockerInvestigationSandbox(snapshot, investigation_id=f"symlink-{uuid.uuid4().hex[:8]}")
        sandbox.start()
        try:
            for link_path in links.values():
                assert not (snapshot / link_path.name).exists()
                result = sandbox.execute(f"cat {link_path.name}")
                assert result.exit_code != 0 or "no such file" in result.output.lower()
        finally:
            sandbox.destroy()
            remove_snapshot(snapshot)
