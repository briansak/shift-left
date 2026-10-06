"""Shared fixtures for orchestrator Phase 2 tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
ORCHESTRATOR_SRC = ROOT / "services" / "orchestrator"
FOUNDATION_SEC_SRC = ROOT / "services" / "foundation-sec-server"
SHARED_SRC = ROOT / "services" / "shift-left-shared"

for path in (SHARED_SRC, ORCHESTRATOR_SRC, FOUNDATION_SEC_SRC):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)


TEST_RUNTIME_EGRESS_ENDPOINTS: frozenset[tuple[str, int]] = frozenset(
    {
        ("127.0.0.1", 8090),
        ("127.0.0.1", 8091),
        ("127.0.0.1", 18090),
        ("127.0.0.1", 18091),
        ("localhost", 8090),
        ("localhost", 8091),
        ("::1", 8090),
        ("::1", 8091),
        ("forgejo", 3000),
    }
)


@pytest.fixture
def test_runtime_egress_endpoints() -> frozenset[tuple[str, int]]:
    return TEST_RUNTIME_EGRESS_ENDPOINTS


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@pytest.fixture
def reference_cache_dir(tmp_path: Path, repo_root: Path) -> Path:
    from shift_left.reference.sync import sync_reference_cache

    cache_dir = tmp_path / "reference"
    sync_reference_cache(cache_dir, seed_dir=repo_root / "reference-seed")
    return cache_dir
