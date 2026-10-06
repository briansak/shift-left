"""Antares weight verification."""

from __future__ import annotations

from pathlib import Path

import pytest

from shift_left_shared.weights import (
    VERIFIED_ANTARES_1B,
    VERIFIED_ANTARES_350M,
    antares_manifest_meta_for_dir,
    load_prewarm_manifest,
    verify_antares_weights,
    WeightVerificationError,
)


def test_antares_manifest_meta_for_dir_resolves_by_folder_name() -> None:
    assert antares_manifest_meta_for_dir(Path("/tmp/models/1b")) == VERIFIED_ANTARES_1B
    assert antares_manifest_meta_for_dir(Path("/tmp/models/350m")) == VERIFIED_ANTARES_350M


def test_verify_antares_weights_requires_manifest_entry(tmp_path: Path) -> None:
    model_dir = tmp_path / "models" / "1b"
    model_dir.mkdir(parents=True)
    (model_dir / "model.safetensors").write_bytes(b"not-the-real-weights")
    with pytest.raises(WeightVerificationError):
        verify_antares_weights(model_dir, {"models": {}})


def test_verify_antares_1b_with_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path
    model_dir = repo / "models" / "1b"
    model_dir.mkdir(parents=True)
    weights = model_dir / "model.safetensors"
    weights.write_bytes(b"placeholder")

    def fake_sha256(path: Path) -> str:
        return VERIFIED_ANTARES_1B["sha256"]

    monkeypatch.setattr("shift_left_shared.weights.sha256_file", fake_sha256)
    manifest = {
        "models": {
            VERIFIED_ANTARES_1B["manifest_key"]: {
                "weight_filename": "model.safetensors",
                "sha256": VERIFIED_ANTARES_1B["sha256"],
            }
        }
    }
    resolved = verify_antares_weights(model_dir, manifest)
    assert resolved == weights
